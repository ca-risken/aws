package cloudsploit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/datasource-api/pkg/message"
)

type CloudsploitConfig struct {
	ResultDir       string
	ConfigDir       string
	CloudsploitDir  string
	ConfigPath      string
	MaxMemSizeMB    int
	ParallelScanNum int

	assumeRole string
	externalID string
	logger     logging.Logger
}

func NewCloudsploitConfig(
	resultDir string,
	configDir string,
	cloudsploitDir string,
	region string,
	maxMem int,
	parallelScanNum int,
	l logging.Logger,
) *CloudsploitConfig {
	return &CloudsploitConfig{
		ResultDir:       resultDir,
		ConfigDir:       configDir,
		CloudsploitDir:  cloudsploitDir,
		MaxMemSizeMB:    maxMem,
		ParallelScanNum: parallelScanNum,
		logger:          l,
	}
}

func (s *SqsHandler) run(ctx context.Context, msg *message.AWSQueueMessage) ([]*cloudSploitResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	now := time.Now().UnixNano()
	if s.cloudsploitConf.MaxMemSizeMB > 0 {
		os.Setenv("NODE_OPTIONS", fmt.Sprintf("--max-old-space-size=%d", s.cloudsploitConf.MaxMemSizeMB))
	}
	err := s.cloudsploitConf.generate(ctx, msg.AssumeRoleArn, msg.ExternalID, msg.AWSID, msg.AccountID)
	if err != nil {
		return nil, err
	}
	defer os.Remove(s.cloudsploitConf.ConfigPath)

	var results []*cloudSploitResult
	var wg sync.WaitGroup
	resultChan := make(chan []*cloudSploitResult)
	errChan := make(chan error, 1)
	s.logger.Debugf(ctx, "exec parallel scan: accountID=%s, plugins=%d, parallelScanNum=%d, maxMemSizeMB=%d",
		msg.AccountID, len(s.cloudsploitSetting.SpecificPluginSetting), s.cloudsploitConf.ParallelScanNum, s.cloudsploitConf.MaxMemSizeMB)
	semaphore := make(chan struct{}, s.cloudsploitConf.ParallelScanNum) // parallel scan
	for plugin := range s.cloudsploitSetting.SpecificPluginSetting {
		if s.cloudsploitSetting.IsIgnorePlugin(plugin) {
			continue
		}
		split := strings.Split(plugin, "/")
		if len(split) < 2 {
			return nil, fmt.Errorf("invalid plugin format: plugin=%s", plugin)
		}
		category := split[0]
		pluginName := split[1]

		wg.Add(1)
		go func(accountID, category, pluginName string, now int64) {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}: // get semaphore
				s.logger.Debugf(ctx, "start scan: accountID=%s, category=%s, plugin=%s", accountID, category, pluginName)
				startUnix := time.Now().Unix()
				pluginResults, err := s.scan(ctx, accountID, category, pluginName, now)
				<-semaphore // release semaphore immediately after scan
				if err != nil {
					errChan <- fmt.Errorf("accountID=%s, category=%s, plugin=%s, error=%w", accountID, category, pluginName, err)
					cancel()
					return
				}
				endUnix := time.Now().Unix()
				s.logger.Debugf(ctx, "end scan: accountID=%s, category=%s, plugin=%s, time=%d(sec)", accountID, category, pluginName, endUnix-startUnix)
				resultChan <- pluginResults
			case <-ctx.Done(): // handle parent cancel
				return
			}
		}(msg.AccountID, category, pluginName, now)
	}
	go func() {
		wg.Wait()
		close(resultChan)
		close(errChan)
	}()

	if len(errChan) > 0 {
		return nil, fmt.Errorf("scan error: %w", <-errChan) // return first error
	}
	for res := range resultChan {
		results = append(results, res...)
	}

	// add meta data
	results, err = s.addMetaData(ctx, msg.AccountID, results)
	if err != nil {
		return nil, err
	}
	// remove ignore plugin
	results = s.removeIgnorePlugin(ctx, results)
	return results, nil
}

func (s *SqsHandler) scan(ctx context.Context, accountID, category, pluginName string, scanUnixNano int64) ([]*cloudSploitResult, error) {
	filePath := fmt.Sprintf("%s/%s_%s_%s_%d.json", s.cloudsploitConf.ResultDir, accountID, category, pluginName, scanUnixNano)
	if fileExists(filePath) {
		return nil, fmt.Errorf("result file already exists: file=%s", filePath)
	}
	defer os.Remove(filePath)

	cmd := exec.CommandContext(ctx, fmt.Sprintf("%s/index.js", s.cloudsploitConf.CloudsploitDir),
		"--config", s.cloudsploitConf.ConfigPath,
		"--console", "none",
		"--plugin", pluginName,
		"--json", filePath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed exec cloudsploit. error: %w, detail: %s", err, stderr.String())
	}

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, EmptyOutputError{errors.New("scan output file is empty")}
	}

	var results []*cloudSploitResult
	if err := json.Unmarshal(buf, &results); err != nil {
		return nil, fmt.Errorf("json parse error(scan output file): output_length=%d, err=%v", len(string(buf)), err)
	}
	return results, nil
}

type cloudSploitResult struct {
	// CloudSpliot Scan Result
	Plugin      string `json:"Plugin"`
	Category    string `json:"Category"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Resource    string `json:"Resource"`
	Region      string `json:"Region"`
	Status      string `json:"Status"`
	Message     string `json:"Message"`

	// MetaData
	AccountID                      string   `json:"AccountID"`
	SecurityGroupAttachedResources []string `json:"SecurityGroupAttachedResources,omitempty"`
	AliasResourceName              string   `json:"AliasResourceName,omitempty"`
}

const (
	WARN_MESSAGE                   = "UNKNOWN status detected. Some scans may have failed. Please take action if you don't have enough permissions."
	STATUS_DETAIL_LENGTH_THRESHOLD = 30000
	LOW_SCORE                      = 3.0
)

func unknownFindings(findings []*cloudSploitResult) string {
	unknowns := map[string]int{}
	for _, f := range findings {
		if f.Status == resultUNKNOWN {
			unknowns[fmt.Sprintf("%s: %s", f.Category, f.Message)]++
		}
	}
	statusDetail := ""
	for k := range unknowns {
		unknown := fmt.Sprintf("- %s\n", k)
		statusDetail += unknown
		if STATUS_DETAIL_LENGTH_THRESHOLD <= len(statusDetail) {
			statusDetail += " ..."
			break
		}
	}
	if statusDetail != "" {
		statusDetail = fmt.Sprintf("%s\n\n%s", WARN_MESSAGE, statusDetail)
	}
	return statusDetail
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type SecurityGroupMetaData struct {
	SecurityGroupAttachedResources []string
	AliasResourceName              string
}

func (s *SqsHandler) addMetaData(ctx context.Context, accountID string, findings []*cloudSploitResult) ([]*cloudSploitResult, error) {
	availableRegions, err := s.cloudsploitConf.listAvailableRegion(ctx)
	if err != nil {
		return nil, err
	}
	updatedFindings := []*cloudSploitResult{}
	cacheSgMetaData := map[string]*SecurityGroupMetaData{} // prevent duplicate request
	for _, f := range findings {
		f.AccountID = accountID
		sgMeta, err := s.addSecurityGroupMetaData(ctx, *f, availableRegions, cacheSgMetaData)
		if err != nil {
			return nil, err
		}
		if sgMeta != nil {
			cacheSgMetaData[f.Resource] = sgMeta
			f.SecurityGroupAttachedResources = sgMeta.SecurityGroupAttachedResources
			f.AliasResourceName = sgMeta.AliasResourceName
		}
		updatedFindings = append(updatedFindings, f)
	}
	return updatedFindings, nil
}

func (s *SqsHandler) addSecurityGroupMetaData(ctx context.Context, f cloudSploitResult, availableRegions map[string]bool, cacheSgMetaData map[string]*SecurityGroupMetaData) (*SecurityGroupMetaData, error) {
	sgMeta := SecurityGroupMetaData{}

	if sgMeta, ok := cacheSgMetaData[f.Resource]; ok {
		return sgMeta, nil
	}
	if f.Status != resultFAIL {
		return nil, nil
	}
	if !isSecurityGroupResource(&f) {
		return nil, nil
	}
	if ok := availableRegions[f.Region]; !ok {
		return nil, nil
	}
	sgPlugin, ok := s.cloudsploitSetting.SpecificPluginSetting[fmt.Sprintf("%s/%s", f.Category, f.Plugin)]
	if !ok || sgPlugin.Score == nil || *sgPlugin.Score <= LOW_SCORE {
		return nil, nil
	}

	client, err := newEC2Session(ctx, s.cloudsploitConf.assumeRole, s.cloudsploitConf.externalID, f.Region)
	if err != nil || client == nil {
		return nil, fmt.Errorf("failed to create ec2 client. region: %s, err: %v", f.Region, err)
	}

	// Find the ENI where the security group is used
	groupID := getSecurityGroupID(f.Resource)
	eni, err := client.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{groupID},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke DescribeNetworkInterfaces. region: %s, err: %v", f.Region, err)
	}
	for _, n := range eni.NetworkInterfaces {
		sgMeta.SecurityGroupAttachedResources = append(
			sgMeta.SecurityGroupAttachedResources,
			fmt.Sprintf("%s (%s)", aws.ToString(n.NetworkInterfaceId), aws.ToString(n.Description)),
		)
	}

	// Get Security Group Name
	sg, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{groupID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke DescribeSecurityGroups. region: %s, groupID: %s, err: %v", f.Region, groupID, err)
	}
	if len(sg.SecurityGroups) > 0 {
		sgMeta.AliasResourceName = aws.ToString(sg.SecurityGroups[0].GroupName)
	}
	return &sgMeta, nil
}

func isSecurityGroupResource(r *cloudSploitResult) bool {
	// ARN
	if !strings.HasPrefix(r.Resource, fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/", r.Region, r.AccountID)) {
		return false
	}

	// sg-xxxx
	return strings.HasPrefix(getSecurityGroupID(r.Resource), "sg-")
}

func getSecurityGroupID(resource string) string {
	split := strings.Split(resource, "/")
	if len(split) < 2 {
		return ""
	}
	return split[len(split)-1]
}

func (c *CloudsploitConfig) listAvailableRegion(ctx context.Context) (map[string]bool, error) {
	client, err := newEC2Session(ctx, c.assumeRole, c.externalID, REGION_US_EAST_1)
	if err != nil || client == nil {
		return nil, fmt.Errorf("failed to create EC2 client: %w", err)
	}
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		c.logger.Warn(ctx, "Got no regions")
		return nil, nil
	}
	availableRegions := map[string]bool{}
	for _, r := range out.Regions {
		availableRegions[*r.RegionName] = true
	}
	return availableRegions, nil
}

func (s *SqsHandler) removeIgnorePlugin(ctx context.Context, findings []*cloudSploitResult) []*cloudSploitResult {
	removedResult := []*cloudSploitResult{}
	for _, f := range findings {
		plugin := fmt.Sprintf("%s/%s", f.Category, f.Plugin)
		if s.cloudsploitSetting.IsSkipResourceNamePattern(plugin, f.Resource, f.AliasResourceName) {
			s.logger.Infof(ctx, "Ignore resource: plugin=%s, resource=%s", plugin, f.Resource)
			continue
		}
		if s.cloudsploitSetting.IsIgnoreMessagePattern(plugin, []string{f.Message, f.Description}) {
			s.logger.Infof(ctx, "Ignore message: plugin=%s, resource=%s, msg=%s, desc=%s", plugin, f.Resource, f.Message, f.Description)
			continue
		}
		removedResult = append(removedResult, f)
	}
	return removedResult
}
