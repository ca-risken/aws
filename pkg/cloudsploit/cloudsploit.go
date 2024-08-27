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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/ca-risken/common/pkg/logging"
)

type CloudsploitConfig struct {
	ResultDir      string
	ConfigDir      string
	CloudsploitDir string
	ConfigPath     string
	MaxMemSizeMB   int

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
	l logging.Logger,
) *CloudsploitConfig {
	return &CloudsploitConfig{
		ResultDir:      resultDir,
		ConfigDir:      configDir,
		CloudsploitDir: cloudsploitDir,
		MaxMemSizeMB:   maxMem,
		logger:         l,
	}
}

func (s *SqsHandler) run(ctx context.Context, accountID string) ([]*cloudSploitResult, error) {
	now := time.Now().UnixNano()
	if s.cloudsploitConf.MaxMemSizeMB > 0 {
		os.Setenv("NODE_OPTIONS", fmt.Sprintf("--max-old-space-size=%d", s.cloudsploitConf.MaxMemSizeMB))
	}
	filePath := fmt.Sprintf("%v/%v_%v.json", s.cloudsploitConf.ResultDir, accountID, now)
	if fileExists(filePath) {
		return nil, fmt.Errorf("result file already exists: file=%s", filePath)
	}
	cmd := exec.Command(fmt.Sprintf("%v/index.js", s.cloudsploitConf.CloudsploitDir),
		"--config", s.cloudsploitConf.ConfigPath,
		"--console", "none",
		"--json", filePath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed exec cloudsploit. error: %+v, detail: %s", err, stderr.String())
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
	// delete result
	if err := os.Remove(filePath); err != nil {
		s.logger.Warnf(ctx, "Failed to delete result file. error: %v", err)
	}

	// delete config
	if err := os.Remove(s.cloudsploitConf.ConfigPath); err != nil {
		s.logger.Warnf(ctx, "Failed to delete config file. error: %v", err)
	}

	// add meta data
	results, err = s.addMetaData(ctx, accountID, results)
	if err != nil {
		return nil, err
	}

	// remove ignore plugin
	results = s.removeIgnorePlugin(ctx, results)
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

func (s *SqsHandler) addMetaData(ctx context.Context, accountID string, findings []*cloudSploitResult) ([]*cloudSploitResult, error) {
	availableRegions, err := s.cloudsploitConf.listAvailableRegion(ctx)
	if err != nil {
		return nil, err
	}
	updatedFindings := []*cloudSploitResult{}
	for _, f := range findings {
		f.AccountID = accountID
		updatedF, err := s.addSecurityGroupMetaData(ctx, *f, availableRegions)
		if err != nil {
			return nil, err
		}
		updatedFindings = append(updatedFindings, updatedF)
	}
	return updatedFindings, nil
}

func (s *SqsHandler) addSecurityGroupMetaData(ctx context.Context, f cloudSploitResult, availableRegions map[string]bool) (*cloudSploitResult, error) {
	if f.Status != resultFAIL {
		return &f, nil
	}
	if !isSecurityGroupResource(&f) {
		return &f, nil
	}
	if ok := availableRegions[f.Region]; !ok {
		return &f, nil
	}
	sgPlugin, ok := s.cloudsploitSetting.SpecificPluginSetting[fmt.Sprintf("%s/%s", f.Category, f.Plugin)]
	if !ok || sgPlugin.Score == nil || *sgPlugin.Score <= LOW_SCORE {
		return &f, nil
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
		f.SecurityGroupAttachedResources = append(
			f.SecurityGroupAttachedResources,
			fmt.Sprintf("%s (%s)", aws.ToString(n.NetworkInterfaceId), aws.ToString(n.Description)),
		)
	}
	if len(f.SecurityGroupAttachedResources) == 0 {
		return &f, nil
	}

	// Get Security Group Name
	sg, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: []string{groupID},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to invoke DescribeSecurityGroups. region: %s, groupID: %s, err: %v", f.Region, groupID, err)
	}
	if len(sg.SecurityGroups) > 0 {
		f.AliasResourceName = aws.ToString(sg.SecurityGroups[0].GroupName)
	}
	return &f, nil
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
		if s.cloudsploitSetting.IsIgnorePlugin(plugin) {
			continue
		}
		if s.cloudsploitSetting.IsSkipResourceNamePattern(plugin, f.Resource, f.AliasResourceName) {
			s.logger.Infof(ctx, "Ignore resource: %s", f.Resource)
			continue
		}
		removedResult = append(removedResult, f)
	}
	return removedResult
}
