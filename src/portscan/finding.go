package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/common/pkg/portscan"
	"github.com/ca-risken/core/proto/finding"
	"github.com/vikyd/zero"
)

func makeFindings(results []*portscan.NmapResult, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for _, r := range results {
		externalLink := makeURL(r.Target, r.Port)
		data, err := json.Marshal(map[string]interface{}{"data": *r, "external_link": externalLink})
		if err != nil {
			return nil, err
		}
		findings = append(findings, r.GetFindings(message.ProjectID, message.DataSource, string(data))...)
	}
	return findings, nil
}

func makeExcludeFindings(results []*excludeResult, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for _, r := range results {
		data, err := json.Marshal(map[string]excludeResult{"data": *r})
		if err != nil {
			return nil, err
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      getExcludeDescription(r.Target, r.Protocol, r.FromPort, r.ToPort, r.SecurityGroup),
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("%v:%v:%v:%v", r.Target, r.Protocol, r.FromPort, r.ToPort)),
			ResourceName:     r.Arn,
			ProjectId:        message.ProjectID,
			OriginalScore:    6.0,
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
	}
	return findings, nil
}

func makeSecurityGroupFindings(results map[string]*relSecurityGroupArn, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for groupArn, r := range results {
		data, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		score := float32(1.0)
		if r.IsPublic {
			score = 3.0
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      getSecurityGroupDescription(groupArn, r.SecurityGroup.GroupId, r.IsPublic),
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("%v:portscan_sg:%v", message.AWSID, groupArn)),
			ResourceName:     groupArn,
			ProjectId:        message.ProjectID,
			OriginalScore:    score,
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
	}
	return findings, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, nmapResults []*portscan.NmapResult, excludeResults []*excludeResult, securityGroups map[string]*relSecurityGroupArn) error {
	findingsNmap, err := makeFindings(nmapResults, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsNmap {
		err := s.putFinding(ctx, f, msg, categoryNmap)
		if err != nil {
			return err
		}
	}
	findingsExclude, err := makeExcludeFindings(excludeResults, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsExclude {
		err := s.putFinding(ctx, f, msg, categoryManyOpen)
		if err != nil {
			return err
		}
	}
	findingsSecurityGroup, err := makeSecurityGroupFindings(securityGroups, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsSecurityGroup {
		err := s.putFinding(ctx, f, msg, categoryManyOpen)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putFinding(ctx context.Context, f *finding.FindingForUpsert, msg *message.AWSQueueMessage, category string) error {
	res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
	if err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, msg.AccountID); err != nil {
		return err
	}
	tagService := common.GetAWSServiceTagByARN(res.Finding.ResourceName)
	if !zero.IsZeroVal(tagService) {
		if tagService == common.TagEC2 && strings.Contains(res.Finding.ResourceName, "security-group") {
			tagService = "securitygroup"
		}
		if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, tagService); err != nil {
			return err
		}
	}
	// recommend
	if err = s.putRecommend(ctx, res.Finding.ProjectId, res.Finding.FindingId, category, tagService); err != nil {
		appLogger.Errorf("Failed to put recommend project_id=%d, finding_id=%d, category=%s,service=%s, err=%+v",
			res.Finding.ProjectId, res.Finding.FindingId, category, tagService, err)
		return err
	}

	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) error {
	if _, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}}); err != nil {
		return fmt.Errorf("Failed to TagFinding. error: %v", err)
	}
	return nil
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, category, service string) error {
	recommendType := getRecommendType(category, service)
	if zero.IsZeroVal(recommendType) {
		appLogger.Warnf("Failed to get recommendation, Unknown category,service=%s", fmt.Sprintf("%v:%v", category, service))
		return nil
	}
	r := getRecommend(recommendType, service)
	if r.Risk == "" && r.Recommendation == "" {
		appLogger.Warnf("Failed to get recommendation, Unknown reccomendType,service=%s", fmt.Sprintf("%v:%v", category, service))
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.PortscanDataSource,
		Type:           recommendType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return err
	}
	return nil
}

func getExcludeDescription(target, protocol string, fPort, tPort int, securityGroup string) string {
	if securityGroup != "" {
		return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v,securiry_group: %v", target, protocol, fPort, tPort, securityGroup)
	}
	return fmt.Sprintf("Too many ports are exposed.target:%v protocol: %v, port %v-%v", target, protocol, fPort, tPort)
}

func getSecurityGroupDescription(groupArn string, groupID *string, isPublic bool) string {
	if groupID == nil {
		return fmt.Sprintf("security group was found. groupArn: %v, Public: %v", groupArn, isPublic)
	}
	return fmt.Sprintf("security group was found. groupID: %v, Public: %v", *groupID, isPublic)

}

func generateDataSourceID(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func makeURL(target string, port int) string {
	switch port {
	case 443:
		return fmt.Sprintf("https://%v", target)
	case 80:
		return fmt.Sprintf("http://%v", target)
	default:
		return fmt.Sprintf("http://%v:%v", target, port)
	}
}
