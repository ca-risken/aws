package portscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/common/pkg/portscan"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
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

func (s *SqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, nmapResults []*portscan.NmapResult, excludeResults []*excludeResult, securityGroups map[string]*relSecurityGroupArn) error {
	findingBatchParam := []*finding.FindingBatchForUpsert{}
	findingsNmap, err := makeFindings(nmapResults, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsNmap {
		findingBatchParam = append(findingBatchParam, s.generateFindingBatch(ctx, msg.AccountID, categoryNmap, f, true))
	}

	findingsExclude, err := makeExcludeFindings(excludeResults, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsExclude {
		findingBatchParam = append(findingBatchParam, s.generateFindingBatch(ctx, msg.AccountID, categoryManyOpen, f, true))
	}

	findingsSecurityGroup, err := makeSecurityGroupFindings(securityGroups, msg)
	if err != nil {
		return err
	}
	for _, f := range findingsSecurityGroup {
		findingBatchParam = append(findingBatchParam, s.generateFindingBatch(ctx, msg.AccountID, categoryManyOpen, f, false))
	}
	if err := s.putFindingBatch(ctx, msg.ProjectID, findingBatchParam); err != nil {
		return err
	}
	s.logger.Infof(ctx, "putFindings(%d) succeeded", len(findingBatchParam))
	return nil
}

func (s *SqsHandler) generateFindingBatch(ctx context.Context, awsAccountID, category string, f *finding.FindingForUpsert, addPublicTag bool) *finding.FindingBatchForUpsert {
	data := &finding.FindingBatchForUpsert{Finding: f}
	// tag
	tags := []*finding.FindingTagForBatch{
		{Tag: common.TagAWS},
		{Tag: common.TagPortscan},
		{Tag: awsAccountID},
	}
	if addPublicTag {
		tags = append(tags, &finding.FindingTagForBatch{Tag: common.TagPublicFacing})
	}
	service := common.GetAWSServiceTagByARN(f.ResourceName)
	if service == common.TagEC2 && strings.Contains(f.ResourceName, "security-group") {
		tags = append(tags, &finding.FindingTagForBatch{Tag: "securitygroup"})
	}
	data.Tag = tags

	// recommend
	recommendType := getRecommendType(category, service)
	if zero.IsZeroVal(recommendType) {
		s.logger.Warnf(ctx, "Failed to get recommendation, Unknown category,service=%s", fmt.Sprintf("%v:%v", category, service))
		return data
	}
	r := getRecommend(recommendType, service)
	if r.Risk == "" && r.Recommendation == "" {
		s.logger.Warnf(ctx, "Failed to get recommendation, Unknown reccomendType,service=%s", fmt.Sprintf("%v:%v", category, service))
		return data
	}
	data.Recommend = &finding.RecommendForBatch{
		Type:           recommendType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}
	return data
}

func (s *SqsHandler) putFindingBatch(ctx context.Context, projectID uint32, params []*finding.FindingBatchForUpsert) error {
	s.logger.Infof(ctx, "Putting findings(%d)...", len(params))
	for idx := 0; idx < len(params); idx = idx + finding.PutFindingBatchMaxLength {
		lastIdx := idx + finding.PutFindingBatchMaxLength
		if lastIdx > len(params) {
			lastIdx = len(params)
		}
		// request per API limits
		s.logger.Debugf(ctx, "Call PutFindingBatch API, (%d ~ %d / %d)", idx+1, lastIdx, len(params))
		req := &finding.PutFindingBatchRequest{ProjectId: projectID, Finding: params[idx:lastIdx]}
		if _, err := s.findingClient.PutFindingBatch(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func getExcludeDescription(target, protocol string, fPort, tPort int, securityGroup string) string {
	if securityGroup != "" {
		return fmt.Sprintf("Too many ports are exposed. (target=%s:%d-%d, securiry_group=%s", target, fPort, tPort, securityGroup)
	}
	return fmt.Sprintf("Too many ports are exposed. (target=%s:%d-%d", target, fPort, tPort)
}

func getSecurityGroupDescription(groupArn string, groupID *string, isPublic bool) string {
	if groupID == nil {
		return fmt.Sprintf("Security group was found. (GroupArn: %s, Public: %t)", groupArn, isPublic)
	}
	return fmt.Sprintf("Security group was found. (GroupID: %s, Public: %t)", aws.ToString(groupID), isPublic)

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
