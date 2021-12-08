package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

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

func (s *sqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, nmapResults []*portscan.NmapResult, excludeResults []*excludeResult) error {
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
	return nil
}

func (s *sqsHandler) putFinding(ctx context.Context, f *finding.FindingForUpsert, msg *message.AWSQueueMessage, category string) error {
	res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
	if err != nil {
		return err
	}
	s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS)
	s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan)
	s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, msg.AccountID)
	tagService := common.GetAWSServiceTagByARN(res.Finding.ResourceName)
	if !zero.IsZeroVal(tagService) {
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, tagService)
	}
	// recommend
	if err = s.putRecommend(ctx, res.Finding.ProjectId, res.Finding.FindingId, category, tagService); err != nil {
		appLogger.Errorf("Failed to put recommend project_id=%d, finding_id=%d, category=%s,service=%s, err=%+v",
			res.Finding.ProjectId, res.Finding.FindingId, category, tagService, err)
		return err
	}

	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding. error: %v", err)
	}
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
		DataSource:     message.CloudsploitDataSource,
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
