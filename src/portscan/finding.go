package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vikyd/zero"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-core/proto/finding"
)

func makeFindings(results []*nmapResult, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for _, r := range results {
		data, err := json.Marshal(map[string]nmapResult{"data": *r})
		if err != nil {
			return nil, err
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      getDescription(r.Target, r.Protocol, r.Status, r.Port),
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("%v:%v:%v", r.Target, r.Protocol, r.Port)),
			ResourceName:     r.Arn,
			ProjectId:        message.ProjectID,
			OriginalScore:    getScore(r),
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
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

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {

		res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagPortscan)
		tagService := common.GetAWSServiceTagByARN(res.Finding.ResourceName)
		if !zero.IsZeroVal(tagService) {
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, tagService)
		}
		//appLogger.Infof("Success to PutFinding. finding: %v", f)

	}

	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) error {

	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding. error: %v", err)
		return err
	}
	return nil
}

func getDescription(target, protocol, status string, port int) string {
	return fmt.Sprintf("%v is %v. protocol: %v, port %v", target, status, protocol, port)
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

func getScore(result *nmapResult) float32 {
	status := result.Status
	protocol := result.Protocol
	port := result.Port
	if strings.ToUpper(status) == "CLOSED" || (strings.ToUpper(protocol) == "TCP" && strings.Index(strings.ToUpper(status), "FILTERED") > -1) {
		return 1.0
	}
	if strings.ToUpper(protocol) == "UDP" {
		return 6.0
	}
	switch port {
	case 22, 3306, 5432, 6379:
		return 8.0
	default:
		score := getScoreByScanDetail(result.ScanDetail)
		return score
	}
}

func getScoreByScanDetail(detail map[string]interface{}) float32 {
	val, ok := detail["status"]
	if !ok {
		return 6.0
	}
	if strings.Index(val.(string), "401") > -1 || strings.Index(val.(string), "403") > -1 {
		return 1.0
	}
	return 6.0

}
