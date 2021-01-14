package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-core/proto/finding"
)

func makeFindings(results *[]cloudSploitResult, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for _, r := range *results {
		data, err := json.Marshal(map[string]cloudSploitResult{"data": r})
		if err != nil {
			return nil, err
		}
		if r.Resource == cloudsploitNA {
			r.Resource = cloudsploitUnknown
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      r.Description,
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("description_%v_%v_%v", r.Description, r.Region, r.Resource)),
			ResourceName:     getResourceName(r.Resource, r.Category, message.AccountID),
			ProjectId:        message.ProjectID,
			OriginalScore:    getScore(r.Status, r.Resource),
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
	}
	return findings, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		if f.OriginalScore == 0.0 {
			_, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
				Resource: &finding.ResourceForUpsert{
					ResourceName: f.ResourceName,
					ProjectId:    f.ProjectId,
				},
			})
			if err != nil {
				appLogger.Errorf("Failed to put finding project_id=%d, resource=%s, err=%+v", f.ProjectId, f.ResourceName, err)
				return err
			}
			//appLogger.Infof("Success to PutResource, finding_id=%d", resp.Resource.ResourceId)
		} else {
			res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
			if err != nil {
				return err
			}
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS)
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagCloudsploit)
			tagService := getServiceTag(res.Finding.ResourceName)
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, tagService)
			//appLogger.Infof("Success to PutFinding. finding: %v", f)
		}
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

func generateDataSourceID(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func getScore(status, resource string) float32 {
	if strings.ToUpper(status) == "OK" {
		return 0.0
	}
	if resource == "Unknown" || resource == "N/A" {
		return 1.0
	}
	return 3.0
}

const (

	// Unknown
	cloudsploitUnknown = "Unknown"
	cloudsploitNA      = "N/A"
)

func getResourceName(resource, category, accountID string) string {
	if resource == cloudsploitUnknown {
		return fmt.Sprintf("%s/%s/%s", accountID, category, resource)
	}
	return resource
}

func getServiceTag(resource string) string {
	tag := common.GetAWSServiceTagByARN(resource)
	if tag != common.TagUnknown {
		appLogger.Infof("service: %s", tag)
		return tag
	}
	if strings.HasSuffix(resource, cloudsploitUnknown) {
		splited := strings.Split(resource, "/")
		if len(splited) < 3 {
			appLogger.Infof("service: %s", tag)
			return tag
		}
		appLogger.Infof("service: %s", splited[2])
		return splited[2]
	}
	appLogger.Infof("service: %s", tag)
	return tag
}
