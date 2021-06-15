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
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/finding"
)

func (s *sqsHandler) putFindings(ctx context.Context, results *[]cloudSploitResult, message *message.AWSQueueMessage) error {
	for _, result := range *results {
		data, err := json.Marshal(map[string]cloudSploitResult{"data": result})
		if err != nil {
			return err
		}
		if result.Resource == cloudsploitNA {
			result.Resource = cloudsploitUnknown
		}
		finding := &finding.FindingForUpsert{
			Description:      result.Description,
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("description_%v_%v_%v", result.Description, result.Region, result.Resource)),
			ResourceName:     getResourceName(result.Resource, result.Category, message.AccountID),
			ProjectId:        message.ProjectID,
			OriginalScore:    getScore(result.Status, result.Category, result.Plugin),
			OriginalMaxScore: 10.0,
			Data:             string(data),
		}
		err = s.putFinding(ctx, finding, &result, message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putFinding(ctx context.Context, cloudsploitFinding *finding.FindingForUpsert, result *cloudSploitResult, msg *message.AWSQueueMessage) error {
	if cloudsploitFinding.OriginalScore == 0.0 {
		_, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			Resource: &finding.ResourceForUpsert{
				ResourceName: cloudsploitFinding.ResourceName,
				ProjectId:    cloudsploitFinding.ProjectId,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to put finding project_id=%d, resource=%s, err=%+v", cloudsploitFinding.ProjectId, cloudsploitFinding.ResourceName, err)
			return err
		}
	} else {
		res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: cloudsploitFinding})
		if err != nil {
			return err
		}
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagCloudsploit)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, msg.AccountID)
		serviceTag := getServiceTag(res.Finding.ResourceName)
		s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, serviceTag)
		complianceTags := getComplianceTags(result.Category, result.Plugin)
		for _, complianceTag := range complianceTags {
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, complianceTag)
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

const (

	// Unknown
	cloudsploitUnknown = "Unknown"
	cloudsploitNA      = "N/A"

	resultOK      string = "OK"      // 0: PASS: No risks
	resultWARN    string = "WARN"    // 1: WARN: The result represents a potential misconfiguration or issue but is not an immediate risk
	resultFAIL    string = "FAIL"    // 2: FAIL: The result presents an immediate risk to the security of the account
	resultUNKNOWN string = "UNKNOWN" // 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)

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
		return tag
	}
	if strings.HasSuffix(resource, cloudsploitUnknown) {
		splited := strings.Split(resource, "/")
		if len(splited) < 3 {
			return tag
		}
		return splited[2]
	}
	return tag
}

func getScore(status, category, plugin string) float32 {
	switch strings.ToUpper(status) {
	case resultOK:
		return 0.0
	case resultUNKNOWN:
		return 1.0
	case resultWARN:
		return 3.0
	default:
		findingInf, ok := cloudSploitFindingMap[fmt.Sprintf("%s/%s", category, plugin)]
		if ok {
			return findingInf.Score
		}
		return 3.0
	}
}

func getComplianceTags(category, plugin string) []string {
	findingInf, ok := cloudSploitFindingMap[fmt.Sprintf("%s/%s", category, plugin)]
	if ok {
		return findingInf.ComplianceTag
	}
	return []string{}
}

func (s *sqsHandler) clearFindingScore(ctx context.Context, msg *message.AWSQueueMessage) error {
	maxScore, err := s.getCloudSploitMaxScore(ctx, msg)
	if err != nil {
		appLogger.Errorf("Failed to getCloudSploitMaxScore. error: %+v", err)
		return err
	}

	var findingIDs []uint64
	var offset int32
	for {
		resp, err := s.findingClient.ListFinding(ctx, &finding.ListFindingRequest{
			ProjectId:  msg.ProjectID,
			DataSource: []string{message.CloudsploitDataSource},
			Tag:        []string{msg.AccountID},
			FromScore:  0.01,
			Status:     finding.FindingStatus_FINDING_ACTIVE,
			Offset:     offset,
			Limit:      200,
		})
		if err != nil {
			appLogger.Errorf("Failed to ListFinding. error: %+v", err)
			return err
		}
		findingIDs = append(findingIDs, resp.FindingId...)
		if uint32(len(findingIDs)) >= resp.Total || len(resp.FindingId) <= 0 {
			break
		}
		offset = +offset + int32(len(resp.FindingId))
	}

	for _, id := range findingIDs {
		f, err := s.findingClient.GetFinding(ctx, &finding.GetFindingRequest{ProjectId: msg.ProjectID, FindingId: id})
		if err != nil {
			appLogger.Errorf("Failed to GetFinding. error: %+v", err)
			return err
		}
		if _, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{
			ProjectId: f.Finding.ProjectId,
			Finding: &finding.FindingForUpsert{
				Description:      f.Finding.Description,
				DataSource:       message.CloudsploitDataSource,
				DataSourceId:     f.Finding.DataSourceId,
				ResourceName:     f.Finding.ResourceName,
				ProjectId:        f.Finding.ProjectId,
				OriginalScore:    0.0, // update
				OriginalMaxScore: maxScore,
				Data:             f.Finding.Data,
			},
		}); err != nil {
			appLogger.Errorf("Failed to clear siding score. error: %+v", err)
			return err
		}
	}
	return nil
}

func (s *sqsHandler) getCloudSploitMaxScore(ctx context.Context, msg *message.AWSQueueMessage) (float32, error) {
	resp, err := s.awsClient.ListDataSource(ctx, &aws.ListDataSourceRequest{
		ProjectId:  msg.ProjectID,
		AwsId:      msg.AWSID,
		DataSource: message.CloudsploitDataSource,
	})
	if err != nil || resp.DataSource == nil || len(resp.DataSource) < 1 {
		appLogger.Errorf("Failed to ListDataSource. error: %+v", err)
		return 0, err
	}
	appLogger.Debugf("Got datasource: %+v", resp.DataSource[0])
	return resp.DataSource[0].MaxScore, nil
}
