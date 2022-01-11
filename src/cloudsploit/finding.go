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
	"github.com/ca-risken/aws/proto/aws"
	"github.com/ca-risken/core/proto/finding"
)

func (s *sqsHandler) putFindings(ctx context.Context, results *[]cloudSploitResult, message *message.AWSQueueMessage) error {
	maxScore, err := s.getCloudSploitMaxScore(ctx, message)
	if err != nil {
		return err
	}
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
			OriginalMaxScore: maxScore,
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
	serviceTag := getServiceTag(cloudsploitFinding.ResourceName)
	if cloudsploitFinding.OriginalScore == 0.0 {
		res, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
			ProjectId: cloudsploitFinding.ProjectId,
			Resource: &finding.ResourceForUpsert{
				ResourceName: cloudsploitFinding.ResourceName,
				ProjectId:    cloudsploitFinding.ProjectId,
			},
		})
		if err != nil {
			appLogger.Errorf("Failed to PutResource project_id=%d, resource=%s, err=%+v", cloudsploitFinding.ProjectId, cloudsploitFinding.ResourceName, err)
			return err
		}
		if err := s.tagResource(ctx, cloudsploitFinding.ProjectId, res.Resource.ResourceId, common.TagAWS); err != nil {
			return err
		}
		if err := s.tagResource(ctx, cloudsploitFinding.ProjectId, res.Resource.ResourceId, serviceTag); err != nil {
			return err
		}
		if err := s.tagResource(ctx, cloudsploitFinding.ProjectId, res.Resource.ResourceId, msg.AccountID); err != nil {
			return err
		}
		return nil
	}

	// finding
	res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: cloudsploitFinding})
	if err != nil {
		appLogger.Errorf("Failed to PutFinding project_id=%d, resource=%s, err=%+v", cloudsploitFinding.ProjectId, cloudsploitFinding.ResourceName, err)
		return err
	}
	// finding tag
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagCloudsploit); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, msg.AccountID); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, result.Plugin); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, serviceTag); err != nil {
		return err
	}
	tags := getPluginTags(result.Category, result.Plugin)
	for _, t := range tags {
		if err := s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, t); err != nil {
			return err
		}
	}
	// recommend
	if err := s.putRecommend(ctx, res.Finding.ProjectId, res.Finding.FindingId, result.Category, result.Plugin); err != nil {
		appLogger.Errorf("Failed to put recommend project_id=%d, finding_id=%d, plugin=%s, err=%+v",
			res.Finding.ProjectId, res.Finding.FindingId, result.Plugin, err)
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
		return fmt.Errorf("Failed to TagFinding. finding_id=%d, error=%v", findingID, err)
	}
	return nil
}

func (s *sqsHandler) tagResource(ctx context.Context, projectID uint32, resourceID uint64, tag string) error {
	if _, err := s.findingClient.TagResource(ctx, &finding.TagResourceRequest{
		ProjectId: projectID,
		Tag: &finding.ResourceTagForUpsert{
			ResourceId: resourceID,
			ProjectId:  projectID,
			Tag:        tag,
		}},
	); err != nil {
		return fmt.Errorf("Failed to TagResource. error: %v", err)
	}
	return nil
}

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, category, plugin string) error {
	recommendType := fmt.Sprintf("%s/%s", category, plugin)
	r := recommendMap[recommendType]
	if r.Risk == "" && r.Recommendation == "" {
		appLogger.Warnf("Failed to get recommendation, Unknown plugin=%s", recommendType)
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
	resultUNKNOWN string = "UNKNOWN" // 3: UNKNOWN: The results could not be determined (API failure, wrong permissions, etc.)
	// resultFAIL    string = "FAIL"    // 2: FAIL: The result presents an immediate risk to the security of the account
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

func getPluginTags(category, plugin string) []string {
	findingInf, ok := cloudSploitFindingMap[fmt.Sprintf("%s/%s", category, plugin)]
	if ok {
		return findingInf.Tags
	}
	return []string{}
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
