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
	var params []*finding.FindingBatchForUpsert
	for _, result := range *results {
		data, err := json.Marshal(map[string]cloudSploitResult{"data": result})
		if err != nil {
			return err
		}
		if result.Resource == cloudsploitNA {
			result.Resource = cloudsploitUnknown
		}
		resrouceName := getResourceName(result.Resource, result.Category, message.AccountID)
		serviceTag := getServiceTag(resrouceName)
		tags := []string{common.TagAWS, serviceTag, message.AccountID}
		score := getScore(result.Status, result.Category, result.Plugin)
		if score == 0.0 {
			if err = s.putResource(ctx, resrouceName, message.ProjectID, tags); err != nil {
				return err
			}
			continue
		}

		// finding
		f := &finding.FindingForUpsert{
			Description:      result.Description,
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("description_%v_%v_%v", result.Description, result.Region, result.Resource)),
			ResourceName:     resrouceName,
			ProjectId:        message.ProjectID,
			OriginalScore:    score,
			OriginalMaxScore: maxScore,
			Data:             string(data),
		}

		// tag
		tags = append(tags, common.TagCloudsploit, result.Plugin)
		tags = append(tags, getPluginTags(result.Category, result.Plugin)...)
		var tagForBatch []*finding.FindingTagForBatch
		for _, tag := range tags {
			tagForBatch = append(tagForBatch, &finding.FindingTagForBatch{Tag: tag})
		}

		// recommend
		var recommend *finding.RecommendForBatch
		recommendType := fmt.Sprintf("%s/%s", result.Category, result.Plugin)
		r := getRecommend(result.Category, result.Plugin)
		if r.Risk == "" && r.Recommendation == "" {
			appLogger.Warnf("Failed to get recommendation, Unknown plugin=%s", recommendType)
		} else {
			recommend = &finding.RecommendForBatch{
				Type:           recommendType,
				Risk:           r.Risk,
				Recommendation: r.Recommendation,
			}
		}

		params = append(params, &finding.FindingBatchForUpsert{
			Finding:   f,
			Tag:       tagForBatch,
			Recommend: recommend,
		})
	}
	return s.putFindingBatch(ctx, message.ProjectID, params)
}

const putFindingBatchAPILimit = 50

func (s *sqsHandler) putFindingBatch(ctx context.Context, projectID uint32, params []*finding.FindingBatchForUpsert) error {
	appLogger.Infof("Putting findings(%d)...", len(params))
	for idx := 0; idx < len(params); idx = idx + putFindingBatchAPILimit {
		lastIdx := idx + putFindingBatchAPILimit
		if lastIdx > len(params) {
			lastIdx = len(params)
		}
		// request per API limits
		appLogger.Debugf("Call PutFindingBatch API, (%d ~ %d / %d)", idx+1, lastIdx+1, len(params))
		req := &finding.PutFindingBatchRequest{ProjectId: projectID, Finding: params[idx:lastIdx]}
		if _, err := s.findingClient.PutFindingBatch(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putResource(ctx context.Context, resourceName string, projectID uint32, tags []string) error {
	res, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
		ProjectId: projectID,
		Resource: &finding.ResourceForUpsert{
			ResourceName: resourceName,
			ProjectId:    projectID,
		},
	})
	if err != nil {
		appLogger.Errorf("Failed to PutResource project_id=%d, resource=%s, err=%+w", projectID, resourceName, err)
		return err
	}
	for _, tag := range tags {
		if err := s.tagResource(ctx, projectID, res.Resource.ResourceId, tag); err != nil {
			return err
		}
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
