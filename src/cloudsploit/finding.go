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
	var (
		findingBatchParam  []*finding.FindingBatchForUpsert
		resourceBatchParam []*finding.ResourceBatchForUpsert
	)
	resourceNameMap := map[string]bool{}
	for _, result := range *results {
		data, err := json.Marshal(map[string]cloudSploitResult{"data": result})
		if err != nil {
			return err
		}
		if result.Resource == cloudsploitNA {
			result.Resource = cloudsploitUnknown
		}
		resourceName := getResourceName(result.Resource, result.Category, message.AccountID)
		serviceTag := getServiceTag(resourceName)
		tags := []string{common.TagAWS, serviceTag, message.AccountID}
		score := getScore(result.Status, result.Category, result.Plugin)
		if score == 0.0 {
			// resource
			if _, ok := resourceNameMap[resourceName]; ok {
				continue // skip duplicated resource
			}
			resourceNameMap[resourceName] = true
			var resourceTagForBatch []*finding.ResourceTagForBatch
			for _, tag := range tags {
				resourceTagForBatch = append(resourceTagForBatch, &finding.ResourceTagForBatch{Tag: tag})
			}
			resourceBatchParam = append(resourceBatchParam, &finding.ResourceBatchForUpsert{
				Resource: &finding.ResourceForUpsert{
					ProjectId:    message.ProjectID,
					ResourceName: resourceName,
				},
				Tag: resourceTagForBatch,
			})
			continue
		}

		// finding
		f := &finding.FindingForUpsert{
			Description:      result.Description,
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("description_%v_%v_%v", result.Description, result.Region, result.Resource)),
			ResourceName:     resourceName,
			ProjectId:        message.ProjectID,
			OriginalScore:    score,
			OriginalMaxScore: maxScore,
			Data:             string(data),
		}
		tags = append(tags, common.TagCloudsploit, result.Plugin)
		tags = append(tags, getPluginTags(result.Category, result.Plugin)...)
		var findingTagForBatch []*finding.FindingTagForBatch
		for _, tag := range tags {
			findingTagForBatch = append(findingTagForBatch, &finding.FindingTagForBatch{Tag: tag})
		}

		// recommend
		var recommend *finding.RecommendForBatch
		recommendType := fmt.Sprintf("%s/%s", result.Category, result.Plugin)
		r := getRecommend(result.Category, result.Plugin)
		if r.Risk == "" && r.Recommendation == "" {
			appLogger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", recommendType)
		} else {
			recommend = &finding.RecommendForBatch{
				Type:           recommendType,
				Risk:           r.Risk,
				Recommendation: r.Recommendation,
			}
		}

		findingBatchParam = append(findingBatchParam, &finding.FindingBatchForUpsert{
			Finding:   f,
			Tag:       findingTagForBatch,
			Recommend: recommend,
		})
	}

	// put
	if err = s.putResourceBatch(ctx, message.ProjectID, resourceBatchParam); err != nil {
		return err
	}
	if err = s.putFindingBatch(ctx, message.ProjectID, findingBatchParam); err != nil {
		return err
	}
	appLogger.Infof(ctx, "putFindings(%d) succeeded", len(*results))
	return nil
}

func (s *sqsHandler) putFindingBatch(ctx context.Context, projectID uint32, params []*finding.FindingBatchForUpsert) error {
	appLogger.Infof(ctx, "Putting findings(%d)...", len(params))
	for idx := 0; idx < len(params); idx = idx + finding.PutFindingBatchMaxLength {
		lastIdx := idx + finding.PutFindingBatchMaxLength
		if lastIdx > len(params) {
			lastIdx = len(params)
		}
		// request per API limits
		appLogger.Debugf(ctx, "Call PutFindingBatch API, (%d ~ %d / %d)", idx+1, lastIdx+1, len(params))
		req := &finding.PutFindingBatchRequest{ProjectId: projectID, Finding: params[idx:lastIdx]}
		if _, err := s.findingClient.PutFindingBatch(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putResourceBatch(ctx context.Context, projectID uint32, params []*finding.ResourceBatchForUpsert) error {
	appLogger.Infof(ctx, "Putting resources(%d)...", len(params))
	for idx := 0; idx < len(params); idx = idx + finding.PutResourceBatchMaxLength {
		lastIdx := idx + finding.PutResourceBatchMaxLength
		if lastIdx > len(params) {
			lastIdx = len(params)
		}
		// request per API limits
		appLogger.Debugf(ctx, "Call PutResourceBatch API, (%d ~ %d / %d)", idx+1, lastIdx+1, len(params))
		req := &finding.PutResourceBatchRequest{ProjectId: projectID, Resource: params[idx:lastIdx]}
		if _, err := s.findingClient.PutResourceBatch(ctx, req); err != nil {
			return err
		}
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
		appLogger.Errorf(ctx, "Failed to ListDataSource. error: %+v", err)
		return 0, err
	}
	appLogger.Debugf(ctx, "Got datasource: %+v", resp.DataSource[0])
	return resp.DataSource[0].MaxScore, nil
}
