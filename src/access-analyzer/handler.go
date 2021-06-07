package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	awsClient     awsClient.AWSServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		alertClient:   newAlertClient(),
		awsClient:     newAWSClient(),
	}
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message: %s", msgBody)
	// Parse message
	message, err := message.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: SQS_msg=%+v, err=%+v", msg, err)
		return err
	}

	ctx := context.Background()
	status := common.InitScanStatus(message)
	accessAnalyzer, err := newAccessAnalyzerClient("", message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create AccessAnalyzer session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	regions, err := accessAnalyzer.listAvailableRegion()
	if err != nil {
		appLogger.Errorf("Faild to get available regions, err = %+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	analyzerEnabled := false
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", message.AccountID)
			continue
		}
		if !supportedRegion(*region.RegionName) {
			appLogger.Infof("Skip the %s region,Because AccessAnalyzer serveice is not supported", *region.RegionName)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		// AccessAnalyzer
		accessAnalyzer, err = newAccessAnalyzerClient(*region.RegionName, message.AssumeRoleArn, message.ExternalID)
		if err != nil {
			appLogger.Errorf("Faild to create AccessAnalyzer session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}

		findings, analyzerArns, err := accessAnalyzer.getAccessAnalyzer(message)
		if err != nil {
			appLogger.Errorf("Faild to get findngs to AWS AccessAnalyzer: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		if analyzerArns != nil && len(*analyzerArns) > 0 {
			analyzerEnabled = true
		}
		// Put finding to core
		if err := s.putFindings(ctx, findings); err != nil {
			appLogger.Errorf("Faild to put findngs: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
			return err
		}
	}
	if !analyzerEnabled {
		if err := s.updateScanStatusError(ctx, &status, "AccessAnalyzer is disabled in all regions"); err != nil {
			return err
		}
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (a *accessAnalyzerClient) getAccessAnalyzer(msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error) {
	putData := []*finding.FindingForUpsert{}
	analyzerArns, err := a.listAnalyzers()
	if err != nil {
		appLogger.Errorf("AccessAnalyzer.ListAnalyzers error: err=%+v", err)
		return nil, &[]string{}, err
	}

	for _, arn := range *analyzerArns {
		appLogger.Infof("Detected analyzer: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
		findings, err := a.listFindings(msg.AccountID, arn)
		if err != nil {
			appLogger.Warnf(
				"AccessAnalyzer.ListFindings error: analyzerArn=%s, accountID=%s, err=%+v", arn, msg.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		appLogger.Debugf("[Debug]Got findings, %+v", findings)
		if len(findings) == 0 {
			appLogger.Infof("No findings: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
			continue
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, &[]string{}, err
			}
			isPublic := false
			if data.IsPublic != nil {
				appLogger.Warnf("API Response parameter `IsPublic` got nil data, maybe something error occured, accountID=%s", msg.AccountID)
				isPublic = *data.IsPublic
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      fmt.Sprintf("AccessAnalyzer: %s (public=%t)", *data.Resource, isPublic),
				DataSource:       msg.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Resource,
				ProjectId:        msg.ProjectID,
				OriginalScore:    scoreAccessAnalyzerFinding(*data.Status, isPublic, data.Action),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			})
		}
	}
	return putData, analyzerArns, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		// finding
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		// finding-tag
		s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, common.TagAccessAnalyzer, resp.Finding.FindingId, resp.Finding.ProjectId)
		awsServiceTag := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
		if awsServiceTag != common.TagUnknown {
			s.tagFinding(ctx, awsServiceTag, resp.Finding.FindingId, resp.Finding.ProjectId)
		}
		appLogger.Infof("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
		return err
	}
	return nil
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_ERROR
	if len(statusDetail) > 200 {
		statusDetail = statusDetail[:200] + " ..." // cut long text
	}
	status.AttachDataSource.StatusDetail = statusDetail
	return s.attachAWSStatus(ctx, status)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, status *awsClient.AttachDataSourceRequest) error {
	status.AttachDataSource.Status = awsClient.Status_OK
	status.AttachDataSource.StatusDetail = ""
	return s.attachAWSStatus(ctx, status)
}

func (s *sqsHandler) attachAWSStatus(ctx context.Context, status *awsClient.AttachDataSourceRequest) error {
	resp, err := s.awsClient.AttachDataSource(ctx, status)
	if err != nil {
		return err
	}
	appLogger.Infof("Success to update AWS status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func scoreAccessAnalyzerFinding(status string, isPublic bool, actions []*string) float32 {
	if status != accessanalyzer.FindingStatusActive {
		return 0.1
	}
	if !isPublic {
		return 0.3
	}
	readable := false
	writable := false
	for _, action := range actions {
		if strings.Contains(*action, "List") ||
			strings.Contains(*action, "Get") ||
			strings.Contains(*action, "Describe") {
			readable = true
			continue
		}
		writable = true
		if readable && writable {
			break
		}
	}
	if readable && !writable {
		return 0.7 // Readable resource
	}
	if !readable && writable {
		return 0.9 // Writable resource
	}
	return 1.0 // Both readable and writable
}

var unsupportedRegions = []string{
	// "ap-east-1",
}

func supportedRegion(region string) bool {
	for _, unsupported := range unsupportedRegions {
		if region == unsupported {
			return false
		}
	}
	return true
}
