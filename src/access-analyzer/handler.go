package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/aws/pkg/message"
	awsClient "github.com/ca-risken/aws/proto/aws"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
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

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *sqs.Message) error {
	msgBody := aws.StringValue(sqsMsg.Body)
	appLogger.Infof("got message: %s", msgBody)
	// Parse message
	msg, err := message.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: SQS_msg=%+v, err=%+v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	appLogger.Infof("start Scan, RequestID=%s", requestID)

	status := common.InitScanStatus(msg)
	accessAnalyzer, err := newAccessAnalyzerClient("", msg.AssumeRoleArn, msg.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create AccessAnalyzer session: err=%+v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}
	regions, err := accessAnalyzer.listAvailableRegion(ctx)
	if err != nil {
		appLogger.Errorf("Faild to get available regions, err = %+v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	analyzerEnabled := false
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", msg.AccountID)
			continue
		}
		if !supportedRegion(*region.RegionName) {
			appLogger.Infof("Skip the %s region,Because AccessAnalyzer serveice is not supported", *region.RegionName)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		// AccessAnalyzer
		accessAnalyzer, err = newAccessAnalyzerClient(*region.RegionName, msg.AssumeRoleArn, msg.ExternalID)
		if err != nil {
			appLogger.Errorf("Faild to create AccessAnalyzer session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}

		findings, analyzerArns, err := accessAnalyzer.getAccessAnalyzer(ctx, msg)
		if err != nil {
			appLogger.Errorf("Faild to get findngs to AWS AccessAnalyzer: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}
		if analyzerArns != nil && len(*analyzerArns) > 0 {
			analyzerEnabled = true
		}
		// Put finding to core
		if err := s.putFindings(ctx, msg, findings); err != nil {
			appLogger.Errorf("Faild to put findngs: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}
		if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
			return mimosasqs.WrapNonRetryable(err)
		}
	}
	if !analyzerEnabled {
		return s.handleErrorWithUpdateStatus(ctx, &status, errors.New("AccessAnalyzer is disabled in all regions"))
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.MustNotifyf(logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) handleErrorWithUpdateStatus(ctx context.Context, scanStatus *awsClient.AttachDataSourceRequest, err error) error {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf("Failed to update scan status error: err=%+v", updateErr)
	}
	return mimosasqs.WrapNonRetryable(err)
}

func (s *sqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		// finding
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		// finding-tag
		if err := s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, common.TagAccessAnalyzer, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, msg.AccountID, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		awsServiceType := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
		if awsServiceType != common.TagUnknown {
			if err := s.tagFinding(ctx, awsServiceType, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
				return err
			}
		}
		// recommend
		if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, awsServiceType); err != nil {
			return err
		}
		appLogger.Debugf("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
	if _, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
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

func (s *sqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, findingType string) error {
	r := getRecommend(findingType)
	if r.Risk == "" && r.Recommendation == "" {
		appLogger.Warnf("Failed to get recommendation, Unknown plugin=%s", findingType)
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.GuardDutyDataSource,
		Type:           findingType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("Failed to TagFinding, finding_id=%d, finding_type=%s, error=%+v", findingID, findingType, err)
	}
	return nil
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
