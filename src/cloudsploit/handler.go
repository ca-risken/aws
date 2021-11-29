package main

import (
	"context"
	"fmt"

	awsClient "github.com/ca-risken/aws/proto/aws"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/common/pkg/logging"
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
	appLogger.Infof("got message. message: %v", msgBody)
	// Parse message
	msg, err := message.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message. message: %v, error: %v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := logging.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	appLogger.Infof("start Scan, RequestID=%s", requestID)

	status := common.InitScanStatus(msg)
	// check AccountID matches Arn for Scan
	if !common.IsMatchAccountIDArn(msg.AccountID, msg.AssumeRoleArn) {
		appLogger.Warnf("AccountID doesn't match AssumeRoleArn, accountID: %v, ARN: %v", msg.AccountID, msg.AssumeRoleArn)
		return s.handleErrorWithUpdateStatus(ctx, &status, fmt.Errorf("AssumeRoleArn for CloudSploit must be created in AWS AccountID: %v", msg.AccountID))
	}

	cloudsploitConfig, err := newcloudsploitConfig(msg.AssumeRoleArn, msg.ExternalID, msg.AWSID, msg.AccountID)
	if err != nil {
		appLogger.Errorf("Error occured when configure: %v, error: %v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Info("Start cloudsploit Client")

	// Run cloudsploit
	_, segment := xray.BeginSubsegment(ctx, "runCloudSploit")
	cloudsploitResult, err := cloudsploitConfig.run(msg.AccountID)
	segment.Close(err)
	if err != nil {
		appLogger.Errorf("Failed to exec cloudsploit, error: %v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
	}); err != nil {
		appLogger.Errorf("Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Put Finding and Tag Finding
	if err := s.putFindings(ctx, cloudsploitResult, msg); err != nil {
		appLogger.Errorf("Faild to put findings. AWSID: %v, error: %v", msg.AWSID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Update status
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		appLogger.Errorf("Faild to update scan status. AWSID: %v, error: %v", msg.AWSID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	// Call AnalyzeAlert
	if err := s.CallAnalyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Errorf("Faild to analyze alert. AWSID: %v, error: %v", msg.AWSID, err)
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

func (s *sqsHandler) CallAnalyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{ProjectId: projectID})
	if err != nil {
		return err
	}
	appLogger.Info("Success to analyze alert.")
	return nil
}
