package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	awsClient "github.com/ca-risken/datasource-api/proto/aws"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

type sqsHandler struct {
	findingClient finding.FindingServiceClient
	alertClient   alert.AlertServiceClient
	awsClient     awsClient.AWSServiceClient
	// cloudsploit
	resultDir      string
	configDir      string
	cloudsploitDir string
	awsRegion      string
	maxMemSizeMB   int
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	appLogger.Infof(ctx, "got message. message: %v", msgBody)
	// Parse message
	msg, err := message.ParseMessageAWS(msgBody)
	if err != nil {
		appLogger.Errorf(ctx, "Invalid message. message: %v, error: %v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := appLogger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	appLogger.Infof(ctx, "start Scan, RequestID=%s", requestID)

	status := common.InitScanStatus(msg)
	// check AccountID matches Arn for Scan
	if !common.IsMatchAccountIDArn(msg.AccountID, msg.AssumeRoleArn) {
		appLogger.Warnf(ctx, "AccountID doesn't match AssumeRoleArn, accountID: %v, ARN: %v", msg.AccountID, msg.AssumeRoleArn)
		err = fmt.Errorf("AssumeRoleArn for CloudSploit must be created in AWS AccountID: %v", msg.AccountID)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	cloudsploitConf := &CloudsploitConfig{
		ResultDir:      s.resultDir,
		ConfigDir:      s.configDir,
		CloudsploitDir: s.cloudsploitDir,
		AWSRegion:      s.awsRegion,
		MaxMemSizeMB:   s.maxMemSizeMB,
	}
	err = cloudsploitConf.generate(ctx, msg.AssumeRoleArn, msg.ExternalID, msg.AWSID, msg.AccountID)
	if err != nil {
		appLogger.Errorf(ctx, "Error occured when configure: %v, error: %v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Run cloudsploit
	tspan, _ := tracer.StartSpanFromContext(ctx, "runCloudSploit")
	appLogger.Infof(ctx, "start cloudsploit scan, RequestID=%s", requestID)
	cloudsploitResult, err := cloudsploitConf.run(ctx, msg.AccountID)
	tspan.Finish(tracer.WithError(err))
	if err != nil {
		appLogger.Errorf(ctx, "Failed to exec cloudsploit, error: %v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end cloudsploit scan, RequestID=%s", requestID)

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
	}); err != nil {
		appLogger.Errorf(ctx, "Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Put Finding and Tag Finding
	if err := s.putFindings(ctx, cloudsploitResult, msg); err != nil {
		appLogger.Errorf(ctx, "Faild to put findings. AWSID: %v, error: %v", msg.AWSID, err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Update status
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		appLogger.Errorf(ctx, "Faild to update scan status. AWSID: %v, error: %v", msg.AWSID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	// Call AnalyzeAlert
	if err := s.CallAnalyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) updateStatusToError(ctx context.Context, scanStatus *awsClient.AttachDataSourceRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
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
	appLogger.Infof(ctx, "Success to update AWS status, response=%+v", resp)
	return nil
}

func (s *sqsHandler) CallAnalyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{ProjectId: projectID})
	if err != nil {
		return err
	}
	appLogger.Info(ctx, "Success to analyze alert.")
	return nil
}
