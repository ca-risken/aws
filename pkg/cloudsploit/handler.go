package cloudsploit

import (
	"context"
	"errors"
	"fmt"
	"time"

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

type SqsHandler struct {
	findingClient      finding.FindingServiceClient
	alertClient        alert.AlertServiceClient
	awsClient          awsClient.AWSServiceClient
	cloudsploitConf    *CloudsploitConfig
	cloudsploitSetting *CloudsploitSetting
	logger             logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	awsc awsClient.AWSServiceClient,
	csConfig *CloudsploitConfig,
	l logging.Logger,
) (*SqsHandler, error) {
	setting, err := LoadDefaultCloudsploitSetting()
	if err != nil {
		l.Errorf(context.Background(), "Failed to load cloudsploit setting. error: %v", err)
		return nil, err
	}
	return &SqsHandler{
		findingClient:      fc,
		alertClient:        ac,
		awsClient:          awsc,
		cloudsploitConf:    csConfig,
		cloudsploitSetting: setting,
		logger:             l,
	}, nil
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message. message: %v", msgBody)
	// Parse message
	msg, err := message.ParseMessageAWS(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message. message: %v, error: %v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	beforeScanAt := time.Now()
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	s.logger.Infof(ctx, "start Scan, RequestID=%s", requestID)

	status := common.InitScanStatus(msg)
	// check AccountID matches Arn for Scan
	if !common.IsMatchAccountIDArn(msg.AccountID, msg.AssumeRoleArn) {
		s.logger.Warnf(ctx, "AccountID doesn't match AssumeRoleArn, accountID: %v, ARN: %v", msg.AccountID, msg.AssumeRoleArn)
		err = fmt.Errorf("AssumeRoleArn for CloudSploit must be created in AWS AccountID: %v", msg.AccountID)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	err = s.cloudsploitConf.generate(ctx, msg.AssumeRoleArn, msg.ExternalID, msg.AWSID, msg.AccountID)
	if err != nil {
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Run cloudsploit
	tspan, _ := tracer.StartSpanFromContext(ctx, "runCloudSploit")
	s.logger.Infof(ctx, "start cloudsploit scan, RequestID=%s", requestID)
	cloudsploitResult, err := s.run(ctx, msg.AccountID)
	tspan.Finish(tracer.WithError(err))
	if err != nil {
		s.logger.Errorf(ctx, "Failed to exec cloudsploit, error: %v", err)
		s.updateStatusToError(ctx, &status, err)
		var target EmptyOutputError
		if errors.As(err, &target) {
			s.logger.Warnf(ctx, "EmptyOutputError detected. Retry scanning ...: %v", err)
			return err // Retryable error
		}
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end cloudsploit scan, RequestID=%s", requestID)

	// Put Finding and Tag Finding
	if err := s.putFindings(ctx, cloudsploitResult, msg); err != nil {
		s.logger.Errorf(ctx, "Faild to put findings. AWSID: %v, error: %v", msg.AWSID, err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Clear score for inactive findings
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
		BeforeAt:   beforeScanAt.Unix(),
	}); err != nil {
		s.logger.Errorf(ctx, "Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	// Update status
	if err := s.updateScanStatusSuccess(ctx, &status, unknownFindings(cloudsploitResult)); err != nil {
		s.logger.Errorf(ctx, "Faild to update scan status. AWSID: %v, error: %v", msg.AWSID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	// Call AnalyzeAlert
	if err := s.CallAnalyzeAlert(ctx, msg.ProjectID); err != nil {
		s.logger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *SqsHandler) updateStatusToError(ctx context.Context, scanStatus *awsClient.AttachDataSourceRequest, err error) {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		s.logger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
}

func (s *SqsHandler) updateScanStatusError(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_ERROR
	status.AttachDataSource.StatusDetail = statusDetail
	return s.attachAWSStatus(ctx, status)
}

func (s *SqsHandler) updateScanStatusSuccess(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_OK
	status.AttachDataSource.StatusDetail = statusDetail
	return s.attachAWSStatus(ctx, status)
}

func (s *SqsHandler) attachAWSStatus(ctx context.Context, status *awsClient.AttachDataSourceRequest) error {
	resp, err := s.awsClient.AttachDataSource(ctx, status)
	if err != nil {
		return err
	}
	s.logger.Infof(ctx, "Success to update AWS status, response=%+v", resp)
	return nil
}

func (s *SqsHandler) CallAnalyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{ProjectId: projectID})
	if err != nil {
		return err
	}
	s.logger.Info(ctx, "Success to analyze alert.")
	return nil
}
