package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	cloudsploitConfig cloudsploitConfig
	findingClient     finding.FindingServiceClient
	alertClient       alert.AlertServiceClient
	awsClient         awsClient.AWSServiceClient
}

func newHandler() *sqsHandler {
	h := &sqsHandler{}
	//	h.cloudsploitConfig = newcloudsploitConfig()
	//	appLogger.Info("Start cloudsploit Client")
	h.findingClient = newFindingClient()
	appLogger.Info("Start Finding Client")
	h.alertClient = newAlertClient()
	appLogger.Info("Start Alert Client")
	h.awsClient = newAWSClient()
	appLogger.Info("Start AWS Client")
	return h
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message. message: %v", msgBody)
	// Parse message
	message, err := parseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message. message: %v, error: %v", message, err)
		return err
	}
	s.cloudsploitConfig, err = newcloudsploitConfig(message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Error occured when configure: %v, error: %v", message, err)
		return err
	}
	appLogger.Info("Start cloudsploit Client")

	ctx := context.Background()
	status := awsClient.AttachDataSourceRequest{
		ProjectId: message.ProjectID,
		AttachDataSource: &awsClient.DataSourceForAttach{
			AwsId:           message.AWSID,
			AwsDataSourceId: message.AWSDataSourceID,
			ProjectId:       message.ProjectID,
			AssumeRoleArn:   message.AssumeRoleArn,
			ExternalId:      message.ExternalID,
			ScanAt:          time.Now().Unix(),
			// to be updated below, after the scan
			Status:       awsClient.Status_UNKNOWN,
			StatusDetail: "",
		},
	}

	// Run cloudsploit
	cloudsploitResult, err := s.cloudsploitConfig.run(message.AccountID)
	//cloudsploitResult, err := s.cloudsploitConfig.tmpRun(message.AccountID)
	if err != nil {
		appLogger.Errorf("Failed exec cloudsploit, error: %v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// Put Finding and Tag Finding
	if err := s.putFindings(ctx, cloudsploitResult, message); err != nil {
		appLogger.Errorf("Faild to put findings. AWSID: %v, error: %v", message.AWSID, err)
		return err
	}

	// Put RelOsintDataSource
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		appLogger.Errorf("Faild to put rel_osint_data_source. AWSID: %v, error: %v", message.AWSID, err)
		return err
	}

	// Call AnalyzeAlert
	if err := s.CallAnalyzeAlert(ctx, message.ProjectID); err != nil {
		appLogger.Errorf("Faild to analyze alert. AWSID: %v, error: %v", message.AWSID, err)
		return err
	}
	return nil

}

func parseMessage(msg string) (*message.AWSQueueMessage, error) {
	message := &message.AWSQueueMessage{}
	if err := json.Unmarshal([]byte(msg), message); err != nil {
		return nil, err
	}
	//	if err := message.Validate(); err != nil {
	//		return nil, err
	//	}
	return message, nil
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

func getStatus(isSuccess bool) awsClient.Status {
	if isSuccess {
		return awsClient.Status_OK
	}
	return awsClient.Status_ERROR
}
