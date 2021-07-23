package main

import (
	"context"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-common/pkg/logging"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
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

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *sqs.Message) error {
	msgBody := aws.StringValue(sqsMsg.Body)
	appLogger.Infof("got message: %s", msgBody)
	// Parse message
	msg, err := message.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: SQS_msg=%+v, err=%+v", msg, err)
		return err
	}
	requestID, err := logging.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		appLogger.Warnf("Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	appLogger.Infof("start Scan, RequestID=%s", requestID)

	status := awsClient.AttachDataSourceRequest{
		ProjectId: msg.ProjectID,
		AttachDataSource: &awsClient.DataSourceForAttach{
			AwsId:           msg.AWSID,
			AwsDataSourceId: msg.AWSDataSourceID,
			ProjectId:       msg.ProjectID,
			AssumeRoleArn:   msg.AssumeRoleArn,
			ExternalId:      msg.ExternalID,
			ScanAt:          time.Now().Unix(),
			// to be updated below, after the scan
			Status:       awsClient.Status_UNKNOWN,
			StatusDetail: "",
		},
	}
	// check AccountID matches Arn for Scan
	if !common.IsMatchAccountIDArn(msg.AccountID, msg.AssumeRoleArn) {
		appLogger.Warnf("AccountID doesn't match AssumeRoleArn, accountID: %v, ARN: %v", msg.AccountID, msg.AssumeRoleArn)
		return s.updateScanStatusError(ctx, &status, fmt.Sprintf("AssumeRoleArn for Portscan must be created in AWS AccountID: %v", msg.AccountID))
	}

	// Get portscan
	portscan, err := newPortscanClient("", msg.AssumeRoleArn, msg.ExternalID)
	if err != nil {
		appLogger.Errorf("Failed to create Portscan session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	regions, err := portscan.listAvailableRegion(ctx)
	if err != nil {
		appLogger.Errorf("Failed to get available regions, err = %+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	statusDetail := ""
	isFirstRegion := true
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", msg.AccountID)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		portscan, err = newPortscanClient(*region.RegionName, msg.AssumeRoleArn, msg.ExternalID)
		if err != nil {
			appLogger.Warnf("Failed to create portscan session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			continue
		}
		findings, err := portscan.getResult(ctx, msg, isFirstRegion)
		if err != nil {
			appLogger.Warnf("Failed to get findings to AWS Portscan: AccountID=%+v, err=%+v", msg.AccountID, err)
			continue
		}
		// Put finding to core
		if err := s.putFindings(ctx, msg, findings); err != nil {
			appLogger.Errorf("Failed to put findings: AccountID=%+v, err=%+v", msg.AccountID, err)
			statusDetail = fmt.Sprintf("%v%v", statusDetail, err.Error())
		}
		isFirstRegion = false
	}

	if err := s.updateScanStatusSuccess(ctx, &status, statusDetail); err != nil {
		return err
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	return s.analyzeAlert(ctx, msg.ProjectID)
}

func (s *sqsHandler) updateScanStatusError(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_ERROR
	if len(statusDetail) > 200 {
		statusDetail = statusDetail[:200] + " ..." // cut long text
	}
	status.AttachDataSource.StatusDetail = statusDetail
	return s.attachAWSStatus(ctx, status)
}

func (s *sqsHandler) updateScanStatusSuccess(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_OK
	status.AttachDataSource.StatusDetail = statusDetail
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
