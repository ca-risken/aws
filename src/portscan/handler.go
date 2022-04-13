package main

import (
	"context"
	"fmt"
	"time"

	awsClient "github.com/ca-risken/aws/proto/aws"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
)

type sqsHandler struct {
	findingClient         finding.FindingServiceClient
	alertClient           alert.AlertServiceClient
	awsClient             awsClient.AWSServiceClient
	awsRegion             string
	scanExcludePortNumber int
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
		return s.handleErrorWithUpdateStatus(ctx, &status, fmt.Errorf("AssumeRoleArn for Portscan must be created in AWS AccountID: %v", msg.AccountID))
	}

	// Get portscan
	portscan, err := newPortscanClient(s.awsRegion, msg.AssumeRoleArn, msg.ExternalID, s.scanExcludePortNumber)
	if err != nil {
		appLogger.Errorf("Failed to create Portscan session: err=%+v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}
	regions, err := portscan.listAvailableRegion(ctx)
	if err != nil {
		appLogger.Errorf("Failed to get available regions, err = %+v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}
	statusDetail := ""
	targetsAllRegion := []*target{}
	securityGroupsAllRegion := make(map[string]*relSecurityGroupArn)
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", msg.AccountID)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		portscan, err = newPortscanClient(*region.RegionName, msg.AssumeRoleArn, msg.ExternalID, s.scanExcludePortNumber)
		if err != nil {
			appLogger.Errorf("Failed to create portscan session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}
		targets, securityGroups, err := portscan.getTargets(ctx, msg)
		targetsAllRegion = append(targetsAllRegion, targets...)
		for k, v := range securityGroups {
			securityGroupsAllRegion[k] = v
		}
		if err != nil {
			appLogger.Errorf("Failed to get findings to AWS Portscan: AccountID=%+v, err=%+v", msg.AccountID, err)
			return s.handleErrorWithUpdateStatus(ctx, &status, err)
		}
	}
	scanTargetList, excludeList := excludeScan(s.scanExcludePortNumber, targetsAllRegion)
	nmapResults, err := scan(scanTargetList)
	if err != nil {
		appLogger.Errorf("Error occured when scanning. err: %v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
	}); err != nil {
		appLogger.Errorf("Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Put finding to core
	if err := s.putFindings(ctx, msg, nmapResults, excludeList, securityGroupsAllRegion); err != nil {
		appLogger.Errorf("Failed to put findings: AccountID=%+v, err=%+v", msg.AccountID, err)
		statusDetail = fmt.Sprintf("%v%v", statusDetail, err.Error())
	}

	if err := s.updateScanStatusSuccess(ctx, &status, statusDetail); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
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
