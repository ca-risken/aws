package main

import (
	"context"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	portscan      portscanAPI
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

	// Get portscan
	s.portscan, err = newPortscanClient("", message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create Portscan session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	regions, err := s.portscan.listAvailableRegion()
	if err != nil {
		appLogger.Errorf("Faild to get available regions, err = %+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	statusDetail := ""
	isFirstRegion := true
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", message.AccountID)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		s.portscan, err = newPortscanClient(*region.RegionName, message.AssumeRoleArn, message.ExternalID)
		if err != nil {
			appLogger.Warnf("Faild to create portscan session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			continue
		}
		findings, err := s.getResult(message, isFirstRegion)
		if err != nil {
			appLogger.Warnf("Faild to get findngs to AWS Portscan: AccountID=%+v, err=%+v", message.AccountID, err)
			continue
		}
		// Put finding to core
		if err := s.putFindings(ctx, findings); err != nil {
			appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", message.AccountID, err)
			statusDetail = fmt.Sprintf("%v%v", statusDetail, err.Error())
		}
		isFirstRegion = false
	}

	if err := s.updateScanStatusSuccess(ctx, &status, statusDetail); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getResult(message *message.AWSQueueMessage, isFirstRegion bool) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	err := s.portscan.listSecurityGroup()
	if err != nil {
		appLogger.Errorf("Faild to describeSecurityGroups: err=%+v", err)
		return putData, err
	}
	err = s.portscan.listEC2(message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeInstances: err=%+v", err)
		return putData, err
	}
	err = s.portscan.listELB(message.AccountID)
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers: err=%+v", err)
		return putData, err
	}
	err = s.portscan.listELBv2()
	if err != nil {
		appLogger.Errorf("Faild to describeLoadBalancers(elbv2): err=%+v", err)
		return putData, err
	}
	err = s.portscan.listRDS()
	if err != nil {
		appLogger.Errorf("Faild to describeDBInstances(rds): err=%+v", err)
		return putData, err
	}
	err = s.portscan.listLightsail()
	if err != nil {
		appLogger.Errorf("Faild to getInstances(lightsail): err=%+v", err)
		return putData, err
	}
	excludeList := s.portscan.excludeScan()
	nmapResults, err := s.portscan.scan()
	if err != nil {
		appLogger.Errorf("Faild to describeSecurityGroups: err=%+v", err)
		return putData, err
	}
	putData, err = makeFindings(nmapResults, message)
	if err != nil {
		appLogger.Errorf("Faild to make findings: err=%+v", err)
		return putData, err
	}
	putDataExclude, err := makeExcludeFindings(excludeList, message)
	if err != nil {
		appLogger.Errorf("Faild to make findings: err=%+v", err)
		return putData, err
	}
	putData = append(putData, putDataExclude...)
	return putData, nil
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
