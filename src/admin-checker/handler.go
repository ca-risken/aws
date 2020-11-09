package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	adminChecker  adminCheckerAPI
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
			Status:          awsClient.Status_UNKNOWN, // After scan, will be updated
			StatusDetail:    "",
		},
	}

	// IAM Admin Checker
	s.adminChecker, err = newAdminCheckerClient(message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create AdminChecker session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	findings, err := s.getAdminUser(message)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS AdminChecker: AccountID=%+v, err=%+v", message.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())

	}

	// Put finding to core
	if err := s.putFindings(ctx, findings); err != nil {
		appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", message.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		return err
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getAdminUser(msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	iamUsers, err := s.adminChecker.listUser()
	if err != nil {
		appLogger.Errorf("IAM.ListUser error: err=%+v", err)
		return nil, err
	}

	for _, user := range *iamUsers {
		appLogger.Infof("Detect IAM user: %+v", user)
		buf, err := json.Marshal(user)
		if err != nil {
			appLogger.Errorf("Failed to marshal user data, userArn=%s, err=%+v", user.UserArn, err)
			return nil, err
		}
		putData = append(putData, &finding.FindingForUpsert{
			Description:      fmt.Sprintf("AdminChekcer: %s(admin=%t)", user.UserName, (user.IsUserAdmin || user.IsGroupAdmin)),
			DataSource:       msg.DataSource,
			DataSourceId:     user.UserArn,
			ResourceName:     common.GetResourceName(common.IAM, msg.AccountID, fmt.Sprintf("user/%s", user.UserName)),
			ProjectId:        msg.ProjectID,
			OriginalScore:    scoreAdminUser(&user),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		})
	}
	return putData, nil
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
		s.tagFinding(ctx, common.TagAdminChecker, resp.Finding.FindingId, resp.Finding.ProjectId)
		awsServiceTag := common.GetAWSServiceTagByResourceName(resp.Finding.ResourceName)
		if awsServiceTag != "" {
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

func scoreAdminUser(user *iamUser) float32 {
	isAdmin := false
	if user.IsUserAdmin || user.IsGroupAdmin {
		isAdmin = true
	}
	if !isAdmin {
		return 0.3
	}
	if isAdmin && user.EnabledPermissionBoundory {
		return 0.7
	}
	return 0.9
}
