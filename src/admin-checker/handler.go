package main

import (
	"context"
	"encoding/json"
	"fmt"

	awsClient "github.com/ca-risken/aws/proto/aws"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdca-risken/aws
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
	appLogger.Infof("got message: %s", msgBody)
	msg, err := message.ParseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: SQS_msg=%+v, err=%+v", sqsMsg, err)
		return err
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
		return s.updateScanStatusError(ctx, &status, fmt.Sprintf("AssumeRoleArn for Portscan must be created in AWS AccountID: %v", msg.AccountID))
	}
	// IAM Admin Checker
	adminChecker, err := newAdminCheckerClient(msg.AssumeRoleArn, msg.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create AdminChecker session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// IAM User
	userFindings, err := adminChecker.listUserFinding(ctx, msg)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS AdminChecker: AccountID=%+v, err=%+v", msg.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	// IAM Role
	roleFindings, err := adminChecker.listRoleFinding(ctx, msg)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS AdminChecker: AccountID=%+v, err=%+v", msg.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
	}); err != nil {
		appLogger.Errorf("Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// Put finding
	if err := s.putUserFindings(ctx, msg, userFindings); err != nil {
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	if err := s.putRoleFindings(ctx, msg, roleFindings); err != nil {
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// finish
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		return err
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	return s.analyzeAlert(ctx, msg.ProjectID)
}

const (
	typeAdmin          = "admin"
	typeAccessReport   = "access-report"
	prefixAccessReport = "AccessReport/"
)

func (s *sqsHandler) putUserFindings(ctx context.Context, msg *message.AWSQueueMessage, userFindings *[]iamUser) error {
	for _, user := range *userFindings {
		appLogger.Infof("Detect IAM user: %+v", user)
		buf, err := json.Marshal(user)
		if err != nil {
			appLogger.Errorf("Failed to marshal user data, userArn=%s, err=%+v", user.UserArn, err)
			return err
		}
		// Put finding to core
		if err := s.putFindings(ctx, typeAdmin, msg, &finding.FindingForUpsert{
			Description:      fmt.Sprintf("AdminChekcer: %s(admin=%t)", user.UserName, (user.IsUserAdmin || user.IsGroupAdmin)),
			DataSource:       msg.DataSource,
			DataSourceId:     user.UserArn,
			ResourceName:     user.UserArn,
			ProjectId:        msg.ProjectID,
			OriginalScore:    scoreAdminUser(&user),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		}); err != nil {
			appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
			return err
		}
		if err := s.putFindings(ctx, typeAccessReport, msg, &finding.FindingForUpsert{
			Description:      fmt.Sprintf("AccessReport: %.1f%% unused service(%s)", (1-user.ServiceAccessedReport.AccessRate)*100, user.UserName),
			DataSource:       msg.DataSource,
			DataSourceId:     prefixAccessReport + user.UserArn,
			ResourceName:     user.UserArn,
			ProjectId:        msg.ProjectID,
			OriginalScore:    scoreAccessReport(&user.ServiceAccessedReport),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		}); err != nil {
			appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putRoleFindings(ctx context.Context, msg *message.AWSQueueMessage, roleFindings *[]iamRole) error {
	for _, role := range *roleFindings {
		appLogger.Infof("Detect IAM role: %+v", role)
		buf, err := json.Marshal(role)
		if err != nil {
			appLogger.Errorf("Failed to marshal user data, userArn=%s, err=%+v", role.RoleArn, err)
			return err
		}
		// Put finding to core
		if err := s.putFindings(ctx, typeAccessReport, msg, &finding.FindingForUpsert{
			Description:      fmt.Sprintf("AccessReport: %.1f%% unused service(%s)", (1-role.ServiceAccessedReport.AccessRate)*100, role.RoleName),
			DataSource:       msg.DataSource,
			DataSourceId:     prefixAccessReport + role.RoleArn,
			ResourceName:     role.RoleArn,
			ProjectId:        msg.ProjectID,
			OriginalScore:    scoreAccessReport(&role.ServiceAccessedReport),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		}); err != nil {
			appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findingType string, msg *message.AWSQueueMessage, f *finding.FindingForUpsert) error {
	// finding
	resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
	if err != nil {
		return err
	}
	// finding-tag
	s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, common.TagAdminChecker, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, findingType, resp.Finding.FindingId, resp.Finding.ProjectId)
	s.tagFinding(ctx, msg.AccountID, resp.Finding.FindingId, resp.Finding.ProjectId)
	awsServiceTag := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
	if awsServiceTag != common.TagUnknown {
		s.tagFinding(ctx, awsServiceTag, resp.Finding.FindingId, resp.Finding.ProjectId)
	}
	appLogger.Debugf("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
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

func scoreAccessReport(accessedReport *serviceAccessedReport) float32 {
	if accessedReport.AccessRate > 0.7 {
		return 0.1
	}
	if accessedReport.AccessRate > 0.5 {
		return 0.3
	}
	if accessedReport.AccessRate > 0.3 {
		return 0.4
	}
	if accessedReport.AccessRate > 0.1 {
		return 0.5
	}
	return 0.6
}
