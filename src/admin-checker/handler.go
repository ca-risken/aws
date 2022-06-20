package main

import (
	"context"
	"encoding/json"
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
)

type sqsHandler struct {
	findingClient    finding.FindingServiceClient
	alertClient      alert.AlertServiceClient
	awsClient        awsClient.AWSServiceClient
	awsRegion        string
	retryMaxAttempts int
}

func (s *sqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	appLogger.Infof(ctx, "got message: %s", msgBody)
	msg, err := message.ParseMessageAWS(msgBody)
	if err != nil {
		appLogger.Errorf(ctx, "Invalid message: SQS_msg=%+v, err=%+v", sqsMsg, err)
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
		return s.handleErrorWithUpdateStatus(ctx, &status, fmt.Errorf("AssumeRoleArn for admin-checker must be created in AWS AccountID: %v", msg.AccountID))
	}
	// IAM Admin Checker
	adminChecker, err := newAdminCheckerClient(ctx, s.awsRegion, msg.AssumeRoleArn, msg.ExternalID, s.retryMaxAttempts)
	if err != nil {
		appLogger.Errorf(ctx, "Faild to create AdminChecker session: err=%+v", err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// IAM User
	userFindings, err := adminChecker.listUserFinding(ctx, msg)
	if err != nil {
		appLogger.Errorf(ctx, "Faild to get findngs to AWS AdminChecker: AccountID=%+v, err=%+v", msg.AccountID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}
	// IAM Role
	roleFindings, err := adminChecker.listRoleFinding(ctx, msg)
	if err != nil {
		appLogger.Errorf(ctx, "Faild to get findngs to AWS AdminChecker: AccountID=%+v, err=%+v", msg.AccountID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Clear finding score
	if _, err := s.findingClient.ClearScore(ctx, &finding.ClearScoreRequest{
		DataSource: msg.DataSource,
		ProjectId:  msg.ProjectID,
		Tag:        []string{msg.AccountID},
	}); err != nil {
		appLogger.Errorf(ctx, "Failed to clear finding score. AWSID: %v, error: %v", msg.AWSID, err)
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// Put finding
	if err := s.putUserFindings(ctx, msg, userFindings); err != nil {
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}
	if err := s.putRoleFindings(ctx, msg, roleFindings); err != nil {
		return s.handleErrorWithUpdateStatus(ctx, &status, err)
	}

	// finish
	if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
		return mimosasqs.WrapNonRetryable(err)
	}
	appLogger.Infof(ctx, "end Scan, RequestID=%s", requestID)

	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
		appLogger.Notifyf(ctx, logging.ErrorLevel, "Failed to analyzeAlert, project_id=%d, err=%+v", msg.ProjectID, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	return nil
}

func (s *sqsHandler) handleErrorWithUpdateStatus(ctx context.Context, scanStatus *awsClient.AttachDataSourceRequest, err error) error {
	if updateErr := s.updateScanStatusError(ctx, scanStatus, err.Error()); updateErr != nil {
		appLogger.Warnf(ctx, "Failed to update scan status error: err=%+v", updateErr)
	}
	return mimosasqs.WrapNonRetryable(err)
}

const (
	typeAdmin          = "admin"
	typeAccessReport   = "access-report"
	prefixAccessReport = "AccessReport/"
)

func (s *sqsHandler) putUserFindings(ctx context.Context, msg *message.AWSQueueMessage, userFindings *[]iamUser) error {
	for _, user := range *userFindings {
		appLogger.Debugf(ctx, "Detect IAM user: %+v", user)
		buf, err := json.Marshal(user)
		if err != nil {
			appLogger.Errorf(ctx, "Failed to marshal user data, userArn=%s, err=%+v", user.UserArn, err)
			return err
		}
		// Put finding to core
		if err := s.putFindings(ctx, typeAdmin, msg, &finding.FindingForUpsert{
			Description:      fmt.Sprintf("AdminChekcer: %s(admin=%t)", user.UserName, user.IsUserAdmin || user.IsGroupAdmin),
			DataSource:       msg.DataSource,
			DataSourceId:     user.UserArn,
			ResourceName:     user.UserArn,
			ProjectId:        msg.ProjectID,
			OriginalScore:    scoreAdminUser(&user),
			OriginalMaxScore: 1.0,
			Data:             string(buf),
		}); err != nil {
			appLogger.Errorf(ctx, "Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
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
			appLogger.Errorf(ctx, "Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
			return err
		}
	}
	return nil
}

func (s *sqsHandler) putRoleFindings(ctx context.Context, msg *message.AWSQueueMessage, roleFindings *[]iamRole) error {
	for _, role := range *roleFindings {
		appLogger.Debugf(ctx, "Detect IAM role: %+v", role)
		buf, err := json.Marshal(role)
		if err != nil {
			appLogger.Errorf(ctx, "Failed to marshal user data, userArn=%s, err=%+v", role.RoleArn, err)
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
			appLogger.Errorf(ctx, "Faild to put findngs: AccountID=%+v, err=%+v", msg.AccountID, err)
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
	if err := s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, common.TagAdminChecker, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, findingType, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	if err := s.tagFinding(ctx, msg.AccountID, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
		return err
	}
	awsServiceTag := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
	if awsServiceTag != common.TagUnknown {
		if err := s.tagFinding(ctx, awsServiceTag, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
	}
	// recommend
	if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, findingType); err != nil {
		return err
	}
	appLogger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
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
		return fmt.Errorf("failed to TagFinding, finding_id=%d, tag=%s, error=%+v", findingID, tag, err)
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
	appLogger.Infof(ctx, "Success to update AWS status, response=%+v", resp)
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
		appLogger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", findingType)
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.AWSAdminCheckerDataSource,
		Type:           findingType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("failed to PutRecommend, finding_id=%d, finding_type=%s, error=%+v", findingID, findingType, err)
	}
	return nil
}

func scoreAdminUser(user *iamUser) float32 {
	isAdmin := false
	if user.IsUserAdmin || user.IsGroupAdmin {
		isAdmin = true
	}
	if !isAdmin {
		return 0.3
	}
	enabledMFA := user.EnabledPhysicalMFA || user.EnabledVirtualMFA
	if len(user.ActiveAccessKeyID) == 0 && enabledMFA {
		return 0.5
	}
	if user.EnabledPermissionBoundory {
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
