package guardduty

import (
	"context"
	"errors"
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

type SqsHandler struct {
	findingClient    finding.FindingServiceClient
	alertClient      alert.AlertServiceClient
	awsClient        awsClient.AWSServiceClient
	awsRegion        string
	retryMaxAttempts int
	logger           logging.Logger
}

func NewSqsHandler(
	fc finding.FindingServiceClient,
	ac alert.AlertServiceClient,
	awsc awsClient.AWSServiceClient,
	region string,
	retry int,
	l logging.Logger,
) *SqsHandler {
	return &SqsHandler{
		findingClient:    fc,
		alertClient:      ac,
		awsClient:        awsc,
		awsRegion:        region,
		retryMaxAttempts: retry,
		logger:           l,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Infof(ctx, "got message: %s", msgBody)
	// Parse message
	msg, err := message.ParseMessageAWS(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid message: SQS_msg=%+v, err=%+v", msg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}
	s.logger.Infof(ctx, "start Scan, RequestID=%s", requestID)

	status := common.InitScanStatus(msg)
	guardduty, err := newGuardDutyClient(ctx, s.awsRegion, msg.AssumeRoleArn, msg.ExternalID, s.retryMaxAttempts, s.logger)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to create GuardDuty session: err=%+v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	regions, err := guardduty.listAvailableRegion(ctx)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get available regions, err = %+v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	guardDutyEnabled := false
	for _, region := range *regions {
		if region.RegionName == nil || *region.RegionName == "" {
			s.logger.Warnf(ctx, "Invalid region in AccountID=%s", msg.AccountID)
			continue
		}
		if !supportedRegion(*region.RegionName) {
			s.logger.Infof(ctx, "Skip the %s region,Because GuadDuty serveice is not supported", *region.RegionName)
			continue
		}
		s.logger.Infof(ctx, "Start %s region search...", *region.RegionName)
		guardduty, err = newGuardDutyClient(ctx, *region.RegionName, msg.AssumeRoleArn, msg.ExternalID, s.retryMaxAttempts, s.logger)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to create GuardDuty session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			s.updateStatusToError(ctx, &status, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		// Get guardduty
		findings, detecterIDs, err := guardduty.getGuardDuty(ctx, msg)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to get findngs to AWS GuardDuty: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			s.updateStatusToError(ctx, &status, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		if detecterIDs != nil && len(*detecterIDs) > 0 {
			guardDutyEnabled = true
			s.logger.Infof(ctx, "detecterIDs: %+v, length: %d", *detecterIDs, len(*detecterIDs))
		}
		// Put finding to core
		if err := s.putFindings(ctx, msg, findings); err != nil {
			s.logger.Errorf(ctx, "Failed to put findngs: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			s.updateStatusToError(ctx, &status, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
			return mimosasqs.WrapNonRetryable(err)
		}
	}
	if !guardDutyEnabled {
		err = errors.New("GuardDuty is disabled in all regions")
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Infof(ctx, "end Scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	if err := s.analyzeAlert(ctx, msg.ProjectID); err != nil {
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

var unsupportedRegions = []string{
	// "ap-east-1",
}

func supportedRegion(region string) bool {
	for _, unsupported := range unsupportedRegions {
		if region == unsupported {
			return false
		}
	}
	return true
}

func (s *SqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, findings []*guardDutyFinding) error {
	for _, f := range findings {
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: &finding.FindingForUpsert{
			Description:      f.Description,
			DataSource:       f.DataSource,
			DataSourceId:     f.DataSourceId,
			ResourceName:     f.ResourceName,
			ProjectId:        f.ProjectId,
			OriginalScore:    f.OriginalScore,
			OriginalMaxScore: f.OriginalMaxScore,
			Data:             f.Data,
		}})
		if err != nil {
			return err
		}
		s.logger.Debugf(ctx, "PutFinding response: finding_id=%d, project_id=%d", resp.Finding.FindingId, resp.Finding.ProjectId)

		// tag
		if err := s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, common.TagGuardduty, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
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
		if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, f.GuardDutyType); err != nil {
			return err
		}
		s.logger.Debugf(ctx, "Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
	}
	return nil
}

func (s *SqsHandler) tagFinding(ctx context.Context, tag string, findingID uint64, projectID uint32) error {
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

func (s *SqsHandler) updateScanStatusError(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_ERROR
	if len(statusDetail) > 200 {
		statusDetail = statusDetail[:200] + " ..." // cut long text
	}
	status.AttachDataSource.StatusDetail = statusDetail
	return s.attachAWSStatus(ctx, status)
}

func (s *SqsHandler) updateScanStatusSuccess(ctx context.Context, status *awsClient.AttachDataSourceRequest) error {
	status.AttachDataSource.Status = awsClient.Status_OK
	status.AttachDataSource.StatusDetail = ""
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

func (s *SqsHandler) analyzeAlert(ctx context.Context, projectID uint32) error {
	_, err := s.alertClient.AnalyzeAlert(ctx, &alert.AnalyzeAlertRequest{
		ProjectId: projectID,
	})
	return err
}

func (s *SqsHandler) putRecommend(ctx context.Context, projectID uint32, findingID uint64, findingType string) error {
	r := getRecommend(findingType)
	if r.Risk == "" && r.Recommendation == "" {
		s.logger.Warnf(ctx, "Failed to get recommendation, Unknown plugin=%s", findingType)
		return nil
	}
	if _, err := s.findingClient.PutRecommend(ctx, &finding.PutRecommendRequest{
		ProjectId:      projectID,
		FindingId:      findingID,
		DataSource:     message.AWSGuardDutyDataSource,
		Type:           findingType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("failed to TagFinding, finding_id=%d, finding_type=%s, error=%+v", findingID, findingType, err)
	}
	return nil
}
