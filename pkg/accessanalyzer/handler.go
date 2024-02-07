package accessanalyzer

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
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

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *sqsTypes.Message) error {
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

	ds, err := s.awsClient.ListDataSource(ctx, &awsClient.ListDataSourceRequest{
		ProjectId: msg.ProjectID,
		AwsId:     msg.AWSID,
	})
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get AWS data source: err=%+v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	accessAnalyzer, err := newAccessAnalyzerClient(ctx, s.awsRegion, msg, ds.DataSource, s.retryMaxAttempts, s.logger)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to create AccessAnalyzer session: err=%+v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	regions, err := accessAnalyzer.listAvailableRegion(ctx)
	if err != nil {
		s.logger.Errorf(ctx, "Failed to get available regions, err = %+v", err)
		s.updateStatusToError(ctx, &status, err)
		return mimosasqs.WrapNonRetryable(err)
	}

	analyzerEnabled := false
	for _, region := range *regions {
		if *region.RegionName == "" {
			s.logger.Warnf(ctx, "Invalid region in AccountID=%s", msg.AccountID)
			continue
		}
		if !supportedRegion(*region.RegionName) {
			s.logger.Infof(ctx, "Skip the %s region,Because AccessAnalyzer serveice is not supported", *region.RegionName)
			continue
		}
		s.logger.Infof(ctx, "Start %s region search...", *region.RegionName)
		// AccessAnalyzer
		accessAnalyzer, err = newAccessAnalyzerClient(ctx, *region.RegionName, msg, ds.DataSource, s.retryMaxAttempts, s.logger)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to create AccessAnalyzer session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			s.updateStatusToError(ctx, &status, err)
			return mimosasqs.WrapNonRetryable(err)
		}

		findings, analyzerArns, err := accessAnalyzer.getAccessAnalyzer(ctx, msg)
		if err != nil {
			s.logger.Errorf(ctx, "Failed to get findngs to AWS AccessAnalyzer: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			s.updateStatusToError(ctx, &status, err)
			return mimosasqs.WrapNonRetryable(err)
		}
		if analyzerArns != nil && len(*analyzerArns) > 0 {
			analyzerEnabled = true
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
	if !analyzerEnabled {
		err := errors.New("AccessAnalyzer is disabled in all regions")
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

func (s *SqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, findings []*finding.FindingForUpsert) error {
	sort.Slice(findings, func(i, j int) bool { return findings[i].OriginalScore < findings[j].OriginalScore })
	for _, f := range findings {
		// finding
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		// finding-tag
		if err := s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, common.TagAccessAnalyzer, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		if err := s.tagFinding(ctx, msg.AccountID, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
			return err
		}
		awsServiceType := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
		if awsServiceType != common.TagUnknown {
			if err := s.tagFinding(ctx, awsServiceType, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
				return err
			}
		}
		public, err := isPublic(f.Data)
		if err != nil {
			return err
		}
		if public {
			if err := s.tagFinding(ctx, common.TagPublicFacing, resp.Finding.FindingId, resp.Finding.ProjectId); err != nil {
				return err
			}
		} else {
			if err := s.untagResource(ctx, common.TagPublicFacing, resp.Finding.ResourceName, resp.Finding.ProjectId); err != nil {
				return err
			}
		}
		// recommend
		if err := s.putRecommend(ctx, resp.Finding.ProjectId, resp.Finding.FindingId, awsServiceType); err != nil {
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

func (s *SqsHandler) untagResource(ctx context.Context, tag string, resourceName string, projectID uint32) error {
	if _, err := s.findingClient.UntagByResourceName(ctx, &finding.UntagByResourceNameRequest{
		ProjectId:    projectID,
		ResourceName: resourceName,
		Tag:          tag,
	}); err != nil {
		return fmt.Errorf("failed to UntagByResourceName, tag=%s, error=%+v", tag, err)
	}
	return nil
}

func (s *SqsHandler) updateScanStatusError(ctx context.Context, status *awsClient.AttachDataSourceRequest, statusDetail string) error {
	status.AttachDataSource.Status = awsClient.Status_ERROR
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
		DataSource:     message.AWSAccessAnalyzerDataSource,
		Type:           findingType,
		Risk:           r.Risk,
		Recommendation: r.Recommendation,
	}); err != nil {
		return fmt.Errorf("failed to TagFinding, finding_id=%d, finding_type=%s, error=%+v", findingID, findingType, err)
	}
	return nil
}

func scoreAccessAnalyzerFinding(status types.FindingStatus, isPublic bool, actions []string) float32 {
	if status != types.FindingStatusActive {
		return 0.1
	}
	if !isPublic {
		return 0.3
	}
	readable := false
	writable := false
	for _, action := range actions {
		if strings.Contains(action, "Check") ||
			strings.Contains(action, "Describe") ||
			strings.Contains(action, "ESHttpHead") ||
			strings.Contains(action, "Get") ||
			strings.Contains(action, "List") ||
			strings.Contains(action, "Lookup") ||
			strings.Contains(action, "Query") ||
			strings.Contains(action, "Read") ||
			strings.Contains(action, "Retrieve") ||
			strings.Contains(action, "Scan") ||
			strings.Contains(action, "Search") ||
			strings.Contains(action, "Select") ||
			strings.Contains(action, "Validate") ||
			strings.Contains(action, "View") {
			readable = true
			continue
		}
		writable = true
		if readable && writable {
			break
		}
	}
	if readable && !writable {
		return 0.7 // Readable resource
	}
	if !readable && writable {
		return 0.9 // Writable resource
	}
	return 1.0 // Both readable and writable
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
