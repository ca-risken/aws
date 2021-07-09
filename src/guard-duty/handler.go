package main

import (
	"context"
	"encoding/json"
	"fmt"

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

func (s *sqsHandler) HandleMessage(sqsMsg *sqs.Message) error {
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

	ctx := context.Background()
	status := common.InitScanStatus(msg)
	guardduty, err := newGuardDutyClient("", msg.AssumeRoleArn, msg.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create GuardDuty session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	regions, err := guardduty.listAvailableRegion()
	if err != nil {
		appLogger.Errorf("Faild to get available regions, err = %+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	guardDutyEnabled := false
	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", msg.AccountID)
			continue
		}
		if !supportedRegion(*region.RegionName) {
			appLogger.Infof("Skip the %s region,Because GuadDuty serveice is not supported", *region.RegionName)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		guardduty, err = newGuardDutyClient(*region.RegionName, msg.AssumeRoleArn, msg.ExternalID)
		if err != nil {
			appLogger.Errorf("Faild to create GuardDuty session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		// Get guardduty
		findings, detecterIDs, err := guardduty.getGuardDuty(msg)
		if err != nil {
			appLogger.Errorf("Faild to get findngs to AWS GuardDuty: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		appLogger.Infof("detecterIDs: %+v, length: %d", *detecterIDs, len(*detecterIDs))
		if detecterIDs != nil && len(*detecterIDs) > 0 {
			guardDutyEnabled = true
		}
		// Put finding to core
		if err := s.putFindings(ctx, msg, findings); err != nil {
			appLogger.Errorf("Faild to put findngs: Region=%s, AccountID=%s, err=%+v", *region.RegionName, msg.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
			return err
		}
	}
	if !guardDutyEnabled {
		if err := s.updateScanStatusError(ctx, &status, "GuardDuty is disabled in all regions"); err != nil {
			return err
		}
	}
	appLogger.Infof("end Scan, RequestID=%s", requestID)
	if msg.ScanOnly {
		return nil
	}
	return s.analyzeAlert(ctx, msg.ProjectID)
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

func (g *guardDutyClient) getGuardDuty(message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error) {
	putData := []*finding.FindingForUpsert{}
	detecterIDs, err := g.listDetectors()
	if err != nil {
		appLogger.Errorf("GuardDuty.ListDetectors error: err=%+v", err)
		return nil, &[]string{}, err
	}
	if detecterIDs == nil || len(*detecterIDs) == 0 {
		return nil, &[]string{}, nil // guardduty not enabled
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := g.listFindings(message.AccountID, id)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		if len(findingIDs) == 0 {
			appLogger.Infof("No findings: accountID=%s", message.AccountID)
			continue
		}
		findings, err := g.getFindings(id, findingIDs)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, detecterIDs, err
			}
			var score float32
			if *data.Service.Archived {
				score = 1.0
			} else {
				score = float32(*data.Severity)
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      *data.Title,
				DataSource:       message.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Arn,
				ProjectId:        message.ProjectID,
				OriginalScore:    score,
				OriginalMaxScore: 10.0,
				Data:             string(buf),
			})
		}
	}
	return putData, detecterIDs, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, msg *message.AWSQueueMessage, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		appLogger.Debugf("PutFinding response: finding_id=%d, project_id=%d", resp.Finding.FindingId, resp.Finding.ProjectId)

		// tag
		s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, common.TagGuardduty, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, msg.AccountID, resp.Finding.FindingId, resp.Finding.ProjectId)
		awsServiceTag := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
		if awsServiceTag != common.TagUnknown {
			s.tagFinding(ctx, awsServiceTag, resp.Finding.FindingId, resp.Finding.ProjectId)
		}
		appLogger.Debugf("Success to PutFinding, finding_id=%d", resp.Finding.FindingId)
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
