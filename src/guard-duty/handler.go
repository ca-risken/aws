package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	guardduty     guardDutyAPI
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
	status := common.InitScanStatus(message)
	s.guardduty, err = newGuardDutyClient("", message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create GuardDuty session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	regions, err := s.guardduty.listAvailableRegion()
	if err != nil {
		appLogger.Errorf("Faild to get available regions, err = %+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	for _, region := range regions {
		if region == nil || *region.RegionName == "" {
			appLogger.Warnf("Invalid region in AccountID=%s", message.AccountID)
			continue
		}
		appLogger.Infof("Start %s region search...", *region.RegionName)
		s.guardduty, err = newGuardDutyClient(*region.RegionName, message.AssumeRoleArn, message.ExternalID)
		if err != nil {
			appLogger.Errorf("Faild to create GuardDuty session: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		// Get guardduty
		findings, err := s.getGuardDuty(message)
		if err != nil {
			appLogger.Errorf("Faild to get findngs to AWS GuardDuty: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		// Put finding to core
		if err := s.putFindings(ctx, findings); err != nil {
			appLogger.Errorf("Faild to put findngs: Region=%s, AccountID=%s, err=%+v", *region.RegionName, message.AccountID, err)
			return s.updateScanStatusError(ctx, &status, err.Error())
		}
		if err := s.updateScanStatusSuccess(ctx, &status); err != nil {
			return err
		}
	}
	return s.analyzeAlert(ctx, message.ProjectID)
}

func (s *sqsHandler) getGuardDuty(message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	detecterIDs, err := s.guardduty.listDetectors()
	if err != nil {
		appLogger.Errorf("GuardDuty.ListDetectors error: err=%+v", err)
		return nil, err
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := s.guardduty.listFindings(message.AccountID, id)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		if len(findingIDs) == 0 {
			appLogger.Infof("No findings: accountID=%s", message.AccountID)
			continue
		}
		findings, err := s.guardduty.getFindings(id, findingIDs)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, err
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
	return putData, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		appLogger.Debugf("PutFinding response: finding_id=%d, project_id=%d", resp.Finding.FindingId, resp.Finding.ProjectId)

		// tag
		s.tagFinding(ctx, common.TagAWS, resp.Finding.FindingId, resp.Finding.ProjectId)
		s.tagFinding(ctx, common.TagGuardduty, resp.Finding.FindingId, resp.Finding.ProjectId)
		awsServiceTag := common.GetAWSServiceTagByARN(resp.Finding.ResourceName)
		if awsServiceTag != common.TagUnknown {
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
