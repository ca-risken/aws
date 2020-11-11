package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/alert"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	accessAnalyzer accessAnalyzerAPI
	findingClient  finding.FindingServiceClient
	alertClient    alert.AlertServiceClient
	awsClient      awsClient.AWSServiceClient
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

	// AccessAnalyzer
	s.accessAnalyzer, err = newAccessAnalyzerClient(message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create AccessAnalyzer session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	findings, err := s.getAccessAnalyzer(message)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS AccessAnalyzer: AccountID=%+v, err=%+v", message.AccountID, err)
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

func (s *sqsHandler) getAccessAnalyzer(msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	analyzerArns, err := s.accessAnalyzer.listAnalyzers()
	if err != nil {
		appLogger.Errorf("AccessAnalyzer.ListAnalyzers error: err=%+v", err)
		return nil, err
	}

	for _, arn := range *analyzerArns {
		appLogger.Infof("Detected analyzer: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
		findings, err := s.accessAnalyzer.listFindings(msg.AccountID, arn)
		if err != nil {
			appLogger.Errorf(
				"AccessAnalyzer.ListFindings error: analyzerArn=%s, accountID=%s, err=%+v", arn, msg.AccountID, err)
			return nil, err
		}

		if len(findings) == 0 {
			appLogger.Infof("No findings: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
			continue
		}
		for _, data := range findings {
			if data == nil {
				continue
			}
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, err
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      fmt.Sprintf("AccessAnalyzer: %s (public=%t)", *data.Resource, *data.IsPublic),
				DataSource:       msg.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     getFormatedResourceName(msg.AccountID, *data.ResourceType, *data.Resource),
				ProjectId:        msg.ProjectID,
				OriginalScore:    scoreAccessAnalyzerFinding(*data.Status, *data.IsPublic, data.Action),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			})
		}
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
		s.tagFinding(ctx, common.TagAccessAnalyzer, resp.Finding.FindingId, resp.Finding.ProjectId)
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

func getFormatedResourceName(accountID, resourceType, resource string) string {
	shortName := ""
	if !strings.Contains(resource, ":") {
		shortName = resource
	} else {
		shortName = resource[strings.LastIndex(resource, ":")+1:] // aaa:bbb:ccc => ccc
	}
	var svc common.AWSService
	switch resourceType {
	case accessanalyzer.ResourceTypeAwsS3Bucket:
		svc = common.S3
	case accessanalyzer.ResourceTypeAwsIamRole:
		svc = common.IAM
	case accessanalyzer.ResourceTypeAwsSqsQueue:
		svc = common.SQS
	case accessanalyzer.ResourceTypeAwsLambdaFunction, accessanalyzer.ResourceTypeAwsLambdaLayerVersion:
		svc = common.Lambda
	case accessanalyzer.ResourceTypeAwsKmsKey:
		svc = common.KMS
	default:
		svc = common.Unknown
	}
	return common.GetResourceName(svc, accountID, shortName)
}

func scoreAccessAnalyzerFinding(status string, isPublic bool, actions []*string) float32 {
	if status != accessanalyzer.FindingStatusActive {
		return 0.1
	}
	if !isPublic {
		return 0.3
	}
	readable := false
	writable := false
	for _, action := range actions {
		if strings.Contains(*action, "List") ||
			strings.Contains(*action, "Get") ||
			strings.Contains(*action, "Describe") {
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
