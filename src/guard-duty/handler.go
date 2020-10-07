package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	awsClient "github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type sqsHandler struct {
	guardduty     guardDutyAPI
	findingClient finding.FindingServiceClient
	awsClient     awsClient.AWSServiceClient
}

func newHandler() *sqsHandler {
	return &sqsHandler{
		findingClient: newFindingClient(),
		awsClient:     newAWSClient(),
	}
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message: %s", msgBody)
	// Parse message
	message, err := parseMessage(msgBody)
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

	// Get guardduty
	s.guardduty, err = newGuardDutyClient(message.AssumeRoleArn, message.ExternalID)
	if err != nil {
		appLogger.Errorf("Faild to create GuardDuty session: err=%+v", err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	findings, err := s.getGuardDuty(message)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS GuardDuty: AccountID=%+v, err=%+v", message.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}

	// Put finding to core
	if err := s.putFindings(ctx, findings); err != nil {
		appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", message.AccountID, err)
		return s.updateScanStatusError(ctx, &status, err.Error())
	}
	return s.updateScanStatusSuccess(ctx, &status)
}

func parseMessage(msg string) (*message.AWSQueueMessage, error) {
	message := &message.AWSQueueMessage{}
	if err := json.Unmarshal([]byte(msg), message); err != nil {
		return nil, err
	}
	if err := message.Validate(); err != nil {
		return nil, err
	}
	return message, nil
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
			appLogger.Errorf(
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			return nil, err
		}

		if len(findingIDs) == 0 {
			appLogger.Infof("No findings: accountID=%s", message.AccountID)
			continue
		}
		findings, err := s.guardduty.getFindings(id, findingIDs)
		if err != nil {
			appLogger.Errorf(
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			return nil, err
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, err
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      *data.Title,
				DataSource:       message.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     getResourceName(data),
				ProjectId:        message.ProjectID,
				OriginalScore:    float32(*data.Severity),
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
		appLogger.Infof("Success to PutFinding, response=%+v", resp)
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
	appLogger.Infof("Success to AttachDataSource, response=%+v", resp)
	return nil
}

const (
	// Unknown
	resourceUnknown = "UnknownResource"

	// Resource Type
	resourceTypeInstance  = "INSTANCE"
	resourceTypeAccessKey = "ACCESSKEY"
	resourceTypeS3Bucket  = "S3BUCKET"
	resourceTypeUnknown   = "UnknownResourceType"

	// EC2
	ec2InstanceUnknown = "UnknownInstance"

	// IAM
	iamUserUnknown        = "UnknownUser"
	userTypeRoot          = "ROOT"
	userTypeIAMUser       = "IAMUSER"
	userTypeAssumedRole   = "ASSUMEDROLE"
	userTypeFederatedUser = "FEDERATEDUSER"
	userTypeAWSService    = "AWSSERVICE"
	userTypeAWSAccount    = "AWSACCOUNT"
	userTypeUnknown       = "UnknownUserType"

	// S3
	s3BucketUnknown = "UnknownBucket"

	// Resource Name template
	ec2ResourceTemplate = "ec2/%s/%s" // ec2/{account-id}/{instance-id}
	iamResourceTemplate = "iam/%s/%s" // iam/{account-id}/{user-name}
	s3ResourceTemplate  = "s3/%s/%s"  // s3/{account-id}/{bucket-name}
)

func getResourceName(f *guardduty.Finding) string {
	if f == nil || f.Resource == nil || f.Resource.ResourceType == nil {
		return resourceUnknown
	}

	switch strings.ToUpper(*f.Resource.ResourceType) {
	case resourceTypeInstance:
		if f.Resource.InstanceDetails == nil || f.Resource.InstanceDetails.InstanceId == nil {
			return ec2InstanceUnknown
		}
		return fmt.Sprintf(ec2ResourceTemplate, *f.AccountId, *f.Resource.InstanceDetails.InstanceId)
	case resourceTypeAccessKey:
		if f.Resource.AccessKeyDetails == nil || f.Resource.AccessKeyDetails.UserName == nil {
			return iamUserUnknown
		}
		switch strings.ToUpper(*f.Resource.AccessKeyDetails.UserType) {
		case userTypeRoot,
			userTypeIAMUser,
			userTypeAssumedRole,
			userTypeFederatedUser,
			userTypeAWSService,
			userTypeAWSAccount:
			return fmt.Sprintf(iamResourceTemplate, *f.AccountId, *f.Resource.AccessKeyDetails.UserName)
		default:
			return userTypeUnknown
		}
	case resourceTypeS3Bucket:
		if len(f.Resource.S3BucketDetails) > 0 {
			buckets := ""
			for _, b := range f.Resource.S3BucketDetails {
				if b.Name == nil {
					continue
				}
				buckets += *b.Name + ","
			}
			buckets = strings.TrimRight(buckets, ",")
			return fmt.Sprintf(s3ResourceTemplate, *f.AccountId, buckets)
		}
		return fmt.Sprintf(s3ResourceTemplate, *f.AccountId, s3BucketUnknown)
	default:
		return resourceTypeUnknown
	}
}
