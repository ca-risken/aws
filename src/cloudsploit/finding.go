package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-core/proto/finding"
)

func makeFindings(results *[]cloudSploitResult, message *message.AWSQueueMessage) ([]*finding.FindingForUpsert, error) {
	var findings []*finding.FindingForUpsert
	for _, r := range *results {
		data, err := json.Marshal(map[string]cloudSploitResult{"data": r})
		if err != nil {
			return nil, err
		}
		findings = append(findings, &finding.FindingForUpsert{
			Description:      r.Description,
			DataSource:       message.DataSource,
			DataSourceId:     generateDataSourceID(fmt.Sprintf("description_%v_%v_%v", r.Description, r.Region, r.Resource)),
			ResourceName:     getResourceName(r.Resource, message.AccountID),
			ProjectId:        message.ProjectID,
			OriginalScore:    getScore(r.Status, r.Resource),
			OriginalMaxScore: 10.0,
			Data:             string(data),
		})
	}
	return findings, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		if f.OriginalScore == 0.0 {
			_, err := s.findingClient.PutResource(ctx, &finding.PutResourceRequest{
				Resource: &finding.ResourceForUpsert{
					ResourceName: f.ResourceName,
					ProjectId:    f.ProjectId,
				},
			})
			if err != nil {
				appLogger.Errorf("Failed to put finding project_id=%d, resource=%s, err=%+v", f.ProjectId, f.ResourceName, err)
				return err
			}
			//appLogger.Infof("Success to PutResource, finding_id=%d", resp.Resource.ResourceId)
		} else {
			res, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
			if err != nil {
				return err
			}
			s.tagFinding(ctx, res.Finding.ProjectId, res.Finding.FindingId, common.TagAWS)

			//appLogger.Infof("Success to PutFinding. finding: %v", f)
		}
	}

	return nil
}

func (s *sqsHandler) tagFinding(ctx context.Context, projectID uint32, findingID uint64, tag string) error {

	_, err := s.findingClient.TagFinding(ctx, &finding.TagFindingRequest{
		ProjectId: projectID,
		Tag: &finding.FindingTagForUpsert{
			FindingId: findingID,
			ProjectId: projectID,
			Tag:       tag,
		}})
	if err != nil {
		appLogger.Errorf("Failed to TagFinding. error: %v", err)
		return err
	}
	return nil
}

func generateDataSourceID(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func getScore(status, resource string) float32 {
	if strings.ToUpper(status) == "OK" {
		return 0.0
	}
	if resource == "Unknown" || resource == "N/A" {
		return 1.0
	}
	return 3.0
}

const (
	// cloudsploit resource
	cloudsploitUnknown = "Unknown"
	cloudsploitNA      = "N/A"

	// Unknown
	resourceUnknown = "UnknownResource"

	// Resource Type
	resourceTypeInstance  = "INSTANCE"
	resourceTypeAccessKey = "ACCESSKEY"
	resourceTypeS3        = "S3"
	resourceTypeEC2       = "EC2"
	resourceTypeIAM       = "IAM"
	resourceTypeKMS       = "KMS"
	resourceTypeLambda    = "LAMBDA"
	resourceTypeGuardDuty = "GUARDDUTY"
	resourceTypeUnknown   = "UnknownResourceType"

	// EC2
	ec2InstanceUnknown = "UnknownInstance"

	// IAM
	iamUserUnknown = "UnknownUser"
	userTypeRoot   = "ROOT"
	userTypeUser   = "USER"
	userTypeRole   = "ROLE"

	// S3
	s3BucketUnknown = "UnknownBucket"
)

func getResourceName(originalResource, accountID string) string {
	if originalResource == cloudsploitUnknown || originalResource == cloudsploitNA {
		return resourceUnknown
	}
	resource := strings.Replace(originalResource, "arn:aws:", "", 1)
	service := strings.Split(resource, ":")[0]
	detail := strings.Join(strings.Split(resource, ":")[1:], ":")
	splitDetail := strings.Split(detail, ":")
	switch strings.ToUpper(service) {
	case resourceTypeIAM:
		iamDetail := splitDetail[len(splitDetail)-1]
		if iamDetail == "" {
			appLogger.Infof("resource: %v, detail: %v, iamDetail: %v", resource, detail, iamDetail)
			return iamUserUnknown
		}
		return common.GetResourceName(common.IAM, accountID, iamDetail)
	case resourceTypeEC2:
		ec2Detail := splitDetail[len(splitDetail)-1]
		if ec2Detail == "" {
			appLogger.Infof("resource: %v, detail: %v, iamDetail: %v", resource, detail, ec2Detail)
			return ec2InstanceUnknown
		}
		instanceID := strings.Split(ec2Detail, "/")[1]
		return common.GetResourceName(common.EC2, accountID, instanceID)
	case resourceTypeS3:
		s3Detail := splitDetail[len(splitDetail)-1]
		if s3Detail == "" {
			return s3BucketUnknown
		}
		return common.GetResourceName(common.S3, accountID, s3Detail)
	case resourceTypeGuardDuty:
		gdDetail := splitDetail[len(splitDetail)-1]
		if gdDetail == "" {
			return resourceUnknown
		}
		//		return common.GetResourceName(common.GuardDuty, accountID, gdDetail)
		return resourceUnknown
	case resourceTypeKMS:
		kmsDetail := splitDetail[len(splitDetail)-1]
		if kmsDetail == "" {
			return resourceUnknown
		}
		return common.GetResourceName(common.KMS, accountID, kmsDetail)
	case resourceTypeLambda:
		kmsDetail := splitDetail[len(splitDetail)-1]
		if kmsDetail == "" {
			return resourceUnknown
		}
		return common.GetResourceName(common.Lambda, accountID, kmsDetail)
	default:
		appLogger.Infof("resource: %v, service: %v, detail: %v", resource, service, detail)
		return resourceUnknown
	}
}
