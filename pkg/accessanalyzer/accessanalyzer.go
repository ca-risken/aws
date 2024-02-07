package accessanalyzer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
	riskenaws "github.com/ca-risken/datasource-api/proto/aws"
)

type accessAnalyzerAPI interface {
	getAccessAnalyzer(ctx context.Context, msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error)
	listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error)
	listAnalyzers(ctx context.Context) (*[]string, error)
	listFindings(ctx context.Context, accountID string, analyzerArn string) (*[]types.FindingSummary, error)
}

type accessAnalyzerClient struct {
	Svc    *accessanalyzer.Client
	EC2    *ec2.Client
	SNS    *sns.Client
	SQS    *sqs.Client
	logger logging.Logger
}

func newAccessAnalyzerClient(ctx context.Context, region string, msg *message.AWSQueueMessage, ds []*riskenaws.DataSource, retry int, l logging.Logger) (accessAnalyzerAPI, error) {
	a := accessAnalyzerClient{logger: l}
	cfg, err := a.newAWSSession(ctx, region, msg.AssumeRoleArn, msg.ExternalID, retry)
	if err != nil {
		return nil, err
	}
	a.Svc = accessanalyzer.New(accessanalyzer.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	a.EC2 = ec2.New(ec2.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})

	if strings.Contains(msg.AssumeRoleArn, msg.AccountID) {
		a.SNS = sns.New(sns.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
		a.SQS = sqs.New(sqs.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	} else {
		// If AssumeRoleArn is different from AccountID, it is necessary to assume the same account role to access specific services.
		for _, d := range ds {
			if strings.Contains(d.AssumeRoleArn, msg.AccountID) {
				cfg, err = a.newAWSSession(ctx, region, d.AssumeRoleArn, d.ExternalId, retry) // overwrite session
				if err != nil {
					return nil, err
				}
				a.SNS = sns.New(sns.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
				a.SQS = sqs.New(sqs.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
				break
			}
		}
	}
	return &a, nil
}

const REGION_US_EAST_1 = "us-east-1"

func (a *accessAnalyzerClient) newAWSSession(ctx context.Context, region, assumeRole, externalID string, retry int) (*aws.Config, error) {
	if assumeRole == "" {
		return nil, errors.New("required AWS AssumeRole")
	}
	if externalID == "" {
		return nil, errors.New("required AWS ExternalID")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(REGION_US_EAST_1))
	if err != nil {
		return nil, err
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, assumeRole,
		func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = "RISKEN"
			p.ExternalID = &externalID
		},
	)
	cfg.Credentials = aws.NewCredentialsCache(provider)
	_, err = cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (a *accessAnalyzerClient) getAccessAnalyzer(ctx context.Context, msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error) {
	putData := []*finding.FindingForUpsert{}
	analyzerArns, err := a.listAnalyzers(ctx)
	if err != nil {
		a.logger.Errorf(ctx, "AccessAnalyzer.ListAnalyzers error: err=%+v", err)
		return nil, &[]string{}, err
	}

	for _, arn := range *analyzerArns {
		a.logger.Infof(ctx, "Detected analyzer: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
		findings, err := a.listFindings(ctx, msg.AccountID, arn)
		if err != nil {
			// If Organization gathering enabled, requesting an invalid Region may result in an error.
			// But we don't know what kind of error is it, so notify all errors and handle in operation.
			// TODO skip above case after we know what kind of the error
			a.logger.Notifyf(ctx, logging.ErrorLevel,
				"AccessAnalyzer.ListFindings error: analyzerArn=%s, accountID=%s, err=%+v", arn, msg.AccountID, err)
			return nil, &[]string{}, err
		}
		if findings == nil || len(*findings) == 0 {
			a.logger.Infof(ctx, "No findings: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
			continue
		}
		for _, data := range *findings {
			buf, err := json.Marshal(data)
			if err != nil {
				a.logger.Errorf(ctx, "Failed to json encoding error: err=%+v", err)
				return nil, &[]string{}, err
			}
			isPublic := false
			if data.IsPublic != nil {
				isPublic = *data.IsPublic
			}
			description := "Unpublished resource detected"
			if isPublic {
				description = "The resource is public from Internet or any AWS account"
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      description,
				DataSource:       msg.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Resource,
				ProjectId:        msg.ProjectID,
				OriginalScore:    scoreAccessAnalyzerFinding(data.Status, isPublic, data.Action),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			})
		}
	}
	return putData, analyzerArns, nil
}

func (a *accessAnalyzerClient) listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error) {
	out, err := a.EC2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		a.logger.Warn(ctx, "Got no regions")
		return nil, nil
	}
	return &out.Regions, nil
}

func (a *accessAnalyzerClient) listAnalyzers(ctx context.Context) (*[]string, error) {
	var nextToken string
	var analyzers []string
	for {
		out, err := a.Svc.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{
			MaxResults: aws.Int32(50),
			NextToken:  &nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, analyzer := range out.Analyzers {
			analyzers = append(analyzers, *analyzer.Arn)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
	}
	return &analyzers, nil
}

func (a *accessAnalyzerClient) listFindings(ctx context.Context, accountID string, analyzerArn string) (*[]types.FindingSummary, error) {
	var nextToken string
	input := &accessanalyzer.ListFindingsInput{
		AnalyzerArn: aws.String(analyzerArn),
		Filter: map[string]types.Criterion{
			"resourceOwnerAccount": {Eq: []string{accountID}},

			// EFS(ignore type): Access to EFS is excluded as it requires internal network reachability as a prerequisite.
			// https://docs.aws.amazon.com/ja_jp/efs/latest/ug/NFS-access-control-efs.html
			"resourceType": {Neq: []string{string(types.ResourceTypeAwsEfsFilesystem)}},
		},
		MaxResults: aws.Int32(50),
	}
	var findings []types.FindingSummary
	for {
		if nextToken != "" {
			input.NextToken = &nextToken
		}
		out, err := a.Svc.ListFindings(ctx, input)
		if err != nil {
			return nil, err
		}
		findings = append(findings, out.Findings...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
		time.Sleep(time.Millisecond * 500)
	}

	for idx, f := range findings {
		if f.Condition == nil || len(f.Condition) == 0 {
			// Condition is empty, so we will analyze more deeply.
			condition, err := a.analyzeCondition(ctx, f)
			if err != nil {
				return nil, err
			}
			findings[idx].Condition = condition // Update condition
		}
	}
	return &findings, nil
}

type accessAnalyzerAPIResponse struct {
	IsPublic bool `json:"IsPublic"`
}

func isPublic(data string) (bool, error) {
	var res accessAnalyzerAPIResponse
	err := json.Unmarshal([]byte(data), &res)
	if err != nil {
		return false, err
	}
	return res.IsPublic, nil
}

func (a *accessAnalyzerClient) analyzeCondition(ctx context.Context, finding types.FindingSummary) (map[string]string, error) {
	if a.SNS == nil || a.SQS == nil {
		return nil, nil
	}
	switch finding.ResourceType {
	case types.ResourceTypeAwsSnsTopic:
		return a.analyzeSnsTopicCondition(ctx, finding)
	case types.ResourceTypeAwsSqsQueue:
		return a.analyzeSqsQueueCondition(ctx, finding)
	}
	return nil, nil
}

const (
	ERROR_CODE_SNS_NOT_FOUND = "NotFound"
	ERROR_CODE_SQS_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
)

func (a *accessAnalyzerClient) analyzeSnsTopicCondition(ctx context.Context, finding types.FindingSummary) (map[string]string, error) {
	attr, err := a.SNS.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
		TopicArn: aws.String(*finding.Resource),
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			a.logger.Warnf(ctx, "SNS.GetTopicAttributes error: code=%s, message=%s, fault=%s", ae.ErrorCode(), ae.ErrorMessage(), ae.ErrorFault().String())
			if ae.ErrorCode() == ERROR_CODE_SNS_NOT_FOUND {
				a.logger.Warnf(ctx, "SNS topic not found: arn=%s", *finding.Resource)
				return nil, nil
			}
		}
		return nil, err
	}
	return map[string]string{
		"Policy": attr.Attributes["Policy"],
	}, nil
}

func (a *accessAnalyzerClient) analyzeSqsQueueCondition(ctx context.Context, finding types.FindingSummary) (map[string]string, error) {
	url := getQueueURLFromArn(*finding.Resource)
	if url == "" {
		return nil, fmt.Errorf("failed to get queue name from ARN, ARN=%s", *finding.Resource)
	}
	attr, err := a.SQS.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl: aws.String(url),
		AttributeNames: []sqstypes.QueueAttributeName{
			sqstypes.QueueAttributeNamePolicy,
		},
	})
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			a.logger.Warnf(ctx, "SQS.GetQueueAttributes error: code=%s, message=%s, fault=%s", ae.ErrorCode(), ae.ErrorMessage(), ae.ErrorFault().String())
			if ae.ErrorCode() == ERROR_CODE_SQS_NOT_FOUND {
				return nil, nil
			}
		}
		return nil, err
	}
	return map[string]string{
		"Policy": attr.Attributes["Policy"],
	}, nil
}

func getQueueURLFromArn(queueArn string) string {
	parts := strings.Split(queueArn, ":")
	if len(parts) < 6 {
		return ""
	}
	return fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", parts[3], parts[4], parts[5])
}
