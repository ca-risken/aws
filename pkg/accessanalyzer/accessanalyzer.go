package accessanalyzer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
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
	logger logging.Logger
}

func newAccessAnalyzerClient(ctx context.Context, region, assumeRole, externalID string, retry int, l logging.Logger) (accessAnalyzerAPI, error) {
	a := accessAnalyzerClient{logger: l}
	if err := a.newAWSSession(ctx, region, assumeRole, externalID, retry); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *accessAnalyzerClient) newAWSSession(ctx context.Context, region, assumeRole, externalID string, retry int) error {
	if assumeRole == "" {
		return errors.New("required AWS AssumeRole")
	}
	if externalID == "" {
		return errors.New("required AWS ExternalID")
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return err
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
		return err
	}
	a.Svc = accessanalyzer.New(accessanalyzer.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	a.EC2 = ec2.New(ec2.Options{Credentials: cfg.Credentials, Region: region, RetryMaxAttempts: retry})
	return nil
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
		a.logger.Debugf(ctx, "[Debug]Got findings, %+v", findings)
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
			putData = append(putData, &finding.FindingForUpsert{
				Description:      fmt.Sprintf("AccessAnalyzer: %s (public=%t)", *data.Resource, isPublic),
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
	return &findings, nil
}
