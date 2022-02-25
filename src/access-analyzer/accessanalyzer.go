package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/core/proto/finding"
)

type accessAnalyzerAPI interface {
	getAccessAnalyzer(ctx context.Context, msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error)
	listAvailableRegion(ctx context.Context) ([]*ec2.Region, error)
	listAnalyzers(ctx context.Context) (*[]string, error)
	listFindings(ctx context.Context, accountID string, analyzerArn string) ([]*accessanalyzer.FindingSummary, error)
}

type accessAnalyzerClient struct {
	Sess *session.Session
	Svc  *accessanalyzer.AccessAnalyzer
	EC2  *ec2.EC2
}

func newAccessAnalyzerClient(region, assumeRole, externalID string) (accessAnalyzerAPI, error) {
	a := accessAnalyzerClient{}
	if err := a.newAWSSession(region, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *accessAnalyzerClient) newAWSSession(region, assumeRole, externalID string) error {
	if assumeRole == "" {
		return errors.New("Required AWS AssumeRole")
	}
	sess, err := session.NewSession()
	if err != nil {
		appLogger.Errorf("Failed to create session, err=%+v", err)
		return err
	}
	var cred *credentials.Credentials
	if externalID != "" {
		cred = stscreds.NewCredentials(
			sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
			},
		)
	} else {
		cred = stscreds.NewCredentials(sess, assumeRole)
	}
	sessWithCred, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: &region, Credentials: cred},
	})
	if err != nil {
		return err
	}
	a.Sess = sessWithCred
	a.Svc = accessanalyzer.New(a.Sess, aws.NewConfig().WithRegion(region))
	a.EC2 = ec2.New(a.Sess, aws.NewConfig().WithRegion(region))
	return nil
}

func (a *accessAnalyzerClient) getAccessAnalyzer(ctx context.Context, msg *message.AWSQueueMessage) ([]*finding.FindingForUpsert, *[]string, error) {
	putData := []*finding.FindingForUpsert{}
	analyzerArns, err := a.listAnalyzers(ctx)
	if err != nil {
		appLogger.Errorf("AccessAnalyzer.ListAnalyzers error: err=%+v", err)
		return nil, &[]string{}, err
	}

	for _, arn := range *analyzerArns {
		appLogger.Infof("Detected analyzer: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
		findings, err := a.listFindings(ctx, msg.AccountID, arn)
		if err != nil {
			appLogger.Warnf(
				"AccessAnalyzer.ListFindings error: analyzerArn=%s, accountID=%s, err=%+v", arn, msg.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		appLogger.Debugf("[Debug]Got findings, %+v", findings)
		if len(findings) == 0 {
			appLogger.Infof("No findings: analyzerArn=%s, accountID=%s", arn, msg.AccountID)
			continue
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, &[]string{}, err
			}
			isPublic := false
			if data.IsPublic != nil {
				appLogger.Warnf("API Response parameter `IsPublic` got nil data, maybe something error occured, accountID=%s", msg.AccountID)
				isPublic = *data.IsPublic
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      fmt.Sprintf("AccessAnalyzer: %s (public=%t)", *data.Resource, isPublic),
				DataSource:       msg.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Resource,
				ProjectId:        msg.ProjectID,
				OriginalScore:    scoreAccessAnalyzerFinding(*data.Status, isPublic, data.Action),
				OriginalMaxScore: 1.0,
				Data:             string(buf),
			})
		}
	}
	return putData, analyzerArns, nil
}

func (a *accessAnalyzerClient) listAvailableRegion(ctx context.Context) ([]*ec2.Region, error) {
	out, err := a.EC2.DescribeRegionsWithContext(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn("Got no regions")
		return nil, nil
	}
	return out.Regions, nil
}

func (a *accessAnalyzerClient) listAnalyzers(ctx context.Context) (*[]string, error) {
	var nextToken string
	var analyzers []string
	for {
		out, err := a.Svc.ListAnalyzersWithContext(ctx, &accessanalyzer.ListAnalyzersInput{
			MaxResults: aws.Int64(50),
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

func (a *accessAnalyzerClient) listFindings(ctx context.Context, accountID string, analyzerArn string) ([]*accessanalyzer.FindingSummary, error) {
	var nextToken string
	input := &accessanalyzer.ListFindingsInput{
		AnalyzerArn: aws.String(analyzerArn),
		Filter: map[string]*accessanalyzer.Criterion{
			"resourceOwnerAccount": {Eq: []*string{aws.String(accountID)}},
			// "status":               {Eq: []*string{aws.String("ACTIVE")}},
		},
		MaxResults: aws.Int64(50),
	}
	var findings []*accessanalyzer.FindingSummary
	for {
		if nextToken != "" {
			input.NextToken = &nextToken
		}
		out, err := a.Svc.ListFindingsWithContext(ctx, input)
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
	return findings, nil
}
