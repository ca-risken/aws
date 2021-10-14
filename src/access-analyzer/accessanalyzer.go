package main

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/core/proto/finding"
	"github.com/gassara-kys/envconfig"
)

type accessAnalyzerAPI interface {
	getAccessAnalyzer(*message.AWSQueueMessage) ([]*finding.FindingForUpsert, error)
	listAvailableRegion() ([]*ec2.Region, error)
	listAnalyzers() (*[]string, error)
	listFindings(string, string) ([]*accessanalyzer.FindingSummary, error)
}

type accessAnalyzerClient struct {
	Sess *session.Session
	Svc  *accessanalyzer.AccessAnalyzer
	EC2  *ec2.EC2
}

type accessAnalyzerConfig struct {
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"` // Default region
}

func newAccessAnalyzerClient(region, assumeRole, externalID string) (*accessAnalyzerClient, error) {
	if region == "" {
		var conf accessAnalyzerConfig
		err := envconfig.Process("", &conf)
		if err != nil {
			return nil, err
		}
		region = conf.AWSRegion
	}
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
	var cred *credentials.Credentials
	if externalID != "" {
		cred = stscreds.NewCredentials(
			session.New(), assumeRole, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = aws.String(externalID)
			},
		)
	} else {
		cred = stscreds.NewCredentials(session.New(), assumeRole)
	}
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            aws.Config{Region: &region, Credentials: cred},
	})
	if err != nil {
		return err
	}
	a.Sess = sess
	a.Svc = accessanalyzer.New(a.Sess, aws.NewConfig().WithRegion(region))
	a.EC2 = ec2.New(a.Sess, aws.NewConfig().WithRegion(region))
	return nil
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
		for _, f := range out.Findings {
			findings = append(findings, f)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
		time.Sleep(time.Millisecond * 500)
	}
	return findings, nil
}
