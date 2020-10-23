package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
	"github.com/kelseyhightower/envconfig"
)

type accessAnalyzerAPI interface {
	listAnalyzers() (*[]string, error)
	listFindings(string, string) ([]*accessanalyzer.FindingSummary, error)
}

type accessAnalyzerClient struct {
	Sess *session.Session
	Svc  *accessanalyzer.AccessAnalyzer
}

type accessAnalyzerConfig struct {
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"`
}

func newAccessAnalyzerClient(assumeRole, externalID string) (*accessAnalyzerClient, error) {
	var conf accessAnalyzerConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return nil, err
	}

	a := accessAnalyzerClient{}
	if err := a.newAWSSession(conf.AWSRegion, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *accessAnalyzerClient) newAWSSession(region, assumeRole, externalID string) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region)},
	)
	if err != nil {
		return err
	}
	if assumeRole != "" && externalID != "" {
		sess = session.New(&aws.Config{
			Region: sess.Config.Region,
			Credentials: stscreds.NewCredentials(
				sess, assumeRole, func(p *stscreds.AssumeRoleProvider) {
					p.ExternalID = aws.String(externalID)
				},
			),
		})
	} else if assumeRole != "" && externalID == "" {
		sess = session.New(&aws.Config{
			Region:      sess.Config.Region,
			Credentials: stscreds.NewCredentials(sess, assumeRole),
		})
	}
	a.Sess = sess
	a.Svc = accessanalyzer.New(a.Sess)
	return nil
}

func (a *accessAnalyzerClient) listAnalyzers() (*[]string, error) {
	var nextToken string
	var analyzers []string
	for {
		out, err := a.Svc.ListAnalyzers(&accessanalyzer.ListAnalyzersInput{
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

func (a *accessAnalyzerClient) listFindings(accountID string, analyzerArn string) ([]*accessanalyzer.FindingSummary, error) {
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
		out, err := a.Svc.ListFindings(input)
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
	}
	return findings, nil
}
