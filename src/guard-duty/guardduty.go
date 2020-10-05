package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/kelseyhightower/envconfig"
)

type guardDutyAPI interface {
	listDetectors() (*[]string, error)
	listFindings(string, string) ([]*string, error)
	getFindings(string, []*string) ([]*guardduty.Finding, error)
}

type guardDutyClient struct {
	Sess *session.Session
	Svc  *guardduty.GuardDuty
}

type guardDutyConfig struct {
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"`
}

func newGuardDutyClient(assumeRole, externalID string) (*guardDutyClient, error) {
	var conf guardDutyConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return nil, err
	}

	g := guardDutyClient{}
	if err := g.newAWSSession(conf.AWSRegion, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *guardDutyClient) newAWSSession(region, assumeRole, externalID string) error {
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
	g.Sess = sess
	g.Svc = guardduty.New(g.Sess)
	return nil
}

func (g *guardDutyClient) listDetectors() (*[]string, error) {
	var nextToken string
	var detectorIDs []string
	for {
		out, err := g.Svc.ListDetectors(&guardduty.ListDetectorsInput{
			MaxResults: aws.Int64(50),
			NextToken:  &nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, id := range out.DetectorIds {
			detectorIDs = append(detectorIDs, *id)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
	}
	return &detectorIDs, nil
}

func (g *guardDutyClient) listFindings(accountID, detectorID string) ([]*string, error) {
	var nextToken string
	var findingIDs []*string

	// filter condition for aws accountId
	cond := guardduty.Condition{
		Equals: []*string{aws.String(accountID)},
	}

	for {
		out, err := g.Svc.ListFindings(&guardduty.ListFindingsInput{
			DetectorId: &detectorID,
			FindingCriteria: &guardduty.FindingCriteria{
				Criterion: map[string]*guardduty.Condition{
					"accountId": &cond,
				},
			},
			MaxResults: aws.Int64(50),
			NextToken:  &nextToken,
		})
		if err != nil {
			return nil, err
		}
		for _, id := range out.FindingIds {
			findingIDs = append(findingIDs, id)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
	}
	return findingIDs, nil
}

func (g *guardDutyClient) getFindings(detectorID string, findingIDs []*string) ([]*guardduty.Finding, error) {
	finding, err := g.Svc.GetFindings(&guardduty.GetFindingsInput{
		DetectorId: &detectorID,
		FindingIds: findingIDs,
	})
	if err != nil {
		return nil, err
	}
	return finding.Findings, nil
}