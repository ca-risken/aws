package main

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/kelseyhightower/envconfig"
)

type guardDutyAPI interface {
	listAvailableRegion() ([]*ec2.Region, error)
	listDetectors() (*[]string, error)
	listFindings(string, string) ([]*string, error)
	getFindings(string, []*string) ([]*guardduty.Finding, error)
}

type guardDutyClient struct {
	Sess *session.Session
	Svc  *guardduty.GuardDuty
	EC2  *ec2.EC2
}

type guardDutyConfig struct {
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"` // Default region
}

func newGuardDutyClient(region, assumeRole, externalID string) (*guardDutyClient, error) {
	if region == "" {
		var conf guardDutyConfig
		err := envconfig.Process("", &conf)
		if err != nil {
			return nil, err
		}
		region = conf.AWSRegion
	}

	g := guardDutyClient{}
	if err := g.newAWSSession(region, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *guardDutyClient) newAWSSession(region, assumeRole, externalID string) error {
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
	g.Sess = sess
	g.Svc = guardduty.New(g.Sess, aws.NewConfig().WithRegion(region))
	g.EC2 = ec2.New(g.Sess, aws.NewConfig().WithRegion(region))
	return nil
}

func (g *guardDutyClient) listAvailableRegion() ([]*ec2.Region, error) {
	out, err := g.EC2.DescribeRegions(&ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn("Got no regions")
		return nil, nil
	}
	return out.Regions, nil
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

const findingIdsPerRequest = 50

func (g *guardDutyClient) getFindings(detectorID string, findingIDs []*string) ([]*guardduty.Finding, error) {
	// The `FindingIds` parameter of the GetFindings API allows numbers from 0 to 50
	// @see https://docs.aws.amazon.com/ja_jp/guardduty/latest/APIReference/API_GetFindings.html
	var guardDutyFindings []*guardduty.Finding
	for i := 0; i < len(findingIDs); i += findingIdsPerRequest {
		var end int
		if findingIdsPerRequest < len(findingIDs)-i {
			end = i + findingIdsPerRequest
		} else {
			end = len(findingIDs)
		}
		finding, err := g.Svc.GetFindings(&guardduty.GetFindingsInput{
			DetectorId: &detectorID,
			FindingIds: findingIDs[i:end],
		})
		if err != nil {
			return nil, err
		}
		for _, f := range finding.Findings {
			guardDutyFindings = append(guardDutyFindings, f)
		}
		time.Sleep(time.Millisecond * 500)
	}
	return guardDutyFindings, nil
}
