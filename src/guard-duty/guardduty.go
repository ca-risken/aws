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
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/guardduty"
	"github.com/ca-risken/aws/pkg/message"
)

type guardDutyAPI interface {
	getGuardDuty(ctx context.Context, message *message.AWSQueueMessage) ([]*guardDutyFinding, *[]string, error)
	listAvailableRegion(ctx context.Context) ([]*ec2.Region, error)
	listDetectors(ctx context.Context) (*[]string, error)
	listFindings(ctx context.Context, accountID, detectorID string) ([]*string, error)
	getFindings(ctx context.Context, detectorID string, findingIDs []*string) ([]*guardduty.Finding, error)
}

type guardDutyClient struct {
	Sess *session.Session
	Svc  *guardduty.GuardDuty
	EC2  *ec2.EC2
}

func newGuardDutyClient(region, assumeRole, externalID string) (guardDutyAPI, error) {
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
	g.Sess = sessWithCred
	g.Svc = guardduty.New(g.Sess, aws.NewConfig().WithRegion(region))
	g.EC2 = ec2.New(g.Sess, aws.NewConfig().WithRegion(region))
	return nil
}

type guardDutyFinding struct {
	Description      string  `json:"description,omitempty"`
	DataSource       string  `json:"data_source,omitempty"`
	DataSourceId     string  `json:"data_source_id,omitempty"`
	ResourceName     string  `json:"resource_name,omitempty"`
	ProjectId        uint32  `json:"project_id,omitempty"`
	OriginalScore    float32 `json:"original_score,omitempty"`
	OriginalMaxScore float32 `json:"original_max_score,omitempty"`
	Data             string  `json:"data,omitempty"`
	GuardDutyType    string  `json:"guard_duty_type,omitempty"`
}

func (g *guardDutyClient) getGuardDuty(ctx context.Context, message *message.AWSQueueMessage) ([]*guardDutyFinding, *[]string, error) {
	putData := []*guardDutyFinding{}
	detecterIDs, err := g.listDetectors(ctx)
	if err != nil {
		appLogger.Errorf("GuardDuty.ListDetectors error: err=%+v", err)
		return nil, &[]string{}, err
	}
	if detecterIDs == nil || len(*detecterIDs) == 0 {
		return nil, &[]string{}, nil // guardduty not enabled
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := g.listFindings(ctx, message.AccountID, id)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		if len(findingIDs) == 0 {
			appLogger.Infof("No findings: accountID=%s", message.AccountID)
			continue
		}
		findings, err := g.getFindings(ctx, id, findingIDs)
		if err != nil {
			appLogger.Warnf(
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		for _, data := range findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, detecterIDs, err
			}
			var score float32
			if *data.Service.Archived {
				score = 1.0
			} else {
				score = float32(*data.Severity)
			}
			putData = append(putData, &guardDutyFinding{
				Description:      *data.Title,
				DataSource:       message.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Arn,
				ProjectId:        message.ProjectID,
				OriginalScore:    score,
				OriginalMaxScore: 10.0,
				Data:             string(buf),
				GuardDutyType:    *data.Type,
			})
		}
	}
	return putData, detecterIDs, nil
}

func (g *guardDutyClient) listAvailableRegion(ctx context.Context) ([]*ec2.Region, error) {
	out, err := g.EC2.DescribeRegionsWithContext(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn("Got no regions")
		return nil, nil
	}
	return out.Regions, nil
}

func (g *guardDutyClient) listDetectors(ctx context.Context) (*[]string, error) {
	var nextToken string
	var detectorIDs []string
	for {
		out, err := g.Svc.ListDetectorsWithContext(ctx, &guardduty.ListDetectorsInput{
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

func (g *guardDutyClient) listFindings(ctx context.Context, accountID, detectorID string) ([]*string, error) {
	var nextToken string
	var findingIDs []*string

	// filter condition for aws accountId
	cond := guardduty.Condition{
		Equals: []*string{aws.String(accountID)},
	}

	for {
		out, err := g.Svc.ListFindingsWithContext(ctx, &guardduty.ListFindingsInput{
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
		findingIDs = append(findingIDs, out.FindingIds...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
	}
	return findingIDs, nil
}

const findingIdsPerRequest = 50

func (g *guardDutyClient) getFindings(ctx context.Context, detectorID string, findingIDs []*string) ([]*guardduty.Finding, error) {
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
		finding, err := g.Svc.GetFindingsWithContext(ctx, &guardduty.GetFindingsInput{
			DetectorId: &detectorID,
			FindingIds: findingIDs[i:end],
		})
		if err != nil {
			return nil, err
		}
		guardDutyFindings = append(guardDutyFindings, finding.Findings...)
		time.Sleep(time.Millisecond * 500)
	}
	return guardDutyFindings, nil
}
