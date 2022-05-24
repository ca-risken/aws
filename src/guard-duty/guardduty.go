package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/aws/pkg/message"
)

type guardDutyAPI interface {
	getGuardDuty(ctx context.Context, message *message.AWSQueueMessage) ([]*guardDutyFinding, *[]string, error)
	listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error)
	listDetectors(ctx context.Context) (*[]string, error)
	listFindings(ctx context.Context, accountID, detectorID string) (*[]string, error)
	getFindings(ctx context.Context, detectorID string, findingIDs []string) (*[]types.Finding, error)
}

type guardDutyClient struct {
	Svc *guardduty.Client
	EC2 *ec2.Client
}

func newGuardDutyClient(ctx context.Context, region, assumeRole, externalID string) (guardDutyAPI, error) {
	g := guardDutyClient{}
	if err := g.newAWSSession(ctx, region, assumeRole, externalID); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *guardDutyClient) newAWSSession(ctx context.Context, region, assumeRole, externalID string) error {
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
	g.Svc = guardduty.New(guardduty.Options{Credentials: cfg.Credentials, Region: region})
	g.EC2 = ec2.New(ec2.Options{Credentials: cfg.Credentials, Region: region})
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
		appLogger.Errorf(ctx, "GuardDuty.ListDetectors error: err=%+v", err)
		return nil, &[]string{}, err
	}
	if detecterIDs == nil || len(*detecterIDs) == 0 {
		return nil, &[]string{}, nil // guardduty not enabled
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := g.listFindings(ctx, message.AccountID, id)
		if err != nil {
			appLogger.Warnf(ctx,
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		if findingIDs == nil || len(*findingIDs) == 0 {
			appLogger.Infof(ctx, "No findings: accountID=%s", message.AccountID)
			continue
		}
		findings, err := g.getFindings(ctx, id, *findingIDs)
		if err != nil {
			appLogger.Warnf(ctx,
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			continue // If Organization gathering enabled, requesting an invalid Region may result in an error.
		}
		for _, data := range *findings {
			buf, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf(ctx, "Failed to json encoding error: err=%+v", err)
				return nil, detecterIDs, err
			}
			var score float32
			if data.Service.Archived {
				score = 1.0
			} else {
				score = float32(data.Severity)
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

func (g *guardDutyClient) listAvailableRegion(ctx context.Context) (*[]ec2types.Region, error) {
	out, err := g.EC2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	if out == nil {
		appLogger.Warn(ctx, "Got no regions")
		return nil, nil
	}
	return &out.Regions, nil
}

func (g *guardDutyClient) listDetectors(ctx context.Context) (*[]string, error) {
	var nextToken string
	var detectorIDs []string
	for {
		out, err := g.Svc.ListDetectors(ctx, &guardduty.ListDetectorsInput{
			MaxResults: int32(50),
			NextToken:  &nextToken,
		})
		if err != nil {
			return nil, err
		}
		detectorIDs = append(detectorIDs, out.DetectorIds...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = *out.NextToken
	}
	return &detectorIDs, nil
}

func (g *guardDutyClient) listFindings(ctx context.Context, accountID, detectorID string) (*[]string, error) {
	var nextToken string
	var findingIDs []string

	// filter condition for aws accountId
	cond := types.Condition{
		Equals: []string{accountID},
	}

	for {
		out, err := g.Svc.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: &detectorID,
			FindingCriteria: &types.FindingCriteria{
				Criterion: map[string]types.Condition{
					"accountId": cond,
				},
			},
			MaxResults: int32(50),
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
	return &findingIDs, nil
}

const findingIdsPerRequest = 50

func (g *guardDutyClient) getFindings(ctx context.Context, detectorID string, findingIDs []string) (*[]types.Finding, error) {
	// The `FindingIds` parameter of the GetFindings API allows numbers from 0 to 50
	// @see https://docs.aws.amazon.com/ja_jp/guardduty/latest/APIReference/API_GetFindings.html
	var guardDutyFindings []types.Finding
	for i := 0; i < len(findingIDs); i += findingIdsPerRequest {
		var end int
		if findingIdsPerRequest < len(findingIDs)-i {
			end = i + findingIdsPerRequest
		} else {
			end = len(findingIDs)
		}
		finding, err := g.Svc.GetFindings(ctx, &guardduty.GetFindingsInput{
			DetectorId: &detectorID,
			FindingIds: findingIDs[i:end],
		})
		if err != nil {
			return nil, err
		}
		guardDutyFindings = append(guardDutyFindings, finding.Findings...)
		time.Sleep(time.Millisecond * 500)
	}
	return &guardDutyFindings, nil
}
