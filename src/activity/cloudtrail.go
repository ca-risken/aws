package main

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/ca-risken/aws/proto/activity"
	"github.com/vikyd/zero"
)

type cloudTrailAPI interface {
	lookupEvents(ctx context.Context, req *activity.ListCloudTrailRequest, role, externalID string) (*activity.ListCloudTrailResponse, error)
}

type cloudTrailClient struct {
	defaultRegion string
}

func newCloudTrailClient(defaultRegion string) cloudTrailAPI {
	return &cloudTrailClient{
		defaultRegion: defaultRegion,
	}
}

func (c *cloudTrailClient) newSession(ctx context.Context, region, assumeRole, externalID string) (*cloudtrail.CloudTrail, error) {
	if region == "" {
		region = c.defaultRegion
	}
	if assumeRole == "" {
		return nil, errors.New("required AWS AssumeRole")
	}
	sess, err := session.NewSession()
	if err != nil {
		appLogger.Errorf(ctx, "Failed to create session, err=%+v", err)
		return nil, err
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
		return nil, err
	}
	ct := cloudtrail.New(sessWithCred, aws.NewConfig().WithRegion(region))
	return ct, nil
}

func (c *cloudTrailClient) lookupEvents(ctx context.Context, req *activity.ListCloudTrailRequest, role, externalID string) (*activity.ListCloudTrailResponse, error) {
	sess, err := c.newSession(ctx, req.Region, role, externalID)
	if err != nil {
		return nil, err
	}
	out, err := sess.LookupEventsWithContext(ctx, generateLookupEventInput(ctx, req))
	if err != nil {
		return nil, err
	}
	if out == nil {
		return &activity.ListCloudTrailResponse{}, nil
	}
	appLogger.Infof(ctx, "Got: %+v events, RequestParam: %+v", len(out.Events), req)
	events := []*activity.CloudTrail{}
	for _, e := range out.Events {
		events = append(events, &activity.CloudTrail{
			EventId:         convertNilToString(e.EventId),
			EventName:       convertNilToString(e.EventName),
			ReadOnly:        convertNilToString(e.ReadOnly),
			AccessKeyId:     convertNilToString(e.AccessKeyId),
			EventTime:       e.EventTime.Unix(),
			EventSource:     convertNilToString(e.EventSource),
			Username:        convertNilToString(e.Username),
			Resources:       convertTrailResource(e.Resources),
			CloudtrailEvent: convertNilToString(e.CloudTrailEvent),
		})
	}
	nextToken := ""
	if out.NextToken != nil && aws.StringValue(out.NextToken) != "" {
		nextToken = encodeBase64(aws.StringValue(out.NextToken))
	}
	return &activity.ListCloudTrailResponse{
		Cloudtrail: events,
		NextToken:  nextToken,
	}, nil
}

func generateLookupEventInput(ctx context.Context, req *activity.ListCloudTrailRequest) *cloudtrail.LookupEventsInput {
	lookupInput := &cloudtrail.LookupEventsInput{
		EndTime:    aws.Time(time.Now()),
		StartTime:  aws.Time(time.Now().AddDate(0, 0, -90)),
		MaxResults: aws.Int64(30),
	}
	if !zero.IsZeroVal(req.EndTime) {
		lookupInput.EndTime = aws.Time(time.Unix(req.EndTime, 0))
	}
	if !zero.IsZeroVal(req.StartTime) {
		lookupInput.StartTime = aws.Time(time.Unix(req.StartTime, 0))
	}
	lookupAttributes := []*cloudtrail.LookupAttribute{}
	switch req.AttributeKey {
	case activity.AttributeKey_EVENT_ID:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyEventId),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_EVENT_NAME:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyEventName),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_EVENT_SOURCE:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyEventSource),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_RESOURCE_TYPE:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyResourceType),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_RESOURCE_NAME:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyResourceName),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_USERNAME:
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyUsername),
			AttributeValue: aws.String(req.AttributeValue),
		})
	case activity.AttributeKey_READ_ONLY:
		attrValue := "true"
		if req.AttributeValue != "true" {
			attrValue = "false"
		}
		lookupAttributes = append(lookupAttributes, &cloudtrail.LookupAttribute{
			AttributeKey:   aws.String(cloudtrail.LookupAttributeKeyReadOnly),
			AttributeValue: aws.String(attrValue),
		})
	}
	lookupInput.LookupAttributes = lookupAttributes
	if !zero.IsZeroVal(req.NextToken) {
		lookupInput.NextToken = aws.String(decodeBase64(ctx, req.NextToken))
	}
	return lookupInput
}

func convertTrailResource(input []*cloudtrail.Resource) []*activity.Resource {
	out := []*activity.Resource{}
	for _, r := range input {
		out = append(out, &activity.Resource{
			ResourceType: convertNilToString(r.ResourceType),
			ResourceName: convertNilToString(r.ResourceName),
		})
	}
	return out
}
