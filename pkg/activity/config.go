package activity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/ca-risken/aws/proto/activity"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/vikyd/zero"
)

type configServiceAPI interface {
	listConfigHistory(ctx context.Context, req *activity.ListConfigHistoryRequest, role, externalID string) (*activity.ListConfigHistoryResponse, error)
}

type configServiceClient struct {
	defaultRegion string
	logger        logging.Logger
}

func newConfigServiceClient(defaultRegion string, l logging.Logger) configServiceAPI {
	return &configServiceClient{
		defaultRegion: defaultRegion,
		logger:        l,
	}
}

func (c *configServiceClient) newSession(ctx context.Context, region, assumeRole, externalID string) (*configservice.ConfigService, error) {
	if region == "" {
		region = c.defaultRegion
	}
	if assumeRole == "" {
		return nil, errors.New("required AWS AssumeRole")
	}
	sess, err := session.NewSession()
	if err != nil {
		c.logger.Errorf(ctx, "Failed to create session, err=%+v", err)
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
	cs := configservice.New(sessWithCred, aws.NewConfig().WithRegion(region))
	return cs, nil
}

func (c *configServiceClient) listConfigHistory(ctx context.Context, req *activity.ListConfigHistoryRequest, role, externalID string) (*activity.ListConfigHistoryResponse, error) {
	sess, err := c.newSession(ctx, req.Region, role, externalID)
	if err != nil {
		return nil, err
	}
	input, err := c.generateGetResourceConfigHistoryInput(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate GetResourceConfigHistory input, err=%w", err)
	}
	out, err := sess.GetResourceConfigHistoryWithContext(ctx, input)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return &activity.ListConfigHistoryResponse{}, nil
	}
	c.logger.Infof(ctx, "Got: %d ConfigurationItems, RequestParam: %+v", len(out.ConfigurationItems), req)
	if len(out.ConfigurationItems) == 0 {
		return &activity.ListConfigHistoryResponse{
			Configuration: []*activity.Configuration{},
		}, nil
	}
	items := []*activity.Configuration{}
	for _, item := range out.ConfigurationItems {
		items = append(items, &activity.Configuration{
			Version:                      convertNilToString(item.Version),
			AccountId:                    convertNilToString(item.AccountId),
			Configuration:                convertNilToString(item.Configuration),
			ConfigurationItemCaptureTime: item.ConfigurationItemCaptureTime.Unix(),
			ConfigurationItemStatus:      convertNilToString(item.ConfigurationItemStatus),
			ConfigurationStateId:         convertNilToString(item.ConfigurationStateId),
			ConfigurationItemMD5Hash:     convertNilToString(item.ConfigurationItemMD5Hash),
			Arn:                          convertNilToString(item.Arn),
			ResourceType:                 convertNilToString(item.ResourceType),
			ResourceId:                   convertNilToString(item.ResourceId),
			ResourceName:                 convertNilToString(item.ResourceName),
			AwsRegion:                    convertNilToString(item.AwsRegion),
			AvailabilityZone:             convertNilToString(item.AvailabilityZone),
			ResourceCreationTime:         item.ResourceCreationTime.Unix(),
			Tags:                         convertConfigTag(item.Tags),
			RelatedEvents:                convertStringSlice(item.RelatedEvents),
			Relationships:                convertConfigResource(item.Relationships),
			SupplementaryConfiguration:   convertSupplementaryConfiguration(item.SupplementaryConfiguration),
		})
	}
	nextToken := ""
	if out.NextToken != nil && aws.StringValue(out.NextToken) != "" {
		nextToken = encodeBase64(aws.StringValue(out.NextToken))
	}
	return &activity.ListConfigHistoryResponse{
		Configuration: items,
		NextToken:     nextToken,
	}, nil
}

func (c *configServiceClient) generateGetResourceConfigHistoryInput(ctx context.Context, req *activity.ListConfigHistoryRequest) (*configservice.GetResourceConfigHistoryInput, error) {
	param := &configservice.GetResourceConfigHistoryInput{
		ResourceType: aws.String(req.ResourceType),
		ResourceId:   aws.String(req.ResourceId),
		EarlierTime:  aws.Time(time.Now().AddDate(0, 0, -90)),
		LaterTime:    aws.Time(time.Now()),
		Limit:        aws.Int64(30),
	}
	if !zero.IsZeroVal(req.EarlierTime) {
		param.EarlierTime = aws.Time(time.Unix(req.EarlierTime, 0))
	}
	if !zero.IsZeroVal(req.LaterTime) {
		param.LaterTime = aws.Time(time.Unix(req.LaterTime, 0))
	}
	if !zero.IsZeroVal(req.ChronologicalOrder) {
		param.ChronologicalOrder = aws.String(req.ChronologicalOrder)
	}
	if !zero.IsZeroVal(req.StartingToken) {
		token, err := decodeBase64(req.StartingToken)
		if err != nil {
			return nil, err
		}
		param.NextToken = aws.String(token)
	}
	c.logger.Infof(ctx, "config param: %+v", param)
	return param, nil
}

func convertConfigTag(input map[string]*string) []*activity.Tag {
	out := []*activity.Tag{}
	for k, v := range input {
		out = append(out, &activity.Tag{
			Key:   k,
			Value: convertNilToString(v),
		})
	}
	return out
}

func convertStringSlice(input []*string) []string {
	out := []string{}
	for _, v := range input {
		out = append(out, *v)
	}
	return out
}

func convertConfigResource(input []*configservice.Relationship) []*activity.Resource {
	out := []*activity.Resource{}
	for _, r := range input {
		out = append(out, &activity.Resource{
			RelationshipName: convertNilToString(r.RelationshipName),
			ResourceType:     convertNilToString(r.ResourceType),
			ResourceName:     convertNilToString(r.ResourceName),
			ResourceId:       convertNilToString(r.ResourceId),
		})
	}
	return out
}

func convertSupplementaryConfiguration(input map[string]*string) []*activity.SupplementaryConfiguration {
	out := []*activity.SupplementaryConfiguration{}
	for k, v := range input {
		out = append(out, &activity.SupplementaryConfiguration{
			Key:   k,
			Value: convertNilToString(v),
		})
	}
	return out
}
