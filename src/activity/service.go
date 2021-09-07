package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/aws/proto/activity"
	awsClient "github.com/ca-risken/aws/proto/aws"
)

type activityService struct {
	awsClient        awsClient.AWSServiceClient
	cloudTrailClient cloudTrailAPI
	configClient     configServiceAPI
}

func newActivityService() activity.ActivityServiceServer {
	return &activityService{
		awsClient:        newAWSClient(),
		cloudTrailClient: newCloudTrailClient(),
		configClient:     newConfigServiceClient(),
	}
}

func (a *activityService) DescribeARN(ctx context.Context, req *activity.DescribeARNRequest) (*activity.DescribeARNResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	resp, err := ParseARN(req.Arn)
	if err != nil {
		return nil, err
	}
	return &activity.DescribeARNResponse{Arn: resp}, nil
}

func (a *activityService) ListCloudTrail(ctx context.Context, req *activity.ListCloudTrailRequest) (*activity.ListCloudTrailResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ds, err := a.getAWSDataSource(ctx, req.ProjectId, req.AwsId)
	if err != nil {
		return nil, err
	}
	resp, err := a.cloudTrailClient.lookupEvents(ctx, req, ds.AssumeRoleArn, ds.ExternalId)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *activityService) ListConfigHistory(ctx context.Context, req *activity.ListConfigHistoryRequest) (*activity.ListConfigHistoryResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ds, err := a.getAWSDataSource(ctx, req.ProjectId, req.AwsId)
	if err != nil {
		return nil, err
	}
	resp, err := a.configClient.listConfigHistory(ctx, req, ds.AssumeRoleArn, ds.ExternalId)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (a *activityService) getAWSDataSource(ctx context.Context, projectID, awsID uint32) (*awsClient.DataSource, error) {
	ds, err := a.awsClient.ListDataSource(ctx, &awsClient.ListDataSourceRequest{
		ProjectId:  projectID,
		AwsId:      awsID,
		DataSource: message.ActivityDatasource,
	})
	if err != nil {
		return nil, err
	}
	if ds == nil || len(ds.DataSource) != 1 {
		return nil, fmt.Errorf("Unexpected AWS DataSource, datasource=%+v", ds)
	}
	return ds.DataSource[0], nil
}

func convertNilToString(v *string) string {
	if v == nil || reflect.ValueOf(v).IsNil() {
		return ""
	}
	return *v
}

func encodeBase64(v string) string {
	return base64.URLEncoding.EncodeToString([]byte(v))
}
func decodeBase64(v string) string {
	decoded, err := base64.URLEncoding.DecodeString(v)
	if err != nil {
		appLogger.Warnf("Failed to base64 decode, value=%v", v)
		return ""
	}
	return string(decoded)
}
