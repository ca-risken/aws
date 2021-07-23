package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/CyberAgent/mimosa-aws/proto/activity"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

func TestDescribeARN(t *testing.T) {
	var ctx context.Context
	svc := &activityService{}
	cases := []struct {
		name    string
		input   *activity.DescribeARNRequest
		want    *activity.DescribeARNResponse
		wantErr bool
	}{
		{
			name:  "OK",
			input: &activity.DescribeARNRequest{Arn: "arn:aws:s3:::bucket_name"},
			want: &activity.DescribeARNResponse{Arn: &activity.ARN{
				Partition:    "aws",
				Service:      "s3",
				Resource:     "bucket_name",
				ResourceType: "AWS::S3::Bucket",
				ResourceId:   "bucket_name",
			}},
		},
		{
			name:    "NG invalid param",
			input:   &activity.DescribeARNRequest{Arn: ""},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := svc.DescribeARN(ctx, c.input)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestListCloudTrail(t *testing.T) {
	var ctx context.Context
	mockAWS := &mockAWSClient{}
	mockCloudTrail := &mockCloudTrailClient{}
	svc := &activityService{
		awsClient:        mockAWS,
		cloudTrailClient: mockCloudTrail,
	}
	// fixed response for aws API
	mockAWS.On("ListDataSource").Return(&aws.ListDataSourceResponse{
		DataSource: []*aws.DataSource{
			{DataSource: "aws:activiity", AssumeRoleArn: "role", ExternalId: "external_id"},
		},
	}, nil)
	cases := []struct {
		name         string
		input        *activity.ListCloudTrailRequest
		want         *activity.ListCloudTrailResponse
		wantErr      bool
		mockResponce *activity.ListCloudTrailResponse
		mockErr      error
	}{
		{
			name: "OK",
			input: &activity.ListCloudTrailRequest{
				ProjectId: 1,
				AwsId:     1,
				Region:    "ap-noortheast-1",
			},
			want:         &activity.ListCloudTrailResponse{},
			mockResponce: &activity.ListCloudTrailResponse{},
		},
		{
			name: "NG invalid param",
			input: &activity.ListCloudTrailRequest{
				// ProjectId:    1,
				AwsId:          1,
				Region:         "ap-noortheast-1",
				AttributeKey:   activity.AttributeKey_RESOURCE_NAME,
				AttributeValue: "AWS::S3::Bucket",
			},
			wantErr: true,
		},
		{
			name: "NG AWS error",
			input: &activity.ListCloudTrailRequest{
				ProjectId:      1,
				AwsId:          1,
				Region:         "ap-noortheast-1",
				AttributeKey:   activity.AttributeKey_RESOURCE_NAME,
				AttributeValue: "AWS::S3::Bucket",
			},
			mockErr: errors.New("something error"),
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockErr != nil {
				mockCloudTrail.On("lookupEvents").Return(c.mockResponce, c.mockErr).Once()
			}
			got, err := svc.ListCloudTrail(ctx, c.input)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestListConfigHistory(t *testing.T) {
	var ctx context.Context
	mockConfig := &mockConfigServiceClient{}
	mockAWS := &mockAWSClient{}
	svc := &activityService{
		awsClient:    mockAWS,
		configClient: mockConfig,
	}
	// fixed response for aws API
	mockAWS.On("ListDataSource").Return(&aws.ListDataSourceResponse{
		DataSource: []*aws.DataSource{
			{DataSource: "aws:activiity", AssumeRoleArn: "role", ExternalId: "external_id"},
		},
	}, nil)
	cases := []struct {
		name         string
		input        *activity.ListConfigHistoryRequest
		want         *activity.ListConfigHistoryResponse
		wantErr      bool
		mockResponce *activity.ListConfigHistoryResponse
		mockErr      error
	}{
		{
			name: "OK",
			input: &activity.ListConfigHistoryRequest{
				ProjectId:    1,
				AwsId:        1,
				Region:       "ap-noortheast-1",
				ResourceType: "AWS::S3::Bucket",
				ResourceId:   "bucket_name",
			},
			want:         &activity.ListConfigHistoryResponse{},
			mockResponce: &activity.ListConfigHistoryResponse{},
		},
		{
			name: "NG invalid param",
			input: &activity.ListConfigHistoryRequest{
				// ProjectId:    1,
				AwsId:        1,
				Region:       "ap-noortheast-1",
				ResourceType: "AWS::S3::Bucket",
				ResourceId:   "bucket_name",
			},
			wantErr: true,
		},
		{
			name: "NG AWS error",
			input: &activity.ListConfigHistoryRequest{
				ProjectId:    1,
				AwsId:        1,
				Region:       "ap-noortheast-1",
				ResourceType: "AWS::S3::Bucket",
				ResourceId:   "bucket_name",
			},
			mockErr: errors.New("something error"),
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockErr != nil {
				mockConfig.On("listConfigHistory").Return(c.mockResponce, c.mockErr).Once()
			}
			got, err := svc.ListConfigHistory(ctx, c.input)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

/**
 * Mock
**/
type mockAWSClient struct {
	mock.Mock
}

func (m *mockAWSClient) ListAWS(ctx context.Context, in *aws.ListAWSRequest, opts ...grpc.CallOption) (*aws.ListAWSResponse, error) {
	args := m.Called()
	return args.Get(0).(*aws.ListAWSResponse), args.Error(1)
}
func (m *mockAWSClient) PutAWS(ctx context.Context, in *aws.PutAWSRequest, opts ...grpc.CallOption) (*aws.PutAWSResponse, error) {
	args := m.Called()
	return args.Get(0).(*aws.PutAWSResponse), args.Error(1)
}
func (m *mockAWSClient) DeleteAWS(ctx context.Context, in *aws.DeleteAWSRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	args := m.Called()
	return args.Get(0).(*empty.Empty), args.Error(1)
}
func (m *mockAWSClient) ListDataSource(ctx context.Context, in *aws.ListDataSourceRequest, opts ...grpc.CallOption) (*aws.ListDataSourceResponse, error) {
	args := m.Called()
	return args.Get(0).(*aws.ListDataSourceResponse), args.Error(1)
}
func (m *mockAWSClient) AttachDataSource(ctx context.Context, in *aws.AttachDataSourceRequest, opts ...grpc.CallOption) (*aws.AttachDataSourceResponse, error) {
	args := m.Called()
	return args.Get(0).(*aws.AttachDataSourceResponse), args.Error(1)
}
func (m *mockAWSClient) DetachDataSource(ctx context.Context, in *aws.DetachDataSourceRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	args := m.Called()
	return args.Get(0).(*empty.Empty), args.Error(1)
}
func (m *mockAWSClient) InvokeScan(ctx context.Context, in *aws.InvokeScanRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	args := m.Called()
	return args.Get(0).(*empty.Empty), args.Error(1)
}
func (m *mockAWSClient) InvokeScanAll(ctx context.Context, in *empty.Empty, opts ...grpc.CallOption) (*empty.Empty, error) {
	args := m.Called()
	return args.Get(0).(*empty.Empty), args.Error(1)
}

type mockCloudTrailClient struct {
	mock.Mock
}

func (m *mockCloudTrailClient) lookupEvents(context.Context, *activity.ListCloudTrailRequest, string, string) (*activity.ListCloudTrailResponse, error) {
	args := m.Called()
	return args.Get(0).(*activity.ListCloudTrailResponse), args.Error(1)
}

type mockConfigServiceClient struct {
	mock.Mock
}

func (m *mockConfigServiceClient) listConfigHistory(context.Context, *activity.ListConfigHistoryRequest, string, string) (*activity.ListConfigHistoryResponse, error) {
	args := m.Called()
	return args.Get(0).(*activity.ListConfigHistoryResponse), args.Error(1)
}
