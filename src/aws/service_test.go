package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/aws/pkg/model"
	"github.com/ca-risken/aws/proto/aws"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestListAWS(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name         string
		input        *aws.ListAWSRequest
		want         *aws.ListAWSResponse
		mockResponce *[]model.AWS
		mockError    error
	}{
		{
			name:  "OK",
			input: &aws.ListAWSRequest{ProjectId: 1},
			want: &aws.ListAWSResponse{Aws: []*aws.AWS{
				{AwsId: 1, ProjectId: 1, AwsAccountId: "123456789012", CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
				{AwsId: 2, ProjectId: 1, AwsAccountId: "123456789013", CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
			}},
			mockResponce: &[]model.AWS{
				{AWSID: 1, ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
				{AWSID: 2, ProjectID: 1, AWSAccountID: "123456789013", CreatedAt: now, UpdatedAt: now},
			},
		},
		{
			name:      "NG Record not found",
			input:     &aws.ListAWSRequest{ProjectId: 1, AwsId: 1, AwsAccountId: "123456789012"},
			want:      &aws.ListAWSResponse{},
			mockError: gorm.ErrRecordNotFound,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResponce != nil || c.mockError != nil {
				mockDB.On("ListAWS").Return(c.mockResponce, c.mockError).Once()
			}
			got, err := svc.ListAWS(ctx, c.input)
			if err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestPutAWS(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name        string
		input       *aws.PutAWSRequest
		want        *aws.PutAWSResponse
		wantErr     bool
		mockGetResp *model.AWS
		mockGetErr  error
		mockUpdResp *model.AWS
		mockUpdErr  error
	}{
		{
			name:        "OK Update",
			input:       &aws.PutAWSRequest{ProjectId: 1, Aws: &aws.AWSForUpsert{Name: "new name", ProjectId: 1, AwsAccountId: "123456789012"}},
			want:        &aws.PutAWSResponse{Aws: &aws.AWS{AwsId: 1, Name: "new name", ProjectId: 1, AwsAccountId: "123456789012", CreatedAt: now.Unix(), UpdatedAt: now.Unix()}},
			mockGetResp: &model.AWS{AWSID: 1, Name: "old name", ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
			mockUpdResp: &model.AWS{AWSID: 1, Name: "new name", ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
		},
		{
			name:        "OK Insert",
			input:       &aws.PutAWSRequest{ProjectId: 1, Aws: &aws.AWSForUpsert{Name: "new name", ProjectId: 1, AwsAccountId: "123456789012"}},
			want:        &aws.PutAWSResponse{Aws: &aws.AWS{AwsId: 1, Name: "new name", ProjectId: 1, AwsAccountId: "123456789012", CreatedAt: now.Unix(), UpdatedAt: now.Unix()}},
			mockGetErr:  gorm.ErrRecordNotFound,
			mockUpdResp: &model.AWS{AWSID: 1, Name: "new name", ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
		},
		{
			name:    "NG Invalid parameter(required project_id)",
			input:   &aws.PutAWSRequest{Aws: &aws.AWSForUpsert{Name: "new name", ProjectId: 1, AwsAccountId: "123456789012"}},
			wantErr: true,
		},
		{
			name:       "Invalid DB error(GetAWSByAccountID)",
			input:      &aws.PutAWSRequest{Aws: &aws.AWSForUpsert{Name: "new name", ProjectId: 1, AwsAccountId: "123456789012"}},
			mockGetErr: gorm.ErrInvalidDB,
			wantErr:    true,
		},
		{
			name:        "Invalid DB error(UpsertAWS)",
			input:       &aws.PutAWSRequest{Aws: &aws.AWSForUpsert{Name: "new name", ProjectId: 1, AwsAccountId: "123456789012"}},
			mockGetResp: &model.AWS{AWSID: 1, Name: "old name", ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
			mockUpdErr:  gorm.ErrInvalidDB,
			wantErr:     true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockGetResp != nil || c.mockGetErr != nil {
				mockDB.On("GetAWSByAccountID").Return(c.mockGetResp, c.mockGetErr).Once()
			}
			if c.mockUpdResp != nil || c.mockUpdErr != nil {
				mockDB.On("UpsertAWS").Return(c.mockUpdResp, c.mockUpdErr).Once()
			}
			got, err := svc.PutAWS(ctx, c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestDeleteAWS(t *testing.T) {
	var ctx context.Context
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name     string
		input    *aws.DeleteAWSRequest
		wantErr  bool
		mockResp error
	}{
		{
			name:    "OK",
			input:   &aws.DeleteAWSRequest{ProjectId: 1, AwsId: 1},
			wantErr: false,
		},
		{
			name:    "Invalid parameter(aws_id)",
			input:   &aws.DeleteAWSRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name:     "Invalid DB error",
			input:    &aws.DeleteAWSRequest{ProjectId: 1, AwsId: 1},
			wantErr:  true,
			mockResp: gorm.ErrInvalidDB,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mockDB.On("ListDataSource").Return(&[]dataSource{{AWSDataSourceID: 1}}, nil)
			mockDB.On("DeleteAWSRelDataSource").Return(nil)
			mockDB.On("DeleteAWS").Return(c.mockResp).Once()
			_, err := svc.DeleteAWS(ctx, c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestListDataSource(t *testing.T) {
	var ctx context.Context
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name     string
		input    *aws.ListDataSourceRequest
		want     *aws.ListDataSourceResponse
		wantErr  bool
		mockResp *[]dataSource
		mockErr  error
	}{
		{
			name:  "OK",
			input: &aws.ListDataSourceRequest{ProjectId: 1, AwsId: 1, DataSource: "aws:guard-duty"},
			want: &aws.ListDataSourceResponse{DataSource: []*aws.DataSource{
				{AwsDataSourceId: 1, DataSource: "ds-1", MaxScore: 1.0, AwsId: 1001, ProjectId: 1, AssumeRoleArn: "role", ExternalId: ""},
				{AwsDataSourceId: 2, DataSource: "ds-2", MaxScore: 1.0},
			}},
			mockResp: &[]dataSource{
				{AWSDataSourceID: 1, DataSource: "ds-1", MaxScore: 1.0, AWSID: 1001, ProjectID: 1, AssumeRoleArn: "role", ExternalID: ""},
				{AWSDataSourceID: 2, DataSource: "ds-2", MaxScore: 1.0},
			},
		},
		{
			name:    "OK NotFound",
			input:   &aws.ListDataSourceRequest{ProjectId: 1, AwsId: 1, DataSource: "aws:guard-duty"},
			want:    &aws.ListDataSourceResponse{DataSource: []*aws.DataSource{}},
			mockErr: gorm.ErrRecordNotFound,
		},
		{
			name:    "NG Invalid parameter(project_id)",
			input:   &aws.ListDataSourceRequest{AwsId: 1, DataSource: "aws:guard-duty"},
			wantErr: true,
		},
		{
			name:    "Invalid DB error(ListDataSource)",
			input:   &aws.ListDataSourceRequest{ProjectId: 1, AwsId: 1, DataSource: "aws:guard-duty"},
			wantErr: true,
			mockErr: gorm.ErrInvalidDB,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResp != nil || c.mockErr != nil {
				mockDB.On("ListDataSource").Return(c.mockResp, c.mockErr).Once()
			}
			got, err := svc.ListDataSource(ctx, c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestAttachDataSource(t *testing.T) {
	now := time.Now()
	var ctx context.Context
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name     string
		input    *aws.AttachDataSourceRequest
		want     *aws.AttachDataSourceResponse
		wantErr  bool
		mockResp *model.AWSRelDataSource
		mockErr  error
	}{
		{
			name: "OK",
			input: &aws.AttachDataSourceRequest{
				ProjectId:        1,
				AttachDataSource: &aws.DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "role", ExternalId: "ex", Status: aws.Status_OK, StatusDetail: "detail", ScanAt: now.Unix()},
			},
			want: &aws.AttachDataSourceResponse{
				DataSource: &aws.AWSRelDataSource{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "role", ExternalId: "ex", Status: aws.Status_OK, StatusDetail: "detail", ScanAt: now.Unix(), CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
			},
			mockResp: &model.AWSRelDataSource{AWSID: 1, AWSDataSourceID: 1, ProjectID: 1, AssumeRoleArn: "role", ExternalID: "ex", Status: "OK", StatusDetail: "detail", ScanAt: now, CreatedAt: now, UpdatedAt: now},
		},
		{
			name: "NG Invalid parameter(project_id)",
			input: &aws.AttachDataSourceRequest{
				ProjectId:        999,
				AttachDataSource: &aws.DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "role", ExternalId: ""},
			},
			wantErr: true,
		},
		{
			name: "Invalid DB error",
			input: &aws.AttachDataSourceRequest{
				ProjectId:        1,
				AttachDataSource: &aws.DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "role", ExternalId: ""},
			},
			wantErr: true,
			mockErr: gorm.ErrInvalidDB,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.mockResp != nil || c.mockErr != nil {
				mockDB.On("UpsertAWSRelDataSource").Return(c.mockResp, c.mockErr).Once()
			}
			got, err := svc.AttachDataSource(ctx, c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestDetachDataSource(t *testing.T) {
	var ctx context.Context
	mockDB := mockAWSRepository{}
	svc := awsService{repository: &mockDB}
	cases := []struct {
		name     string
		input    *aws.DetachDataSourceRequest
		wantErr  bool
		mockResp error
	}{
		{
			name:    "OK",
			input:   &aws.DetachDataSourceRequest{ProjectId: 1, AwsId: 1, AwsDataSourceId: 1},
			wantErr: false,
		},
		{
			name:    "NG Invalid parameter(aws_data_source_id)",
			input:   &aws.DetachDataSourceRequest{ProjectId: 1, AwsId: 1},
			wantErr: true,
		},
		{
			name:     "Invalid DB error",
			input:    &aws.DetachDataSourceRequest{ProjectId: 1, AwsId: 1, AwsDataSourceId: 1},
			wantErr:  true,
			mockResp: gorm.ErrInvalidDB,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mockDB.On("DeleteAWSRelDataSource").Return(c.mockResp).Once()
			_, err := svc.DetachDataSource(ctx, c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
		})
	}
}

func TestConvertFinding(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		input *model.AWS
		want  *aws.AWS
	}{
		{
			name:  "OK Convert unix time",
			input: &model.AWS{AWSID: 1, Name: "nm", ProjectID: 1, AWSAccountID: "123456789012", CreatedAt: now, UpdatedAt: now},
			want:  &aws.AWS{AwsId: 1, Name: "nm", ProjectId: 1, AwsAccountId: "123456789012", CreatedAt: now.Unix(), UpdatedAt: now.Unix()},
		},
		{
			name:  "OK empty",
			input: nil,
			want:  &aws.AWS{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertAWS(c.input)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Unexpected converted: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

/**
 * Mock Repository
**/
type mockAWSRepository struct {
	mock.Mock
}

func (m *mockAWSRepository) ListAWS(context.Context, uint32, uint32, string) (*[]model.AWS, error) {
	args := m.Called()
	return args.Get(0).(*[]model.AWS), args.Error(1)
}
func (m *mockAWSRepository) GetAWSByAccountID(context.Context, uint32, string) (*model.AWS, error) {
	args := m.Called()
	return args.Get(0).(*model.AWS), args.Error(1)
}
func (m *mockAWSRepository) UpsertAWS(context.Context, *model.AWS) (*model.AWS, error) {
	args := m.Called()
	return args.Get(0).(*model.AWS), args.Error(1)
}
func (m *mockAWSRepository) DeleteAWS(context.Context, uint32, uint32) error {
	args := m.Called()
	return args.Error(0)
}
func (m *mockAWSRepository) ListDataSource(context.Context, uint32, uint32, string) (*[]dataSource, error) {
	args := m.Called()
	return args.Get(0).(*[]dataSource), args.Error(1)
}
func (m *mockAWSRepository) ListDataSourceByAWSDataSourceID(context.Context, uint32) (*[]dataSource, error) {
	args := m.Called()
	return args.Get(0).(*[]dataSource), args.Error(1)
}
func (m *mockAWSRepository) UpsertAWSRelDataSource(context.Context, *aws.DataSourceForAttach) (*model.AWSRelDataSource, error) {
	args := m.Called()
	return args.Get(0).(*model.AWSRelDataSource), args.Error(1)
}
func (m *mockAWSRepository) GetAWSRelDataSourceByID(ctx context.Context, awsID, awsDataSourceID, projectID uint32) (*model.AWSRelDataSource, error) {
	args := m.Called()
	return args.Get(0).(*model.AWSRelDataSource), args.Error(1)
}
func (m *mockAWSRepository) DeleteAWSRelDataSource(context.Context, uint32, uint32, uint32) error {
	args := m.Called()
	return args.Error(0)
}
func (m *mockAWSRepository) GetAWSDataSourceForMessage(ctx context.Context, awsID, awsDataSourceID, projectID uint32) (*message.AWSQueueMessage, error) {
	args := m.Called()
	return args.Get(0).(*message.AWSQueueMessage), args.Error(1)
}
