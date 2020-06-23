package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/model"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/mock"
)

func TestListAWS(t *testing.T) {
	var ctx context.Context
	now := time.Now()
	mockDB := mockAWSRepository{}
	svc := newAWSService(&mockDB)
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

func (m *mockAWSRepository) ListAWS(uint32, uint32, string) (*[]model.AWS, error) {
	args := m.Called()
	return args.Get(0).(*[]model.AWS), args.Error(1)
}
