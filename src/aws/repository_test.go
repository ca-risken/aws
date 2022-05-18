package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/ca-risken/aws/pkg/model"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func newMockDB() (*awsRepository, sqlmock.Sqlmock, error) {
	sqlDB, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to open mock sql db, error: %+w", err)
	}
	if sqlDB == nil || mock == nil {
		return nil, nil, fmt.Errorf("Failed to create mock db, db: %+v, mock: %+v", sqlDB, mock)
	}
	gormDB, err := gorm.Open(mysql.New(mysql.Config{
		Conn:                      sqlDB,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to open gorm, error: %+w", err)
	}
	return &awsRepository{
		MasterDB: gormDB,
		SlaveDB:  gormDB,
	}, mock, nil
}

func TestListAWSRelDataSource(t *testing.T) {
	now := time.Now()
	db, mock, err := newMockDB()
	if err != nil {
		t.Fatalf("Failed to open mock sql db, error: %+v", err)
	}
	type args struct {
		projectID uint32
		awsID     uint32
	}
	cases := []struct {
		name       string
		input      args
		want       *[]model.AWSRelDataSource
		wantErr    bool
		mockResult *sqlmock.Rows
		mockErr    error
	}{
		{
			name:  "OK",
			input: args{projectID: 1, awsID: 1},
			want: &[]model.AWSRelDataSource{
				{AWSID: 1, AWSDataSourceID: 1, ProjectID: 1, AssumeRoleArn: "role1", ExternalID: "ext-id", Status: "OK", StatusDetail: "detail", CreatedAt: now, UpdatedAt: now},
				{AWSID: 1, AWSDataSourceID: 2, ProjectID: 1, AssumeRoleArn: "role2", ExternalID: "ext-id", Status: "OK", StatusDetail: "detail", CreatedAt: now, UpdatedAt: now},
			},
			wantErr: false,
			mockResult: sqlmock.NewRows([]string{
				"aws_id", "aws_data_source_id", "project_id", "assume_role_arn", "external_id", "status", "status_detail", "created_at", "updated_at"}).
				AddRow(uint32(1), uint32(1), uint32(1), "role1", "ext-id", "OK", "detail", now, now).
				AddRow(uint32(1), uint32(2), uint32(1), "role2", "ext-id", "OK", "detail", now, now),
		},
		{
			name:    "NG DB error",
			input:   args{projectID: 1, awsID: 1},
			want:    nil,
			wantErr: true,
			mockErr: errors.New("DB error"),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			if c.mockResult != nil {
				mock.ExpectQuery(regexp.QuoteMeta(selectListAWSRelDataSource)).WillReturnRows(c.mockResult)
			} else if c.mockErr != nil {
				mock.ExpectQuery(regexp.QuoteMeta(selectListAWSRelDataSource)).WillReturnError(c.mockErr)
			}
			got, err := db.ListAWSRelDataSource(ctx, c.input.projectID, c.input.awsID)
			if err != nil && !c.wantErr {
				t.Fatalf("Unexpected error: %+v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Unexpected mapping: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
