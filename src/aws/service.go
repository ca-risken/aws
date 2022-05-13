package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/aws/pkg/model"
	"github.com/ca-risken/aws/proto/aws"
	"github.com/ca-risken/core/proto/project"
	"github.com/golang/protobuf/ptypes/empty"
	"gorm.io/gorm"
)

type awsService struct {
	repository    awsRepoInterface
	sqs           sqsAPI
	projectClient project.ProjectServiceClient
}

func (a *awsService) ListAWS(ctx context.Context, req *aws.ListAWSRequest) (*aws.ListAWSResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := a.repository.ListAWS(ctx, req.ProjectId, req.AwsId, req.AwsAccountId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &aws.ListAWSResponse{}, nil
		}
		return nil, err
	}
	data := aws.ListAWSResponse{}
	for _, d := range *list {
		data.Aws = append(data.Aws, convertAWS(&d))
	}
	return &data, nil
}

func (a *awsService) PutAWS(ctx context.Context, req *aws.PutAWSRequest) (*aws.PutAWSResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	savedData, err := a.repository.GetAWSByAccountID(ctx, req.ProjectId, req.Aws.AwsAccountId)
	noRecord := errors.Is(err, gorm.ErrRecordNotFound)
	if err != nil && !noRecord {
		return nil, err
	}

	// PKが登録済みの場合は取得した値をセット。未登録はゼロ値のママでAutoIncrementさせる（更新の都度、無駄にAutoIncrementさせないように）
	var awsID uint32
	if !noRecord {
		awsID = savedData.AWSID
	}
	data := &model.AWS{
		AWSID:        awsID,
		Name:         req.Aws.Name,
		ProjectID:    req.Aws.ProjectId,
		AWSAccountID: req.Aws.AwsAccountId,
	}

	// aws upsert
	registerdData, err := a.repository.UpsertAWS(ctx, data)
	if err != nil {
		return nil, err
	}
	return &aws.PutAWSResponse{Aws: convertAWS(registerdData)}, nil
}

func (a *awsService) DeleteAWS(ctx context.Context, req *aws.DeleteAWSRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := a.repository.ListDataSource(ctx, req.ProjectId, req.AwsId, "")
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	for _, ds := range *list {
		if err := a.repository.DeleteAWSRelDataSource(ctx, req.ProjectId, req.AwsId, ds.AWSDataSourceID); err != nil {
			return nil, err
		}
	}
	if err := a.repository.DeleteAWS(ctx, req.ProjectId, req.AwsId); err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}

func getStatus(s string) aws.Status {
	statusKey := strings.ToUpper(s)
	if _, ok := aws.Status_value[statusKey]; !ok {
		return aws.Status_UNKNOWN
	}
	switch statusKey {
	case aws.Status_OK.String():
		return aws.Status_OK
	case aws.Status_CONFIGURED.String():
		return aws.Status_CONFIGURED
	case aws.Status_IN_PROGRESS.String():
		return aws.Status_IN_PROGRESS
	case aws.Status_ERROR.String():
		return aws.Status_ERROR
	default:
		return aws.Status_UNKNOWN
	}
}

func (a *awsService) ListDataSource(ctx context.Context, req *aws.ListDataSourceRequest) (*aws.ListDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := a.repository.ListDataSource(ctx, req.ProjectId, req.AwsId, req.DataSource)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &aws.ListDataSourceResponse{DataSource: []*aws.DataSource{}}, nil
		}
		return nil, err
	}
	ds := []*aws.DataSource{}
	for _, d := range *list {
		var scanAt int64
		if !d.ScanAt.IsZero() {
			scanAt = d.ScanAt.Unix()
		}
		ds = append(ds, &aws.DataSource{
			AwsDataSourceId: d.AWSDataSourceID,
			DataSource:      d.DataSource,
			MaxScore:        d.MaxScore,
			AwsId:           d.AWSID,
			ProjectId:       d.ProjectID,
			AssumeRoleArn:   d.AssumeRoleArn,
			ExternalId:      d.ExternalID,
			Status:          getStatus(d.Status),
			StatusDetail:    d.StatusDetail,
			ScanAt:          scanAt,
		})
	}
	return &aws.ListDataSourceResponse{DataSource: ds}, nil
}

func (a *awsService) AttachDataSource(ctx context.Context, req *aws.AttachDataSourceRequest) (*aws.AttachDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	registerd, err := a.repository.UpsertAWSRelDataSource(ctx, req.AttachDataSource)
	if err != nil {
		return nil, err
	}
	var scanAt int64
	if !registerd.ScanAt.IsZero() {
		scanAt = registerd.ScanAt.Unix()
	}
	return &aws.AttachDataSourceResponse{DataSource: &aws.AWSRelDataSource{
		AwsId:           registerd.AWSID,
		AwsDataSourceId: registerd.AWSDataSourceID,
		ProjectId:       registerd.ProjectID,
		AssumeRoleArn:   registerd.AssumeRoleArn,
		ExternalId:      registerd.ExternalID,
		Status:          getStatus(registerd.Status),
		StatusDetail:    registerd.StatusDetail,
		ScanAt:          scanAt,
		CreatedAt:       registerd.CreatedAt.Unix(),
		UpdatedAt:       registerd.UpdatedAt.Unix(),
	}}, nil
}

func (a *awsService) DetachDataSource(ctx context.Context, req *aws.DetachDataSourceRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	if err := a.repository.DeleteAWSRelDataSource(ctx, req.ProjectId, req.AwsId, req.AwsDataSourceId); err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}

func (a *awsService) InvokeScan(ctx context.Context, req *aws.InvokeScanRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	msg, err := a.repository.GetAWSDataSourceForMessage(ctx, req.AwsId, req.AwsDataSourceId, req.ProjectId)
	if err != nil {
		return nil, err
	}
	msg.ScanOnly = req.ScanOnly
	resp, err := a.sqs.send(ctx, msg)
	if err != nil {
		return nil, err
	}
	data, err := a.repository.GetAWSRelDataSourceByID(ctx, msg.AWSID, msg.AWSDataSourceID, msg.ProjectID)
	if err != nil {
		return nil, err
	}
	if _, err = a.repository.UpsertAWSRelDataSource(ctx, &aws.DataSourceForAttach{
		AwsId:           data.AWSID,
		AwsDataSourceId: data.AWSDataSourceID,
		ProjectId:       data.ProjectID,
		AssumeRoleArn:   data.AssumeRoleArn,
		ExternalId:      data.ExternalID,
		Status:          aws.Status_IN_PROGRESS,
		StatusDetail:    fmt.Sprintf("Start scan at %+v", time.Now().Format(time.RFC3339)),
		ScanAt:          data.ScanAt.Unix(),
	}); err != nil {
		return nil, err
	}
	appLogger.Infof("Invoke scanned, messageId: %v", resp.MessageId)
	return &empty.Empty{}, nil
}

func convertAWS(data *model.AWS) *aws.AWS {
	if data == nil {
		return &aws.AWS{}
	}
	return &aws.AWS{
		AwsId:        data.AWSID,
		Name:         data.Name,
		ProjectId:    data.ProjectID,
		AwsAccountId: data.AWSAccountID,
		CreatedAt:    data.CreatedAt.Unix(),
		UpdatedAt:    data.CreatedAt.Unix(),
	}
}

func (a *awsService) InvokeScanAll(ctx context.Context, req *aws.InvokeScanAllRequest) (*empty.Empty, error) {
	list, err := a.repository.ListDataSourceByAWSDataSourceID(ctx, req.AwsDataSourceId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &empty.Empty{}, nil
		}
		return nil, err
	}
	for _, dataSource := range *list {
		if skipScanDataSource(dataSource.DataSource) {
			continue
		}
		if resp, err := a.projectClient.IsActive(ctx, &project.IsActiveRequest{ProjectId: dataSource.ProjectID}); err != nil {
			appLogger.Errorf("Failed to project.IsActive API, err=%+v", err)
			continue
		} else if !resp.Active {
			appLogger.Infof("Skip deactive project, project_id=%d", dataSource.ProjectID)
			continue
		}
		if _, err := a.InvokeScan(ctx, &aws.InvokeScanRequest{
			ProjectId:       dataSource.ProjectID,
			AwsId:           dataSource.AWSID,
			AwsDataSourceId: dataSource.AWSDataSourceID,
			ScanOnly:        true,
		}); err != nil {
			// エラーログはいて握りつぶす（すべてのスキャナ登録しきる）
			appLogger.Errorf("AWS InvokeScan error: project_id=%d, aws_id=%d, aws_datasource_id=%d, err=%+v",
				dataSource.ProjectID, dataSource.AWSID, dataSource.AWSDataSourceID, err)
		}
		time.Sleep(time.Millisecond * 100) // jitter
	}
	return &empty.Empty{}, nil
}

var skipScanDataSourceList = []string{
	message.ActivityDatasource,
}

func skipScanDataSource(ds string) bool {
	for _, skipDS := range skipScanDataSourceList {
		if ds == skipDS {
			return true
		}
	}
	return false
}
