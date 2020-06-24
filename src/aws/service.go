package main

import (
	"context"

	"github.com/CyberAgent/mimosa-aws/pkg/model"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/jinzhu/gorm"
)

type awsService struct {
	repository awsRepoInterface
}

func newAWSService(repo awsRepoInterface) aws.AWSServiceServer {
	return &awsService{
		repository: repo,
	}
}

func (a *awsService) ListAWS(ctx context.Context, req *aws.ListAWSRequest) (*aws.ListAWSResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	list, err := a.repository.ListAWS(req.ProjectId, req.AwsId, req.AwsAccountId)
	if err != nil {
		if gorm.IsRecordNotFoundError(err) {
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
	savedData, err := a.repository.GetAWSByAccountID(req.ProjectId, req.Aws.AwsAccountId)
	noRecord := gorm.IsRecordNotFoundError(err)
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
	registerdData, err := a.repository.UpsertAWS(data)
	if err != nil {
		return nil, err
	}
	return &aws.PutAWSResponse{Aws: convertAWS(registerdData)}, nil
}

func (a *awsService) DeleteAWS(ctx context.Context, req *aws.DeleteAWSRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *awsService) ListDataSource(ctx context.Context, req *aws.ListDataSourceRequest) (*aws.ListDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *awsService) AttachDataSource(ctx context.Context, req *aws.AttachDataSourceRequest) (*aws.AttachDataSourceResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *awsService) DetachDataSource(ctx context.Context, req *aws.DetachDataSourceRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (a *awsService) InvokeScan(ctx context.Context, req *aws.InvokeScanRequest) (*empty.Empty, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, nil
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
