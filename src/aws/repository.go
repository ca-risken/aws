package main

import (
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-aws/pkg/model"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

type awsRepoInterface interface {
	ListAWS(projectID, awsID uint32, awsAccountID string) (*[]model.AWS, error)
	GetAWSByAccountID(projectID uint32, awsAccountID string) (*model.AWS, error)
	UpsertAWS(data *model.AWS) (*model.AWS, error)
	DeleteAWS(projectID, awsID uint32) error
	ListDataSource(projectID, awsID uint32, ds string) (*[]dataSource, error)
	UpsertAWSRelDataSource(data *aws.DataSourceForAttach) (*model.AWSRelDataSource, error)
	GetAWSRelDataSourceByID(awsID, awsDataSourceID, projectID uint32) (*model.AWSRelDataSource, error)
	DeleteAWSRelDataSource(projectID, awsID, awsDataSourceID uint32) error
	GetAWSDataSourceForMessage(awsID, awsDataSourceID, projectID uint32) (*message.AWSQueueMessage, error)
}

type awsRepository struct {
	MasterDB *gorm.DB
	SlaveDB  *gorm.DB
}

func newAWSRepository() awsRepoInterface {
	repo := awsRepository{}
	repo.MasterDB = initDB(true)
	repo.SlaveDB = initDB(false)
	return &repo
}

type dbConfig struct {
	MasterHost     string `split_words:"true" required:"true"`
	MasterUser     string `split_words:"true" required:"true"`
	MasterPassword string `split_words:"true" required:"true"`
	SlaveHost      string `split_words:"true"`
	SlaveUser      string `split_words:"true"`
	SlavePassword  string `split_words:"true"`

	Schema  string `required:"true"`
	Port    int    `required:"true"`
	LogMode bool   `split_words:"true" default:"false"`
}

func initDB(isMaster bool) *gorm.DB {
	conf := &dbConfig{}
	if err := envconfig.Process("DB", conf); err != nil {
		appLogger.Fatalf("Failed to load DB config. err: %+v", err)
	}

	var user, pass, host string
	if isMaster {
		user = conf.MasterUser
		pass = conf.MasterPassword
		host = conf.MasterHost
	} else {
		user = conf.SlaveUser
		pass = conf.SlavePassword
		host = conf.SlaveHost
	}

	dsn := fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?charset=utf8mb4&interpolateParams=true&parseTime=true&loc=Local",
		user, pass, host, conf.Port, conf.Schema)
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{NamingStrategy: schema.NamingStrategy{SingularTable: true}})
	if err != nil {
		appLogger.Fatalf("Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	if conf.LogMode {
		db.Logger.LogMode(glogger.Info)
	}
	appLogger.Infof("Connected to Database. isMaster: %t", isMaster)
	return db
}

func (a *awsRepository) ListAWS(projectID, awsID uint32, awsAccountID string) (*[]model.AWS, error) {
	query := `
select
  *
from
  aws
where
  project_id = ?
`
	var params []interface{}
	params = append(params, projectID)
	if !zero.IsZeroVal(awsID) {
		query += " and aws_id = ?"
		params = append(params, awsID)
	}
	if !zero.IsZeroVal(awsAccountID) {
		query += " and aws_account_id = ?"
		params = append(params, awsAccountID)
	}

	data := []model.AWS{}
	if err := a.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const selectGetAWSByAccountID = `select * from aws where project_id = ? and aws_account_id = ?`

func (a *awsRepository) GetAWSByAccountID(projectID uint32, awsAccountID string) (*model.AWS, error) {
	data := model.AWS{}
	if err := a.MasterDB.Raw(selectGetAWSByAccountID, projectID, awsAccountID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertUpsertAWS = `
INSERT INTO aws
  (aws_id, name, project_id, aws_account_id)
VALUES
  (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  name=VALUES(name)
`

func (a *awsRepository) UpsertAWS(data *model.AWS) (*model.AWS, error) {
	if err := a.MasterDB.Exec(insertUpsertAWS,
		data.AWSID, data.Name, data.ProjectID, data.AWSAccountID).Error; err != nil {
		return nil, err
	}

	updated, err := a.GetAWSByAccountID(data.ProjectID, data.AWSAccountID)
	if err != nil {
		return nil, err
	}
	return updated, nil
}

const deleteAws = `delete from aws where project_id = ? and aws_id = ?`

func (a *awsRepository) DeleteAWS(projectID, awsID uint32) error {
	if err := a.MasterDB.Exec(deleteAws, projectID, awsID).Error; err != nil {
		return err
	}
	return nil
}

type dataSource struct {
	AWSDataSourceID uint32
	DataSource      string
	MaxScore        float32
	AWSID           uint32 `gorm:"column:aws_id"`
	ProjectID       uint32
	AssumeRoleArn   string
	ExternalID      string
	Status          string
	StatusDetail    string
	ScanAt          time.Time
}

func (a *awsRepository) ListDataSource(projectID, awsID uint32, ds string) (*[]dataSource, error) {
	var params []interface{}
	query := `
select
  ads.aws_data_source_id
  , ads.data_source
  , ads.max_score
  , ards.aws_id
  , ards.project_id
  , ards.assume_role_arn
  , ards.external_id
  , ards.status
  , ards.status_detail
  , ards.scan_at
from
  aws_data_source ads
  left outer join (
		select * from aws_rel_data_source where 1=1 `
	if !zero.IsZeroVal(awsID) {
		query += " and project_id = ? "
		params = append(params, projectID)
	}
	if !zero.IsZeroVal(awsID) {
		query += " and aws_id = ?"
		params = append(params, awsID)
	}
	query += `
	) ards using(aws_data_source_id)`
	if !zero.IsZeroVal(ds) {
		query += `
where
  ads.data_source = ?`
		params = append(params, ds)
	}
	query += `
order by
	ards.project_id
	, ards.aws_id
  , ads.aws_data_source_id
`
	data := []dataSource{}
	if err := a.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertUpsertAWSRelDataSource = `
INSERT INTO aws_rel_data_source
  (aws_id, aws_data_source_id, project_id, assume_role_arn, external_id, status, status_detail, scan_at)
VALUES
  (?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  project_id=VALUES(project_id),
  assume_role_arn=VALUES(assume_role_arn),
  external_id=VALUES(external_id),
  status=VALUES(status),
  status_detail=VALUES(status_detail),
  scan_at=VALUES(scan_at)
`

func (a *awsRepository) UpsertAWSRelDataSource(data *aws.DataSourceForAttach) (*model.AWSRelDataSource, error) {
	if err := a.MasterDB.Exec(insertUpsertAWSRelDataSource,
		data.AwsId, data.AwsDataSourceId, data.ProjectId,
		data.AssumeRoleArn, data.ExternalId,
		data.Status.String(), data.StatusDetail, time.Unix(data.ScanAt, 0),
	).Error; err != nil {
		return nil, err
	}
	return a.GetAWSRelDataSourceByID(data.AwsId, data.AwsDataSourceId, data.ProjectId)
}

const selectGetAWSRelDataSourceByID = `select * from aws_rel_data_source where aws_id = ? and aws_data_source_id = ? and project_id = ?`

func (a *awsRepository) GetAWSRelDataSourceByID(awsID, awsDataSourceID, projectID uint32) (*model.AWSRelDataSource, error) {
	data := model.AWSRelDataSource{}
	if err := a.MasterDB.Raw(selectGetAWSRelDataSourceByID, awsID, awsDataSourceID, projectID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const deleteAWSRelDataSource = `delete from aws_rel_data_source where project_id = ? and aws_id = ? and aws_data_source_id = ?`

func (a *awsRepository) DeleteAWSRelDataSource(projectID, awsID, awsDataSourceID uint32) error {
	if err := a.MasterDB.Exec(deleteAWSRelDataSource, projectID, awsID, awsDataSourceID).Error; err != nil {
		return err
	}
	return nil
}

const selectAWSDataSourceForMessage = `
select 
	a.aws_id                  as aws_id
  , ards.aws_data_source_id as aws_data_source_id
  , ads.data_source         as data_source
  , ards.project_id         as project_id
  , a.aws_account_id        as account_id
  , ards.assume_role_arn    as assume_role_arn
  , ards.external_id        as external_id
from
  aws_rel_data_source ards
  inner join aws a using(aws_id)
  inner join aws_data_source ads using(aws_data_source_id)
where
  ards.aws_id = ?
  and ards.aws_data_source_id = ?
	and ards.project_id = ? 
`

func (a *awsRepository) GetAWSDataSourceForMessage(awsID, awsDataSourceID, projectID uint32) (*message.AWSQueueMessage, error) {
	data := message.AWSQueueMessage{}
	if err := a.SlaveDB.Raw(selectAWSDataSourceForMessage, awsID, awsDataSourceID, projectID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}
