package main

import (
	"fmt"

	"github.com/CyberAgent/mimosa-aws/pkg/model"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
)

type awsRepoInterface interface {
	ListAWS(uint32, uint32, string) (*[]model.AWS, error)
	GetAWSByAccountID(uint32, string) (*model.AWS, error)
	UpsertAWS(*model.AWS) (*model.AWS, error)
	DeleteAWS(uint32, uint32) error
	ListDataSource(uint32, uint32, string) (*[]dataSource, error)
	UpsertAWSRelDataSource(*aws.DataSourceForAttach) (*model.AWSRelDataSource, error)
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

	db, err := gorm.Open("mysql",
		fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?charset=utf8mb4&interpolateParams=true&parseTime=true&loc=Local",
			user, pass, host, conf.Port, conf.Schema))
	if err != nil {
		appLogger.Fatalf("Failed to open DB. isMaster: %t, err: %+v", isMaster, err)
		return nil
	}
	db.LogMode(conf.LogMode)
	db.SingularTable(true) // if set this to true, `User`'s default table name will be `user`
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
	if err := a.SlaveDB.Raw(selectGetAWSByAccountID, projectID, awsAccountID).First(&data).Error; err != nil {
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
  name=VALUES(name),
  project_id=VALUES(project_id)
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
from
  aws_data_source ads
  left outer join (
    select * from aws_rel_data_source where project_id = ? `
	params = append(params, projectID)

	if !zero.IsZeroVal(awsID) {
		query += " and aws_id = ?"
		params = append(params, awsID)
	}
	if !zero.IsZeroVal(ds) {
		query += " and dataSource = ?"
		params = append(params, ds)
	}
	query += `
  ) ards using(aws_data_source_id)
order by
  ads.aws_data_source_id
`
	data := []dataSource{}
	if err := a.SlaveDB.Raw(query, params...).Scan(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}

const insertUpsertAWSRelDataSource = `
INSERT INTO aws_rel_data_source
  (aws_id, aws_data_source_id, project_id, assume_role_arn, external_id)
VALUES
  (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
  project_id=VALUES(project_id),
  assume_role_arn=VALUES(assume_role_arn),
  external_id=VALUES(external_id)
`

func (a *awsRepository) UpsertAWSRelDataSource(data *aws.DataSourceForAttach) (*model.AWSRelDataSource, error) {
	if err := a.MasterDB.Exec(insertUpsertAWSRelDataSource, data.AwsId, data.AwsDataSourceId, data.ProjectId, data.AssumeRoleArn, data.ExternalId).Error; err != nil {
		return nil, err
	}
	return a.GetAWSRelDataSourceByID(data.AwsId, data.AwsDataSourceId)
}

const selectGetAWSRelDataSourceByID = `select * from aws_rel_data_source where aws_id = ? and aws_data_source_id = ?`

func (a *awsRepository) GetAWSRelDataSourceByID(awsID, awsDataSourceID uint32) (*model.AWSRelDataSource, error) {
	data := model.AWSRelDataSource{}
	if err := a.SlaveDB.Raw(selectGetAWSRelDataSourceByID, awsID, awsDataSourceID).First(&data).Error; err != nil {
		return nil, err
	}
	return &data, nil
}
