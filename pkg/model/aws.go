package model

import "time"

// AWS entity
type AWS struct {
	AWSID        uint32 `gorm:"column:aws_id"`
	Name         string
	ProjectID    uint32
	AWSAccountID string `gorm:"column:aws_account_id"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AWSDataSource entity
type AWSDataSource struct {
	AWSDataSourceID uint32 `gorm:"column:aws_data_source_id"`
	DataSource      string
	MaxScore        float32
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AWSRelDataSource entity
type AWSRelDataSource struct {
	AWSID           uint32 `gorm:"column:aws_id"`
	AWSDataSourceID uint32 `gorm:"column:aws_data_source_id"`
	ProjectID       uint32
	AssumeRoleArn   string
	ExternalID      string
	Status          string
	StatusDetail    string
	ScanAt          time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
