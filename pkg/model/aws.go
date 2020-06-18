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

// AWSRole entity
type AWSRole struct {
	AWSRoleID     uint32 `gorm:"column:aws_role_id"`
	Name          string
	AssumeRoleArn string
	ExternalID    string
	Activated     bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AWSRelDataSource entity
type AWSRelDataSource struct {
	AWSID           uint32 `gorm:"column:aws_id"`
	AWSDataSourceID uint32 `gorm:"column:aws_data_source_id"`
	AWSRoleID       uint32 `gorm:"column:aws_role_id"`
	ProjectID       uint32
	CreatedAt       time.Time
	UpdatedAt       time.Time
}
