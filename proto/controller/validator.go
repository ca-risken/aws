package controller

import (
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

// Validate ListAWSRequest
func (l *ListAWSRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
		validation.Field(&l.AwsAccountId, validation.Length(12, 12), is.Digit),
	)
}

// Validate PutAWSRequest
func (p *PutAWSRequest) Validate() error {
	return p.Aws.Validate()
}

// Validate DeleteAWSRequest
func (d *DeleteAWSRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.ProjectId, validation.Required),
	)
}

// Validate ListDataSourceRequest
func (l *ListDataSourceRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.DataSource, validation.Length(0, 64)),
		validation.Field(&l.AwsId, validation.Required),
		validation.Field(&l.ProjectId, validation.Required),
	)
}

// Validate AttachDataSourceRequest
func (a *AttachDataSourceRequest) Validate() error {
	return a.AttachDataSource.Validate()
}

// Validate DetachDataSourceRequest
func (d *DetachDataSourceRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.AwsDataSourceId, validation.Required),
		validation.Field(&d.ProjectId, validation.Required),
	)
}

// Validate InvokeScanRequest
func (i *InvokeScanRequest) Validate() error {
	return validation.ValidateStruct(i,
		validation.Field(&i.AwsId, validation.Required),
		validation.Field(&i.AwsDataSourceId, validation.Required),
		validation.Field(&i.ProjectId, validation.Required),
	)
}

/**
 * Entity
**/

// Validate AWSForUpsert
func (a *AWSForUpsert) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.Name, validation.Length(0, 200)),
		validation.Field(&a.ProjectId, validation.Required),
		validation.Field(&a.AwsAccountId, validation.Required, is.Digit, validation.Length(12, 12)),
	)
}

// Validate DataSourceForAttach
func (d *DataSourceForAttach) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.AwsDataSourceId, validation.Required),
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.AssumeRoleArn, validation.Required, validation.Length(0, 255)),
		validation.Field(&d.ExternalId, validation.Length(0, 255)),
	)
}
