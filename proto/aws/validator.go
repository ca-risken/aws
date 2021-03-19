package aws

import (
	"errors"

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
	if p.Aws == nil {
		return errors.New("Required Aws")
	}
	if err := validation.ValidateStruct(p,
		validation.Field(&p.ProjectId, validation.Required, validation.In(p.Aws.ProjectId)),
	); err != nil {
		return err
	}
	return p.Aws.Validate()
}

// Validate DeleteAWSRequest
func (d *DeleteAWSRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.AwsId, validation.Required),
	)
}

// Validate ListDataSourceRequest
func (l *ListDataSourceRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
		validation.Field(&l.DataSource, validation.Length(0, 64)),
		validation.Field(&l.AwsId, validation.Required),
	)
}

// Validate AttachDataSourceRequest
func (a *AttachDataSourceRequest) Validate() error {
	if a.AttachDataSource == nil {
		return errors.New("Required AttachDataSource")
	}
	if err := validation.ValidateStruct(a,
		validation.Field(&a.ProjectId, validation.Required, validation.In(a.AttachDataSource.ProjectId)),
	); err != nil {
		return err
	}
	return a.AttachDataSource.Validate()
}

// ValidateForUser AttachDataSourceRequest
func (a *AttachDataSourceRequest) ValidateForUser() error {
	if a.AttachDataSource == nil {
		return errors.New("Required AttachDataSource")
	}
	if err := validation.ValidateStruct(a,
		validation.Field(&a.ProjectId, validation.Required, validation.In(a.AttachDataSource.ProjectId)),
	); err != nil {
		return err
	}
	return a.AttachDataSource.ValidateForUser()
}

// Validate DetachDataSourceRequest
func (d *DetachDataSourceRequest) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.AwsDataSourceId, validation.Required),
	)
}

// Validate InvokeScanRequest
func (i *InvokeScanRequest) Validate() error {
	return validation.ValidateStruct(i,
		validation.Field(&i.ProjectId, validation.Required),
		validation.Field(&i.AwsId, validation.Required),
		validation.Field(&i.AwsDataSourceId, validation.Required),
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
		validation.Field(&d.StatusDetail, validation.Length(0, 255)),
		validation.Field(&d.ScanAt, validation.Min(0), validation.Max(253402268399)), //  1970-01-01T00:00:00 ~ 9999-12-31T23:59:59
	)
}

// ValidateForUser DataSourceForAttach
func (d *DataSourceForAttach) ValidateForUser() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.AwsDataSourceId, validation.Required),
		validation.Field(&d.ProjectId, validation.Required),
		validation.Field(&d.AssumeRoleArn, validation.Required, validation.Length(0, 255)),
		validation.Field(&d.ExternalId, validation.Required, validation.Length(8, 255)),
		validation.Field(&d.StatusDetail, validation.Length(0, 255)),
		validation.Field(&d.ScanAt, validation.Min(0), validation.Max(253402268399)), //  1970-01-01T00:00:00 ~ 9999-12-31T23:59:59
	)
}
