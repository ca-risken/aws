package controller

import validation "github.com/go-ozzo/ozzo-validation"

// Validate ListAWSRequest
func (l *ListAWSRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.ProjectId, validation.Required),
		validation.Field(&l.AwsAccountId, validation.Length(12, 12)),
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
	)
}

// Validate ListAWSRoleRequest
func (l *ListAWSRoleRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.Name, validation.Length(0, 200)),
	)
}

// Validate PutAWSRoleRequest
func (p *PutAWSRoleRequest) Validate() error {
	return p.AwsRole.Validate()
}

// Validate ListDataSourceRequest
func (l *ListDataSourceRequest) Validate() error {
	return validation.ValidateStruct(l,
		validation.Field(&l.DataSource, validation.Length(0, 64)),
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
		validation.Field(&a.AwsAccountId, validation.Required, validation.Length(12, 12)),
	)
}

// Validate AWSRoleForUpsert
func (a *AWSRoleForUpsert) Validate() error {
	return validation.ValidateStruct(a,
		validation.Field(&a.Name, validation.Length(0, 200)),
		validation.Field(&a.AssumeRoleArn, validation.Required),
		validation.Field(&a.ExternalId, validation.Length(0, 255)),
		validation.Field(&a.Activated, validation.Required),
	)
}

// Validate DataSourceForAttach
func (d *DataSourceForAttach) Validate() error {
	return validation.ValidateStruct(d,
		validation.Field(&d.AwsId, validation.Required),
		validation.Field(&d.AwsDataSourceId, validation.Required),
		validation.Field(&d.AwsRoleId, validation.Required),
		validation.Field(&d.ProjectId, validation.Required),
	)
}
