package main

import validation "github.com/go-ozzo/ozzo-validation"

// GuardDutyType is the specific data_source label for guard-duty
const GuardDutyType = "aws:guard-duty"

// GuardDutyMessage is the message for SQS queue
type GuardDutyMessage struct {
	DataSource    string `json:"data_source"`
	ProjectID     uint32 `json:"project_id"`
	AccountID     string `json:"account_id"`
	AssumeRoleArn string `json:"assume_role_arn"`
	ExternalID    string `json:"external_id"`
}

// Validate is the validation to GuardDutyMessage
func (g *GuardDutyMessage) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.DataSource, validation.Required, validation.In(GuardDutyType)),
		validation.Field(&g.ProjectID, validation.Required),
		validation.Field(&g.AccountID, validation.Required, validation.Length(12, 12)),
	)
}
