package main

import validation "github.com/go-ozzo/ozzo-validation"

const guardDutyType = "aws:guard-duty"

type guardDutyMessage struct {
	DataSource    string `json:"data_source"`
	ProjectID     uint32 `json:"project_id"`
	AccountID     string `json:"account_id"`
	AssumeRoleArn string `json:"assume_role_arn"`
	ExternalID    string `json:"external_id"`
}

func (g *guardDutyMessage) validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.DataSource, validation.Required, validation.In(guardDutyType)),
		validation.Field(&g.ProjectID, validation.Required),
		validation.Field(&g.AccountID, validation.Required, validation.Length(12, 12)),
	)
}
