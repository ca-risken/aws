package message

import validation "github.com/go-ozzo/ozzo-validation"

// GuardDutyType is the specific data_source label for guard-duty
const GuardDutyType = "aws:guard-duty"

// AWSQueueMessage is the message for SQS queue
type AWSQueueMessage struct {
	AWSID           uint32 `json:"aws_id"`
	AWSDataSourceID uint32 `json:"aws_data_source_id"`
	ProjectID       uint32 `json:"project_id"`
}

// Validate is the validation to GuardDutyMessage
func (g *AWSQueueMessage) Validate() error {
	return validation.ValidateStruct(g,
		validation.Field(&g.AWSID, validation.Required),
		validation.Field(&g.AWSDataSourceID, validation.Required),
		validation.Field(&g.ProjectID, validation.Required),
	)
}
