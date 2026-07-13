package airemediationproposal

import (
	"encoding/json"
	"errors"
	"fmt"
)

type QueueMessage struct {
	RemediationProposalID uint32 `json:"remediation_proposal_id"`
	FindingID             uint64 `json:"finding_id"`
	ProjectID             uint32 `json:"project_id"`
	DataSource            string `json:"data_source"`
	AWSID                 uint32 `json:"aws_id"`
	AWSDataSourceID       uint32 `json:"aws_data_source_id"`
	AccountID             string `json:"account_id"`
	AssumeRoleArn         string `json:"assume_role_arn"`
	ExternalID            string `json:"external_id"`
}

func ParseQueueMessage(body string) (*QueueMessage, error) {
	var msg QueueMessage
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AI remediation proposal queue message: %w", err)
	}
	if err := msg.Validate(); err != nil {
		return nil, err
	}
	return &msg, nil
}

func (m *QueueMessage) Validate() error {
	if m.RemediationProposalID == 0 {
		return errors.New("remediation_proposal_id is required")
	}
	if m.FindingID == 0 {
		return errors.New("finding_id is required")
	}
	if m.ProjectID == 0 {
		return errors.New("project_id is required")
	}
	if m.DataSource == "" {
		return errors.New("data_source is required")
	}
	if m.AWSID == 0 {
		return errors.New("aws_id is required")
	}
	if m.AWSDataSourceID == 0 {
		return errors.New("aws_data_source_id is required")
	}
	if m.AccountID == "" {
		return errors.New("account_id is required")
	}
	if m.AssumeRoleArn == "" {
		return errors.New("assume_role_arn is required")
	}
	return nil
}
