package remediationproposal

import (
	"encoding/json"
	"errors"
	"fmt"
)

type QueueMessage struct {
	RemediationProposalID uint32 `json:"remediation_proposal_id"`
	FindingID             uint64 `json:"finding_id"`
	ProjectID             uint32 `json:"project_id"`
	AssumeRoleArn         string `json:"assume_role_arn"`
	ExternalID            string `json:"external_id"`
}

func ParseQueueMessage(body string) (*QueueMessage, error) {
	var msg QueueMessage
	if err := json.Unmarshal([]byte(body), &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remediation proposal queue message: %w", err)
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
	if m.AssumeRoleArn == "" {
		return errors.New("assume_role_arn is required")
	}
	return nil
}
