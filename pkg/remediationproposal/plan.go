package remediationproposal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type RemediationPlan struct {
	FindingID uint64      `json:"finding_id"`
	Plan      PlanContent `json:"remediation_plan"`
}

type PlanContent struct {
	Summary      string            `json:"summary"`
	CurrentState []string          `json:"current_state"`
	Steps        []RemediationStep `json:"steps"`
	Metadata     PlanMetadata      `json:"metadata"`
}

type RemediationStep struct {
	Order               int    `json:"order"`
	Title               string `json:"title"`
	Command             string `json:"command"`
	VerificationCommand string `json:"verification_command"`
}

type PlanMetadata struct {
	GeneratedAt int64  `json:"generated_at"`
	Model       string `json:"model"`
}

func parsePlan(output string) (*PlanContent, error) {
	var plan PlanContent
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("invalid remediation plan JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected trailing remediation plan data")
	}
	if strings.TrimSpace(plan.Summary) == "" || len(plan.CurrentState) == 0 || plan.Steps == nil {
		return nil, errors.New("incomplete remediation plan")
	}
	for _, state := range plan.CurrentState {
		if strings.TrimSpace(state) == "" {
			return nil, errors.New("empty resource state")
		}
	}
	for i, step := range plan.Steps {
		if step.Order != i+1 || strings.TrimSpace(step.Title) == "" || strings.TrimSpace(step.Command) == "" || strings.TrimSpace(step.VerificationCommand) == "" {
			return nil, errors.New("invalid remediation step")
		}
		if err := validateAWSCommand(step.Command); err != nil {
			return nil, fmt.Errorf("invalid remediation command: %w", err)
		}
		if err := validateReadOnlyAWSCommand(step.VerificationCommand); err != nil {
			return nil, fmt.Errorf("invalid verification command: %w", err)
		}
	}
	return &plan, nil
}

func planSchema() map[string]any {
	text := map[string]any{"type": "string"}
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"summary", "current_state", "steps"},
		"properties": map[string]any{
			"summary":       text,
			"current_state": map[string]any{"type": "array", "items": text},
			"steps": map[string]any{"type": "array", "items": map[string]any{
				"type": "object", "additionalProperties": false,
				"required":   []string{"order", "title", "command", "verification_command"},
				"properties": map[string]any{"order": map[string]any{"type": "integer"}, "title": text, "command": text, "verification_command": text},
			}},
		},
	}
}
