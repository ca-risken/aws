package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/ai"
	coreaimocks "github.com/ca-risken/core/proto/ai/mocks"
	"github.com/stretchr/testify/mock"
)

type mockProcessor struct {
	called    bool
	requestID string
	msg       *QueueMessage
	err       error
	nilPlan   bool
}

func (m *mockProcessor) Process(ctx context.Context, msg *QueueMessage, requestID string) (*RemediationPlan, error) {
	m.called = true
	m.requestID = requestID
	m.msg = msg
	if m.nilPlan {
		return nil, m.err
	}
	return &RemediationPlan{FindingID: msg.FindingID, Plan: PlanContent{Summary: "test", CurrentState: []string{"verified"}, Steps: []RemediationStep{}, Metadata: PlanMetadata{GeneratedAt: 1, Model: "test-model"}}}, m.err
}

func TestHandleMessage(t *testing.T) {
	errProcess := errors.New("process error")
	cases := []struct {
		name              string
		body              string
		processorErr      error
		wantProcessorCall bool
		wantErr           bool
	}{
		{
			name:              "OK",
			body:              `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`,
			wantProcessorCall: true,
		},
		{
			name:    "NG invalid message",
			body:    `{"remediation_proposal_id":1001}`,
			wantErr: true,
		},
		{
			name:              "NG processor error",
			body:              `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`,
			processorErr:      errProcess,
			wantProcessorCall: true,
			wantErr:           true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			processor := &mockProcessor{err: c.processorErr}
			aiClient := coreaimocks.NewAIServiceClient(t)
			status := remediationProposalStatusSucceeded
			statusDetail := ""
			if c.processorErr != nil {
				status = remediationProposalStatusFailed
				statusDetail = "failed to generate remediation proposal"
			}
			if c.wantProcessorCall {
				aiClient.On("UpdateRemediationProposalStatus", mock.Anything, mock.MatchedBy(func(req *ai.UpdateRemediationProposalStatusRequest) bool {
					if status == remediationProposalStatusSucceeded {
						var plan RemediationPlan
						if json.Unmarshal([]byte(req.RemediationPlan), &plan) != nil || plan.FindingID != 2001 || plan.Plan.Metadata.Model != "test-model" {
							return false
						}
					}
					return req.ProjectId == 1001 && req.RemediationProposalId == 1001 && req.Status == status && req.StatusDetail == statusDetail && ((status == remediationProposalStatusSucceeded && req.RemediationPlan != "" && req.GeneratedAt == 1) || (status == remediationProposalStatusFailed && req.RemediationPlan == "" && req.GeneratedAt == 0))
				})).Return(&ai.UpdateRemediationProposalStatusResponse{}, nil).Once()
			}
			handler := NewSqsHandler(logging.NewLogger(), processor, aiClient)
			err := handler.HandleMessage(context.Background(), &types.Message{Body: aws.String(c.body)})
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if err == nil && c.wantErr {
				t.Fatal("expected error but got nil")
			}
			if processor.called != c.wantProcessorCall {
				t.Fatalf("unexpected processor call: want=%t, got=%t", c.wantProcessorCall, processor.called)
			}
			if c.wantProcessorCall && processor.msg.RemediationProposalID != 1001 {
				t.Fatalf("unexpected remediation_proposal_id: got=%d", processor.msg.RemediationProposalID)
			}
		})
	}
}

func TestRemediationProposalStatusDetail(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{name: "finding", err: errors.New("failed to get finding: account_id=123"), want: "failed to get finding"},
		{name: "assume role", err: errors.New("failed to assume role: arn=secret"), want: "failed to assume role"},
		{name: "mcp proxy", err: errors.New("failed to start AWS MCP proxy: command=secret"), want: "failed to start MCP proxy"},
		{name: "provider", err: errors.New("unsupported finding provider: provider=secret"), want: "unsupported finding provider"},
		{name: "provider target", err: errors.New("invalid finding provider target: account_id=123"), want: "invalid finding provider target"},
		{name: "unknown", err: errors.New("internal error: secret"), want: "failed to generate remediation proposal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := remediationProposalStatusDetail(c.err); got != c.want {
				t.Fatalf("unexpected status detail: got=%q, want=%q", got, c.want)
			}
		})
	}
}

func TestHandleMessageWithoutProcessor(t *testing.T) {
	handler := NewSqsHandler(logging.NewLogger(), nil, coreaimocks.NewAIServiceClient(t))
	err := handler.HandleMessage(context.Background(), &types.Message{})
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if err.Error() != "remediation proposal processor is required" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleMessageResultFailures(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		nilPlan, updateError bool
	}{
		{name: "missing plan", nilPlan: true}, {name: "core failure", updateError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := coreaimocks.NewAIServiceClient(t)
			status := remediationProposalStatusSucceeded
			if tt.nilPlan {
				status = remediationProposalStatusFailed
			}
			var updateErr error
			if tt.updateError {
				updateErr = errors.New("core unavailable")
			}
			client.On("UpdateRemediationProposalStatus", mock.Anything, mock.MatchedBy(func(req *ai.UpdateRemediationProposalStatusRequest) bool { return req.Status == status })).Return(&ai.UpdateRemediationProposalStatusResponse{}, updateErr).Once()
			handler := NewSqsHandler(logging.NewLogger(), &mockProcessor{nilPlan: tt.nilPlan}, client)
			err := handler.HandleMessage(context.Background(), &types.Message{Body: aws.String(`{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`)})
			if err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}
