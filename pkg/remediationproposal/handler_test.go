package remediationproposal

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
)

type mockProcessor struct {
	called    bool
	requestID string
	msg       *QueueMessage
	err       error
}

func (m *mockProcessor) Process(ctx context.Context, msg *QueueMessage, requestID string) error {
	m.called = true
	m.requestID = requestID
	m.msg = msg
	return m.err
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
			handler := NewSqsHandler(logging.NewLogger(), WithProcessor(processor))
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
