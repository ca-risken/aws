package remediationproposal

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	coreai "github.com/ca-risken/core/proto/ai"
	coreaimocks "github.com/ca-risken/core/proto/ai/mocks"
	"github.com/stretchr/testify/mock"
)

func TestHandleMessage(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		setup   func(ai *coreaimocks.AIServiceClient)
		wantErr bool
	}{
		{
			name: "OK",
			body: `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`,
			setup: func(ai *coreaimocks.AIServiceClient) {
				ai.On("UpdateRemediationProposalStatus", mock.Anything, mock.MatchedBy(func(req *coreai.UpdateRemediationProposalStatusRequest) bool {
					return req.ProjectId == 1001 &&
						req.RemediationProposalId == 1001 &&
						req.Status == remediationProposalStatusFailed &&
						req.StatusDetail == remediationProposalStatusDetailNotImplemented
				})).Return(&coreai.UpdateRemediationProposalStatusResponse{}, nil).Once()
			},
		},
		{
			name:    "NG invalid message",
			body:    `{"remediation_proposal_id":1001}`,
			wantErr: true,
		},
		{
			name: "NG update remediation proposal status error",
			body: `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`,
			setup: func(ai *coreaimocks.AIServiceClient) {
				ai.On("UpdateRemediationProposalStatus", mock.Anything, mock.Anything).Return(nil, assertAnError{}).Once()
			},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			aiClient := coreaimocks.NewAIServiceClient(t)
			if c.setup != nil {
				c.setup(aiClient)
			}
			handler := NewSqsHandler(logging.NewLogger(), aiClient)
			err := handler.HandleMessage(context.Background(), &types.Message{Body: aws.String(c.body)})
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if err == nil && c.wantErr {
				t.Fatal("expected error but got nil")
			}
		})
	}
}

type assertAnError struct{}

func (assertAnError) Error() string {
	return "error"
}
