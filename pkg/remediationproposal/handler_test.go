package remediationproposal

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
)

func TestHandleMessage(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "OK",
			body: `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":""}`,
		},
		{
			name:    "NG invalid message",
			body:    `{"remediation_proposal_id":1001}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := NewSqsHandler(logging.NewLogger())
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
