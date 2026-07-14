package remediationproposal

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	commonsqs "github.com/ca-risken/common/pkg/sqs"
)

type mockQueueClient struct {
	receiveResp *awssqs.ReceiveMessageOutput
	receiveErr  error
	deleteErr   error
	deleted     bool
}

func (m *mockQueueClient) ReceiveMessage(ctx context.Context, input *awssqs.ReceiveMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error) {
	if m.receiveErr != nil {
		return nil, m.receiveErr
	}
	return m.receiveResp, nil
}

func (m *mockQueueClient) DeleteMessage(ctx context.Context, input *awssqs.DeleteMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error) {
	m.deleted = true
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return &awssqs.DeleteMessageOutput{}, nil
}

func TestRunOnce(t *testing.T) {
	errReceive := errors.New("receive error")
	errHandle := errors.New("handle error")
	errDelete := errors.New("delete error")

	cases := []struct {
		name          string
		client        *mockQueueClient
		handler       commonsqs.Handler
		wantProcessed bool
		wantDeleted   bool
		wantErr       bool
	}{
		{
			name: "OK no message",
			client: &mockQueueClient{
				receiveResp: &awssqs.ReceiveMessageOutput{},
			},
			handler:       commonsqs.HandlerFunc(func(ctx context.Context, msg *types.Message) error { return nil }),
			wantProcessed: false,
		},
		{
			name: "OK handle and delete",
			client: &mockQueueClient{
				receiveResp: &awssqs.ReceiveMessageOutput{
					Messages: []types.Message{
						{Body: aws.String(`{}`), ReceiptHandle: aws.String("receipt")},
					},
				},
			},
			handler:       commonsqs.HandlerFunc(func(ctx context.Context, msg *types.Message) error { return nil }),
			wantProcessed: true,
			wantDeleted:   true,
		},
		{
			name: "NG receive error",
			client: &mockQueueClient{
				receiveErr: errReceive,
			},
			handler: commonsqs.HandlerFunc(func(ctx context.Context, msg *types.Message) error { return nil }),
			wantErr: true,
		},
		{
			name: "NG handle error keeps message",
			client: &mockQueueClient{
				receiveResp: &awssqs.ReceiveMessageOutput{
					Messages: []types.Message{
						{Body: aws.String(`{}`), ReceiptHandle: aws.String("receipt")},
					},
				},
			},
			handler:       commonsqs.HandlerFunc(func(ctx context.Context, msg *types.Message) error { return errHandle }),
			wantProcessed: true,
			wantErr:       true,
		},
		{
			name: "NG delete error",
			client: &mockQueueClient{
				receiveResp: &awssqs.ReceiveMessageOutput{
					Messages: []types.Message{
						{Body: aws.String(`{}`), ReceiptHandle: aws.String("receipt")},
					},
				},
				deleteErr: errDelete,
			},
			handler:       commonsqs.HandlerFunc(func(ctx context.Context, msg *types.Message) error { return nil }),
			wantProcessed: true,
			wantDeleted:   true,
			wantErr:       true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			processed, err := RunOnce(context.Background(), c.client, "http://localhost:9324/queue/test", 1, c.handler, logging.NewLogger())
			if (err != nil) != c.wantErr {
				t.Fatalf("unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if processed != c.wantProcessed {
				t.Fatalf("unexpected processed: want=%t, got=%t", c.wantProcessed, processed)
			}
			if c.client.deleted != c.wantDeleted {
				t.Fatalf("unexpected delete: want=%t, got=%t", c.wantDeleted, c.client.deleted)
			}
		})
	}
}
