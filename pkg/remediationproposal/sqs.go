package remediationproposal

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awssqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	commonsqs "github.com/ca-risken/common/pkg/sqs"
)

type QueueClient interface {
	ReceiveMessage(ctx context.Context, params *awssqs.ReceiveMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.ReceiveMessageOutput, error)
	DeleteMessage(ctx context.Context, params *awssqs.DeleteMessageInput, optFns ...func(*awssqs.Options)) (*awssqs.DeleteMessageOutput, error)
}

type Runner struct {
	client          QueueClient
	queueURL        string
	waitTimeSeconds int32
	handler         commonsqs.Handler
	logger          logging.Logger
}

func NewRunner(client QueueClient, queueURL string, waitTimeSeconds int32, handler commonsqs.Handler, logger logging.Logger) *Runner {
	return &Runner{
		client:          client,
		queueURL:        queueURL,
		waitTimeSeconds: waitTimeSeconds,
		handler:         handler,
		logger:          logger,
	}
}

func NewSQSClient(ctx context.Context, region, endpoint string) (QueueClient, error) {
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service != awssqs.ServiceID {
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		}
		if endpoint == "" {
			return aws.Endpoint{PartitionID: "aws", SigningRegion: region}, nil
		}
		return aws.Endpoint{PartitionID: "aws", URL: endpoint, SigningRegion: region}, nil
	})
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithEndpointResolverWithOptions(customResolver))
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	return awssqs.NewFromConfig(cfg), nil
}

func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	r.logger.Debug(ctx, "receive one remediation proposal message")
	resp, err := r.client.ReceiveMessage(ctx, &awssqs.ReceiveMessageInput{
		QueueUrl:            aws.String(r.queueURL),
		MaxNumberOfMessages: 1,
		AttributeNames: []types.QueueAttributeName{
			"All",
		},
		WaitTimeSeconds: r.waitTimeSeconds,
	})
	if err != nil {
		return false, fmt.Errorf("failed to receive remediation proposal message: %w", err)
	}
	if len(resp.Messages) == 0 {
		r.logger.Info(ctx, "no remediation proposal message received")
		return false, nil
	}

	return true, r.handleMessage(ctx, &resp.Messages[0])
}

func (r *Runner) handleMessage(ctx context.Context, msg *types.Message) error {
	r.logger.Info(ctx, "received remediation proposal message")
	if err := r.handler.HandleMessage(ctx, msg); err != nil {
		return err
	}
	if _, err := r.client.DeleteMessage(ctx, &awssqs.DeleteMessageInput{
		QueueUrl:      aws.String(r.queueURL),
		ReceiptHandle: msg.ReceiptHandle,
	}); err != nil {
		return fmt.Errorf("failed to delete remediation proposal message: %w", err)
	}
	r.logger.Debugf(ctx, "deleted remediation proposal message: receipt_handle=%s", aws.ToString(msg.ReceiptHandle))
	return nil
}
