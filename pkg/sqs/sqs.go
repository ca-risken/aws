package sqs

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
)

type SQSConfig struct {
	Debug              string
	AWSRegion          string
	SQSEndpoint        string
	QueueName          string
	QueueURL           string
	MaxNumberOfMessage int32
	WaitTimeSecond     int32
}

func NewSQSConsumer(ctx context.Context, conf *SQSConfig, l logging.Logger) (*worker.Worker, error) {
	if conf.Debug == "true" {
		l.Level(logging.DebugLevel)
	}
	sqsClient, err := worker.CreateSqsClient(ctx, conf.AWSRegion, conf.SQSEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new sqs client, %w", err)
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.QueueName,
			QueueURL:           conf.QueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       l,
		SqsClient: sqsClient,
	}, nil
}
