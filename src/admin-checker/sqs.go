package main

import (
	"context"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
)

type sqsConfig struct {
	Debug string

	AWSRegion   string
	SQSEndpoint string

	AWSAdminCheckerQueueName string
	AWSAdminCheckerQueueURL  string
	MaxNumberOfMessage       int32
	WaitTimeSecond           int32
}

func newSQSConsumer(ctx context.Context, conf *sqsConfig) *worker.Worker {
	if conf.Debug == "true" {
		appLogger.Level(logging.DebugLevel)
	}
	sqsClient, err := worker.CreateSqsClient(ctx, conf.AWSRegion, conf.SQSEndpoint)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create a new client, %v", err)
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.AWSAdminCheckerQueueName,
			QueueURL:           conf.AWSAdminCheckerQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}
