package main

import (
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/go-sqs-poller/worker/v5"
	"golang.org/x/net/context"
)

type sqsConfig struct {
	Debug string

	AWSRegion   string
	SQSEndpoint string

	PortscanQueueName  string
	PortscanQueueURL   string
	MaxNumberOfMessage int32
	WaitTimeSecond     int32
	ScanConcurrency    int64
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
			QueueName:          conf.PortscanQueueName,
			QueueURL:           conf.PortscanQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}
