package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/h2ik/go-sqs-poller/v3/worker"
	"github.com/kelseyhightower/envconfig"
	"github.com/vikyd/zero"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint"` // At local, set the endpoint url. e.g.)`http://localhost:9324`. But other environments do not set the value.

	GuardDutyQueueName string `split_words:"true" default:"aws-guardduty"`
	GuardDutyQueueURL  string `split_words:"true" default:"http://localhost:9324/queue/aws-guardduty"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`
}

func newSQSConsumer() *worker.Worker {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	var sqsClient *sqs.SQS
	if !zero.IsZeroVal(&conf.SQSEndpoint) {
		sqsClient = sqs.New(session.New(), &aws.Config{
			Region:   &conf.AWSRegion,
			Endpoint: &conf.SQSEndpoint,
		})
	} else {
		sqsClient = sqs.New(session.New(), &aws.Config{
			Region: &conf.AWSRegion,
		})
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.GuardDutyQueueName,
			QueueURL:           conf.GuardDutyQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}