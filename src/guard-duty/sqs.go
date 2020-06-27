package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/h2ik/go-sqs-poller/v3/worker"
	"github.com/kelseyhightower/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://localhost:9324"`

	QueueName          string `split_words:"true" default:"aws-guardduty"`
	QueueURL           string `split_words:"true" default:"http://localhost:9324/queue/aws-guardduty"`
	MaxNumberOfMessage int64  `split_words:"true" default:"10"`
	WaitTimeSecond     int64  `split_words:"true" default:"20"`
}

func newSQSConsumer() *worker.Worker {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	sqsClient := sqs.New(session.New(), &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.QueueName,
			QueueURL:           conf.QueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}
