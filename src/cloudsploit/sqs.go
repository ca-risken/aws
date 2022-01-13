package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/gassara-kys/envconfig"
	"github.com/gassara-kys/go-sqs-poller/worker/v4"
	"github.com/vikyd/zero"
)

type sqsConfig struct {
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	CloudsploitQueueName string `split_words:"true" default:"aws-cloudsploit"`
	CloudsploitQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-cloudsploit"`
	MaxNumberOfMessage   int64  `split_words:"true" default:"5"`
	WaitTimeSecond       int64  `split_words:"true" default:"20"`
}

func newSQSConsumer() *worker.Worker {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	if conf.Debug == "true" {
		appLogger.Level(logging.DebugLevel)
	}
	var sqsClient *sqs.SQS
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		appLogger.Fatalf("Failed to create a new session, %v", err)
	}
	if !zero.IsZeroVal(&conf.SQSEndpoint) {
		sqsClient = sqs.New(sess, &aws.Config{
			Region:   &conf.AWSRegion,
			Endpoint: &conf.SQSEndpoint,
		})
	} else {
		sqsClient = sqs.New(sess, &aws.Config{
			Region: &conf.AWSRegion,
		})
	}
	return &worker.Worker{
		Config: &worker.Config{
			QueueName:          conf.CloudsploitQueueName,
			QueueURL:           conf.CloudsploitQueueURL,
			MaxNumberOfMessage: conf.MaxNumberOfMessage,
			WaitTimeSecond:     conf.WaitTimeSecond,
		},
		Log:       appLogger,
		SqsClient: sqsClient,
	}
}
