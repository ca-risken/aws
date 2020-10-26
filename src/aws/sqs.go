package main

import (
	"encoding/json"
	"fmt"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://localhost:9324"`

	GuardDutyQueueURL      string `split_words:"true" required:"true"`
	AccessAnalyzerQueueURL string `split_words:"true" required:"true"`
	AdminCheckerQueueURL   string `split_words:"true" required:"true"`
}

type sqsAPI interface {
	send(msg *message.AWSQueueMessage) (*sqs.SendMessageOutput, error)
}

type sqsClient struct {
	svc         *sqs.SQS
	queueURLMap map[string]string
}

func newSQSClient() *sqsClient {
	var conf sqsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	session := sqs.New(session.New(), &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})

	return &sqsClient{
		svc: session,
		queueURLMap: map[string]string{
			// queueURLMap:
			// key="data_source_label", value="SQS URL",
			message.GuardDutyDataSource:      conf.GuardDutyQueueURL,
			message.AccessAnalyzerDataSource: conf.AccessAnalyzerQueueURL,
			message.AdminCheckerDataSource:   conf.AdminCheckerQueueURL,
		},
	}
}

func (s *sqsClient) send(msg *message.AWSQueueMessage) (*sqs.SendMessageOutput, error) {
	url := s.queueURLMap[msg.DataSource]
	if url == "" {
		return nil, fmt.Errorf("Unknown data_source, value=%s", msg.DataSource)
	}
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse message, err=%+v", err)
	}
	resp, err := s.svc.SendMessage(&sqs.SendMessageInput{
		MessageBody:  aws.String(string(buf)),
		QueueUrl:     &url,
		DelaySeconds: aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
