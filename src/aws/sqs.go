package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/pkg/message"
	"github.com/kelseyhightower/envconfig"
)

type sqsConfig struct {
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://localhost:9324"`

	GuardDutyQueueURL      string `split_words:"true" required:"true"`
	AccessAnalyzerQueueURL string `split_words:"true" required:"true"`
	AdminCheckerQueueURL   string `split_words:"true" required:"true"`
	CloudsploitQueueURL    string `split_words:"true" required:"true"`
	PortscanQueueURL       string `split_words:"true" required:"true"`
}

type sqsAPI interface {
	send(ctx context.Context, msg *message.AWSQueueMessage) (*sqs.SendMessageOutput, error)
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
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		appLogger.Fatalf("Failed to create a new session, %v", err)
	}
	session := sqs.New(sess, &aws.Config{
		Region:   &conf.AWSRegion,
		Endpoint: &conf.SQSEndpoint,
	})
	xray.AWS(session.Client)
	return &sqsClient{
		svc: session,
		queueURLMap: map[string]string{
			// queueURLMap:
			// key="data_source_label", value="SQS URL",
			message.GuardDutyDataSource:      conf.GuardDutyQueueURL,
			message.AccessAnalyzerDataSource: conf.AccessAnalyzerQueueURL,
			message.AdminCheckerDataSource:   conf.AdminCheckerQueueURL,
			message.CloudsploitDataSource:    conf.CloudsploitQueueURL,
			message.PortscanDataSource:       conf.PortscanQueueURL,
		},
	}
}

func (s *sqsClient) send(ctx context.Context, msg *message.AWSQueueMessage) (*sqs.SendMessageOutput, error) {
	url := s.queueURLMap[msg.DataSource]
	if url == "" {
		return nil, fmt.Errorf("Unknown data_source, value=%s", msg.DataSource)
	}
	buf, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse message, err=%+v", err)
	}
	resp, err := s.svc.SendMessageWithContext(ctx, &sqs.SendMessageInput{
		MessageBody:  aws.String(string(buf)),
		QueueUrl:     &url,
		DelaySeconds: aws.Int64(1),
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
