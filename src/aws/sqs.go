package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/ca-risken/aws/pkg/message"
)

type SQSConfig struct {
	AWSRegion   string
	SQSEndpoint string

	GuardDutyQueueURL      string
	AccessAnalyzerQueueURL string
	AdminCheckerQueueURL   string
	CloudsploitQueueURL    string
	PortscanQueueURL       string
}

type sqsAPI interface {
	send(ctx context.Context, msg *message.AWSQueueMessage) (*sqs.SendMessageOutput, error)
}

type sqsClient struct {
	svc         *sqs.SQS
	queueURLMap map[string]string
}

func newSQSClient(ctx context.Context, conf *SQSConfig) *sqsClient {
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create a new session, %v", err)
	}
	session := sqs.New(sess, &aws.Config{
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
