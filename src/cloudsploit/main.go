package main

import (
	"context"

	"github.com/aws/aws-xray-sdk-go/xray"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
)

type AppConfig struct {
	EnvName string `default:"local" split_words:"true"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	CloudsploitQueueName string `split_words:"true" default:"aws-cloudsploit"`
	CloudsploitQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-cloudsploit"`
	MaxNumberOfMessage   int64  `split_words:"true" default:"5"`
	WaitTimeSecond       int64  `split_words:"true" default:"20"`

	// grpc
	FindingSvcAddr string `required:"true" split_words:"true" default:"finding.core.svc.cluster.local:8001"`
	AlertSvcAddr   string `required:"true" split_words:"true" default:"alert.core.svc.cluster.local:8004"`
	AWSSvcAddr     string `required:"true" split_words:"true" default:"aws.aws.svc.cluster.local:9001"`

	// cloudsploit
	ResultDir      string `required:"true" split_words:"true" default:"/tmp"`
	ConfigDir      string `required:"true" split_words:"true" default:"/tmp"`
	CloudsploitDir string `required:"true" split_words:"true" default:"/opt/cloudsploit"`
}

func main() {
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	err = mimosaxray.InitXRay(xray.Config{})
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	handler := &sqsHandler{
		resultDir:      conf.ResultDir,
		configDir:      conf.ConfigDir,
		cloudsploitDir: conf.CloudsploitDir,
		awsRegion:      conf.AWSRegion,
	}
	handler.findingClient = newFindingClient(conf.FindingSvcAddr)
	handler.alertClient = newAlertClient(conf.AlertSvcAddr)
	handler.awsClient = newAWSClient(conf.AWSSvcAddr)

	sqsConf := &SQSConfig{
		Debug:                conf.Debug,
		AWSRegion:            conf.AWSRegion,
		SQSEndpoint:          conf.SQSEndpoint,
		CloudsploitQueueName: conf.CloudsploitQueueName,
		CloudsploitQueueURL:  conf.CloudsploitQueueURL,
		MaxNumberOfMessage:   conf.MaxNumberOfMessage,
		WaitTimeSecond:       conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(sqsConf)

	appLogger.Info("Start the cloudsploit SQS consumer server...")
	ctx := context.Background()
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosaxray.MessageTracingHandler(conf.EnvName, "aws.cloudsploit", handler)))))
}
