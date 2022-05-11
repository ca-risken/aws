package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "aws"
	serviceName = "accessanalyzer"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

	// grpc
	CoreSvcAddr string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`

	// aws
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"` // Default region

	// accessAnalyzer
	AlertSvcAddr string `required:"true" split_words:"true" default:"alert.core.svc.cluster.local:8004"`
	AWSSvcAddr   string `required:"true" split_words:"true" default:"aws.aws.svc.cluster.local:9001"`

	// sqs
	Debug string `default:"false"`

	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	AccessAnalyzerQueueName string `split_words:"true" default:"aws-accessanalyzer"`
	AccessAnalyzerQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-accessanalyzer"`
	MaxNumberOfMessage      int64  `split_words:"true" default:"10"`
	WaitTimeSecond          int64  `split_words:"true" default:"20"`
}

func main() {
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer pc.Stop()

	tc := &tracer.Config{
		ServiceName: getFullServiceName(),
		Environment: conf.EnvName,
		Debug:       conf.TraceDebug,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	handler := &sqsHandler{
		awsRegion: conf.AWSRegion,
	}
	handler.findingClient = newFindingClient(conf.CoreSvcAddr)
	handler.alertClient = newAlertClient(conf.AlertSvcAddr)
	handler.awsClient = newAWSClient(conf.AWSSvcAddr)

	sqsConf := &SQSConfig{
		Debug:                   conf.Debug,
		AWSRegion:               conf.AWSRegion,
		SQSEndpoint:             conf.SQSEndpoint,
		AccessAnalyzerQueueName: conf.AccessAnalyzerQueueName,
		AccessAnalyzerQueueURL:  conf.AccessAnalyzerQueueURL,
		MaxNumberOfMessage:      conf.MaxNumberOfMessage,
		WaitTimeSecond:          conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(sqsConf)

	appLogger.Info("Start the AWS AccessAnalyzer SQS consumer server...")
	ctx := context.Background()
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosasqs.TracingHandler(getFullServiceName(), handler)))))
}
