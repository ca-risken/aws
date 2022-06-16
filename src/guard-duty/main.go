package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "aws"
	serviceName = "guardduty"
	settingURL  = "https://docs.security-hub.jp/aws/overview_datasource/"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

type AppConfig struct {
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

	// sqs
	Debug string `default:"false"`

	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	AWSGuardDutyQueueName string `split_words:"true" default:"aws-guardduty"`
	AWSGuardDutyQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-guardduty"`
	MaxNumberOfMessage    int32  `split_words:"true" default:"10"`
	WaitTimeSecond        int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr          string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.core.svc.cluster.local:8081"`
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	defer pc.Stop()

	tc := &tracer.Config{
		ServiceName: getFullServiceName(),
		Environment: conf.EnvName,
		Debug:       conf.TraceDebug,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	sqsConf := &sqsConfig{
		Debug:                 conf.Debug,
		AWSRegion:             conf.AWSRegion,
		SQSEndpoint:           conf.SQSEndpoint,
		AWSGuardDutyQueueName: conf.AWSGuardDutyQueueName,
		AWSGuardDutyQueueURL:  conf.AWSGuardDutyQueueURL,
		MaxNumberOfMessage:    conf.MaxNumberOfMessage,
		WaitTimeSecond:        conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(ctx, sqsConf)

	handler := &sqsHandler{
		awsRegion: conf.AWSRegion,
	}
	handler.findingClient = newFindingClient(conf.CoreSvcAddr)
	handler.alertClient = newAlertClient(conf.CoreSvcAddr)
	handler.awsClient = newAWSClient(conf.DataSourceAPISvcAddr)
	f, err := mimosasqs.NewFinalizer(message.AWSGuardDutyDataSource, settingURL, conf.CoreSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create finalizer, err=%+v", err)
	}

	appLogger.Info(ctx, "Start the guard-duty SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger,
						f.FinalizeHandler(handler))))))
}
