package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/aws/pkg/grpc"
	"github.com/ca-risken/aws/pkg/portscan"
	"github.com/ca-risken/aws/pkg/sqs"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/ca-risken/datasource-api/pkg/message"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "aws"
	serviceName = "portscan"
	settingURL  = "https://docs.security-hub.jp/aws/overview_datasource/"
)

var appLogger = logging.NewLogger()

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

	AWSRegion   string `envconfig:"aws_region"   default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	AWSPortscanQueueName string `split_words:"true" default:"aws-portscan"`
	AWSPortscanQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-portscan"`
	MaxNumberOfMessage   int32  `split_words:"true" default:"5"`
	WaitTimeSecond       int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr          string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.datasource.svc.cluster.local:8081"`

	// portsan
	ScanExcludePortNumber int   `split_words:"true" default:"1000"`
	ScanConcurrency       int64 `split_words:"true" default:"5"`
	RetryMaxAttempts      int   `split_words:"true" default:"10"`
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

	sqsConf := &sqs.SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		QueueName:          conf.AWSPortscanQueueName,
		QueueURL:           conf.AWSPortscanQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer, err := sqs.NewSQSConsumer(ctx, sqsConf, appLogger)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS consumer, err=%+v", err)
	}

	fc, err := grpc.NewFindingClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create finding client, err=%+v", err)
	}
	ac, err := grpc.NewAlertClient(ctx, conf.CoreSvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create alert client, err=%+v", err)
	}
	awsc, err := grpc.NewAWSClient(ctx, conf.DataSourceAPISvcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create aws client, err=%+v", err)
	}
	handler := portscan.NewSqsHandler(fc, ac, awsc, conf.AWSRegion, conf.ScanExcludePortNumber, conf.ScanConcurrency, conf.RetryMaxAttempts, appLogger)
	f, err := mimosasqs.NewFinalizer(message.AWSPortscanDataSource, settingURL, conf.CoreSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Finalizer, err=%+v", err)
	}

	appLogger.Info(ctx, "Start the portscan SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger,
						f.FinalizeHandler(handler))))))
}
