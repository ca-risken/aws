package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/common/pkg/profiler"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "aws"
	serviceName = "cloudsploit"
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

	CloudsploitQueueName string `split_words:"true" default:"aws-cloudsploit"`
	CloudsploitQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-cloudsploit"`
	MaxNumberOfMessage   int32  `split_words:"true" default:"5"`
	WaitTimeSecond       int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	AWSSvcAddr  string `required:"true" split_words:"true" default:"aws.aws.svc.cluster.local:9001"`

	// cloudsploit
	ResultDir      string `required:"true" split_words:"true" default:"/tmp"`
	ConfigDir      string `required:"true" split_words:"true" default:"/tmp"`
	CloudsploitDir string `required:"true" split_words:"true" default:"/opt/cloudsploit"`
	MaxMemSizeMB   int    `split_words:"true" default:"0"`
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

	handler := &sqsHandler{
		resultDir:      conf.ResultDir,
		configDir:      conf.ConfigDir,
		cloudsploitDir: conf.CloudsploitDir,
		awsRegion:      conf.AWSRegion,
		maxMemSizeMB:   conf.MaxMemSizeMB,
	}
	handler.findingClient = newFindingClient(conf.CoreSvcAddr)
	handler.alertClient = newAlertClient(conf.CoreSvcAddr)
	handler.awsClient = newAWSClient(conf.AWSSvcAddr)
	f, err := mimosasqs.NewFinalizer(message.CloudsploitDataSource, settingURL, conf.CoreSvcAddr, nil)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create Finalizer, err=%+v", err)
	}

	sqsConf := &SQSConfig{
		Debug:                conf.Debug,
		AWSRegion:            conf.AWSRegion,
		SQSEndpoint:          conf.SQSEndpoint,
		CloudsploitQueueName: conf.CloudsploitQueueName,
		CloudsploitQueueURL:  conf.CloudsploitQueueURL,
		MaxNumberOfMessage:   conf.MaxNumberOfMessage,
		WaitTimeSecond:       conf.WaitTimeSecond,
	}
	consumer := newSQSConsumer(ctx, sqsConf)

	appLogger.Info(ctx, "Start the cloudsploit SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger,
						f.FinalizeHandler(handler))))))
}
