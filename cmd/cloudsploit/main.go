package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/aws/pkg/cloudsploit"
	"github.com/ca-risken/aws/pkg/grpc"
	"github.com/ca-risken/aws/pkg/sqs"
	"github.com/ca-risken/common/pkg/logging"
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

var (
	appLogger            = logging.NewLogger()
	samplingRate float64 = 0.3000
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

	AWSCloudSploitQueueName string `split_words:"true" default:"aws-cloudsploit"`
	AWSCloudSploitQueueURL  string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-cloudsploit"`
	MaxNumberOfMessage      int32  `split_words:"true" default:"5"`
	WaitTimeSecond          int32  `split_words:"true" default:"20"`

	// grpc
	CoreSvcAddr          string `required:"true" split_words:"true" default:"core.core.svc.cluster.local:8080"`
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.datasource.svc.cluster.local:8081"`

	// cloudsploit
	ResultDir              string `required:"true" split_words:"true" default:"/tmp"`
	ConfigDir              string `required:"true" split_words:"true" default:"/tmp"`
	CloudsploitDir         string `required:"true" split_words:"true" default:"/opt/cloudsploit"`
	MaxMemSizeMB           int    `split_words:"true" default:"0"`
	CloudSploitSettingPath string `envconfig:"CLOUDSPLOIT_SETTING_PATH" default:""`
	ParallelScanNum        int    `envconfig:"PARALLEL_SCAN_NUM" default:"30"`
	ScanTimeoutMinutes     int    `envconfig:"SCAN_TIMEOUT_MINUTES" default:"20"`
	ScanTimeoutAllMinutes  int    `envconfig:"SCAN_TIMEOUT_ALL_PLUGINS_MINUTES" default:"90"`
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	if conf.Debug == "true" {
		appLogger.Level(logging.DebugLevel)
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
		ServiceName:  getFullServiceName(),
		Environment:  conf.EnvName,
		Debug:        conf.TraceDebug,
		SamplingRate: &samplingRate,
	}
	tracer.Start(tc)
	defer tracer.Stop()

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
	cloudsploitConf := cloudsploit.NewCloudsploitConfig(
		conf.ResultDir,
		conf.ConfigDir,
		conf.CloudsploitDir,
		conf.AWSRegion,
		conf.MaxMemSizeMB,
		conf.ParallelScanNum,
		conf.ScanTimeoutMinutes,
		conf.ScanTimeoutAllMinutes,
		appLogger,
	)
	handler, err := cloudsploit.NewSqsHandler(fc, ac, awsc, cloudsploitConf, conf.CloudSploitSettingPath, appLogger)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create handler, err=%+v", err)
	}
	sqsConf := &sqs.SQSConfig{
		Debug:              conf.Debug,
		AWSRegion:          conf.AWSRegion,
		SQSEndpoint:        conf.SQSEndpoint,
		QueueName:          conf.AWSCloudSploitQueueName,
		QueueURL:           conf.AWSCloudSploitQueueURL,
		MaxNumberOfMessage: conf.MaxNumberOfMessage,
		WaitTimeSecond:     conf.WaitTimeSecond,
	}
	consumer, err := sqs.NewSQSConsumer(ctx, sqsConf, appLogger)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create sqs consumer, err=%+v", err)
	}

	appLogger.Info(ctx, "Start the cloudsploit SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.TracingHandler(getFullServiceName(),
					mimosasqs.StatusLoggingHandler(appLogger, handler)))))
}
