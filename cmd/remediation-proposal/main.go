package main

import (
	"context"
	"fmt"

	"github.com/ca-risken/aws/pkg/remediationproposal"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/common/pkg/profiler"
	commonsqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
)

const (
	nameSpace   = "aws"
	serviceName = "remediation-proposal"
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

	Debug       string `default:"false"`
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`
	MCPRegion   string `split_words:"true" default:"us-east-1"`

	RemediationProposalQueueURL string `split_words:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-remediation-proposal"`
	WaitTimeSecond              int32  `split_words:"true" default:"20"`
	MCPProxyCommand             string `split_words:"true" default:"uvx"`
	MCPProxyPackage             string `split_words:"true" default:"mcp-proxy-for-aws@latest"`
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	if err := envconfig.Process("", &conf); err != nil {
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
	if err := pc.Start(); err != nil {
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

	queueClient, err := remediationproposal.NewSQSClient(ctx, conf.AWSRegion, conf.SQSEndpoint)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to create SQS client, err=%+v", err)
	}

	processor := remediationproposal.NewRemediationProcessor(
		conf.AWSRegion,
		conf.MCPRegion,
		remediationproposal.NewSTSCredentialProvider(),
		remediationproposal.NewExecMCPProxyRunner(conf.MCPProxyCommand, conf.MCPProxyPackage),
		appLogger,
	)
	handler := remediationproposal.NewSqsHandler(appLogger, remediationproposal.WithProcessor(processor))
	appLogger.Info(ctx, "Start the AWS remediation proposal job...")
	runner := remediationproposal.NewRunner(queueClient, conf.RemediationProposalQueueURL, conf.WaitTimeSecond,
		commonsqs.RetryableErrorHandler(
			commonsqs.TracingHandler(getFullServiceName(),
				commonsqs.StatusLoggingHandler(appLogger, handler))), appLogger)
	processed, err := runner.RunOnce(ctx)
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to handle remediation proposal message, err=%+v", err)
	}
	if !processed {
		appLogger.Info(ctx, "No remediation proposal message to process")
	}
}
