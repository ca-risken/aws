package main

import (
	"context"

	"github.com/aws/aws-xray-sdk-go/xray"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/kelseyhightower/envconfig"
)

type cloudSploitConfig struct {
	EnvName string `default:"default" split_words:"true"`
}

func main() {
	var conf cloudSploitConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	ctx := context.Background()
	mimosaxray.InitXRay(xray.Config{})
	consumer := newSQSConsumer()
	appLogger.Info("Start the cloudsploit SQS consumer server...")
	consumer.Start(ctx,
		mimosasqs.InitializeHandler(
			mimosasqs.RetryableErrorHandler(
				mimosasqs.StatusLoggingHandler(appLogger,
					mimosaxray.MessageTracingHandler(conf.EnvName, "aws.cloudsploit", newHandler())))))

}
