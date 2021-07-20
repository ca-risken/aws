package main

import (
	"context"

	mimosaxray "github.com/CyberAgent/mimosa-common/pkg/xray"
	"github.com/aws/aws-xray-sdk-go/xray"
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
		mimosaxray.MessageTracingHandler(conf.EnvName, "aws.cloudsploit", newHandler()))
}
