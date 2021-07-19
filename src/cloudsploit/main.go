package main

import (
	"context"

	mimosaxray "github.com/CyberAgent/mimosa-common/pkg/xray"
	"github.com/aws/aws-xray-sdk-go/xray"
)

func main() {
	ctx := context.Background()
	mimosaxray.InitXRay(xray.Config{})
	consumer := newSQSConsumer()
	appLogger.Info("Start the cloudsploit SQS consumer server...")
	consumer.Start(ctx, XRayTracingHandler(newHandler()))
}
