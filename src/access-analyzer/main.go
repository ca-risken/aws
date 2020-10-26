package main

import (
	"context"
)

func main() {
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the AWS AccessAnalyzer SQS consumer server...")
	consumer.Start(ctx, newHandler())
}
