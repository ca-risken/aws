package main

import (
	"context"
)

func main() {
	ctx := context.Background()
	consumer := newSQSConsumer()
	appLogger.Info("Start the guard-duty SQS consumer server...")
	consumer.Start(ctx, newHandler())
}
