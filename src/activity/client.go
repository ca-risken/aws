package main

import (
	"context"
	"time"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/proto/aws"
	"github.com/gassara-kys/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type awsConfig struct {
	AWSSvcAddr string `required:"true" split_words:"true" default:"aws.aws.svc.cluster.local:9001"`
}

func newAWSClient() aws.AWSServiceClient {
	var conf awsConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Faild to load aws config error: err=%+v", err)
	}

	ctx := context.Background()
	conn, err := getGRPCConn(ctx, conf.AWSSvcAddr)
	if err != nil {
		appLogger.Fatalf("Faild to get GRPC connection: err=%+v", err)
	}
	return aws.NewAWSServiceClient(conn)
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithUnaryInterceptor(xray.UnaryClientInterceptor()), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		appLogger.Fatalf("Failed to connect backend gRPC server, addr=%s, err=%+v", addr, err)
		return nil, err
	}
	return conn, nil
}
