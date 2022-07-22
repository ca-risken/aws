package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ca-risken/datasource-api/proto/aws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpctrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/google.golang.org/grpc"
)

func newAWSClient(svcAddr string) (aws.AWSServiceClient, error) {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get GRPC connection: err=%w", err)
	}
	return aws.NewAWSServiceClient(conn), nil
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithUnaryInterceptor(grpctrace.UnaryClientInterceptor()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		appLogger.Fatalf(ctx, "Failed to connect backend gRPC server, addr=%s, err=%+v", addr, err)
		return nil, err
	}
	return conn, nil
}
