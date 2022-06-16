package main

import (
	"context"
	"time"

	"github.com/ca-risken/core/proto/alert"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/proto/aws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func newFindingClient(svcAddr string) finding.FindingServiceClient {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Faild to get GRPC connection: err=%+v", err)
	}
	return finding.NewFindingServiceClient(conn)
}

func newAlertClient(svcAddr string) alert.AlertServiceClient {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Faild to get GRPC connection: err=%+v", err)
	}
	return alert.NewAlertServiceClient(conn)
}

func newAWSClient(svcAddr string) aws.AWSServiceClient {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Faild to get GRPC connection: err=%+v", err)
	}
	return aws.NewAWSServiceClient(conn)
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	// gRPCクライアントの呼び出し回数が非常に多くトレーシング情報の送信がエラーになるため、トレースは無効にしておく
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
