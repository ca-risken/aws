package main

import (
	"context"
	"time"

	"github.com/ca-risken/core/proto/project"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func newProjectClient(svcAddr string) project.ProjectServiceClient {
	ctx := context.Background()
	conn, err := getGRPCConn(ctx, svcAddr)
	if err != nil {
		appLogger.Fatalf(ctx, "Faild to get GRPC connection: err=%+v", err)
	}
	return project.NewProjectServiceClient(conn)
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
