package main

import (
	"context"
	"time"

	"github.com/ca-risken/core/proto/project"
	"github.com/gassara-kys/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type projectConfig struct {
	ProjectSvcAddr string `required:"true" split_words:"true" default:"project.core.svc.cluster.local:8003"`
}

func newProjectClient() project.ProjectServiceClient {
	var conf projectConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Faild to load project config error: err=%+v", err)
	}

	ctx := context.Background()
	conn, err := getGRPCConn(ctx, conf.ProjectSvcAddr)
	if err != nil {
		appLogger.Fatalf("Faild to get GRPC connection: err=%+v", err)
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
