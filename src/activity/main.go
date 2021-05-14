package main

import (
	"fmt"
	"net"

	"github.com/CyberAgent/mimosa-aws/proto/activity"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type acitivityConfig struct {
	Port string `default:"9007"`
}

func main() {
	var conf acitivityConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer()
	activityServer := newActivityService()
	activity.RegisterActivityServiceServer(server, activityServer)
	reflection.Register(server)
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
