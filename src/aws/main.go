package main

import (
	"fmt"
	"net"

	"github.com/CyberAgent/mimosa-aws/proto/aws"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type awsConfig struct {
	Port string `default:"9001"`
}

func main() {
	var conf awsConfig
	err := envconfig.Process("AWS", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer()
	awsServer := newAWSService(newAWSRepository()) // DI service & repository
	aws.RegisterAWSServiceServer(server, awsServer)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
