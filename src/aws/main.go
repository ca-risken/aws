package main

import (
	"fmt"
	"net"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/proto/aws"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type awsConfig struct {
	Port    string `default:"9001"`
	EnvName string `default:"local" split_words:"true"`
}

func main() {
	var conf awsConfig
	err := envconfig.Process("AWS", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	mimosaxray.InitXRay(xray.Config{})

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				xray.UnaryServerInterceptor(),
				mimosaxray.AnnotateEnvTracingUnaryServerInterceptor(conf.EnvName))))
	awsServer := newAWSService()
	aws.RegisterAWSServiceServer(server, awsServer)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
