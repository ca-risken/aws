package main

import (
	"fmt"
	"net"

	"github.com/CyberAgent/mimosa-aws/proto/activity"
	mimosaxray "github.com/CyberAgent/mimosa-common/pkg/xray"
	"github.com/aws/aws-xray-sdk-go/xray"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type acitivityConfig struct {
	Port    string `default:"9007"`
	EnvName string `default:"default" split_words:"true"`
}

func main() {
	var conf acitivityConfig
	err := envconfig.Process("", &conf)
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
	activityServer := newActivityService()
	activity.RegisterActivityServiceServer(server, activityServer)
	reflection.Register(server)
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
