package main

import (
	"fmt"
	"net"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/proto/activity"
	"github.com/ca-risken/common/pkg/profiler"
	mimosarpc "github.com/ca-risken/common/pkg/rpc"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type AppConfig struct {
	Port            string   `default:"9007"`
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`

	// aws
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"` // Default region

	// grpc
	AWSSvcAddr string `required:"true" split_words:"true" default:"aws.aws.svc.cluster.local:9001"`
}

const (
	nameSpace   = "aws"
	serviceName = "activity"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

func main() {
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	err = mimosaxray.InitXRay(xray.Config{})
	if err != nil {
		appLogger.Fatal(err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(err.Error())
	}
	defer pc.Stop()

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	service := &activityService{}
	service.awsClient = newAWSClient(conf.AWSSvcAddr)
	service.cloudTrailClient = newCloudTrailClient(conf.AWSRegion)
	service.configClient = newConfigServiceClient(conf.AWSRegion)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				mimosarpc.LoggingUnaryServerInterceptor(appLogger),
				xray.UnaryServerInterceptor(),
				mimosaxray.AnnotateEnvTracingUnaryServerInterceptor(conf.EnvName))))
	activity.RegisterActivityServiceServer(server, service)
	reflection.Register(server)
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
