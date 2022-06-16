package main

import (
	"context"
	"fmt"
	"net"

	"github.com/ca-risken/aws/proto/activity"
	"github.com/ca-risken/common/pkg/profiler"
	mimosarpc "github.com/ca-risken/common/pkg/rpc"
	"github.com/ca-risken/common/pkg/tracer"
	"github.com/gassara-kys/envconfig"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	grpctrace "gopkg.in/DataDog/dd-trace-go.v1/contrib/google.golang.org/grpc"
)

type AppConfig struct {
	Port            string   `default:"9007"`
	EnvName         string   `default:"local" split_words:"true"`
	ProfileExporter string   `split_words:"true" default:"nop"`
	ProfileTypes    []string `split_words:"true"`
	TraceDebug      bool     `split_words:"true" default:"false"`

	// aws
	AWSRegion string `envconfig:"aws_region" default:"ap-northeast-1"` // Default region

	// grpc
	DataSourceAPISvcAddr string `required:"true" split_words:"true" default:"datasource-api.core.svc.cluster.local:8081"`
}

const (
	nameSpace   = "aws"
	serviceName = "activity"
)

func getFullServiceName() string {
	return fmt.Sprintf("%s.%s", nameSpace, serviceName)
}

func main() {
	ctx := context.Background()
	var conf AppConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}

	pTypes, err := profiler.ConvertProfileTypeFrom(conf.ProfileTypes)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pExporter, err := profiler.ConvertExporterTypeFrom(conf.ProfileExporter)
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	pc := profiler.Config{
		ServiceName:  getFullServiceName(),
		EnvName:      conf.EnvName,
		ProfileTypes: pTypes,
		ExporterType: pExporter,
	}
	err = pc.Start()
	if err != nil {
		appLogger.Fatal(ctx, err.Error())
	}
	defer pc.Stop()

	tc := &tracer.Config{
		ServiceName: getFullServiceName(),
		Environment: conf.EnvName,
		Debug:       conf.TraceDebug,
	}
	tracer.Start(tc)
	defer tracer.Stop()

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(ctx, err)
	}

	service := &activityService{}
	service.awsClient = newAWSClient(conf.DataSourceAPISvcAddr)
	service.cloudTrailClient = newCloudTrailClient(conf.AWSRegion)
	service.configClient = newConfigServiceClient(conf.AWSRegion)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				mimosarpc.LoggingUnaryServerInterceptor(appLogger),
				grpctrace.UnaryServerInterceptor())))
	activity.RegisterActivityServiceServer(server, service)
	reflection.Register(server)
	appLogger.Infof(ctx, "Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf(ctx, "Failed to gRPC serve: %v", err)
	}
}
