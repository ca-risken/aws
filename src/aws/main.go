package main

import (
	"fmt"
	"net"

	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/ca-risken/aws/proto/aws"
	mimosarpc "github.com/ca-risken/common/pkg/rpc"
	mimosaxray "github.com/ca-risken/common/pkg/xray"
	"github.com/gassara-kys/envconfig"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type AppConfig struct {
	Port    string `default:"9001"`
	EnvName string `default:"local" split_words:"true"`

	// grpc
	ProjectSvcAddr string `required:"true" split_words:"true" default:"project.core.svc.cluster.local:8003"`

	// sqs
	AWSRegion   string `envconfig:"aws_region" default:"ap-northeast-1"`
	SQSEndpoint string `envconfig:"sqs_endpoint" default:"http://queue.middleware.svc.cluster.local:9324"`

	GuardDutyQueueURL      string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-guardduty"`
	AccessAnalyzerQueueURL string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-accessanalyzer"`
	AdminCheckerQueueURL   string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-adminchecker"`
	CloudsploitQueueURL    string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-cloudsploit"`
	PortscanQueueURL       string `split_words:"true" required:"true" default:"http://queue.middleware.svc.cluster.local:9324/queue/aws-portscan"`

	// DB
	DBMasterHost     string `split_words:"true" default:"db.middleware.svc.cluster.local"`
	DBMasterUser     string `split_words:"true" default:"hoge"`
	DBMasterPassword string `split_words:"true" default:"moge"`
	DBSlaveHost      string `split_words:"true" default:"db.middleware.svc.cluster.local"`
	DBSlaveUser      string `split_words:"true" default:"hoge"`
	DBSlavePassword  string `split_words:"true" default:"moge"`

	DBSchema        string `required:"true"    default:"mimosa"`
	DBPort          int    `required:"true"    default:"3306"`
	DBLogMode       bool   `split_words:"true" default:"false"`
	DBMaxConnection int    `split_words:"true" default:"10"`
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

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", conf.Port))
	if err != nil {
		appLogger.Fatal(err)
	}

	service := &awsService{}
	dbConf := &DBConfig{
		MasterHost:     conf.DBMasterHost,
		MasterUser:     conf.DBMasterUser,
		MasterPassword: conf.DBMasterPassword,
		SlaveHost:      conf.DBSlaveHost,
		SlaveUser:      conf.DBSlaveUser,
		SlavePassword:  conf.DBSlavePassword,
		Schema:         conf.DBSchema,
		Port:           conf.DBPort,
		LogMode:        conf.DBLogMode,
		MaxConnection:  conf.DBMaxConnection,
	}
	service.repository = newAWSRepository(dbConf)
	sqsConf := &SQSConfig{
		AWSRegion:              conf.AWSRegion,
		SQSEndpoint:            conf.SQSEndpoint,
		GuardDutyQueueURL:      conf.GuardDutyQueueURL,
		AccessAnalyzerQueueURL: conf.AccessAnalyzerQueueURL,
		AdminCheckerQueueURL:   conf.AdminCheckerQueueURL,
		CloudsploitQueueURL:    conf.CloudsploitQueueURL,
		PortscanQueueURL:       conf.PortscanQueueURL,
	}
	service.sqs = newSQSClient(sqsConf)
	service.projectClient = newProjectClient(conf.ProjectSvcAddr)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(
			grpcmiddleware.ChainUnaryServer(
				mimosarpc.LoggingUnaryServerInterceptor(appLogger),
				xray.UnaryServerInterceptor(),
				mimosaxray.AnnotateEnvTracingUnaryServerInterceptor(conf.EnvName))))
	aws.RegisterAWSServiceServer(server, service)

	reflection.Register(server) // enable reflection API
	appLogger.Infof("Starting gRPC server at :%s", conf.Port)
	if err := server.Serve(l); err != nil {
		appLogger.Fatalf("Failed to gRPC serve: %v", err)
	}
}
