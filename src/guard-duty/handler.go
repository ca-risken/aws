package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CyberAgent/mimosa-core/proto/finding"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc"
)

type sqsHandler struct {
	guardduty     guardDutyClient
	findingClient finding.FindingServiceClient
}

func newHandler() *sqsHandler {
	h := &sqsHandler{}
	h.guardduty = newGuardDutyClient()
	h.findingClient = newFindingClient()
	return h
}

func (s *sqsHandler) HandleMessage(msg *sqs.Message) error {
	msgBody := aws.StringValue(msg.Body)
	appLogger.Infof("got message: %s", msgBody)
	// Parse message
	message, err := parseMessage(msgBody)
	if err != nil {
		appLogger.Errorf("Invalid message: SQS_msg=%+v, err=%+v", msg, err)
		return err
	}

	// Get guardduty
	findings, err := s.getFindings(message)
	if err != nil {
		appLogger.Errorf("Faild to get findngs to AWS GuardDuty: AccountID=%+v, err=%+v", message.AccountID, err)
		return err
	}

	// Put finding to core
	ctx := context.Background()
	if err := s.putFindings(ctx, findings); err != nil {
		appLogger.Errorf("Faild to put findngs: AccountID=%+v, err=%+v", message.AccountID, err)
		return err
	}
	return nil
}

func parseMessage(msg string) (*guardDutyMessage, error) {
	message := &guardDutyMessage{}
	if err := json.Unmarshal([]byte(msg), message); err != nil {
		return nil, err
	}
	if err := message.validate(); err != nil {
		return nil, err
	}
	return message, nil
}

func (s *sqsHandler) getFindings(message *guardDutyMessage) ([]*finding.FindingForUpsert, error) {
	putData := []*finding.FindingForUpsert{}
	detecterIDs, err := s.guardduty.listDetectors()
	if err != nil {
		appLogger.Errorf("GuardDuty.ListDetectors error: err=%+v", err)
		return nil, err
	}
	for _, id := range *detecterIDs {
		fmt.Printf("detecterId: %s\n", id)
		findingIDs, err := s.guardduty.listFindings(message.AccountID, id)
		if err != nil {
			appLogger.Errorf(
				"GuardDuty.ListDetectors error: detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			return nil, err
		}

		findings, err := s.guardduty.getFindings(id, findingIDs)
		if err != nil {
			appLogger.Errorf(
				"GuardDuty.GetFindings error:detectorID=%s, accountID=%s, err=%+v", id, message.AccountID, err)
			return nil, err
		}
		for _, data := range findings {
			json, err := json.Marshal(data)
			if err != nil {
				appLogger.Errorf("Failed to json encoding error: err=%+v", err)
				return nil, err
			}
			putData = append(putData, &finding.FindingForUpsert{
				Description:      *data.Title,
				DataSource:       message.DataSource,
				DataSourceId:     *data.Id,
				ResourceName:     *data.Arn, // TODO: fix reousrce_name
				ProjectId:        message.ProjectID,
				OriginalScore:    float32(*data.Severity),
				OriginalMaxScore: 10.0,
				Data:             string(json),
			})
		}
	}
	return putData, nil
}

type findingConfig struct {
	FindingSvcAddr string `required:"true" split_words:"true"`
}

func newFindingClient() finding.FindingServiceClient {
	var conf findingConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		appLogger.Fatalf("Faild to load finding config error: err=%+v", err)
	}

	ctx := context.Background()
	conn, err := getGRPCConn(ctx, conf.FindingSvcAddr)
	if err != nil {
		appLogger.Fatalf("Faild to get GRPC connection: err=%+v", err)
	}
	return finding.NewFindingServiceClient(conn)
}

func getGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure(), grpc.WithTimeout(time.Second*3))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *sqsHandler) putFindings(ctx context.Context, findings []*finding.FindingForUpsert) error {
	for _, f := range findings {
		resp, err := s.findingClient.PutFinding(ctx, &finding.PutFindingRequest{Finding: f})
		if err != nil {
			return err
		}
		appLogger.Infof("Success to PutFinding, response=%+v", resp)
	}
	return nil
}
