package remediationproposal

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/aws/pkg/common"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
)

type SqsHandler struct {
	logger logging.Logger
}

func NewSqsHandler(l logging.Logger) *SqsHandler {
	return &SqsHandler{logger: l}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Info(ctx, "got remediation proposal message")
	s.logger.Debugf(ctx, "remediation proposal message body: %s", msgBody)

	msg, err := ParseQueueMessage(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid remediation proposal message: SQS_msg=%+v, err=%+v", sqsMsg, err)
		return mimosasqs.WrapNonRetryable(err)
	}
	if !common.IsMatchAccountIDArn(msg.AccountID, msg.AssumeRoleArn) {
		err := fmt.Errorf("assume_role_arn must be in AWS account_id: %s", msg.AccountID)
		s.logger.Warnf(ctx, "AccountID doesn't match AssumeRoleArn, accountID=%s, ARN=%s", msg.AccountID, msg.AssumeRoleArn)
		return mimosasqs.WrapNonRetryable(err)
	}

	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start remediation proposal, RequestID=%s", requestID)
	s.logger.Infof(ctx, "end remediation proposal, RequestID=%s", requestID)
	return nil
}
