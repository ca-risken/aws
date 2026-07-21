package remediationproposal

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
)

type SqsHandler struct {
	logger    logging.Logger
	processor Processor
}

type Processor interface {
	Process(ctx context.Context, msg *QueueMessage, requestID string) error
}

func NewSqsHandler(l logging.Logger, processor Processor) *SqsHandler {
	return &SqsHandler{
		logger:    l,
		processor: processor,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	msgBody := aws.ToString(sqsMsg.Body)
	s.logger.Info(ctx, "got remediation proposal message")

	msg, err := ParseQueueMessage(msgBody)
	if err != nil {
		s.logger.Errorf(ctx, "Invalid remediation proposal message: message_id=%s, err=%+v", aws.ToString(sqsMsg.MessageId), err)
		return mimosasqs.WrapNonRetryable(err)
	}
	s.logger.Debugf(ctx,
		"remediation proposal message: remediation_proposal_id=%d, finding_id=%d, project_id=%d",
		msg.RemediationProposalID,
		msg.FindingID,
		msg.ProjectID,
	)

	requestID, err := s.logger.GenerateRequestID(fmt.Sprint(msg.ProjectID))
	if err != nil {
		s.logger.Warnf(ctx, "Failed to generate requestID: err=%+v", err)
		requestID = fmt.Sprint(msg.ProjectID)
	}

	s.logger.Infof(ctx, "start remediation proposal, RequestID=%s", requestID)
	if s.processor != nil {
		if err := s.processor.Process(ctx, msg, requestID); err != nil {
			return err
		}
	}
	s.logger.Infof(ctx, "end remediation proposal, RequestID=%s", requestID)
	return nil
}
