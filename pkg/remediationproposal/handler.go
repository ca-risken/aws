package remediationproposal

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	coreai "github.com/ca-risken/core/proto/ai"
	"google.golang.org/grpc"
)

const (
	remediationProposalStatusFailed = "FAILED"

	remediationProposalStatusDetailNotImplemented = "remediation proposal generation is not implemented"
)

type remediationProposalUpdater interface {
	UpdateRemediationProposalStatus(ctx context.Context, in *coreai.UpdateRemediationProposalStatusRequest, opts ...grpc.CallOption) (*coreai.UpdateRemediationProposalStatusResponse, error)
}

type SqsHandler struct {
	logger logging.Logger
	ai     remediationProposalUpdater
}

func NewSqsHandler(l logging.Logger, ai remediationProposalUpdater) *SqsHandler {
	return &SqsHandler{logger: l, ai: ai}
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
	if err := s.updateRemediationProposalStatus(ctx, msg, remediationProposalStatusFailed, remediationProposalStatusDetailNotImplemented); err != nil {
		return err
	}
	s.logger.Infof(ctx, "end remediation proposal, RequestID=%s", requestID)
	return nil
}

func (s *SqsHandler) updateRemediationProposalStatus(ctx context.Context, msg *QueueMessage, status, statusDetail string) error {
	if _, err := s.ai.UpdateRemediationProposalStatus(ctx, &coreai.UpdateRemediationProposalStatusRequest{
		ProjectId:             msg.ProjectID,
		RemediationProposalId: msg.RemediationProposalID,
		Status:                status,
		StatusDetail:          statusDetail,
	}); err != nil {
		return fmt.Errorf("failed to update remediation proposal status: remediation_proposal_id=%d, status=%s, err=%w", msg.RemediationProposalID, status, err)
	}
	return nil
}
