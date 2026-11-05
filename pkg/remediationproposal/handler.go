package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/ca-risken/common/pkg/logging"
	mimosasqs "github.com/ca-risken/common/pkg/sqs"
	"github.com/ca-risken/core/proto/ai"
	"google.golang.org/grpc"
)

const (
	remediationProposalStatusFailed    = "FAILED"
	remediationProposalStatusSucceeded = "SUCCEEDED"
)

type remediationProposalUpdater interface {
	UpdateRemediationProposalStatus(ctx context.Context, in *ai.UpdateRemediationProposalStatusRequest, opts ...grpc.CallOption) (*ai.UpdateRemediationProposalStatusResponse, error)
}

type SqsHandler struct {
	logger    logging.Logger
	processor Processor
	ai        remediationProposalUpdater
}

type Processor interface {
	Process(ctx context.Context, msg *QueueMessage, requestID string) (*RemediationPlan, error)
}

func NewSqsHandler(l logging.Logger, processor Processor, ai remediationProposalUpdater) *SqsHandler {
	return &SqsHandler{
		logger:    l,
		processor: processor,
		ai:        ai,
	}
}

func (s *SqsHandler) HandleMessage(ctx context.Context, sqsMsg *types.Message) error {
	if s.processor == nil {
		return errors.New("remediation proposal processor is required")
	}

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
	plan, err := s.processor.Process(ctx, msg, requestID)
	if err == nil && (plan == nil || plan.FindingID != msg.FindingID || plan.Plan.Metadata.GeneratedAt <= 0 || plan.Plan.Metadata.Model == "") {
		err = errors.New("invalid generated remediation plan")
	}
	var encoded []byte
	if err == nil {
		encoded, err = json.Marshal(plan.Plan)
	}
	if err != nil {
		if statusErr := s.updateRemediationProposalStatus(ctx, msg, remediationProposalStatusFailed, remediationProposalStatusDetail(err), "", 0); statusErr != nil {
			return fmt.Errorf("failed to update remediation proposal status: process_err=%v: %w", err, statusErr)
		}
		return err
	}
	if err := s.updateRemediationProposalStatus(ctx, msg, remediationProposalStatusSucceeded, "", string(encoded), plan.Plan.Metadata.GeneratedAt); err != nil {
		return err
	}
	s.logger.Infof(ctx, "end remediation proposal, RequestID=%s", requestID)
	return nil
}

func remediationProposalStatusDetail(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "failed to get finding"):
		return "failed to get finding"
	case strings.Contains(message, "failed to assume role"):
		return "failed to assume role"
	case strings.Contains(message, "failed to start AWS MCP proxy"):
		return "failed to start MCP proxy"
	case strings.Contains(message, "unsupported finding provider"):
		return "unsupported finding provider"
	case strings.Contains(message, "invalid finding provider target"):
		return "invalid finding provider target"
	default:
		return "failed to generate remediation proposal"
	}
}

func (s *SqsHandler) updateRemediationProposalStatus(ctx context.Context, msg *QueueMessage, status, statusDetail, plan string, generatedAt int64) error {
	if s.ai == nil {
		return errors.New("remediation proposal AI client is required")
	}
	if _, err := s.ai.UpdateRemediationProposalStatus(ctx, &ai.UpdateRemediationProposalStatusRequest{
		ProjectId:             msg.ProjectID,
		RemediationProposalId: msg.RemediationProposalID,
		Status:                status,
		StatusDetail:          statusDetail,
		RemediationPlan:       plan,
		GeneratedAt:           generatedAt,
	}); err != nil {
		return fmt.Errorf("failed to update remediation proposal status: remediation_proposal_id=%d, status=%s, err=%w", msg.RemediationProposalID, status, err)
	}
	return nil
}
