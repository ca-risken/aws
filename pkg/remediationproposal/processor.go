package remediationproposal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/common/pkg/logging"
	corefinding "github.com/ca-risken/core/proto/finding"
	"google.golang.org/grpc"
)

const roleSessionNamePrefix = "RISKEN-AI"

const awsRegionMetadataKey = "AWS_REGION"

type CredentialProvider interface {
	AssumeRole(ctx context.Context, region, roleARN, externalID, sessionName string) (aws.Credentials, error)
}

type MCPProxyRunner interface {
	StartProxy(ctx context.Context, creds aws.Credentials, region string) (MCPProxyProcess, error)
}

type MCPProxyProcess interface {
	Stop() error
}

type FindingClient interface {
	GetFinding(ctx context.Context, in *corefinding.GetFindingRequest, opts ...grpc.CallOption) (*corefinding.GetFindingResponse, error)
}

type RemediationProcessor struct {
	awsRegion          string
	mcpRegion          string
	findingClient      FindingClient
	credentialProvider CredentialProvider
	mcpProxyRunner     MCPProxyRunner
	logger             logging.Logger
}

func NewRemediationProcessor(awsRegion, mcpRegion string, findingClient FindingClient, credentialProvider CredentialProvider, mcpProxyRunner MCPProxyRunner, logger logging.Logger) *RemediationProcessor {
	return &RemediationProcessor{
		awsRegion:          awsRegion,
		mcpRegion:          mcpRegion,
		findingClient:      findingClient,
		credentialProvider: credentialProvider,
		mcpProxyRunner:     mcpProxyRunner,
		logger:             logger,
	}
}

func (p *RemediationProcessor) Process(ctx context.Context, msg *QueueMessage, requestID string) error {
	finding, err := p.getFinding(ctx, msg)
	if err != nil {
		return err
	}
	if finding.Provider != "aws" {
		return fmt.Errorf("unsupported finding provider: finding_id=%d, provider=%s", msg.FindingID, finding.Provider)
	}
	if err := validateProviderTarget(finding.ProviderTarget, msg.AssumeRoleArn); err != nil {
		return fmt.Errorf("invalid finding provider target: finding_id=%d, err=%w", msg.FindingID, err)
	}

	sessionName := buildRoleSessionName(requestID)
	creds, err := p.credentialProvider.AssumeRole(ctx, p.awsRegion, msg.AssumeRoleArn, msg.ExternalID, sessionName)
	if err != nil {
		return fmt.Errorf("failed to assume role for remediation proposal: remediation_proposal_id=%d, err=%w", msg.RemediationProposalID, err)
	}
	proxy, err := p.mcpProxyRunner.StartProxy(ctx, creds, p.mcpRegion)
	if err != nil {
		return fmt.Errorf("failed to start AWS MCP proxy: remediation_proposal_id=%d, err=%w", msg.RemediationProposalID, err)
	}
	defer func() {
		if err := proxy.Stop(); err != nil {
			p.logger.Warnf(ctx, "Failed to stop AWS MCP proxy: remediation_proposal_id=%d, err=%+v", msg.RemediationProposalID, err)
		}
	}()
	p.logger.Infof(ctx, "started AWS MCP proxy, remediation_proposal_id=%d", msg.RemediationProposalID)
	return nil
}

func (p *RemediationProcessor) getFinding(ctx context.Context, msg *QueueMessage) (*corefinding.Finding, error) {
	if p.findingClient == nil {
		return nil, errors.New("finding client is required")
	}
	resp, err := p.findingClient.GetFinding(ctx, &corefinding.GetFindingRequest{
		ProjectId: msg.ProjectID,
		FindingId: msg.FindingID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get finding: finding_id=%d, err=%w", msg.FindingID, err)
	}
	if resp == nil || resp.Finding == nil {
		return nil, fmt.Errorf("finding not found: finding_id=%d", msg.FindingID)
	}
	return resp.Finding, nil
}

func validateProviderTarget(providerTarget, roleARN string) error {
	if !isAWSAccountID(providerTarget) {
		return errors.New("provider_target must be an AWS account ID")
	}
	parsedARN, err := arn.Parse(roleARN)
	if err != nil {
		return fmt.Errorf("invalid assume_role_arn: %w", err)
	}
	if parsedARN.AccountID != providerTarget {
		return fmt.Errorf("provider_target does not match assume_role_arn account")
	}
	return nil
}

func buildRoleSessionName(requestID string) string {
	return fmt.Sprintf("%s-%s", roleSessionNamePrefix, requestID)
}

type STSCredentialProvider struct{}

func NewSTSCredentialProvider() *STSCredentialProvider {
	return &STSCredentialProvider{}
}

func (p *STSCredentialProvider) AssumeRole(ctx context.Context, region, roleARN, externalID, sessionName string) (aws.Credentials, error) {
	if externalID == "" {
		return aws.Credentials{}, errors.New("external_id is required")
	}
	if sessionName == "" {
		return aws.Credentials{}, errors.New("role session name is required")
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return aws.Credentials{}, err
	}
	stsClient := sts.NewFromConfig(cfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(options *stscreds.AssumeRoleOptions) {
		options.RoleSessionName = sessionName
		options.ExternalID = &externalID
	})
	return aws.NewCredentialsCache(provider).Retrieve(ctx)
}

func validateRoleARN(roleARN string) error {
	parsedARN, err := arn.Parse(roleARN)
	if err != nil {
		return fmt.Errorf("invalid assume_role_arn: %w", err)
	}
	if parsedARN.Partition != "aws" || parsedARN.Service != "iam" || !isAWSAccountID(parsedARN.AccountID) || !strings.HasPrefix(parsedARN.Resource, "role/") || len(parsedARN.Resource) <= len("role/") {
		return errors.New("invalid assume_role_arn")
	}
	return nil
}

func isAWSAccountID(accountID string) bool {
	if len(accountID) != 12 {
		return false
	}
	for _, c := range accountID {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type AWSMCPProxyRunner struct {
	command string
	args    []string
}

func newAWSMCPProxyRunner(command string, args ...string) *AWSMCPProxyRunner {
	return &AWSMCPProxyRunner{command: command, args: args}
}

func NewAWSMCPProxyRunner(command, packageName, endpoint, region string) *AWSMCPProxyRunner {
	return newAWSMCPProxyRunner(
		command,
		packageName,
		endpoint,
		"--metadata",
		fmt.Sprintf("%s=%s", awsRegionMetadataKey, region),
	)
}

func (r *AWSMCPProxyRunner) StartProxy(ctx context.Context, creds aws.Credentials, region string) (MCPProxyProcess, error) {
	if r.command == "" {
		return nil, errors.New("MCP proxy command is required")
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" {
		return nil, errors.New("AWS temporary credentials are required")
	}
	cmd := exec.CommandContext(ctx, r.command, r.args...)
	cmd.Env = buildMCPProxyEnv(creds, region)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &mcpProxyProcess{cmd: cmd}, nil
}

type mcpProxyProcess struct {
	cmd *exec.Cmd
}

func (p *mcpProxyProcess) Stop() error {
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	if err := p.cmd.Process.Kill(); err != nil {
		return err
	}
	_ = p.cmd.Wait()
	return nil
}

func buildMCPProxyEnv(creds aws.Credentials, region string) []string {
	return []string{
		"AWS_ACCESS_KEY_ID=" + creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + creds.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + creds.SessionToken,
		"AWS_REGION=" + region,
		"AWS_DEFAULT_REGION=" + region,
	}
}
