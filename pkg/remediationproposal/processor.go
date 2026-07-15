package remediationproposal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ca-risken/common/pkg/logging"
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

type RemediationProcessor struct {
	awsRegion          string
	mcpRegion          string
	credentialProvider CredentialProvider
	mcpProxyRunner     MCPProxyRunner
	logger             logging.Logger
}

func NewRemediationProcessor(awsRegion, mcpRegion string, credentialProvider CredentialProvider, mcpProxyRunner MCPProxyRunner, logger logging.Logger) *RemediationProcessor {
	return &RemediationProcessor{
		awsRegion:          awsRegion,
		mcpRegion:          mcpRegion,
		credentialProvider: credentialProvider,
		mcpProxyRunner:     mcpProxyRunner,
		logger:             logger,
	}
}

func (p *RemediationProcessor) Process(ctx context.Context, msg *QueueMessage, requestID string) error {
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

func buildRoleSessionName(requestID string) string {
	return fmt.Sprintf("%s-%s", roleSessionNamePrefix, requestID)
}

type STSCredentialProvider struct{}

func NewSTSCredentialProvider() *STSCredentialProvider {
	return &STSCredentialProvider{}
}

func (p *STSCredentialProvider) AssumeRole(ctx context.Context, region, roleARN, externalID, sessionName string) (aws.Credentials, error) {
	if roleARN == "" {
		return aws.Credentials{}, errors.New("assume_role_arn is required")
	}
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
	env := preservedEnv()
	env = append(env,
		"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"AWS_SESSION_TOKEN="+creds.SessionToken,
		"AWS_REGION="+region,
		"AWS_DEFAULT_REGION="+region,
	)
	return env
}

func preservedEnv() []string {
	keys := []string{"PATH", "HOME", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}
