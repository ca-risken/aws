package remediationproposal

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/ca-risken/common/pkg/logging"
)

type mockCredentialProvider struct {
	region      string
	roleARN     string
	externalID  string
	sessionName string
	err         error
}

func (m *mockCredentialProvider) AssumeRole(ctx context.Context, region, roleARN, externalID, sessionName string) (aws.Credentials, error) {
	m.region = region
	m.roleARN = roleARN
	m.externalID = externalID
	m.sessionName = sessionName
	if m.err != nil {
		return aws.Credentials{}, m.err
	}
	return aws.Credentials{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
	}, nil
}

type mockMCPProxyRunner struct {
	region  string
	creds   aws.Credentials
	err     error
	process *mockMCPProxyProcess
}

func (m *mockMCPProxyRunner) StartProxy(ctx context.Context, creds aws.Credentials, region string) (MCPProxyProcess, error) {
	m.creds = creds
	m.region = region
	if m.err != nil {
		return nil, m.err
	}
	m.process = &mockMCPProxyProcess{}
	return m.process, nil
}

type mockMCPProxyProcess struct {
	stopped bool
}

func (m *mockMCPProxyProcess) Stop() error {
	m.stopped = true
	return nil
}

func TestRemediationProcessorProcess(t *testing.T) {
	errAssumeRole := errors.New("assume role error")
	errStartProxy := errors.New("start proxy error")
	msg := &QueueMessage{
		RemediationProposalID: 1001,
		FindingID:             2001,
		ProjectID:             3001,
		AssumeRoleArn:         "arn:aws:iam::123456789012:role/test",
		ExternalID:            "external",
	}

	cases := []struct {
		name          string
		credentialErr error
		proxyErr      error
		wantErr       bool
		wantStopped   bool
	}{
		{
			name:        "OK",
			wantStopped: true,
		},
		{
			name:          "NG assume role error",
			credentialErr: errAssumeRole,
			wantErr:       true,
		},
		{
			name:        "NG proxy start error",
			proxyErr:    errStartProxy,
			wantErr:     true,
			wantStopped: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			credentialProvider := &mockCredentialProvider{err: c.credentialErr}
			proxyRunner := &mockMCPProxyRunner{err: c.proxyErr}
			processor := NewRemediationProcessor("ap-northeast-1", "us-east-1", credentialProvider, proxyRunner, logging.NewLogger())

			err := processor.Process(context.Background(), msg, "request-id")
			if (err != nil) != c.wantErr {
				t.Fatalf("unexpected error: wantErr=%t, err=%+v", c.wantErr, err)
			}
			if credentialProvider.region != "ap-northeast-1" {
				t.Fatalf("unexpected assume role region: got=%s", credentialProvider.region)
			}
			if credentialProvider.roleARN != msg.AssumeRoleArn {
				t.Fatalf("unexpected assume role arn: got=%s", credentialProvider.roleARN)
			}
			if credentialProvider.externalID != msg.ExternalID {
				t.Fatalf("unexpected external id: got=%s", credentialProvider.externalID)
			}
			if credentialProvider.sessionName != "RISKEN-AI-request-id" {
				t.Fatalf("unexpected session name: got=%s", credentialProvider.sessionName)
			}
			if c.credentialErr == nil && proxyRunner.region != "us-east-1" {
				t.Fatalf("unexpected MCP proxy region: got=%s", proxyRunner.region)
			}
			if proxyRunner.process != nil && proxyRunner.process.stopped != c.wantStopped {
				t.Fatalf("unexpected proxy stop: want=%t, got=%t", c.wantStopped, proxyRunner.process.stopped)
			}
		})
	}
}

func TestBuildMCPProxyEnv(t *testing.T) {
	t.Setenv("PATH", "/usr/local/bin")
	t.Setenv("AWS_ACCESS_KEY_ID", "parent-access-key")
	creds := aws.Credentials{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		SessionToken:    "session-token",
	}

	env := buildMCPProxyEnv(creds, "us-east-1")
	got := strings.Join(env, "\n")
	for _, want := range []string{
		"PATH=/usr/local/bin",
		"AWS_ACCESS_KEY_ID=access-key",
		"AWS_SECRET_ACCESS_KEY=secret-key",
		"AWS_SESSION_TOKEN=session-token",
		"AWS_REGION=us-east-1",
		"AWS_DEFAULT_REGION=us-east-1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected env to contain %s, got=%v", want, env)
		}
	}
	if strings.Contains(got, "parent-access-key") {
		t.Fatalf("parent AWS credential leaked to MCP proxy env: %v", env)
	}
}

func TestNewAWSMCPProxyRunner(t *testing.T) {
	runner := NewAWSMCPProxyRunner("uvx", "mcp-proxy-for-aws@latest", "https://aws-mcp.us-east-1.api.aws/mcp", "us-west-2")
	if runner.command != "uvx" {
		t.Fatalf("unexpected command: got=%s", runner.command)
	}
	wantArgs := []string{
		"mcp-proxy-for-aws@latest",
		"https://aws-mcp.us-east-1.api.aws/mcp",
		"--metadata",
		"AWS_REGION=us-west-2",
	}
	if strings.Join(runner.args, "\n") != strings.Join(wantArgs, "\n") {
		t.Fatalf("unexpected args: got=%v, want=%v", runner.args, wantArgs)
	}
}

func TestAWSMCPProxyRunnerStartValidation(t *testing.T) {
	runner := newAWSMCPProxyRunner("")
	_, err := runner.StartProxy(context.Background(), aws.Credentials{}, "us-east-1")
	if err == nil {
		t.Fatal("expected command validation error")
	}

	runner = newAWSMCPProxyRunner(os.Args[0])
	_, err = runner.StartProxy(context.Background(), aws.Credentials{}, "us-east-1")
	if err == nil {
		t.Fatal("expected credential validation error")
	}
}
