package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestMCPProxyHelperProcess(t *testing.T) {
	const prefix = "--risken-mcp-test="
	arg := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(arg, prefix) {
		return
	}
	scenario := strings.TrimPrefix(arg, prefix)
	if os.Getenv("AWS_ACCESS_KEY_ID") != "test-access" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "test-secret" || os.Getenv("AWS_SESSION_TOKEN") != "test-session" || os.Getenv("AWS_REGION") != "us-east-1" {
		os.Exit(2)
	}
	if os.Getenv("OPENAI_API_KEY") != "" || os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" || os.Getenv("AWS_PROFILE") != "" {
		os.Exit(3)
	}
	if scenario == "silent" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "test-aws-mcp", Version: "1.0.0"}, nil)
	server.AddTool(&mcp.Tool{
		Name: "call_aws", Description: "Test AWS tool",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"cli_command": map[string]any{"type": "string"}}, "required": []string{"cli_command"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if scenario == "call-block" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if scenario == "exit" {
			os.Exit(0)
		}
		if scenario == "tool-error" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "private upstream details"}}}, nil
		}
		var arguments map[string]string
		if err := json.Unmarshal(req.Params.Arguments, &arguments); err != nil {
			return nil, err
		}
		if arguments["cli_command"] != "aws sts get-caller-identity" {
			return nil, errors.New("unexpected tool arguments")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: `{"Account":"123456789012"}`}}}, nil
	})
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "initialize" {
				if scenario == "initialize-error" {
					return nil, errors.New("initialization rejected")
				}
				if scenario == "unsupported-version" {
					return &mcp.InitializeResult{ProtocolVersion: "unsupported", ServerInfo: &mcp.Implementation{Name: "test", Version: "1"}, Capabilities: &mcp.ServerCapabilities{}}, nil
				}
			}
			if method == "tools/list" {
				switch scenario {
				case "list-error":
					return nil, errors.New("tool list failed")
				case "pagination":
					params := req.GetParams().(*mcp.ListToolsParams)
					if params.Cursor == "" {
						return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Name: "first"}}, NextCursor: "next"}, nil
					}
					if params.Cursor != "next" {
						return nil, errors.New("invalid cursor")
					}
					return &mcp.ListToolsResult{Tools: []*mcp.Tool{{Name: "second"}}}, nil
				}
			}
			return next(ctx, method, req)
		}
	})
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

func startTestMCPProxy(t *testing.T, scenario string) MCPProxyProcess {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "must-not-be-forwarded")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/must-not-be-forwarded")
	t.Setenv("AWS_PROFILE", "must-not-be-forwarded")
	runner := newAWSMCPProxyRunner(os.Args[0], "-test.run=^TestMCPProxyHelperProcess$", "--risken-mcp-test="+scenario)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	proxy, err := runner.StartProxy(ctx, aws.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-secret", SessionToken: "test-session"}, "us-east-1")
	require.NoError(t, err)
	t.Cleanup(func() { _ = proxy.Stop() })
	return proxy
}

func TestMCPProxyListTools(t *testing.T) {
	for _, scenario := range []string{"normal", "pagination", "list-error"} {
		t.Run(scenario, func(t *testing.T) {
			proxy := startTestMCPProxy(t, scenario)
			tools, err := proxy.ListTools(context.Background())
			if scenario == "list-error" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if scenario == "pagination" {
				require.Len(t, tools, 2)
				require.Equal(t, "first", tools[0].Name)
				require.Equal(t, "second", tools[1].Name)
			} else {
				require.Len(t, tools, 1)
				require.Equal(t, "call_aws", tools[0].Name)
				require.Equal(t, "Test AWS tool", tools[0].Description)
				require.NotNil(t, tools[0].InputSchema)
			}
			require.NoError(t, proxy.Stop())
			require.NoError(t, proxy.Stop())
			_, err = proxy.ListTools(context.Background())
			require.Error(t, err)
		})
	}
}

func TestMCPProxyCallTool(t *testing.T) {
	for _, scenario := range []string{"normal", "tool-error", "unknown-tool", "empty-name", "exit", "call-block"} {
		t.Run(scenario, func(t *testing.T) {
			proxy := startTestMCPProxy(t, scenario)
			name := "call_aws"
			if scenario == "unknown-tool" {
				name = "unknown"
			} else if scenario == "empty-name" {
				name = ""
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			result, err := proxy.CallTool(ctx, name, map[string]any{"cli_command": "aws sts get-caller-identity"})
			if scenario == "normal" {
				require.NoError(t, err)
				require.Len(t, result.Content, 1)
				require.Equal(t, `{"Account":"123456789012"}`, result.Content[0].(*mcp.TextContent).Text)
			} else {
				require.Error(t, err)
				if scenario == "tool-error" {
					require.True(t, result.IsError)
					require.NotContains(t, err.Error(), "private upstream details")
				}
				if scenario == "call-block" {
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			}
		})
	}
}

func TestMCPProxyInitializationFailure(t *testing.T) {
	for _, scenario := range []string{"initialize-error", "unsupported-version", "silent", "missing-command"} {
		t.Run(scenario, func(t *testing.T) {
			runner := newAWSMCPProxyRunner(os.Args[0], "-test.run=^TestMCPProxyHelperProcess$", "--risken-mcp-test="+scenario)
			if scenario == "missing-command" {
				runner.command = "/risken-test-nonexistent/mcp"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			proxy, err := runner.StartProxy(ctx, aws.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-secret", SessionToken: "test-session"}, "us-east-1")
			require.Error(t, err)
			require.Nil(t, proxy)
			if scenario == "silent" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
		})
	}
}
