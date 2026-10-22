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
	if scenario == "case-sensitive" || scenario == "null-key" {
		if err := serveMCPParserTest(scenario); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "test-aws-mcp", Version: "1.0.0"}, nil)
	server.AddTool(&mcp.Tool{
		Name: "call_aws", Description: "Test AWS tool",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"cli_command": map[string]any{"type": "string"}}, "required": []string{"cli_command"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if scenario == "call-error" {
			return nil, errors.New("tool execution failed")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(req.Params.Arguments)}}}, nil
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

func serveMCPParserTest(scenario string) error {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"params"`
		}
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(request.ID) == 0 {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": request.Params.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "parser-test", "version": "1"},
			}
		case "tools/list":
			if scenario == "case-sensitive" {
				result = json.RawMessage(`{"tools":[{"name":"expected","inputSchema":{"type":"object"}}],"Tools":[{"name":"unexpected","inputSchema":{"type":"object"}}]}`)
			} else {
				result = json.RawMessage(`{"tools":[{"name":"expected","inputSchema":{"type":"object"}}],"tools\u0000":[{"name":"unexpected","inputSchema":{"type":"object"}}]}`)
			}
		default:
			return errors.New("unexpected MCP request")
		}
		if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result}); err != nil {
			return err
		}
	}
}

func TestMCPProxyRejectsAmbiguousJSONKeys(t *testing.T) {
	for _, scenario := range []string{"case-sensitive", "null-key"} {
		t.Run(scenario, func(t *testing.T) {
			proxy := startTestMCPProxy(t, scenario)
			tools, err := proxy.ListTools(context.Background())
			require.NoError(t, err)
			require.Len(t, tools, 1)
			require.Equal(t, "expected", tools[0].Name)
		})
	}
}

func startTestMCPProxy(t *testing.T, scenario string) MCPProxyProcess {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "must-not-be-forwarded")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/must-not-be-forwarded")
	t.Setenv("AWS_PROFILE", "must-not-be-forwarded")
	runner := newAWSMCPProxyRunner(os.Args[0], "-test.run=^TestMCPProxyHelperProcess$", "--", "--risken-mcp-test="+scenario)
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

func TestMCPProxyInitializationFailure(t *testing.T) {
	for _, scenario := range []string{"initialize-error", "unsupported-version", "silent", "missing-command"} {
		t.Run(scenario, func(t *testing.T) {
			runner := newAWSMCPProxyRunner(os.Args[0], "-test.run=^TestMCPProxyHelperProcess$", "--", "--risken-mcp-test="+scenario)
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

func TestMCPProxyCallTool(t *testing.T) {
	for _, scenario := range []string{"normal", "call-error"} {
		t.Run(scenario, func(t *testing.T) {
			proxy := startTestMCPProxy(t, scenario)
			result, err := proxy.CallTool(context.Background(), "call_aws", map[string]any{"cli_command": "aws s3api list-buckets"})
			if scenario == "call-error" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.False(t, result.IsError)
			require.Len(t, result.Content, 1)
			require.Contains(t, result.Content[0].(*mcp.TextContent).Text, "aws s3api list-buckets")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = proxy.CallTool(ctx, "call_aws", map[string]any{})
			require.Error(t, err)
		})
	}
}
