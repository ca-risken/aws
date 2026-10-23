package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corefinding "github.com/ca-risken/core/proto/finding"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/stretchr/testify/require"
)

const validPlanJSON = `{"summary":"公開設定を修正します。","current_state":["公開状態を確認済み"],"steps":[{"order":1,"title":"公開を停止","command":"aws s3api put-public-access-block --bucket {bucket_name}","verification_command":"aws s3api get-public-access-block --bucket {bucket_name}"}]}`

type agentProxy struct {
	mockMCPProxyProcess
	toolName  string
	arguments map[string]any
	callErr   error
	toolError bool
	callCount int
}

type agentRoundTripper struct{ handler http.Handler }

func (r agentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	response := httptest.NewRecorder()
	r.handler.ServeHTTP(response, req)
	return response.Result(), nil
}

func (p *agentProxy) CallTool(ctx context.Context, name string, arguments map[string]any) (*mcp.CallToolResult, error) {
	p.toolName, p.arguments = name, arguments
	p.callCount++
	return &mcp.CallToolResult{IsError: p.toolError, Content: []mcp.Content{&mcp.TextContent{Text: "resource is public"}}}, p.callErr
}

func TestNewOpenAIAgent(t *testing.T) {
	for _, tt := range []struct {
		token, model string
		wantErr      bool
	}{
		{"", "model", true}, {"token", "", true}, {"token", "model", false},
	} {
		agent, err := NewOpenAIAgent(tt.token, tt.model)
		if tt.wantErr {
			require.Error(t, err)
			require.Nil(t, agent)
		} else {
			require.NoError(t, err)
			require.NotNil(t, agent.client)
			require.Equal(t, tt.model, agent.model)
		}
	}
}

func TestOpenAIAgentGenerate(t *testing.T) {
	for _, tt := range []struct {
		name                                                         string
		firstTool                                                    string
		skipTool, toolError, apiError, incomplete, invalidPlan, loop bool
		callErr                                                      error
		wantErr                                                      bool
	}{
		{name: "success", firstTool: "call_aws"},
		{name: "no verification", skipTool: true, wantErr: true},
		{name: "run script blocked", firstTool: "run_script", wantErr: true},
		{name: "tool failure", firstTool: "call_aws", toolError: true, wantErr: true},
		{name: "transport failure", firstTool: "call_aws", callErr: errors.New("transport"), wantErr: true},
		{name: "API failure", apiError: true, wantErr: true},
		{name: "incomplete", incomplete: true, wantErr: true},
		{name: "invalid plan", firstTool: "call_aws", invalidPlan: true, wantErr: true},
		{name: "call limit", firstTool: "call_aws", loop: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				requests++
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				var req map[string]any
				require.NoError(t, json.Unmarshal(body, &req))
				require.Equal(t, false, req["store"])
				require.Equal(t, false, req["parallel_tool_calls"])
				require.NotContains(t, string(body), `"name":"run_script"`)
				if requests > 1 {
					require.Contains(t, string(body), "function_call_output")
					require.Contains(t, string(body), "resource is public")
					require.Contains(t, string(body), "reasoning")
				}
				if tt.apiError {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":{"message":"bad request"}}`))
					return
				}
				if tt.incomplete {
					_, _ = w.Write([]byte(`{"status":"incomplete","output":[]}`))
					return
				}
				if (requests == 1 && !tt.skipTool) || tt.loop {
					output := map[string]any{"status": "completed", "output": []any{
						map[string]any{"type": "reasoning", "id": "rs_test", "summary": []any{}},
						map[string]any{"type": "function_call", "name": tt.firstTool, "arguments": `{"cli_command":"aws s3api get-public-access-block --bucket example"}`, "call_id": "call_test", "id": "fc_test"},
					}}
					_ = json.NewEncoder(w).Encode(output)
					return
				}
				text := validPlanJSON
				if tt.invalidPlan {
					text = `{}`
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "status": "completed", "id": "msg_test", "content": []any{map[string]any{"type": "output_text", "text": text}}}}})
			})
			client := openai.NewClient(option.WithAPIKey("test-token"), option.WithHTTPClient(&http.Client{Transport: agentRoundTripper{handler: handler}}), option.WithMaxRetries(0))
			agent := &OpenAIAgent{client: &client.Responses, model: "test-model"}
			proxy := &agentProxy{callErr: tt.callErr, toolError: tt.toolError}
			tools := []*mcp.Tool{
				{Name: "call_aws", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"cli_command": map[string]any{"type": "string"}}}},
				{Name: "run_script", InputSchema: map[string]any{"type": "object"}},
			}
			plan, err := agent.Generate(context.Background(), &corefinding.Finding{FindingId: 123, ProviderTarget: "123456789012"}, proxy, tools)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, plan)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(123), plan.FindingID)
				require.Equal(t, "test-model", plan.Plan.Metadata.Model)
				require.Positive(t, plan.Plan.Metadata.GeneratedAt)
				require.Equal(t, "call_aws", proxy.toolName)
				require.Contains(t, proxy.arguments["cli_command"], "get-public-access-block")
			}
			require.LessOrEqual(t, proxy.callCount, maxAgentToolCalls)
		})
	}
}

func TestOpenAIAgentGenerateMissingInputs(t *testing.T) {
	agent, err := NewOpenAIAgent("token", "model")
	require.NoError(t, err)
	_, err = agent.Generate(context.Background(), nil, &agentProxy{}, nil)
	require.Error(t, err)
	_, err = agent.Generate(context.Background(), &corefinding.Finding{}, nil, nil)
	require.Error(t, err)
	_, err = agent.Generate(context.Background(), &corefinding.Finding{}, &agentProxy{}, nil)
	require.ErrorContains(t, err, "verification tool")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = agent.Generate(ctx, &corefinding.Finding{}, &agentProxy{}, []*mcp.Tool{{Name: "call_aws", InputSchema: map[string]any{"type": "object"}}})
	require.ErrorIs(t, err, context.Canceled)
}

func TestParsePlan(t *testing.T) {
	for _, tt := range []struct {
		name, value string
		wantErr     bool
	}{
		{"valid", validPlanJSON, false},
		{"invalid JSON", "{", true},
		{"missing fields", "{}", true},
		{"unknown field", strings.Replace(validPlanJSON, `"summary":`, `"unknown":1,"summary":`, 1), true},
		{"trailing data", validPlanJSON + " {}", true},
		{"empty verification", strings.Replace(validPlanJSON, `aws s3api get-public-access-block --bucket {bucket_name}`, "", 1), true},
		{"wrong order", strings.Replace(validPlanJSON, `"order":1`, `"order":2`, 1), true},
		{"resolved", `{"summary":"解決済み","current_state":["非公開を確認"],"steps":[]}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePlan(tt.value)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
