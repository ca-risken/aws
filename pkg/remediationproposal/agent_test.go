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
	"github.com/openai/openai-go/responses"
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
		finalAfter                                                   int
		unapprovedSecond                                             bool
	}{
		{name: "success", firstTool: "call_aws"},
		{name: "no verification", skipTool: true, wantErr: true},
		{name: "run script blocked", firstTool: "run_script", wantErr: true},
		{name: "unpublished tool blocked", firstTool: "read_documentation", wantErr: true},
		{name: "unapproved second call blocks whole batch", firstTool: "call_aws", unapprovedSecond: true, wantErr: true},
		{name: "tool failure", firstTool: "call_aws", toolError: true, wantErr: true},
		{name: "transport failure", firstTool: "call_aws", callErr: errors.New("transport"), wantErr: true},
		{name: "API failure", apiError: true, wantErr: true},
		{name: "incomplete", incomplete: true, wantErr: true},
		{name: "invalid plan", firstTool: "call_aws", invalidPlan: true, wantErr: true},
		{name: "call limit", firstTool: "call_aws", loop: true, wantErr: true},
		{name: "final answer after last allowed call", firstTool: "call_aws", finalAfter: maxAgentToolCalls},
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
					require.Contains(t, string(body), "encrypted-reasoning")
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
				if (requests == 1 && !tt.skipTool) || tt.loop || requests <= tt.finalAfter {
					output := map[string]any{"status": "completed", "output": []any{
						map[string]any{"type": "reasoning", "id": "rs_test", "summary": []any{}, "encrypted_content": "encrypted-reasoning"},
						map[string]any{"type": "function_call", "name": tt.firstTool, "arguments": `{"cli_command":"aws s3api get-public-access-block --bucket example"}`, "call_id": "call_test", "id": "fc_test"},
					}}
					if tt.unapprovedSecond {
						output["output"] = append(output["output"].([]any), map[string]any{"type": "function_call", "name": "run_script", "arguments": "{}", "call_id": "call_blocked", "id": "fc_blocked"})
					}
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
			if tt.firstTool == "run_script" || tt.firstTool == "read_documentation" || tt.unapprovedSecond {
				require.Zero(t, proxy.callCount)
			}
			if tt.finalAfter > 0 {
				require.Equal(t, tt.finalAfter, proxy.callCount)
				require.Equal(t, tt.finalAfter+1, requests)
			}
		})
	}
}

func TestAppendResponseOutput(t *testing.T) {
	var response responses.Response
	require.NoError(t, json.Unmarshal([]byte(`{"output":[{"type":"reasoning","id":"rs_test","summary":[],"encrypted_content":"encrypted-reasoning"},{"type":"function_call","id":"fc_test","call_id":"call_test","name":"call_aws","arguments":"{}"}]}`), &response))
	input := responses.ResponseInputParam{responses.ResponseInputItemParamOfMessage("finding", responses.EasyInputMessageRoleUser)}
	updated, err := appendResponseOutput(input, response.Output)
	require.NoError(t, err)
	encoded, err := json.Marshal(updated)
	require.NoError(t, err)
	var items []map[string]any
	require.NoError(t, json.Unmarshal(encoded, &items))
	require.Len(t, items, 3)
	require.Equal(t, "finding", items[0]["content"])
	require.Equal(t, "reasoning", items[1]["type"])
	require.Equal(t, "encrypted-reasoning", items[1]["encrypted_content"])
	require.Equal(t, "function_call", items[2]["type"])
	require.Equal(t, "call_test", items[2]["call_id"])
	calls := extractFunctionCalls(response.Output)
	require.Len(t, calls, 1)
	require.Equal(t, "call_test", calls[0].CallID)
}

func TestBuildAgentTools(t *testing.T) {
	for _, tt := range []struct {
		name    string
		schema  any
		wantErr bool
	}{
		{name: "valid", schema: map[string]any{"type": "object"}},
		{name: "nil schema"},
		{name: "invalid schema"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tools, allowed, err := buildAgentTools([]*mcp.Tool{nil, {Name: "run_script"}, {Name: "call_aws", InputSchema: tt.schema}, {Name: "search_documentation", InputSchema: map[string]any{"type": "object"}}})
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, tools, 2)
			require.True(t, allowed["call_aws"])
			require.True(t, allowed["search_documentation"])
			require.False(t, allowed["run_script"])
		})
	}
}

func TestHandleFunctionCalls(t *testing.T) {
	for _, tt := range []struct {
		name     string
		tools    []string
		verified bool
	}{
		{name: "documentation only", tools: []string{"read_documentation"}},
		{name: "AWS and documentation", tools: []string{"call_aws", "read_documentation"}, verified: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &agentProxy{}
			var calls []responses.ResponseFunctionToolCall
			for _, name := range tt.tools {
				calls = append(calls, responses.ResponseFunctionToolCall{Name: name, CallID: name, Arguments: `{}`})
			}
			for i := range calls {
				if calls[i].Name == "call_aws" {
					calls[i].Arguments = `{"cli_command":"aws s3api get-public-access-block --bucket example"}`
				}
			}
			outputs, verified, err := handleFunctionCalls(context.Background(), proxy, calls)
			require.NoError(t, err)
			require.Equal(t, tt.verified, verified)
			require.Equal(t, len(calls), proxy.callCount)
			require.Len(t, outputs, len(calls))
			encoded, err := json.Marshal(outputs)
			require.NoError(t, err)
			var items []map[string]any
			require.NoError(t, json.Unmarshal(encoded, &items))
			for i, item := range items {
				require.Equal(t, calls[i].CallID, item["call_id"])
				require.Equal(t, "function_call_output", item["type"])
			}
		})
	}
}

func TestValidateReadOnlyAWSCommand(t *testing.T) {
	for _, tt := range []struct {
		name    string
		command string
		wantErr bool
	}{
		{name: "get", command: "aws s3api get-public-access-block --bucket example"},
		{name: "global region option", command: "aws --region us-east-1 ec2 describe-instances"},
		{name: "global query option", command: "aws --query list s3api delete-bucket --bucket example", wantErr: true},
		{name: "describe", command: "aws ec2 describe-instances"},
		{name: "list", command: "aws iam list-roles"},
		{name: "secret value blocked", command: "aws secretsmanager get-secret-value --secret-id example", wantErr: true},
		{name: "parameter blocked", command: "aws ssm get-parameter --name example --with-decryption", wantErr: true},
		{name: "login password blocked", command: "aws ecr get-login-password", wantErr: true},
		{name: "update blocked", command: "aws s3api put-bucket-policy --bucket example", wantErr: true},
		{name: "pipeline blocked", command: "aws s3api get-bucket-acl --bucket example | cat", wantErr: true},
		{name: "semicolon blocked", command: "aws s3api get-bucket-acl --bucket example; aws s3api delete-bucket --bucket example", wantErr: true},
		{name: "not aws", command: "sh -c whoami", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReadOnlyAWSCommand(tt.command)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCallAWSToolSchema(t *testing.T) {
	schema := callAWSToolSchema()
	require.Equal(t, false, schema["additionalProperties"] == true)
	require.Equal(t, []string{"cli_command"}, schema["required"])
}

func TestDecodeCallAWSArguments(t *testing.T) {
	_, err := decodeCallAWSArguments(`{"cli_command":"aws s3api get-bucket-acl --bucket example","extra":"blocked"}`)
	require.Error(t, err)

	_, err = decodeCallAWSArguments(`{"cli_command":"aws s3api get-bucket-acl --bucket example"} trailing`)
	require.Error(t, err)
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
		{"unsafe verification", strings.Replace(validPlanJSON, `aws s3api get-public-access-block --bucket {bucket_name}`, `aws s3api put-bucket-policy --bucket {bucket_name}`, 1), true},
		{"shell remediation command", strings.Replace(validPlanJSON, `aws s3api put-public-access-block --bucket {bucket_name}`, `aws s3api put-public-access-block --bucket {bucket_name} | cat`, 1), true},
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
