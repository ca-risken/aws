package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/responses"
)

type callAWSArguments struct {
	CLICommand string `json:"cli_command"`
}

type callAWSResult struct {
	ToolName       string              `json:"tool_name"`
	CLICommand     string              `json:"cli_command"`
	ReadOnly       bool                `json:"read_only"`
	PolicyDecision string              `json:"policy_decision"`
	ResultStatus   string              `json:"result_status"`
	Result         *mcp.CallToolResult `json:"result"`
}

var readOnlyAWSOperations = map[string]bool{
	"get":      true,
	"describe": true,
	"list":     true,
	"head":     true,
	"lookup":   true,
}

var sensitiveAWSOperations = map[string]bool{
	"ecr:get-login-password":                true,
	"ecr:get-authorization-token":           true,
	"lambda:get-function":                   true,
	"lambda:get-function-configuration":     true,
	"s3api:get-object":                      true,
	"s3api:get-object-attributes":           true,
	"secretsmanager:get-secret-value":       true,
	"secretsmanager:batch-get-secret-value": true,
	"ssm:get-parameter":                     true,
	"ssm:get-parameters":                    true,
	"ssm:get-parameters-by-path":            true,
	"ssm:get-parameter-history":             true,
	"sts:get-access-key-info":               true,
	"sts:get-federation-token":              true,
	"sts:get-session-token":                 true,
	"dynamodb:get-item":                     true,
	"logs:get-log-events":                   true,
}

func callAWSToolSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"cli_command"},
		"properties": map[string]any{
			"cli_command": map[string]any{
				"type": "string",
			},
		},
	}
}

func buildAgentTools(tools []*mcp.Tool) ([]responses.ToolUnionParam, map[string]bool, error) {
	allowed := map[string]bool{}
	var functions []responses.ToolUnionParam
	for _, tool := range tools {
		if tool == nil || (tool.Name != "call_aws" && tool.Name != "search_documentation" && tool.Name != "read_documentation") {
			continue
		}
		rawParameters := tool.InputSchema
		strict := false
		if tool.Name == "call_aws" {
			rawParameters = callAWSToolSchema()
			strict = true
		}
		schema, err := json.Marshal(rawParameters)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid MCP input schema: %w", err)
		}
		var parameters map[string]any
		if err := json.Unmarshal(schema, &parameters); err != nil || parameters == nil {
			return nil, nil, errors.New("invalid MCP input schema")
		}
		functions = append(functions, responses.ToolUnionParam{OfFunction: &responses.FunctionToolParam{Name: tool.Name, Description: openai.String(tool.Description), Parameters: parameters, Strict: openai.Bool(strict)}})
		allowed[tool.Name] = true
	}
	if !allowed["call_aws"] {
		return nil, nil, errors.New("AWS verification tool is unavailable")
	}
	return functions, allowed, nil
}

func extractFunctionCalls(output []responses.ResponseOutputItemUnion) []responses.ResponseFunctionToolCall {
	var calls []responses.ResponseFunctionToolCall
	for _, item := range output {
		if item.Type == "function_call" {
			calls = append(calls, item.AsFunctionCall())
		}
	}
	return calls
}

func appendResponseOutput(input responses.ResponseInputParam, output []responses.ResponseOutputItemUnion) (responses.ResponseInputParam, error) {
	for _, item := range output {
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		var previous responses.ResponseInputItemUnionParam
		if err := json.Unmarshal(encoded, &previous); err != nil {
			return nil, err
		}
		input = append(input, previous)
	}
	return input, nil
}

func handleFunctionCalls(ctx context.Context, proxy MCPProxyProcess, calls []responses.ResponseFunctionToolCall) (responses.ResponseInputParam, bool, error) {
	var outputs responses.ResponseInputParam
	verified := false
	for _, call := range calls {
		result, callVerified, err := executeFunctionCall(ctx, proxy, call)
		if err != nil {
			return nil, false, err
		}
		outputs = append(outputs, responses.ResponseInputItemParamOfFunctionCallOutput(call.CallID, result))
		verified = verified || callVerified
	}
	return outputs, verified, nil
}

func executeFunctionCall(ctx context.Context, proxy MCPProxyProcess, call responses.ResponseFunctionToolCall) (string, bool, error) {
	var arguments map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &arguments); err != nil || arguments == nil {
		return "", false, wrapAgentNonRetryable(errors.New("invalid MCP tool arguments"))
	}
	if call.Name == "call_aws" {
		params, err := decodeCallAWSArguments(call.Arguments)
		if err != nil {
			return "", false, wrapAgentNonRetryable(err)
		}
		if err := validateReadOnlyAWSCommand(params.CLICommand); err != nil {
			return "", false, wrapAgentNonRetryable(err)
		}
	}
	result, err := proxy.CallTool(ctx, call.Name, arguments)
	if err != nil {
		return "", false, fmt.Errorf("failed to call MCP tool: %w", err)
	}
	if result == nil {
		return "", false, wrapAgentNonRetryable(errors.New("MCP tool returned an empty result"))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", false, err
	}
	if len(encoded) > 256*1024 {
		return "", false, wrapAgentNonRetryable(errors.New("MCP tool result exceeds size limit"))
	}
	if call.Name != "call_aws" {
		return string(encoded), false, nil
	}
	params, err := decodeCallAWSArguments(call.Arguments)
	if err != nil {
		return "", false, wrapAgentNonRetryable(err)
	}
	output, err := marshalCallAWSResult(params.CLICommand, result)
	return output, !result.IsError && err == nil, err
}

func decodeCallAWSArguments(raw string) (callAWSArguments, error) {
	var params callAWSArguments
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&params); err != nil {
		return callAWSArguments{}, errors.New("invalid AWS tool arguments")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return callAWSArguments{}, errors.New("invalid AWS tool arguments")
	}
	if strings.TrimSpace(params.CLICommand) == "" {
		return callAWSArguments{}, errors.New("invalid AWS tool arguments")
	}
	return params, nil
}

func validateReadOnlyAWSCommand(command string) error {
	service, operation, err := parseAWSCLICommand(command)
	if err != nil {
		return err
	}
	if sensitiveAWSOperations[service+":"+operation] {
		return fmt.Errorf("AWS operation may return sensitive data: %s %s", service, operation)
	}
	if !isReadOnlyAWSOperation(operation) {
		return fmt.Errorf("AWS operation is not read-only: %s", operation)
	}
	return nil
}

func validateAWSCommand(command string) error {
	if _, _, err := parseAWSCLICommand(command); err != nil {
		return err
	}
	return nil
}

func isReadOnlyAWSOperation(operation string) bool {
	for prefix := range readOnlyAWSOperations {
		if operation == prefix || strings.HasPrefix(operation, prefix+"-") {
			return true
		}
	}
	return false
}

func parseAWSCLICommand(command string) (string, string, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return "", "", errors.New("AWS CLI command is required")
	}
	for _, token := range []string{"|", ";", "&&", "||", "&", ">", "<", "`", "$(", "${", "\n", "\r"} {
		if strings.Contains(trimmed, token) {
			return "", "", fmt.Errorf("AWS CLI command contains forbidden shell token: %q", token)
		}
	}
	parts, err := shellquote.Split(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("invalid AWS CLI quoting: %w", err)
	}
	if len(parts) < 3 || parts[0] != "aws" {
		return "", "", errors.New("AWS CLI command must start with aws and include a service operation")
	}
	globalOptionsWithValue := map[string]bool{
		"--color": true, "--max-items": true, "--output": true,
		"--page-size": true, "--query": true, "--region": true,
		"--starting-token": true,
	}
	globalOptionsWithoutValue := map[string]bool{
		"--no-cli-pager": true, "--no-paginate": true,
	}
	index := 1
	for index < len(parts) && strings.HasPrefix(parts[index], "--") {
		option := parts[index]
		name := option
		if separator := strings.IndexByte(option, '='); separator >= 0 {
			name = option[:separator]
		}
		if globalOptionsWithValue[name] {
			if !strings.Contains(option, "=") {
				if index+1 >= len(parts) {
					return "", "", fmt.Errorf("AWS global option requires a value: %s", name)
				}
				index++
			}
			index++
			continue
		}
		if globalOptionsWithoutValue[name] && !strings.Contains(option, "=") {
			index++
			continue
		}
		return "", "", fmt.Errorf("AWS global option is not allowed: %s", name)
	}
	if len(parts) <= index+1 {
		return "", "", errors.New("AWS CLI command must include a service operation")
	}
	return strings.ToLower(parts[index]), strings.ToLower(parts[index+1]), nil
}

func marshalCallAWSResult(command string, result *mcp.CallToolResult) (string, error) {
	status := "success"
	if result.IsError {
		status = "error"
	}
	encoded, err := json.Marshal(callAWSResult{
		ToolName:       "call_aws",
		CLICommand:     command,
		ReadOnly:       true,
		PolicyDecision: "allowed",
		ResultStatus:   status,
		Result:         result,
	})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
