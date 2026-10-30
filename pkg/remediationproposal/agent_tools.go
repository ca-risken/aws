package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

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
	Result         *mcp.CallToolResult `json:"result"`
}

var readOnlyAWSOperations = map[string]bool{
	"get":      true,
	"describe": true,
	"list":     true,
	"head":     true,
	"lookup":   true,
}

func callAWSToolSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"cli_command"},
		"properties": map[string]any{
			"cli_command": map[string]any{
				"type":      "string",
				"minLength": 1,
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
		result, err := executeFunctionCall(ctx, proxy, call)
		if err != nil {
			return nil, false, err
		}
		outputs = append(outputs, responses.ResponseInputItemParamOfFunctionCallOutput(call.CallID, result))
		verified = verified || call.Name == "call_aws"
	}
	return outputs, verified, nil
}

func executeFunctionCall(ctx context.Context, proxy MCPProxyProcess, call responses.ResponseFunctionToolCall) (string, error) {
	var arguments map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &arguments); err != nil || arguments == nil {
		return "", errors.New("invalid MCP tool arguments")
	}
	if call.Name == "call_aws" {
		params, err := decodeCallAWSArguments(call.Arguments)
		if err != nil {
			return "", err
		}
		if err := validateReadOnlyAWSCommand(params.CLICommand); err != nil {
			return "", err
		}
	}
	result, err := proxy.CallTool(ctx, call.Name, arguments)
	if err != nil {
		return "", fmt.Errorf("failed to call MCP tool: %w", err)
	}
	if result == nil || result.IsError {
		return "", errors.New("MCP tool returned an error")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	if len(encoded) > 256*1024 {
		return "", errors.New("MCP tool result exceeds size limit")
	}
	if call.Name != "call_aws" {
		return string(encoded), nil
	}
	params, err := decodeCallAWSArguments(call.Arguments)
	if err != nil {
		return "", err
	}
	return marshalCallAWSResult(params.CLICommand, result)
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
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return errors.New("AWS CLI command is required")
	}
	for _, token := range []string{"|", ";", "&&", "||", "&", ">", "<", "`", "$(", "${", "\n", "\r"} {
		if strings.Contains(trimmed, token) {
			return fmt.Errorf("AWS CLI command contains forbidden shell token: %q", token)
		}
	}
	parts := strings.Fields(trimmed)
	if len(parts) < 3 || parts[0] != "aws" {
		return errors.New("AWS CLI command must start with aws and include a service operation")
	}
	operation := strings.ToLower(parts[2])
	for prefix := range readOnlyAWSOperations {
		if operation == prefix || strings.HasPrefix(operation, prefix+"-") {
			return nil
		}
	}
	return fmt.Errorf("AWS operation is not read-only: %s", operation)
}

func marshalCallAWSResult(command string, result *mcp.CallToolResult) (string, error) {
	encoded, err := json.Marshal(callAWSResult{
		ToolName:       "call_aws",
		CLICommand:     command,
		ReadOnly:       true,
		PolicyDecision: "allowed",
		Result:         result,
	})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
