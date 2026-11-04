package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/logging"
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

var allowedAWSReadOnlyServices = map[string]bool{
	"accessanalyzer": true,
	"ec2":            true,
	"elbv2":          true,
	"iam":            true,
	"lambda":         true,
	"rds":            true,
	"s3api":          true,
}

var blockedAWSOperations = map[string]bool{
	"lambda:get-function":         true,
	"s3api:get-object":            true,
	"s3api:get-object-attributes": true,
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

func handleFunctionCalls(ctx context.Context, proxy MCPProxyProcess, calls []responses.ResponseFunctionToolCall, logger logging.Logger, auditFields map[string]interface{}) (responses.ResponseInputParam, bool, error) {
	var outputs responses.ResponseInputParam
	verified := false
	for _, call := range calls {
		result, callVerified, err := executeFunctionCall(ctx, proxy, call, logger, auditFields)
		if err != nil {
			return nil, false, err
		}
		outputs = append(outputs, responses.ResponseInputItemParamOfFunctionCallOutput(call.CallID, result))
		verified = verified || callVerified
	}
	return outputs, verified, nil
}

func executeFunctionCall(ctx context.Context, proxy MCPProxyProcess, call responses.ResponseFunctionToolCall, logger logging.Logger, auditFields map[string]interface{}) (string, bool, error) {
	findingID, _ := auditFields["finding_id"].(uint64)
	projectID, _ := auditFields["project_id"].(uint32)
	accountID, _ := auditFields["aws_account_id"].(string)
	service, operation := "", ""
	policyDecision := "not_applicable"
	status := "error"
	responseSize := -1
	started := time.Now()
	if logger != nil {
		logger.Infof(ctx, "MCP tool call started: finding_id=%d, project_id=%d, account_id=%s, tool=%s, call_id=%s", findingID, projectID, accountID, call.Name, call.CallID)
		defer func() {
			logger.Infof(ctx, "MCP tool call finished: finding_id=%d, project_id=%d, account_id=%s, tool=%s, call_id=%s, service=%s, operation=%s, policy=%s, status=%s, response_size=%d, duration_ms=%d", findingID, projectID, accountID, call.Name, call.CallID, service, operation, policyDecision, status, responseSize, time.Since(started).Milliseconds())
		}()
	}
	var arguments map[string]any
	if err := json.Unmarshal([]byte(call.Arguments), &arguments); err != nil || arguments == nil {
		return "", false, wrapAgentNonRetryable(errors.New("invalid MCP tool arguments"))
	}
	if call.Name == "call_aws" {
		params, err := decodeCallAWSArguments(call.Arguments)
		if err != nil {
			status = "invalid_arguments"
			return "", false, wrapAgentNonRetryable(err)
		}
		service, operation, _ = parseAWSCLICommand(params.CLICommand)
		if err := validateReadOnlyAWSCommand(params.CLICommand); err != nil {
			policyDecision = "denied"
			status = "policy_denied"
			return "", false, wrapAgentNonRetryable(err)
		}
		policyDecision = "allowed"
	}
	result, err := proxy.CallTool(ctx, call.Name, arguments)
	if err != nil {
		status = "transport_error"
		return "", false, fmt.Errorf("failed to call MCP tool: %w", err)
	}
	if result == nil {
		status = "empty_result"
		return "", false, wrapAgentNonRetryable(errors.New("MCP tool returned an empty result"))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		status = "marshal_error"
		return "", false, err
	}
	responseSize = len(encoded)
	if len(encoded) > 256*1024 {
		status = "response_too_large"
		return "", false, wrapAgentNonRetryable(errors.New("MCP tool result exceeds size limit"))
	}
	if call.Name != "call_aws" {
		if result.IsError {
			status = "error"
		} else {
			status = "success"
		}
		return string(encoded), false, nil
	}
	params, err := decodeCallAWSArguments(call.Arguments)
	if err != nil {
		status = "invalid_arguments"
		return "", false, wrapAgentNonRetryable(err)
	}
	output, err := marshalCallAWSResult(params.CLICommand, result)
	if err != nil {
		status = "marshal_error"
		return output, false, err
	}
	if result.IsError {
		status = "error"
	} else {
		status = "success"
	}
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
	if !allowedAWSReadOnlyServices[service] {
		return fmt.Errorf("AWS service is not allowed for verification: %s", service)
	}
	if blockedAWSOperations[service+":"+operation] {
		return fmt.Errorf("AWS operation is blocked: %s %s", service, operation)
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
