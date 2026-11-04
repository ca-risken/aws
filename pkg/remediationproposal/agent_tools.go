package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/logging"
	"github.com/kballard/go-shellquote"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/responses"
)

type runScriptResult struct {
	ToolName       string              `json:"tool_name"`
	ReadOnly       bool                `json:"read_only"`
	PolicyDecision string              `json:"policy_decision"`
	ResultStatus   string              `json:"result_status"`
	Result         *mcp.CallToolResult `json:"result"`
}

const awsRunScriptToolName = "aws___run_script"

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
	"lambda:getfunction":                 true,
	"lambda:getfunctionconfiguration":    true,
	"s3api:getobject":                    true,
	"s3api:getobjectattributes":          true,
	"ec2:getpassworddata":                true,
	"ec2:describeinstanceattribute":      true,
	"ec2:getlaunchtemplatedata":          true,
	"ec2:describelaunchtemplateversions": true,
	"ec2:getconsoleoutput":               true,
	"lambda:getlayerversion":             true,
}

func buildAgentTools(tools []*mcp.Tool) ([]responses.ToolUnionParam, map[string]bool, error) {
	allowed := map[string]bool{}
	var functions []responses.ToolUnionParam
	for _, tool := range tools {
		if tool == nil || !isAllowedAgentTool(tool.Name) {
			continue
		}
		rawParameters := tool.InputSchema
		strict := false
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
	if !allowed[awsRunScriptToolName] {
		return nil, nil, errors.New("AWS verification tool is unavailable")
	}
	return functions, allowed, nil
}

func isAllowedAgentTool(name string) bool {
	switch name {
	case awsRunScriptToolName, "aws___search_documentation", "aws___read_documentation", "aws___retrieve_skill", "aws___list_regions", "aws___get_regional_availability":
		return true
	default:
		return false
	}
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
	if call.Name == awsRunScriptToolName {
		script, err := decodeRunScriptArguments(call.Arguments)
		if err != nil {
			status = "invalid_arguments"
			return "", false, wrapAgentNonRetryable(err)
		}
		service, operation = firstRunScriptOperation(script)
		if err := validateReadOnlyRunScript(script); err != nil {
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
	if call.Name != awsRunScriptToolName {
		if result.IsError {
			status = "error"
		} else {
			status = "success"
		}
		return string(encoded), false, nil
	}
	output, err := marshalRunScriptResult(result)
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

func decodeRunScriptArguments(raw string) (string, error) {
	var arguments map[string]any
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&arguments); err != nil || arguments == nil {
		return "", errors.New("invalid AWS run_script arguments")
	}
	for _, key := range []string{"script", "code"} {
		if value, ok := arguments[key].(string); ok && strings.TrimSpace(value) != "" {
			return value, nil
		}
	}
	return "", errors.New("AWS run_script script is required")
}

var runScriptBoto3CallPattern = regexp.MustCompile(`(?m)call_boto3\s*\(\s*service_name\s*=\s*["']([a-z0-9-]+)["']\s*,\s*operation_name\s*=\s*["']([A-Za-z0-9]+)["']`)

func validateReadOnlyRunScript(script string) error {
	if len(script) > 32*1024 {
		return errors.New("AWS run_script script exceeds size limit")
	}
	for _, token := range []string{"import ", "from ", "__", "open(", "exec(", "eval(", "compile(", "os.", "sys.", "subprocess", "socket", "requests", "urllib", "pathlib"} {
		if strings.Contains(strings.ToLower(script), strings.ToLower(token)) {
			return fmt.Errorf("AWS run_script contains forbidden expression: %q", token)
		}
	}
	calls := runScriptBoto3CallPattern.FindAllStringSubmatch(script, -1)
	if len(calls) == 0 || strings.Count(script, "call_boto3") != len(calls) {
		return errors.New("AWS run_script must call call_boto3 with literal service and operation")
	}
	for _, call := range calls {
		service := strings.ToLower(call[1])
		operation := normalizeAWSOperation(call[2])
		if !allowedAWSReadOnlyServices[service] {
			return fmt.Errorf("AWS service is not allowed for verification: %s", service)
		}
		if blockedAWSOperations[service+":"+operation] {
			return fmt.Errorf("AWS operation is blocked: %s %s", service, call[2])
		}
		if !isReadOnlyAWSOperation(operation) {
			return fmt.Errorf("AWS operation is not read-only: %s", call[2])
		}
	}
	return nil
}

func firstRunScriptOperation(script string) (string, string) {
	calls := runScriptBoto3CallPattern.FindStringSubmatch(script)
	if len(calls) < 3 {
		return "", ""
	}
	return strings.ToLower(calls[1]), calls[2]
}

func validateReadOnlyAWSCommand(command string) error {
	service, operation, err := parseAWSCLICommand(command)
	if err != nil {
		return err
	}
	if !allowedAWSReadOnlyServices[service] {
		return fmt.Errorf("AWS service is not allowed for verification: %s", service)
	}
	if blockedAWSOperations[service+":"+normalizeAWSOperation(operation)] {
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
	operation = normalizeAWSOperation(operation)
	for prefix := range readOnlyAWSOperations {
		if operation == prefix || strings.HasPrefix(operation, prefix) {
			return true
		}
	}
	return false
}

func normalizeAWSOperation(operation string) string {
	return strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(operation))
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

func marshalRunScriptResult(result *mcp.CallToolResult) (string, error) {
	status := "success"
	if result.IsError {
		status = "error"
	}
	encoded, err := json.Marshal(runScriptResult{
		ToolName:       awsRunScriptToolName,
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
