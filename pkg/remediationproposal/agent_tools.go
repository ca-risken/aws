package remediationproposal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/responses"
)

func buildAgentTools(tools []*mcp.Tool) ([]responses.ToolUnionParam, map[string]bool, error) {
	allowed := map[string]bool{}
	var functions []responses.ToolUnionParam
	for _, tool := range tools {
		if tool == nil || (tool.Name != "call_aws" && tool.Name != "search_documentation" && tool.Name != "read_documentation") {
			continue
		}
		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid MCP input schema: %w", err)
		}
		var parameters map[string]any
		if err := json.Unmarshal(schema, &parameters); err != nil || parameters == nil {
			return nil, nil, errors.New("invalid MCP input schema")
		}
		functions = append(functions, responses.ToolUnionParam{OfFunction: &responses.FunctionToolParam{Name: tool.Name, Description: openai.String(tool.Description), Parameters: parameters, Strict: openai.Bool(false)}})
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
	return string(encoded), nil
}
