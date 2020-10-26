package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
)

type policyDocumentRaw struct {
	Version   string
	Statement []statementEntryRaw
}

type statementEntryRaw struct {
	Effect   string
	Action   interface{}
	Resource interface{}
}

type policyDocument struct {
	Version   string
	Statement []statementEntry
}

type statementEntry struct {
	Effect   string
	Action   []string
	Resource []string
	// Conditions map[string]interface{}
}

func convertPolicyDocument(doc *string) (*policyDocument, error) {
	var pd policyDocument
	decodedDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		return nil, err
	}
	appLogger.Debugf("Got a policy document decoded: %s", decodedDoc)
	var pdRaw policyDocumentRaw
	if err := json.Unmarshal([]byte(decodedDoc), &pdRaw); err != nil {
		return nil, err
	}
	pd.Version = pdRaw.Version
	for _, stmtRaw := range pdRaw.Statement {
		if stmtRaw.Effect == "" || stmtRaw.Action == nil || stmtRaw.Resource == nil {
			continue
		}
		var stmt statementEntry
		stmt.Effect = stmtRaw.Effect

		// convert action interface
		if err := setStringSlice(&stmt.Action, stmtRaw.Action); err != nil {
			return nil, err
		}

		// convert resource interface
		if err := setStringSlice(&stmt.Resource, stmtRaw.Resource); err != nil {
			return nil, err
		}
		pd.Statement = append(pd.Statement, stmt)
	}
	return &pd, nil
}

func setStringSlice(slice *[]string, target interface{}) error {
	if reflect.TypeOf(target).Name() == "string" {
		*slice = append(*slice, target.(string))
		return nil
	}
	if values, ok := target.([]string); ok {
		*slice = append(*slice, values...)
		return nil
	}
	if values, ok := target.([]interface{}); ok {
		for _, v := range values {
			if str, ok := v.(string); ok {
				*slice = append(*slice, str)
			}
		}
		return nil
	}
	return fmt.Errorf("Not spported types, target=%+v", target)
}
