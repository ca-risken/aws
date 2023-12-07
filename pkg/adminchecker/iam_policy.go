package adminchecker

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

type policyDocumentRawWithSingleStatement struct {
	Version   string
	Statement statementEntryRaw
}

type statementEntryRaw struct {
	Effect   string
	Action   interface{}
	Resource interface{}
}

type policyDocument struct {
	Version   string           `json:"Version,omitempty"`
	Statement []statementEntry `json:"Statement,omitempty"`
}

type statementEntry struct {
	Effect   string   `json:"Effect,omitempty"`
	Action   []string `json:"Action,omitempty"`
	Resource []string `json:"Resource,omitempty"`
	// Conditions map[string]interface{}
}

func convertPolicyDocument(doc *string) (*policyDocument, error) {
	var pd policyDocument
	decodedDoc, err := url.QueryUnescape(*doc)
	if err != nil {
		return nil, err
	}
	var pdRaw policyDocumentRaw
	if err := json.Unmarshal([]byte(decodedDoc), &pdRaw); err != nil {
		var pdSingle policyDocumentRawWithSingleStatement
		if errSingle := json.Unmarshal([]byte(decodedDoc), &pdSingle); errSingle != nil {
			return nil, errSingle
		}
		pdRaw.Statement = append(pdRaw.Statement, pdSingle.Statement)
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
