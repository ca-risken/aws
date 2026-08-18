package accessanalyzer

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

func TestGetQueueURLFromArn(t *testing.T) {
	tests := []struct {
		name     string
		queueArn string
		want     string
	}{
		{
			"OK",
			"arn:aws:sqs:us-west-2:123456789012:my-queue",
			"https://sqs.us-west-2.amazonaws.com/123456789012/my-queue",
		},
		{
			"Invalid ARN with less parts",
			"arn:aws:sqs:us-west-2:123456789012",
			"",
		},
		{
			"Invalid ARN with wrong format",
			"invalid:format",
			"",
		},
		{
			"Empty string",
			"",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getQueueURLFromArn(tt.queueArn); got != tt.want {
				t.Errorf("getQueueNameFromArn(%q) = %q, want %q", tt.queueArn, got, tt.want)
			}
		})
	}
}

func TestIsSupportedAnalyzerType(t *testing.T) {
	tests := []struct {
		name         string
		analyzerType types.Type
		want         bool
	}{
		{name: "account", analyzerType: types.TypeAccount, want: true},
		{name: "organization", analyzerType: types.TypeOrganization, want: true},
		{name: "account unused access", analyzerType: types.Type("ACCOUNT_UNUSED_ACCESS"), want: false},
		{name: "organization unused access", analyzerType: types.Type("ORGANIZATION_UNUSED_ACCESS"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSupportedAnalyzerType(tt.analyzerType); got != tt.want {
				t.Errorf("isSupportedAnalyzerType(%q) = %t, want %t", tt.analyzerType, got, tt.want)
			}
		})
	}
}
