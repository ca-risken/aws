package accessanalyzer

import "testing"

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
