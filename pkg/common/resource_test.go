package common

import (
	"testing"
)

func TestGetResourceName(t *testing.T) {
	accountID := "123456789012"
	resourceName := "name"
	cases := []struct {
		name          string
		inputType     AWSService
		inputAccount  string
		inputResource string
		want          string
	}{
		{
			name:          "Unknown",
			inputType:     Unknown,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "unknown/123456789012/name",
		},
		{
			name:          "EC2",
			inputType:     EC2,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "ec2/123456789012/name",
		},
		{
			name:          "S3",
			inputType:     S3,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "s3/123456789012/name",
		},
		{
			name:          "IAM",
			inputType:     IAM,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "iam/123456789012/name",
		},
		{
			name:          "SQS",
			inputType:     SQS,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "sqs/123456789012/name",
		},
		{
			name:          "Lambda",
			inputType:     Lambda,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "lambda/123456789012/name",
		},
		{
			name:          "KMS",
			inputType:     KMS,
			inputAccount:  accountID,
			inputResource: resourceName,
			want:          "kms/123456789012/name",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetResourceName(c.inputType, c.inputAccount, c.inputResource)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
