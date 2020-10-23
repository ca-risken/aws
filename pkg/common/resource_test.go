package common

import (
	"testing"
)

func TestGetResourceName(t *testing.T) {
	cases := []struct {
		name          string
		inputType     AWSService
		inputAccount  string
		inputResource string
		want          string
	}{
		{
			name:          "EC2",
			inputType:     EC2,
			inputAccount:  "123456789012",
			inputResource: "name",
			want:          "ec2/123456789012/name",
		},
		{
			name:          "S3",
			inputType:     S3,
			inputAccount:  "123456789012",
			inputResource: "name",
			want:          "s3/123456789012/name",
		},
		{
			name:          "IAM",
			inputType:     IAM,
			inputAccount:  "123456789012",
			inputResource: "name",
			want:          "iam/123456789012/name",
		},
		{
			name:          "SQS",
			inputType:     SQS,
			inputAccount:  "123456789012",
			inputResource: "name",
			want:          "sqs/123456789012/name",
		},
		{
			name:          "Lambda",
			inputType:     Lambda,
			inputAccount:  "123456789012",
			inputResource: "name",
			want:          "lambda/123456789012/name",
		},
		{
			name:          "KMS",
			inputType:     KMS,
			inputAccount:  "123456789012",
			inputResource: "name",
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
