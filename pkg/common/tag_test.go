package common

import (
	"testing"
)

func TestGetAWSServiceTagByResourceName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "EC2",
			input: "ec2/any",
			want:  TagEC2,
		},
		{
			name:  "EC2 upper case",
			input: "EC2/any",
			want:  TagEC2,
		},
		{
			name:  "IAM",
			input: "iam/any",
			want:  TagIAM,
		},
		{
			name:  "IAM upper case",
			input: "IAM/any",
			want:  TagIAM,
		},
		{
			name:  "S3",
			input: "s3/any",
			want:  TagS3,
		},
		{
			name:  "S3 upper",
			input: "S3/any",
			want:  TagS3,
		},
		{
			name:  "SQS",
			input: "sqs/any",
			want:  TagSQS,
		},
		{
			name:  "SQS upper",
			input: "SQS/any",
			want:  TagSQS,
		},
		{
			name:  "Lambda",
			input: "Lambda/any",
			want:  TagLambda,
		},
		{
			name:  "Lambda upper",
			input: "lambda/any",
			want:  TagLambda,
		},
		{
			name:  "Lambda",
			input: "kms/any",
			want:  TagKMS,
		},
		{
			name:  "Lambda upper",
			input: "KMS/any",
			want:  TagKMS,
		},
		{
			name:  "unkonwn",
			input: "any",
			want:  TagUnknown,
		},
		{
			name:  "blank",
			input: "",
			want:  TagUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetAWSServiceTagByResourceName(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
