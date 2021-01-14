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
			input: "arn:partition:ec2:region:account-id:resource-name",
			want:  "ec2",
		},
		{
			name:  "IAM",
			input: "arn:partition:iam:region:account-id:resource-name",
			want:  "iam",
		},
		{
			name:  "Trim",
			input: "arn:partition:    iam      :region:account-id:resource-name",
			want:  "iam",
		},
		{
			name:  "Lower case",
			input: "arn:partition:IAM:region:account-id:resource-name",
			want:  "iam",
		},
		{
			name:  "invalid format 1",
			input: "arn:partition iam region account-id resource-name",
			want:  TagUnknown,
		},
		{
			name:  "invalid format 2",
			input: "arn/partition/iam/region/account-id/resource-name",
			want:  TagUnknown,
		},
		{
			name:  "Unkonwn",
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
			got := GetAWSServiceTagByARN(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
