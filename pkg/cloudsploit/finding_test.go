package cloudsploit

import (
	"strings"
	"testing"
)

func TestGetScore(t *testing.T) {
	cases := []struct {
		name  string
		input *cloudSploitResult
		want  float32
	}{
		{
			name: "OK",
			input: &cloudSploitResult{
				Status:    "OK",
				Category:  "ACM",
				Plugin:    "acmCertificateExpiry",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
			},
			want: 0.0,
		}, {
			name: "WARN",
			input: &cloudSploitResult{
				Status:    "WARN",
				Category:  "ACM",
				Plugin:    "acmCertificateExpiry",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
			},
			want: 3.0,
		},
		{
			name: "UNKNOWN",
			input: &cloudSploitResult{
				Status:    "UNKNOWN",
				Category:  "ACM",
				Plugin:    "acmCertificateExpiry",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
			},
			want: 1.0,
		},
		{
			name: "Fail match Map",
			input: &cloudSploitResult{
				Status:    "FAIL",
				Category:  "ACM",
				Plugin:    "acmCertificateExpiry",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
			},
			want: 6.0,
		},
		{
			name: "Fail not match Map",
			input: &cloudSploitResult{
				Status:    "FAIL",
				Category:  "ACM",
				Plugin:    "unknown plugin",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
			},
			want: 3.0,
		},
		{
			name: "Fail SecurityGroup",
			input: &cloudSploitResult{
				Status:    "FAIL",
				Category:  "EC2",
				Plugin:    "openAllPortsProtocols",
				Resource:  "arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-xxxxxxxx",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
				SecurityGroupAttachedResources: []string{
					"eni-xxxxxxxxxx (RDS NetworkInterface)",
					"eni-xxxxxxxxxx (EKS NetworkInterface)",
				},
			},
			want: 8.0,
		},
		{
			name: "Fail unused SecurityGroup",
			input: &cloudSploitResult{
				Status:    "FAIL",
				Category:  "EC2",
				Plugin:    "openAllPortsProtocols",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
				Resource:  "arn:aws:ec2:ap-northeast-1:123456789012:security-group/sg-xxxxxxxx",
			},
			want: 1.0,
		},
		{
			name: "Fail iamRoleLastUsed but managed role",
			input: &cloudSploitResult{
				Status:    "FAIL",
				Category:  "IAM",
				Plugin:    "iamRoleLastUsed",
				Region:    "ap-northeast-1",
				AccountID: "123456789012",
				Resource:  "arn:aws:iam::123456789012:role/aws-service-role/managed-role",
			},
			want: 1.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getScore(c.input)
			if c.want != got {
				t.Fatalf("Unexpected category name: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetComplianceTag(t *testing.T) {
	cases := []struct {
		name     string
		category string
		plugin   string
		want     []string
	}{
		{
			name:     "match Map Exist Tag",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     []string{"pci", "reliability"},
		}, {
			name:     "match Map Not Exist Tag",
			category: "RDS",
			plugin:   "sqlServerTLSVersion",
			want:     []string{},
		},
		{
			name:     "not match Map",
			category: "ACM",
			plugin:   "hogehogehoge",
			want:     []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getPluginTags(c.category, c.plugin)
			if strings.Join(c.want, ",") != strings.Join(got, ",") {
				t.Fatalf("Unexpected category name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
