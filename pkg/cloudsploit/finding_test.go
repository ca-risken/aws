package cloudsploit

import (
	"strings"
	"testing"
)

const (
	STRING_LENGTH_10  = "1234567890"
	STRING_LENGTH_50  = STRING_LENGTH_10 + STRING_LENGTH_10 + STRING_LENGTH_10 + STRING_LENGTH_10 + STRING_LENGTH_10
	STRING_LENGTH_100 = STRING_LENGTH_50 + STRING_LENGTH_50
	STRING_LENGTH_500 = STRING_LENGTH_100 + STRING_LENGTH_100 + STRING_LENGTH_100 + STRING_LENGTH_100 + STRING_LENGTH_100
	STRING_LENGTH_513 = STRING_LENGTH_500 + STRING_LENGTH_10 + "123"
)

var testHandler *SqsHandler

func init() {
	setting, err := LoadDefaultCloudsploitSetting()
	if err != nil {
		panic(err)
	}
	testHandler = &SqsHandler{
		cloudsploitSetting: setting,
	}
}

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
			got := testHandler.getScore(c.input)
			if c.want != got {
				t.Fatalf("Unexpected score: want=%v, got=%v", c.want, got)
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
			got := testHandler.getPluginTags(c.category, c.plugin)
			if strings.Join(c.want, ",") != strings.Join(got, ",") {
				t.Fatalf("Unexpected tags: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetResourceName(t *testing.T) {
	type args struct {
		resource  string
		category  string
		accountID string
	}
	cases := []struct {
		name  string
		input *args
		want  string
	}{
		{
			name: "OK",
			input: &args{
				resource:  "arn:aws:acm:ap-northeast-1:123456789012:certificate/xxxxxxxx",
				category:  "ACM",
				accountID: "123456789012",
			},
			want: "arn:aws:acm:ap-northeast-1:123456789012:certificate/xxxxxxxx",
		},
		{
			name: "Unkonwn",
			input: &args{
				resource:  "Unknown",
				category:  "ACM",
				accountID: "123456789012",
			},
			want: "123456789012/ACM/Unknown",
		},
		{
			name: "Over 512",
			input: &args{
				resource:  STRING_LENGTH_513,
				category:  "ACM",
				accountID: "123456789012",
			},
			want: STRING_LENGTH_513[:512],
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getResourceName(c.input.resource, c.input.category, c.input.accountID)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
