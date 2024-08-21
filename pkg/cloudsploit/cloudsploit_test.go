package cloudsploit

import (
	"context"
	"reflect"
	"testing"

	"github.com/ca-risken/common/pkg/logging"
)

func TestRemoveIgnorePlugin(t *testing.T) {
	testHandler := &SqsHandler{
		logger: logging.NewLogger(),
		cloudsploitSetting: &CloudsploitSetting{
			IgnorePlugin: []string{"category/ignorePlugin"},
			SpecificPluginSetting: map[string]PluginSetting{
				"category/plugin1": {
					SkipResourceNamePattern: []string{"ignore", "test"},
				},
			},
		},
	}
	type args struct {
		findings []*cloudSploitResult
	}
	tests := []struct {
		name  string
		input args
		want  []*cloudSploitResult
	}{
		{
			name: "OK",
			input: args{
				findings: []*cloudSploitResult{
					{Category: "category", Plugin: "plugin1", Resource: "resourceName"},
					{Category: "category", Plugin: "plugin2", Resource: "resourceName"},
				},
			},
			want: []*cloudSploitResult{
				{Category: "category", Plugin: "plugin1", Resource: "resourceName"},
				{Category: "category", Plugin: "plugin2", Resource: "resourceName"},
			},
		},
		{
			name: "Ignore plugin",
			input: args{
				findings: []*cloudSploitResult{
					{Category: "category", Plugin: "ignorePlugin", Resource: "resourceName"},
				},
			},
			want: []*cloudSploitResult{},
		},
		{
			name: "Ignore resource name pattern",
			input: args{
				findings: []*cloudSploitResult{
					{Category: "category", Plugin: "plugin1", Resource: "ignoreResourceName"},
				},
			},
			want: []*cloudSploitResult{},
		},
		{
			name: "Ignore resource name pattern2",
			input: args{
				findings: []*cloudSploitResult{
					{Category: "category", Plugin: "plugin1", Resource: "testResourceName"},
				},
			},
			want: []*cloudSploitResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testHandler.removeIgnorePlugin(context.Background(), tt.input.findings); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("removeIgnorePlugin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSecurityGroupResource(t *testing.T) {
	tests := []struct {
		name   string
		result *cloudSploitResult
		want   bool
	}{
		{
			name: "OK",
			result: &cloudSploitResult{
				Resource:  "arn:aws:ec2:us-west-2:123456789012:security-group/sg-12345678",
				Region:    "us-west-2",
				AccountID: "123456789012",
			},
			want: true,
		},
		{
			name: "Invalid region",
			result: &cloudSploitResult{
				Resource:  "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678",
				Region:    "us-west-2",
				AccountID: "123456789012",
			},
			want: false,
		},
		{
			name: "Invalid account ID",
			result: &cloudSploitResult{
				Resource:  "arn:aws:ec2:us-west-2:987654321098:security-group/sg-12345678",
				Region:    "us-west-2",
				AccountID: "123456789012",
			},
			want: false,
		},
		{
			name: "Not security group resource",
			result: &cloudSploitResult{
				Resource:  "arn:aws:s3:::my-bucket",
				Region:    "us-west-2",
				AccountID: "123456789012",
			},
			want: false,
		},
		{
			name: "Invalid security group ID",
			result: &cloudSploitResult{
				Resource:  "arn:aws:ec2:us-west-2:123456789012:security-group/invalid-12345678",
				Region:    "us-west-2",
				AccountID: "123456789012",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSecurityGroupResource(tt.result); got != tt.want {
				t.Errorf("isSecurityGroupResource() = %v, want %v", got, tt.want)
			}
		})
	}
}
