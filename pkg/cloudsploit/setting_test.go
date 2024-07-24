package cloudsploit

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	TEST_YAML = `
defaultScore: 5.0
ignorePlugin:
  - plugin1
  - plugin2
specificPluginSetting:
  plugin3:
    score: 7.5
    skipResourceNamePattern: "test.*"
    tags:
      - tag1
      - tag2
    recommend:
      risk: "High risk"
      recommendation: "Fix it"
`
)

func TestParseDefaultCloudsploitSetting(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *CloudsploitSetting
		wantErr bool
	}{
		{
			name:  "Valid YAML",
			input: []byte(TEST_YAML),
			want: &CloudsploitSetting{
				DefaultScore: 5.0,
				IgnorePlugin: []string{"plugin1", "plugin2"},
				SpecificPluginSetting: map[string]PluginSetting{
					"plugin3": {
						Score:                   ptr(float32(7.5)),
						SkipResourceNamePattern: []string{"test.*"},
						Tags:                    []string{"tag1", "tag2"},
						Recommend: &PluginRecommend{
							Risk:           ptr("High risk"),
							Recommendation: ptr("Fix it"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Invalid structure",
			input:   []byte("invalid: yaml: content:"),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Missing required field",
			input:   []byte("ignorePlugin: [plugin1]"),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Empty input",
			input:   []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Invalid YAML",
			input:   []byte("foo: [bar: baz}"),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseCloudsploitSettingYaml(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseCloudsploitSettingYaml() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, result); diff != "" {
					t.Errorf("parseCloudsploitSettingYaml() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestIsIgnorePlugin(t *testing.T) {
	type args struct {
		setting *CloudsploitSetting
		plugin  string
	}
	tests := []struct {
		name  string
		input args
		want  bool
	}{
		{
			name: "Ignore plugin",
			input: args{
				setting: &CloudsploitSetting{
					IgnorePlugin: []string{"plugin1", "plugin2"},
				},
				plugin: "plugin1",
			},
			want: true,
		},
		{
			name: "Not ignore plugin",
			input: args{
				setting: &CloudsploitSetting{
					IgnorePlugin: []string{"plugin1", "plugin2"},
				},
				plugin: "plugin3",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.setting.IsIgnorePlugin(tt.input.plugin); got != tt.want {
				t.Errorf("IsIgnorePlugin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSkipResourceNamePattern(t *testing.T) {
	type args struct {
		setting      *CloudsploitSetting
		plugin       string
		resourceName string
	}
	tests := []struct {
		name  string
		input args
		want  bool
	}{
		{
			name: "Skip resource name pattern matches",
			input: args{
				setting: &CloudsploitSetting{
					SpecificPluginSetting: map[string]PluginSetting{
						"plugin1": {
							SkipResourceNamePattern: []string{"ignore", "test"},
						},
					},
				},
				plugin:       "plugin1",
				resourceName: "testResourceName",
			},
			want: true,
		},
		{
			name: "Skip resource name pattern does not match",
			input: args{
				setting: &CloudsploitSetting{
					SpecificPluginSetting: map[string]PluginSetting{
						"plugin1": {
							SkipResourceNamePattern: []string{"ignore", "test"},
						},
					},
				},
				plugin:       "plugin1",
				resourceName: "resourceName",
			},
			want: false,
		},
		{
			name: "No skip resource name pattern",
			input: args{
				setting: &CloudsploitSetting{
					SpecificPluginSetting: map[string]PluginSetting{
						"plugin1": {},
					},
				},
				plugin:       "plugin1",
				resourceName: "resourceName",
			},
			want: false,
		},
		{
			name: "Plugin not found",
			input: args{
				setting: &CloudsploitSetting{
					SpecificPluginSetting: map[string]PluginSetting{},
				},
				plugin:       "plugin1",
				resourceName: "resourceName",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.input.setting.IsSkipResourceNamePattern(tt.input.plugin, tt.input.resourceName); got != tt.want {
				t.Errorf("IsSkipResourceNamePattern() = %v, want %v", got, tt.want)
			}
		})
	}

}

// Helper function: return pointer of a value
func ptr[T any](v T) *T {
	return &v
}
