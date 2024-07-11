package cloudsploit

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseDefaultCloudsploitSetting(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *CloudsploitSetting
		wantErr bool
	}{
		{
			name: "Valid YAML",
			input: []byte(`
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
`),
			want: &CloudsploitSetting{
				DefaultScore: 5.0,
				IgnorePlugin: []string{"plugin1", "plugin2"},
				SpecificPluginSetting: map[string]PluginSetting{
					"plugin3": {
						Score:                   ptr(float32(7.5)),
						SkipResourceNamePattern: ptr("test.*"),
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
			result, err := parseDefaultCloudsploitSetting(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseDefaultCloudsploitSetting() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if diff := cmp.Diff(tt.want, result); diff != "" {
					t.Errorf("parseDefaultCloudsploitSetting() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// Helper function: return pointer of a value
func ptr[T any](v T) *T {
	return &v
}
