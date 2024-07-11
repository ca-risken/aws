package cloudsploit

import (
	"embed"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

//go:generate cp ../../cloudsploit.yaml ./yaml/

//go:embed yaml/cloudsploit.yaml
var static embed.FS

const (
	CLOUDSPLOIT_FILE = "yaml/cloudsploit.yaml"
)

type CloudsploitSetting struct {
	DefaultScore          float32                  `yaml:"defaultScore" validate:"required"`
	IgnorePlugin          []string                 `yaml:"ignorePlugin"`
	SpecificPluginSetting map[string]PluginSetting `yaml:"specificPluginSetting,omitempty"`
}

type PluginSetting struct {
	Score                   *float32         `yaml:"score,omitempty"`
	SkipResourceNamePattern *string          `yaml:"skipResourceNamePattern,omitempty"`
	Tags                    []string         `yaml:"tags,omitempty"`
	Recommend               *PluginRecommend `yaml:"recommend,omitempty"`
}

type PluginRecommend struct {
	Risk           *string `yaml:"risk,omitempty"`
	Recommendation *string `yaml:"recommendation,omitempty"`
}

func LoadDefaultCloudsploitSetting() (*CloudsploitSetting, error) {
	data, err := readDefaultCloudsploitSetting()
	if err != nil {
		return nil, err
	}

	setting, err := parseDefaultCloudsploitSetting(data)
	if err != nil {
		return nil, err
	}
	return setting, nil
}

func readDefaultCloudsploitSetting() ([]byte, error) {
	data, err := static.ReadFile(CLOUDSPLOIT_FILE)
	if err != nil {
		return nil, err
	}
	return data, nil
}

var validate = validator.New()

func parseDefaultCloudsploitSetting(data []byte) (*CloudsploitSetting, error) {
	var setting CloudsploitSetting
	if err := yaml.Unmarshal(data, &setting); err != nil {
		return nil, err
	}

	// validate
	if err := validate.Struct(setting); err != nil {
		return nil, err
	}
	return &setting, nil
}
