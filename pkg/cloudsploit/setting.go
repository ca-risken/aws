package cloudsploit

import (
	"embed"
	"os"
	"regexp"
	"slices"
	"strings"

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
	SpecificPluginSetting map[string]PluginSetting `yaml:"specificPluginSetting,omitempty" validate:"dive"`
}

type PluginSetting struct {
	Score                   *float32         `yaml:"score,omitempty"`
	SkipResourceNamePattern []string         `yaml:"skipResourceNamePattern,omitempty"`
	IgnoreMessagePattern    []string         `yaml:"ignoreMessagePattern,omitempty" validate:"dive,regexp"`
	Tags                    []string         `yaml:"tags,omitempty"`
	Recommend               *PluginRecommend `yaml:"recommend,omitempty"`
}

type PluginRecommend struct {
	Risk           *string `yaml:"risk,omitempty"`
	Recommendation *string `yaml:"recommendation,omitempty"`
}

func LoadCloudsploitSetting(path string) (*CloudsploitSetting, error) {
	data, err := readCloudsploitSetting(path)
	if err != nil {
		return nil, err
	}

	setting, err := parseCloudsploitSettingYaml(data)
	if err != nil {
		return nil, err
	}
	return setting, nil
}

func readCloudsploitSetting(path string) ([]byte, error) {
	var data []byte
	var err error

	if path != "" {
		data, err = os.ReadFile(path) // Read from path
	} else {
		data, err = static.ReadFile(CLOUDSPLOIT_FILE) // Read from default
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func validateRegexp(fl validator.FieldLevel) bool {
	pattern, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	_, err := regexp.Compile(pattern)
	return err == nil
}

func parseCloudsploitSettingYaml(data []byte) (*CloudsploitSetting, error) {
	var setting CloudsploitSetting
	if err := yaml.Unmarshal(data, &setting); err != nil {
		return nil, err
	}

	// validate
	validate := validator.New()
	if err := validate.RegisterValidation("regexp", validateRegexp); err != nil {
		return nil, err
	}
	if err := validate.Struct(setting); err != nil {
		return nil, err
	}
	return &setting, nil
}

func (c *CloudsploitSetting) IsIgnorePlugin(plugin string) bool {
	return slices.Contains(c.IgnorePlugin, plugin)
}

func (c *CloudsploitSetting) IsSkipResourceNamePattern(plugin, resourceName, aliasResourceName string) bool {
	if c.SpecificPluginSetting[plugin].SkipResourceNamePattern == nil {
		return false
	}
	for _, pattern := range c.SpecificPluginSetting[plugin].SkipResourceNamePattern {
		if strings.Contains(resourceName, pattern) {
			return true
		}
		if aliasResourceName != "" && strings.Contains(aliasResourceName, pattern) {
			return true
		}
	}
	return false
}

func (c *CloudsploitSetting) IsIgnoreMessagePattern(plugin string, messages []string) bool {
	if c.SpecificPluginSetting[plugin].IgnoreMessagePattern == nil {
		return false
	}
	for _, pattern := range c.SpecificPluginSetting[plugin].IgnoreMessagePattern {
		for _, message := range messages {
			matched, err := regexp.MatchString(pattern, message)
			if err != nil {
				return false
			}
			if matched {
				return true // match == ignore finding
			}
		}
	}
	return false
}
