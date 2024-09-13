package cloudsploit

import (
	"embed"

	"github.com/ca-risken/common/pkg/cloudsploit"
)

//go:generate cp ../../cloudsploit.yaml ./yaml/

//go:embed yaml/cloudsploit.yaml
var embeddedYaml embed.FS

const (
	CLOUDSPLOIT_FILE = "yaml/cloudsploit.yaml"
)

func loadCloudsploitSetting(path string) (*cloudsploit.CloudsploitSetting, error) {
	if path != "" {
		return cloudsploit.LoadCloudsploitSetting(path)
	}

	// default setting
	yamlFile, err := embeddedYaml.ReadFile(CLOUDSPLOIT_FILE)
	if err != nil {
		return nil, err
	}
	return cloudsploit.ParseCloudsploitSettingYaml(yamlFile)
}
