package cloudsploit

import (
	"embed"

	"github.com/ca-risken/common/pkg/cloudsploit"
)

//go:generate cp ../../cloudsploit.yaml ./yaml/

//go:embed yaml/cloudsploit.yaml
var _ embed.FS

const (
	CLOUDSPLOIT_FILE = "yaml/cloudsploit.yaml"
)

func loadCloudsploitSetting(path string) (*cloudsploit.CloudsploitSetting, error) {
	if path == "" {
		path = CLOUDSPLOIT_FILE
	}
	return cloudsploit.LoadCloudsploitSetting(path)
}
