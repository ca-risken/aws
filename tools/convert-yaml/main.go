package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/ca-risken/aws/pkg/cloudsploit"
	"gopkg.in/yaml.v3"
)

func main() {
	// 初期化
	cloudsploitYaml := cloudsploit.CloudsploitSetting{
		DefaultScore:          3.0,
		IgnorePlugin:          []string{"ecr/ecrRepositoryPolicy"},
		SpecificPluginSetting: map[string]cloudsploit.PluginSetting{},
	}

	// プラグイン設定
	for plugin, data := range cloudsploit.CloudSploitFindingMap {
		score := data.Score
		pluginSetting := cloudsploit.PluginSetting{}
		if score != 3.0 {
			pluginSetting.Score = &score
		}
		if len(data.Tags) > 0 {
			pluginSetting.Tags = data.Tags
		}
		if recommend, ok := cloudsploit.RecommendMap[plugin]; ok {
			trimmedRisk := trimMultilineString(recommend.Risk)
			trimmedRecommendation := trimMultilineString(recommend.Recommendation)
			pluginSetting.Recommend = &cloudsploit.PluginRecommend{
				Risk:           &trimmedRisk,
				Recommendation: &trimmedRecommendation,
			}
		}
		cloudsploitYaml.SpecificPluginSetting[plugin] = pluginSetting
	}

	// yaml出力
	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(2)
	if err := encoder.Encode(cloudsploitYaml); err != nil {
		panic(err)
	}
}

var whitespaceRegex = regexp.MustCompile(`^\s+|\s+$`)

// 複数行の文字列をトリムする関数
func trimMultilineString(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = whitespaceRegex.ReplaceAllString(strings.TrimSpace(line), "")
	}
	return strings.Join(lines, "\n")
}
