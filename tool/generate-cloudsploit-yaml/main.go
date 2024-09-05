package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ca-risken/aws/pkg/cloudsploit"
	"github.com/dop251/goja"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"gopkg.in/yaml.v3"
)

const (
	REPO_URL    = "https://github.com/aquasecurity/cloudsploit.git"
	TMP_DIR     = "./tmp"
	PLUGIN_DIR  = "plugins/aws"
	PLUGIN_FILE = "../../cloudsploit.yaml"
)

var (
	// parameters
	pluginDir  = ""
	pluginFile = ""
	commitHash = ""
)

func init() {
	pluginDir = PLUGIN_DIR
	if os.Getenv("PLUGIN_FILE") != "" {
		pluginFile = os.Getenv("PLUGIN_FILE")
	}

	pluginFile = PLUGIN_FILE
	if os.Getenv("PLUGIN_FILE") != "" {
		pluginFile = os.Getenv("PLUGIN_FILE")
	}

	if os.Getenv("COMMIT_HASH") != "" {
		commitHash = os.Getenv("COMMIT_HASH")
	}
}

func main() {
	// CloudSploitの最新プラグインを取得
	remotePlugin, err := getRemotePlugin()
	if err != nil {
		log.Fatalf("Failed to get remote plugin: %v", err)
	}
	currentPlugin, err := cloudsploit.LoadCloudsploitSetting(pluginFile)
	if err != nil {
		log.Fatalf("Failed to load current plugin: %v", err)
	}

	// データ更新（差分）
	err = updatePlugin(currentPlugin, remotePlugin)
	if err != nil {
		log.Fatalf("Failed to update plugin: %v", err)
	}
	fmt.Println("Completed processing and cleaned up temporary files.")
}

func getRemotePlugin() (*cloudsploit.CloudsploitSetting, error) {
	err := os.MkdirAll(TMP_DIR, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(TMP_DIR)

	// tmpディレクトリにクローン
	repoDir := filepath.Join(TMP_DIR, "cloudsploit")
	_, err = git.PlainClone(repoDir, false, &git.CloneOptions{
		URL:      REPO_URL,
		Progress: os.Stdout,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to clone repo: %v", err)
	}

	// 指定されたcommit hashにチェックアウト
	if commitHash != "" {
		repo, err := git.PlainOpen(repoDir)
		if err != nil {
			return nil, fmt.Errorf("Failed to open repository: %v", err)
		}
		worktree, err := repo.Worktree()
		if err != nil {
			return nil, fmt.Errorf("Failed to get worktree: %v", err)
		}
		err = worktree.Checkout(&git.CheckoutOptions{
			Hash: plumbing.NewHash(commitHash),
		})
		if err != nil {
			return nil, fmt.Errorf("Failed to checkout commit %s: %v", commitHash, err)
		}
	}

	// プラグインディレクトリを処理 (plugins/aws/{service}/{plugin}.js)
	setting, err := processServices(filepath.Join(repoDir, pluginDir))
	if err != nil {
		return nil, fmt.Errorf("Failed to process JS files: %v", err)
	}
	return setting, nil
}

func processServices(baseDir string) (*cloudsploit.CloudsploitSetting, error) {
	setting := cloudsploit.CloudsploitSetting{
		DefaultScore:          3,
		SpecificPluginSetting: map[string]cloudsploit.PluginSetting{},
	}
	// ディレクトリを再帰的に探索するための関数
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".js") && !strings.HasSuffix(info.Name(), ".spec.js") {
			plugin, pluginSetting, err := extractPluginInfo(path)
			if err != nil {
				log.Printf("Failed to process file %s: %v", path, err)
			}
			setting.SpecificPluginSetting[plugin] = *pluginSetting
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}
	return &setting, nil
}

func extractPluginInfo(filePath string) (string, *cloudsploit.PluginSetting, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read file: %w", err)
	}

	// GojaのVMを作成
	vm := goja.New()
	if err := vm.Set("require", func(call goja.FunctionCall) goja.Value {
		return goja.Undefined() // requiredは無視
	}); err != nil {
		return "", nil, fmt.Errorf("failed to set 'require': %w", err)
	}

	// module.exportsを模倣する
	script := fmt.Sprintf(`const module = {}; %s; module.exports;`, string(data))
	v, err := vm.RunString(script)
	if err != nil {
		return "", nil, fmt.Errorf("JavaScript execution error: %w", err)
	}
	obj := v.ToObject(vm)

	// PluginSettingを作成
	service := obj.Get("category").String()
	plugin := strings.TrimSuffix(filepath.Base(filePath), ".js")
	pluginFullName := fmt.Sprintf("%s/%s", service, plugin)
	pluginSetting := cloudsploit.PluginSetting{
		Score: ptr(float32(3)),
		Tags:  []string{},
		Recommend: &cloudsploit.PluginRecommend{
			Risk: ptr(generateRisk(
				obj.Get("title").String(),
				obj.Get("description").String(),
				obj.Get("more_info").String(),
			)),
			Recommendation: ptr(generateRecommendation(
				obj.Get("recommended_action").String(),
				obj.Get("link").String(),
			)),
		},
	}
	return pluginFullName, &pluginSetting, nil
}

func generateRisk(title, description, moreInfo string) string {
	risk := fmt.Sprintf("%s\n- %s", title, description)
	if moreInfo != "" {
		risk += fmt.Sprintf("\n- %s", moreInfo)
	}
	return risk
}

func generateRecommendation(recommendedAction, link string) string {
	recommendation := recommendedAction
	if link != "" {
		recommendation += fmt.Sprintf("\n- %s", link)
	}
	return recommendation
}

func updatePlugin(currentPlugin, remotePlugin *cloudsploit.CloudsploitSetting) error {
	newSetting := cloudsploit.CloudsploitSetting{
		DefaultScore:          currentPlugin.DefaultScore,
		IgnorePlugin:          currentPlugin.IgnorePlugin,
		SpecificPluginSetting: map[string]cloudsploit.PluginSetting{}, // プラグインは空にしておく
	}

	// 削除されたプラグイン
	deletedPlugins := map[string]bool{}
	for pluginFullName := range currentPlugin.SpecificPluginSetting {
		if _, ok := remotePlugin.SpecificPluginSetting[pluginFullName]; !ok {
			deletedPlugins[pluginFullName] = true
			log.Printf("Deleted plugin: %s", pluginFullName)
		}
	}

	// プラグインをソート
	sortedPlugins := []string{}
	for pluginFullName := range remotePlugin.SpecificPluginSetting {
		sortedPlugins = append(sortedPlugins, pluginFullName)
	}
	sort.Strings(sortedPlugins)

	// プラグインを更新
	for _, pluginFullName := range sortedPlugins {
		if _, ok := deletedPlugins[pluginFullName]; ok {
			continue // 削除されたプラグインはスキップ
		}
		if _, ok := currentPlugin.SpecificPluginSetting[pluginFullName]; ok {
			// 既存のプラグインはそのまま
			current := currentPlugin.SpecificPluginSetting[pluginFullName]
			newSetting.SpecificPluginSetting[pluginFullName] = cloudsploit.PluginSetting{
				Score:                   current.Score,
				Tags:                    current.Tags,
				SkipResourceNamePattern: current.SkipResourceNamePattern,
				IgnoreMessagePattern:    current.IgnoreMessagePattern,
				Recommend: &cloudsploit.PluginRecommend{
					Risk:           current.Recommend.Risk,
					Recommendation: current.Recommend.Recommendation,
				},
			}
		} else {
			// 新しいプラグインの場合は追加
			new := remotePlugin.SpecificPluginSetting[pluginFullName]
			newSetting.SpecificPluginSetting[pluginFullName] = cloudsploit.PluginSetting{
				Score:                   new.Score,
				Tags:                    new.Tags,
				SkipResourceNamePattern: new.SkipResourceNamePattern,
				IgnoreMessagePattern:    new.IgnoreMessagePattern,
				Recommend: &cloudsploit.PluginRecommend{
					Risk:           new.Recommend.Risk,
					Recommendation: new.Recommend.Recommendation,
				},
			}
		}
	}

	// 更新されたYAMLをファイルに書き込む
	file, err := os.Create(pluginFile)
	if err != nil {
		return fmt.Errorf("failed to create YAML file: %w", err)
	}
	defer file.Close()
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2) // インデントをスペース2つに設定
	err = encoder.Encode(newSetting)
	if err != nil {
		return fmt.Errorf("failed to encode updated YAML: %w", err)
	}
	return nil
}

func ptr[T any](v T) *T {
	return &v
}
