package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/gassara-kys/envconfig"
)

type cloudsploitConfig struct {
	ResultDir      string `required:"true" split_words:"true" default:"/tmp"`
	ConfigDir      string `required:"true" split_words:"true" default:"/tmp"`
	CloudsploitDir string `required:"true" split_words:"true" default:"/opt/cloudsploit"`
	AWSRegion      string `envconfig:"aws_region"             default:"ap-northeast-1"`
	ConfigPath     string
}

func newcloudsploitConfig(assumeRole, externalID string, awsID uint32, accountID string) (cloudsploitConfig, error) {
	var conf cloudsploitConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return conf, err
	}
	configPath, err := conf.makeConfig(conf.AWSRegion, assumeRole, externalID, awsID, accountID)
	if err != nil {
		return conf, err
	}
	conf.ConfigPath = configPath
	return conf, nil
}

func (c *cloudsploitConfig) run(accountID string) (*[]cloudSploitResult, error) {
	now := time.Now().UnixNano()
	filePath := fmt.Sprintf("%v/%v_%v.json", c.ResultDir, accountID, now)
	cmd := exec.Command(fmt.Sprintf("%v/index.js", c.CloudsploitDir),
		"--config", c.ConfigPath,
		"--console", "none",
		"--json", filePath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	if err != nil {
		appLogger.Errorf("Failed to execute theHarvester. stderr: %v", stderr.String())
		appLogger.Errorf("Failed exec cloudsploit. error: %v", err)
		return nil, fmt.Errorf("Failed exec cloudsploit. error: %v", err)
	}

	bytes, err := readFile(filePath)
	if err != nil {
		return nil, err
	}
	var results []cloudSploitResult
	if err := json.Unmarshal(bytes, &results); err != nil {
		appLogger.Errorf("Failed to parse scan results. error: %v", err)
		return nil, err
	}
	// delete result
	err = deleteFile(filePath)
	if err != nil {
		appLogger.Warnf("Failed to delete result file. error: %v", err)
	}
	// delete config
	err = deleteFile(c.ConfigPath)
	if err != nil {
		appLogger.Warnf("Failed to delete config file. error: %v", err)
	}

	return &results, nil
}

func readFile(fileName string) ([]byte, error) {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func deleteFile(fileName string) error {
	if err := os.Remove(fileName); err != nil {
		return err
	}
	return nil
}

type cloudSploitResult struct {
	Plugin      string
	Category    string
	Title       string
	Description string
	Resource    string
	Region      interface{}
	Status      string
	Message     string
}
