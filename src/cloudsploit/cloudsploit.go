package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type cloudsploitConfig struct {
	ResultDir      string `required:"true" split_words:"true"`
	ConfigDir      string `required:"true" split_words:"true"`
	CloudsploitDir string `required:"true" split_words:"true"`
	AWSRegion      string `envconfig:"aws_region" default:"ap-northeast-1"`
	ConfigPath     string
}

func newcloudsploitConfig(assumeRole, externalID string) (cloudsploitConfig, error) {
	var conf cloudsploitConfig
	err := envconfig.Process("", &conf)
	if err != nil {
		return conf, err
	}
	configPath, err := conf.makeConfig(conf.AWSRegion, assumeRole, externalID)
	if err != nil {
		return conf, err
	}
	conf.ConfigPath = configPath
	return conf, nil
}

func (c *cloudsploitConfig) run(accountID string) (*[]cloudSploitResult, error) {
	now := time.Now().Unix()
	filePath := fmt.Sprintf("%v/%v_%v.json", c.ResultDir, accountID, now)
	cmd := exec.Command(fmt.Sprintf("%v/index.js", c.CloudsploitDir), "--config", c.ConfigPath, "--console", "none", "--json", filePath)
	err := cmd.Run()
	if err != nil {
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
	//	err = deleteFile(filePath)
	//	if err != nil {
	//		return nil, err
	//	}
	// delete config
	err = deleteFile(c.ConfigPath)
	if err != nil {
		return nil, err
	}

	return &results, nil
}

func (c *cloudsploitConfig) tmpRun(accountID string) (*[]cloudSploitResult, error) {
	bytes, err := readFile("/tmp/hogehoge.json")
	if err != nil {
		return nil, err
	}
	var results []cloudSploitResult
	if err := json.Unmarshal(bytes, &results); err != nil {
		appLogger.Errorf("Failed to parse scan results. error: %v", err)
		return nil, err
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
