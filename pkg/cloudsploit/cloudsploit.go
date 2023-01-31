package cloudsploit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/ca-risken/common/pkg/logging"
)

type CloudsploitConfig struct {
	ResultDir      string
	ConfigDir      string
	CloudsploitDir string
	AWSRegion      string
	ConfigPath     string
	MaxMemSizeMB   int
	logger         logging.Logger
}

func NewCloudsploitConfig(
	resultDir string,
	configDir string,
	cloudsploitDir string,
	region string,
	maxMem int,
	l logging.Logger,
) *CloudsploitConfig {
	return &CloudsploitConfig{
		ResultDir:      resultDir,
		ConfigDir:      configDir,
		CloudsploitDir: cloudsploitDir,
		AWSRegion:      region,
		MaxMemSizeMB:   maxMem,
		logger:         l,
	}
}

func (c *CloudsploitConfig) run(ctx context.Context, accountID string) (*[]cloudSploitResult, error) {
	now := time.Now().UnixNano()
	if c.MaxMemSizeMB > 0 {
		os.Setenv("NODE_OPTIONS", fmt.Sprintf("--max-old-space-size=%d", c.MaxMemSizeMB))
	}
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
		return nil, fmt.Errorf("failed exec cloudsploit. error: %+v, detail: %s", err, stderr.String())
	}

	bytes, err := readFile(filePath)
	if err != nil {
		return nil, err
	}
	var results []cloudSploitResult
	if err := json.Unmarshal(bytes, &results); err != nil {
		c.logger.Errorf(ctx, "Failed to parse scan results. error: %v", err)
		return nil, err
	}
	// delete result
	err = deleteFile(filePath)
	if err != nil {
		c.logger.Warnf(ctx, "Failed to delete result file. error: %v", err)
	}
	// delete config
	err = deleteFile(c.ConfigPath)
	if err != nil {
		c.logger.Warnf(ctx, "Failed to delete config file. error: %v", err)
	}

	return &results, nil
}

func readFile(fileName string) ([]byte, error) {
	bytes, err := os.ReadFile(fileName)
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