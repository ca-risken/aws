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

	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var results []cloudSploitResult
	if err := json.Unmarshal(buf, &results); err != nil {
		str := string(buf)
		errMsg := fmt.Sprintf("Failed to parse scan results: err=%v", err)
		if len(str) > 10 {
			errMsg += fmt.Sprintf(", length=%d, suffix=%s", len(str), str[len(str)-10:])
		}
		c.logger.Errorf(ctx, errMsg)
		return nil, err
	}
	// delete result
	if err := os.Remove(filePath); err != nil {
		c.logger.Warnf(ctx, "Failed to delete result file. error: %v", err)
	}

	// delete config
	if err := os.Remove(c.ConfigPath); err != nil {
		c.logger.Warnf(ctx, "Failed to delete config file. error: %v", err)
	}

	return &results, nil
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

const (
	STATUS_UNKNOWN = "UNKNOWN"
	WARN_MESSAGE   = "UNKNOWN status detected. Some scans may have failed. Please take action if you don't have enough permissions."
)

func unknownFindings(findings *[]cloudSploitResult) string {
	unknowns := map[string]int{}
	for _, f := range *findings {
		if f.Status == STATUS_UNKNOWN {
			unknowns[fmt.Sprintf("%s: %s", f.Category, f.Message)]++
		}
	}
	statusDetail := ""
	for k := range unknowns {
		statusDetail += fmt.Sprintf("- %s\n", k)
	}
	if statusDetail != "" {
		statusDetail = fmt.Sprintf("%s\n\n%s", WARN_MESSAGE, statusDetail)
	}
	return statusDetail
}
