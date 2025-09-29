package accessanalyzer

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

//go:generate cp ../../dlp.yaml ./yaml/
//go:generate cp ../../fingerprint.yaml ./yaml/

//go:embed yaml/dlp.yaml
var embeddedDLPYaml embed.FS

//go:embed yaml/fingerprint.yaml
var embeddedFingerprintYaml embed.FS

const (
	DEFAULT_DLP_CONFIG_FILE  = "yaml/dlp.yaml"
	DEFAULT_FINGERPRINT_FILE = "yaml/fingerprint.yaml"
)

// DLPConfig represents the complete DLP configuration
type DLPConfig struct {
	MaxScanFiles         int       `yaml:"max_scan_files" validate:"required,gt=0"`
	MaxScanSizeMB        int       `yaml:"max_scan_size_mb" validate:"required,gt=0"`
	MaxSingleFileSizeMB  int       `yaml:"max_single_file_size_mb" validate:"required,gt=0"`
	MaxMatchesPerFinding int       `yaml:"max_matches_per_finding" validate:"required,gt=0"`
	ExcludeFilePatterns  []string  `yaml:"exclude_file_patterns"`
	FingerprintFilePath  string    `yaml:"fingerprint_file_path,omitempty"` // Optional external fingerprint file
	Rules                []DLPRule `yaml:"rules,omitempty" validate:"dive"` // Optional when using external fingerprint
}

// DLPRule represents a single DLP rule
type DLPRule struct {
	Name               string              `yaml:"name" validate:"required,min=1"`
	Description        string              `yaml:"description"`
	Type               string              `yaml:"type"`
	SeverityThresholds *SeverityThresholds `yaml:"severity_thresholds,omitempty"`
}

// SeverityThresholds defines match count thresholds for different severity levels
type SeverityThresholds struct {
	Critical *int `yaml:"critical,omitempty"`
	High     *int `yaml:"high,omitempty"`
	Medium   *int `yaml:"medium,omitempty"`
	Low      *int `yaml:"low,omitempty"`
}

// LoadDLPConfig loads DLP configuration from file or default
func LoadDLPConfig(configPath string) (*DLPConfig, error) {
	var yamlData []byte
	var err error

	if configPath != "" {
		// Load from external file
		yamlData, err = os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read DLP config file %s: %w", configPath, err)
		}
	} else {
		// Load default embedded configuration
		yamlData, err = embeddedDLPYaml.ReadFile(DEFAULT_DLP_CONFIG_FILE)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded DLP config: %w", err)
		}

	}

	var config DLPConfig
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse DLP config YAML: %w", err)
	}

	// Validate configuration using validator
	validate := validator.New()
	if err := validate.Struct(&config); err != nil {
		return nil, fmt.Errorf("invalid DLP configuration: %w", err)
	}

	// Custom validation: must have either rules or fingerprint file path
	if len(config.Rules) == 0 && config.FingerprintFilePath == "" {
		return nil, fmt.Errorf("must specify either 'rules' or 'fingerprint_file_path' in DLP configuration")
	}

	return &config, nil
}

// GetScanSizeLimits returns size limits in bytes
func (c *DLPConfig) GetMaxScanSizeBytes() int64 {
	return int64(c.MaxScanSizeMB) * 1024 * 1024
}

func (c *DLPConfig) GetMaxSingleFileSizeBytes() int64 {
	return int64(c.MaxSingleFileSizeMB) * 1024 * 1024
}

// GenerateHawkeyeFingerprintYAML generates a fingerprint YAML for hawk-eye from the DLP rules
// or reads from external fingerprint file if configured
func (c *DLPConfig) GetFingerprintFilePath() string {
	if c.FingerprintFilePath != "" {
		return c.FingerprintFilePath
	}
	return DEFAULT_FINGERPRINT_FILE
}

// CopyFingerprintFile copies the fingerprint file to the specified directory and returns the file path
func (c *DLPConfig) CopyFingerprintFile(destDir string) (string, error) {
	fingerprintConfigPath := c.GetFingerprintFilePath()
	if fingerprintConfigPath == "" {
		return "", fmt.Errorf("no fingerprint file configured")
	}
	destFile := filepath.Join(destDir, "fingerprint.yaml")

	// Read fingerprint data
	var fingerprintData []byte
	var err error

	if fingerprintConfigPath == DEFAULT_FINGERPRINT_FILE {
		// Use embedded file
		fingerprintData, err = embeddedFingerprintYaml.ReadFile(fingerprintConfigPath)
		if err != nil {
			return "", fmt.Errorf("failed to read embedded fingerprint file: %w", err)
		}
	} else {
		// Use external file
		fingerprintData, err = os.ReadFile(fingerprintConfigPath)
		if err != nil {
			return "", fmt.Errorf("failed to read fingerprint file %s: %w", fingerprintConfigPath, err)
		}
	}

	// Write to destination
	if err := os.WriteFile(destFile, fingerprintData, 0644); err != nil {
		return "", fmt.Errorf("failed to write fingerprint file: %w", err)
	}
	return destFile, nil
}

func (c *DLPConfig) GetRule(patternName string) *DLPRule {
	for _, rule := range c.Rules {
		if rule.Name == patternName {
			return &rule
		}
	}
	return nil
}

// CalculateSeverity returns the severity level based on the pattern name and match count
func (r *DLPRule) CalculateSeverity(matchCount int) string {
	// If no thresholds are configured, default to LOW
	if r.SeverityThresholds == nil {
		return "LOW"
	}

	// Check thresholds from highest to lowest severity
	if r.SeverityThresholds.Critical != nil && matchCount >= *r.SeverityThresholds.Critical {
		return "CRITICAL"
	}
	if r.SeverityThresholds.High != nil && matchCount >= *r.SeverityThresholds.High {
		return "HIGH"
	}
	if r.SeverityThresholds.Medium != nil && matchCount >= *r.SeverityThresholds.Medium {
		return "MEDIUM"
	}
	if r.SeverityThresholds.Low != nil && matchCount >= *r.SeverityThresholds.Low {
		return "LOW"
	}
	// Default to LOW if rule not found
	return "LOW"
}
