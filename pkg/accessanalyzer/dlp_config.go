package accessanalyzer

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"slices"

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

	SEVERITY_LOW      = "LOW"
	SEVERITY_MEDIUM   = "MEDIUM"
	SEVERITY_HIGH     = "HIGH"
	SEVERITY_CRITICAL = "CRITICAL"
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
	FileFilters        *FileFilters        `yaml:"file_filters,omitempty"`
	SeverityThresholds *SeverityThresholds `yaml:"severity_thresholds,omitempty"`
}

// FileFilters defines file metadata conditions for applying a rule
type FileFilters struct {
	IncludeExtensions []string `yaml:"include_extensions,omitempty"` // e.g., [".csv", ".tsv", ".log"]
	ExcludeFileName   []string `yaml:"exclude_file_name,omitempty"`  // e.g., ["*_backup*", "*_temp*"]
	MinSizeKB         *int     `yaml:"min_size_kb,omitempty"`        // Minimum file size in KB
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
		configPath = filepath.Clean(configPath)
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
	return &config, nil
}

// GetScanSizeLimits returns size limits in bytes
func (c *DLPConfig) GetMaxScanSizeBytes() int64 {
	if c.MaxScanSizeMB <= 0 {
		return 10 * 1024 * 1024 // Default 10MB if invalid
	}
	return int64(c.MaxScanSizeMB) * 1024 * 1024
}

func (c *DLPConfig) GetMaxSingleFileSizeBytes() int64 {
	if c.MaxSingleFileSizeMB <= 0 {
		return 5 * 1024 * 1024 // Default 5MB if invalid
	}
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
		fingerprintConfigPath = filepath.Clean(fingerprintConfigPath)
		fingerprintData, err = os.ReadFile(fingerprintConfigPath)
		if err != nil {
			return "", fmt.Errorf("failed to read fingerprint file %s: %w", fingerprintConfigPath, err)
		}
	}

	// Write to destination
	if err := os.WriteFile(destFile, fingerprintData, 0600); err != nil {
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
		return SEVERITY_LOW
	}

	// Check thresholds from highest to lowest severity
	if r.SeverityThresholds.Critical != nil && matchCount >= *r.SeverityThresholds.Critical {
		return SEVERITY_CRITICAL
	}
	if r.SeverityThresholds.High != nil && matchCount >= *r.SeverityThresholds.High {
		return SEVERITY_HIGH
	}
	if r.SeverityThresholds.Medium != nil && matchCount >= *r.SeverityThresholds.Medium {
		return SEVERITY_MEDIUM
	}
	if r.SeverityThresholds.Low != nil && matchCount >= *r.SeverityThresholds.Low {
		return SEVERITY_LOW
	}
	// Default to LOW if rule not found
	return SEVERITY_LOW
}

// IsApplicableToFile checks if this rule should be applied to the given file
func (r *DLPRule) IsApplicableToFile(fileName string, fileSizeBytes int64) bool {
	// No filters means apply to all files
	if r.FileFilters == nil {
		return true
	}

	// Check minimum file size
	if r.FileFilters.MinSizeKB != nil {
		fileSizeKB := int(fileSizeBytes / 1024)
		if fileSizeKB < *r.FileFilters.MinSizeKB {
			return false
		}
	}

	// Check include extensions (if specified, file must match one of them)
	if len(r.FileFilters.IncludeExtensions) > 0 {
		ext := filepath.Ext(fileName)
		if !slices.Contains(r.FileFilters.IncludeExtensions, ext) {
			return false
		}
	}

	// Check exclude file name patterns
	if len(r.FileFilters.ExcludeFileName) > 0 {
		baseName := filepath.Base(fileName)
		for _, pattern := range r.FileFilters.ExcludeFileName {
			matched, err := filepath.Match(pattern, baseName)
			if err == nil && matched {
				return false
			}
		}
	}

	return true
}
