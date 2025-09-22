package accessanalyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	MAX_SCAN_FILES             = 3000
	MAX_SCAN_SIZE_MB           = 100
	MAX_SCAN_SIZE_BYTES        = MAX_SCAN_SIZE_MB * 1024 * 1024
	MAX_SINGLE_FILE_SIZE_MB    = 5
	MAX_SINGLE_FILE_SIZE_BYTES = MAX_SINGLE_FILE_SIZE_MB * 1024 * 1024
	MAX_MATCHES_PER_FINDING    = 5
)

// DLP_EXCLUDE_PATTERNS defines file patterns to exclude from scanning
var DLP_EXCLUDE_PATTERNS = []string{
	".html",
	".htm",
	".css",
	".js",
	".jsx",
	".ts",
	".tsx",
	".vue",
	".svelte",
	".map",
	"node_modules",
	"vendor",
	"bower_components",
	"venv",
	".venv",
	"virtualenv",
	"__pycache__",
	".npm",
	".yarn",
	".pnpm",
	".pyc",
	".so",
	".dylib",
	".dll",
	".exe",
	".jar",
	".class",
	".woff",
	".woff2",
	".ttf",
	".otf",
}

// FileCandidate represents a file candidate for scanning
type FileCandidate struct {
	BucketName string
	Key        string
	Size       int64
}

// DLPScanResult represents the complete scan result
type DLPScanResult struct {
	BucketName   string       `json:"bucket_name"`
	TotalFiles   int          `json:"total_files"`
	Findings     []DLPFinding `json:"findings"`
	ScanDuration string       `json:"scan_duration"`
}

// DLPFinding represents an individual DLP finding from hawk-eye
type DLPFinding struct {
	FilePath            string   `json:"file_path"`
	PatternName         string   `json:"pattern_name"`
	Matches             []string `json:"matches"`
	Severity            string   `json:"severity"`
	SeverityDescription string   `json:"severity_description"`
}

// HawkEyeOutput represents the complete hawk-eye JSON output structure
type HawkEyeOutput struct {
	Fs []DLPFinding `json:"fs"`
}

func extractBucketNameFromArn(bucketArn string) string {
	// S3 bucket ARN format: arn:aws:s3:::bucket-name
	parts := strings.Split(bucketArn, ":")
	if len(parts) >= 6 && parts[2] == "s3" {
		return parts[5]
	}
	return ""
}

func (a *accessAnalyzerClient) dlpScan(ctx context.Context, bucketArn string, fingerprintPath string) (*DLPScanResult, error) {
	bucketName := extractBucketNameFromArn(bucketArn)
	if bucketName == "" {
		return nil, fmt.Errorf("failed to extract bucket name from ARN: %s", bucketArn)
	}
	a.logger.Infof(ctx, "Starting staged DLP scan for public S3 bucket: %s", bucketName)

	// Collect metadata for s3 objects (lightweight)
	candidates, err := a.collectCandidateFiles(ctx, bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to collect file candidates: %w", err)
	}

	// Select files to scan based on size and file count limits only
	selectedFiles := a.selectFilesToScan(ctx, candidates)

	// Download and scan selected files (batch processing with directory scan)
	scanResults, err := a.downloadAndScanFiles(ctx, selectedFiles, bucketName, fingerprintPath)
	if err != nil {
		return nil, fmt.Errorf("failed to download and scan files: %w", err)
	}

	return scanResults, nil
}

// Collect metadata for s3 objects (lightweight)
func (a *accessAnalyzerClient) collectCandidateFiles(ctx context.Context, bucketName string) ([]FileCandidate, error) {
	var candidates []FileCandidate
	var continuationToken *string
	totalFiles := 0
	a.logger.Debugf(ctx, "Collecting file metadata for bucket: %s", bucketName)
	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucketName),
			MaxKeys:           int32(1000),
			ContinuationToken: continuationToken,
		}

		result, err := a.S3.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in bucket %s: %w", bucketName, err)
		}

		// Collect metadata for s3 objects in current batch
		limitReached := false
		for _, obj := range result.Contents {
			if totalFiles >= MAX_SCAN_FILES {
				a.logger.Warnf(ctx, "Reached maximum file metadata collection limit (%d files)", MAX_SCAN_FILES)
				limitReached = true
				break
			}

			candidate := FileCandidate{
				BucketName: bucketName,
				Key:        aws.ToString(obj.Key),
				Size:       obj.Size,
			}
			candidates = append(candidates, candidate)
			totalFiles++
		}
		if limitReached || result.NextContinuationToken == nil {
			break // Exit if limit reached or no more s3 objects
		}
		continuationToken = result.NextContinuationToken
	}
	return candidates, nil
}

// Select files to scan based on size and file count limits only
func (a *accessAnalyzerClient) selectFilesToScan(ctx context.Context, candidates []FileCandidate) []FileCandidate {
	if len(candidates) == 0 {
		return candidates
	}
	a.logger.Debugf(ctx, "Selecting files to scan from %d candidates", len(candidates))

	// Select files within limits (no priority, just first come first serve)
	var selected []FileCandidate
	totalSize := int64(0)

	for _, candidate := range candidates {
		// Reached limit
		if len(selected) >= MAX_SCAN_FILES {
			a.logger.Warnf(ctx, "Reached maximum file count limit (%d files)", MAX_SCAN_FILES)
			break
		}
		if totalSize+candidate.Size > MAX_SCAN_SIZE_BYTES {
			a.logger.Warnf(ctx, "Reached maximum size limit (%d MB)", MAX_SCAN_SIZE_MB)
			break
		}

		// Exclude files
		// Skip files larger than MAX_SINGLE_FILE_SIZE
		if candidate.Size > MAX_SINGLE_FILE_SIZE_BYTES {
			a.logger.Debugf(ctx, "Skipping file %s: size %.2f MB exceeds single file limit of %d MB",
				candidate.Key, float64(candidate.Size)/(1024*1024), MAX_SINGLE_FILE_SIZE_MB)
			continue
		}
		// Skip files matching exclude patterns
		if slices.ContainsFunc(DLP_EXCLUDE_PATTERNS, func(p string) bool {
			return strings.Contains(candidate.Key, p)
		}) {
			a.logger.Debugf(ctx, "Skipping file %s: matching exclude patterns", candidate.Key)
			continue
		}
		selected = append(selected, candidate)
		totalSize += candidate.Size
	}
	a.logger.Debugf(ctx, "Selected %d files for scanning (%.2f MB total)",
		len(selected), float64(totalSize)/(1024*1024))
	return selected
}

// Download and scan selected files (batch processing with directory scan)
func (a *accessAnalyzerClient) downloadAndScanFiles(ctx context.Context, selectedFiles []FileCandidate, bucketName string, fingerprintPath string) (*DLPScanResult, error) {
	if len(selectedFiles) == 0 {
		a.logger.Debugf(ctx, "No files selected for scanning")
		return nil, nil
	}
	tempDir, err := createTempDir()
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if cleanupErr := cleanupTempDir(tempDir); cleanupErr != nil {
			a.logger.Warnf(ctx, "Failed to cleanup temp directory %s: %+v", tempDir, cleanupErr)
		}
	}()

	if err := a.downloadFiles(ctx, selectedFiles, tempDir); err != nil {
		return nil, fmt.Errorf("failed to download files: %w", err)
	}
	scanResults, err := a.scanDirectoryWithResults(ctx, tempDir, bucketName, len(selectedFiles), fingerprintPath)
	if err != nil {
		return nil, fmt.Errorf("failed to scan directory: %w", err)
	}
	return scanResults, nil
}

// createTempDir creates a temporary directory for DLP scanning
func createTempDir() (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	tempDir := filepath.Join("/tmp", fmt.Sprintf("dlp-scan-%s", timestamp))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create temp directory %s: %w", tempDir, err)
	}
	return tempDir, nil
}

// cleanupTempDir removes the temporary directory and all its contents
func cleanupTempDir(tempDir string) error {
	if tempDir == "" || !strings.HasPrefix(tempDir, "/tmp/dlp-scan-") {
		return fmt.Errorf("invalid temp directory path: %s", tempDir)
	}
	return os.RemoveAll(tempDir)
}

// downloadFiles downloads all selected files to the temporary directory
func (a *accessAnalyzerClient) downloadFiles(ctx context.Context, selectedFiles []FileCandidate, tempDir string) error {
	downloadedCount := 0
	for i, file := range selectedFiles {
		a.logger.Debugf(ctx, "Downloading file %d/%d: %s", i+1, len(selectedFiles), file.Key)

		// Sanitize path while maintaining directory structure
		safePath := sanitizePath(file.Key)
		localPath := filepath.Join(tempDir, safePath)
		localDir := filepath.Dir(localPath)
		if err := os.MkdirAll(localDir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", localDir, err)
		}

		// Download file from S3
		input := &s3.GetObjectInput{
			Bucket: aws.String(file.BucketName),
			Key:    aws.String(file.Key),
		}

		result, err := a.S3.GetObject(ctx, input)
		if err != nil {
			a.logger.Warnf(ctx, "Failed to download file %s: %v", file.Key, err)
			continue // Skip this file but continue with others
		}
		defer result.Body.Close()

		// Create local file and copy content
		if err := saveToLocalFile(result.Body, localPath); err != nil {
			a.logger.Warnf(ctx, "Failed to save file %s: %v", localPath, err)
			continue // Skip this file but continue with others
		}

		downloadedCount++
		a.logger.Debugf(ctx, "Downloaded: %s -> %s", file.Key, localPath)
	}
	a.logger.Debugf(ctx, "Downloaded %d files to %s", downloadedCount, tempDir)
	return nil
}

// sanitizePath creates a safe file path from S3 key while maintaining directory structure
func sanitizePath(key string) string {
	// Normalize path separators to forward slashes
	cleanPath := strings.ReplaceAll(key, "\\", "/")
	parts := strings.Split(cleanPath, "/")
	for i, part := range parts {
		// Remove or replace unsafe characters
		safePart := strings.ReplaceAll(part, "..", "_")
		safePart = strings.ReplaceAll(safePart, ":", "_")
		safePart = strings.ReplaceAll(safePart, "*", "_")
		safePart = strings.ReplaceAll(safePart, "?", "_")
		safePart = strings.ReplaceAll(safePart, "<", "_")
		safePart = strings.ReplaceAll(safePart, ">", "_")
		safePart = strings.ReplaceAll(safePart, "|", "_")
		safePart = strings.ReplaceAll(safePart, "\"", "_")
		if safePart == "" || safePart == "." {
			safePart = "unnamed"
		}
		parts[i] = safePart
	}
	result := strings.Join(parts, "/")
	if result == "" {
		return "unnamed_file"
	}
	return result
}

// saveToLocalFile saves the content from io.Reader to a local file
func saveToLocalFile(reader io.Reader, localPath string) error {
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()

	_, err = io.Copy(localFile, reader)
	if err != nil {
		return fmt.Errorf("failed to copy content to local file: %w", err)
	}
	return nil
}

const CONNECTION_JSON_TEMPLATE = `
{
	"sources": {
		"fs": {
			"fs1": {
				"quick_scan": true,
				"path": "%s"
			}
		}
	}
}
`

// scanDirectoryWithResults executes DLP scan and returns structured results
func (a *accessAnalyzerClient) scanDirectoryWithResults(ctx context.Context, tempDir, bucketName string, totalFiles int, fingerprintPath string) (*DLPScanResult, error) {
	startTime := time.Now()
	a.logger.Infof(ctx, "Starting hawk-eye DLP scan on directory: %s", tempDir)
	outputFile := filepath.Join(tempDir, "hawkeye-results.json")
	connectionJSON := fmt.Sprintf(CONNECTION_JSON_TEMPLATE, tempDir)
	args := []string{"fs", "--connection-json", connectionJSON, "--stdout", "--quiet", "--json", outputFile}
	if fingerprintPath != "" {
		args = append(args, "--fingerprint", fingerprintPath)
	}
	cmd := exec.CommandContext(ctx, "hawk_scanner", args...)
	cmd.Dir = tempDir
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("hawk-eye scan failed: %w", err)
	}

	scanDuration := time.Since(startTime)
	a.logger.Debugf(ctx, "Hawk-eye DLP scan completed in %v", scanDuration)
	return a.processScanResults(ctx, outputFile, bucketName, tempDir, totalFiles, scanDuration)
}

// processScanResults reads hawk-eye results and processes them
func (a *accessAnalyzerClient) processScanResults(ctx context.Context, outputFile, bucketName, tempDir string, totalFiles int, scanDuration time.Duration) (*DLPScanResult, error) {
	// Check if results file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		a.logger.Warnf(ctx, "No hawk-eye results file found: %s", outputFile)
		return &DLPScanResult{
			BucketName:   bucketName,
			TotalFiles:   totalFiles,
			Findings:     []DLPFinding{},
			ScanDuration: scanDuration.String(),
		}, nil
	}

	// Read results file
	resultsData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read results file: %w", err)
	}

	if len(resultsData) == 0 {
		a.logger.Debugf(ctx, "Empty results file, no DLP findings detected")
		return &DLPScanResult{
			BucketName:   bucketName,
			TotalFiles:   totalFiles,
			Findings:     []DLPFinding{},
			ScanDuration: scanDuration.String(),
		}, nil
	}

	// Parse hawk-eye results
	var hawkEyeOutput HawkEyeOutput
	if err := json.Unmarshal(resultsData, &hawkEyeOutput); err != nil {
		a.logger.Warnf(ctx, "Failed to parse hawk-eye results as JSON: %v", err)
		// If JSON parsing fails, store raw results
		findings := []DLPFinding{{
			FilePath:            "raw_output",
			PatternName:         "raw_scan_result",
			Matches:             []string{string(resultsData)},
			Severity:            "info",
			SeverityDescription: "Raw scan output due to parsing error",
		}}
		return &DLPScanResult{
			BucketName:   bucketName,
			TotalFiles:   totalFiles,
			Findings:     findings,
			ScanDuration: scanDuration.String(),
		}, nil
	}

	findings := []DLPFinding{}
	for _, finding := range hawkEyeOutput.Fs {
		path := strings.ReplaceAll(finding.FilePath, tempDir, "")

		// Limit matches to maximum MAX_MATCHES_PER_FINDING items
		matches := finding.Matches
		if len(matches) > MAX_MATCHES_PER_FINDING {
			matches = matches[:MAX_MATCHES_PER_FINDING]
		}

		findings = append(findings, DLPFinding{
			FilePath:            filepath.Join("s3://", bucketName, path),
			PatternName:         finding.PatternName,
			Matches:             matches,
			Severity:            finding.Severity,
			SeverityDescription: finding.SeverityDescription,
		})
	}

	// Create structured scan result
	scanResult := &DLPScanResult{
		BucketName:   bucketName,
		TotalFiles:   totalFiles,
		Findings:     findings,
		ScanDuration: scanDuration.String(),
	}
	a.logger.Debugf(ctx, "Processed %d DLP findings from hawk-eye scan", len(findings))
	return scanResult, nil
}
