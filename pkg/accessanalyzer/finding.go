package accessanalyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/datasource-api/pkg/message"
)

// getPreviousDLPFindings retrieves previous DLP scan results for the specified bucket
func (a *accessAnalyzerClient) getPreviousDLPFindings(ctx context.Context, bucketName string, projectID uint32) (*bucketDLPScan, error) {
	bucketArn := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
	a.logger.Debugf(ctx, "Retrieving previous DLP findings for bucket: %s", bucketArn)

	// Search for existing DLP findings using ListFinding API
	listReq := &finding.ListFindingRequest{
		ProjectId:    projectID,
		DataSource:   []string{message.AWSAccessAnalyzerDataSource},
		ResourceName: []string{bucketArn},
		Limit:        1, // Only get the first finding
	}
	resp, err := a.FindingClient.ListFinding(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list previous DLP findings: %w", err)
	}
	if len(resp.FindingId) == 0 {
		a.logger.Debugf(ctx, "No previous DLP findings found for bucket: %s", bucketName)
		return nil, nil
	}

	// Process only the first finding
	findingID := resp.FindingId[0]
	getReq := &finding.GetFindingRequest{
		ProjectId: projectID,
		FindingId: findingID,
	}

	findingResp, err := a.FindingClient.GetFinding(ctx, getReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get finding details for ID %d: %w", findingID, err)
	}

	// Check if this finding contains DLP scan results
	if !a.isDLPFinding(findingResp.Finding) {
		a.logger.Debugf(ctx, "Finding ID %d is not a DLP finding", findingID)
		return nil, nil
	}
	scanResult, err := a.parseDLPFindingData(findingResp.Finding.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DLP finding data for ID %d: %w", findingID, err)
	}

	// ScanTime is now used for previous scan time comparison
	a.logger.Debugf(ctx, "Loaded previous DLP scan result: bucket=%s, lastScan=%v, files=%d",
		bucketName, time.Unix(scanResult.ScanTime, 0), len(scanResult.SensitiveObjects))

	return scanResult, nil
}

// isDLPFinding checks if a finding contains DLP scan results by checking for dlp_scan key
func (a *accessAnalyzerClient) isDLPFinding(f *finding.Finding) bool {
	var parsedData map[string]any
	if err := json.Unmarshal([]byte(f.Data), &parsedData); err != nil {
		return false
	}

	// Check for dlp_scan key existence
	_, hasDLPScan := parsedData["dlp_scan"]
	return hasDLPScan
}

// parseDLPFindingData parses DLP scan result data from Finding.Data
func (a *accessAnalyzerClient) parseDLPFindingData(data string) (*bucketDLPScan, error) {
	var parsedData map[string]any
	if err := json.Unmarshal([]byte(data), &parsedData); err != nil {
		return nil, fmt.Errorf("failed to parse finding data as JSON: %w", err)
	}

	// Extract dlp_scan data
	dlpScanData, ok := parsedData["dlp_scan"]
	if !ok {
		return nil, fmt.Errorf("no dlp_scan data found in finding")
	}

	// Convert to JSON bytes and parse as DLPScanResult
	dlpBytes, err := json.Marshal(dlpScanData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dlp_scan data: %w", err)
	}

	var dlpResult bucketDLPScan
	if err := json.Unmarshal(dlpBytes, &dlpResult); err != nil {
		return nil, fmt.Errorf("failed to parse DLP scan result: %w", err)
	}

	return &dlpResult, nil
}
