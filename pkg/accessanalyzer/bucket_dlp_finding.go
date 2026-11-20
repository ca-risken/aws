package accessanalyzer

import (
	json "encoding/json/v2"
	"net/url"
	"strings"
	"time"

	"github.com/ca-risken/common/pkg/dlp"
)

type bucketFileScan struct {
	Object  string    `json:"object"`
	URL     string    `json:"url"`
	Updated time.Time `json:"updated,omitzero"`
	dlp.FindingFile
}

type bucketDLPScan struct {
	ResourceName     string           `json:"resource_name"`
	TotalFiles       int              `json:"total_files"`
	ScanDuration     string           `json:"scan_duration"`
	ScanTime         int64            `json:"scan_time"`
	Sensitive        *bool            `json:"sensitive"`
	ContentType      []string         `json:"content_type"`
	SensitiveObjects []bucketFileScan `json:"sensitive_objects"`

	previousFindings []dlp.Finding
	unreportedFiles  []bucketFileScan
}

type previousBucketFileScan struct {
	Object  string    `json:"object"`
	Updated time.Time `json:"updated,omitzero"`
	dlp.ScanResponse
}

func (r *bucketDLPScan) UnmarshalJSON(data []byte) error {
	type storedScan bucketDLPScan
	var stored struct {
		storedScan
		Findings    []dlp.Finding            `json:"findings"`
		ObjectScans []previousBucketFileScan `json:"object_scans"`
		PDFScans    []previousBucketFileScan `json:"pdf_scans"`
	}
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}

	*r = bucketDLPScan(stored.storedScan)
	r.previousFindings = stored.Findings
	seen := make(map[string]struct{}, len(r.SensitiveObjects))
	for i := range r.SensitiveObjects {
		r.SensitiveObjects[i].Sensitivity = new(true)
		seen[r.SensitiveObjects[i].Object] = struct{}{}
	}
	r.readPreviousFileScans(stored.ObjectScans, seen, false)
	r.readPreviousFileScans(stored.PDFScans, seen, true)
	return nil
}

func (r *bucketDLPScan) readPreviousFileScans(files []previousBucketFileScan, seen map[string]struct{}, pdf bool) {
	for _, file := range files {
		if _, exists := seen[file.Object]; exists {
			continue
		}
		if pdf && file.PDFResult == nil {
			file.PDFResult = &dlp.PDFResult{}
		}
		r.addFile(bucketFileScan{
			Object:      file.Object,
			Updated:     file.Updated,
			FindingFile: dlp.NewFindingFile(file.ScanResponse),
		})
		seen[file.Object] = struct{}{}
	}
}

func (r *bucketDLPScan) addFile(file bucketFileScan) {
	if file.Sensitivity != nil && *file.Sensitivity {
		r.SensitiveObjects = append(r.SensitiveObjects, file)
		return
	}
	r.unreportedFiles = append(r.unreportedFiles, file)
}

func (r *bucketDLPScan) withSummary(objectHost string) *bucketDLPScan {
	if len(r.previousFindings) > 0 {
		// A cached result can be returned when the object listing fails.
		r.ContentType = nil
		r.mergeLegacyFindings(r.previousFindings, func(filePath string) (string, bool) {
			return strings.CutPrefix(filePath, r.ResourceName+"/")
		})
		r.previousFindings = nil
	}
	if r.SensitiveObjects == nil {
		r.SensitiveObjects = []bucketFileScan{}
	}
	r.TotalFiles = len(r.SensitiveObjects)
	bucketURL := "https://" + objectHost + "/" + url.PathEscape(r.ResourceName) + "/"
	for i := range r.SensitiveObjects {
		file := &r.SensitiveObjects[i]
		objectKey := strings.ReplaceAll(url.PathEscape(file.Object), "+", "%2B")
		file.URL = bucketURL + objectKey
	}
	if r.ContentType != nil && len(r.unreportedFiles) == 0 {
		return r
	}
	files := make([]dlp.ScanResponse, 0, len(r.SensitiveObjects)+len(r.unreportedFiles))
	for _, file := range r.SensitiveObjects {
		files = append(files, file.ScanResponse())
	}
	for _, file := range r.unreportedFiles {
		files = append(files, file.ScanResponse())
	}
	summary := dlp.NewFindingScan(files, nil)
	r.Sensitive = summary.Sensitive
	r.ContentType = summary.ContentType
	r.unreportedFiles = nil
	return r
}

func (r *bucketDLPScan) mergeLegacyFindings(findings []dlp.Finding, objectName func(string) (string, bool)) {
	if len(findings) == 0 {
		return
	}

	byObject := make(map[string][]dlp.Finding)
	var names []string
	for _, finding := range findings {
		name, ok := objectName(finding.FilePath)
		if !ok || name == "" {
			continue
		}
		if _, exists := byObject[name]; !exists {
			names = append(names, name)
		}
		byObject[name] = append(byObject[name], finding)
	}

	index := make(map[string]int, len(r.SensitiveObjects))
	for i, file := range r.SensitiveObjects {
		index[file.Object] = i
	}
	for _, name := range names {
		if i, exists := index[name]; exists {
			r.SensitiveObjects[i].MergeLegacyFindings(byObject[name])
			continue
		}
		file := dlp.NewFindingFile(dlp.ScanResponse{})
		file.MergeLegacyFindings(byObject[name])
		r.addFile(bucketFileScan{Object: name, FindingFile: file})
	}
}
