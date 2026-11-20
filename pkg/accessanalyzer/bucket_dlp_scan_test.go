package accessanalyzer

import (
	"context"
	json "encoding/json/v2"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ca-risken/common/pkg/dlp"
	"github.com/ca-risken/core/proto/ai"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
)

func TestBucketDLPScanRetainsPreviousFileResponses(t *testing.T) {
	t.Parallel()

	const stored = `{
		"resource_name":"example.test",
		"scan_time":1700000000,
		"total_files":1,
		"total_severity":"HIGH",
		"severity_reason":"previous severity",
		"test_data":null,
		"findings":[{"file_path":"example.test/retained/契約 #+%.txt","type":"PII","matches":["legacy@example.test"]},{"file_path":"example.test/retained/契約 #+%.txt","type":"Credential"}],
		"object_scans":[{"object":"old.csv","input":"text","complete":true,"sensitivity":2}],
		"pdf_scans":[{"object":"old.pdf","complete":true,"total_pages":1,"pages":[
			{"number":1,"input":"text","sensitivity":1,"categories":[4],"test_data":2}
		]},{"object":"unknown.pdf","complete":false},{"object":"deleted.pdf","complete":false}]
	}`
	previous, err := (&accessAnalyzerClient{}).parseDLPFindingData(`{"dlp_scan":` + stored + `}`)
	if err != nil {
		t.Fatal(err)
	}

	cutoff := time.Unix(previous.ScanTime, 0)
	opens := 0
	objects := []dlpObject{
		{Name: "retained/契約 #+%.txt", Updated: cutoff},
		{Name: "old.csv", Updated: cutoff},
		{Name: "old.pdf", Updated: cutoff},
		{Name: "unknown.pdf", Updated: cutoff},
		{
			Name: "new.zip", Updated: cutoff.Add(time.Minute),
			Open: func(context.Context) (io.ReadCloser, error) {
				opens++
				return io.NopCloser(strings.NewReader("PK\x03\x04\x00")), nil
			},
		},
	}
	scanner := dlp.NewScanner(nil, &dlp.Config{})
	started := cutoff.Add(time.Hour)
	const objectHost = "s3.ap-northeast-1.amazonaws.com"
	got := scanDLPFiles(t.Context(), scanner, "example.test", objects, previous, started).withSummary(objectHost)
	if got.ScanTime != started.Unix()-1 || opens != 1 {
		t.Fatalf("scan time = %d, opened files = %d", got.ScanTime, opens)
	}
	wantFiles := []bucketFileScan{
		{
			Object: "old.pdf",
			URL:    "https://s3.ap-northeast-1.amazonaws.com/example.test/old.pdf",
			FindingFile: dlp.FindingFile{
				Input: "pdf", Complete: true, Sensitivity: new(true), TotalPages: 1,
				ContentType: []string{"CLIENT_DATA"}, ContentKind: "DOCUMENT", TestData: new(false),
			},
		},
		{
			Object: "retained/契約 #+%.txt",
			URL:    "https://s3.ap-northeast-1.amazonaws.com/example.test/retained%2F%E5%A5%91%E7%B4%84%20%23%2B%25.txt",
			FindingFile: dlp.FindingFile{
				Sensitivity: new(true), ContentType: []string{"CREDENTIAL", "PII"}, ContentKind: "UNSPECIFIED",
			},
		},
	}
	if diff := cmp.Diff(wantFiles, got.SensitiveObjects); diff != "" {
		t.Errorf("file results mismatch (-want +got):\n%s", diff)
	}
	if got.TotalFiles != len(wantFiles) {
		t.Errorf("total_files = %d, want %d", got.TotalFiles, len(wantFiles))
	}
	if diff := cmp.Diff([]string{"CLIENT_DATA", "CREDENTIAL", "PII"}, got.ContentType); diff != "" {
		t.Errorf("content types mismatch (-want +got):\n%s", diff)
	}

	data, err := json.Marshal(got, json.FormatNilSliceAsNull(true))
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]any
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"findings", "object_scans", "pdf_scans", "total_severity", "severity_reason", "test_data"} {
		if _, exists := output[key]; exists {
			t.Errorf("unexpected field %s", key)
		}
	}
	if strings.Contains(string(data), "legacy@example.test") || strings.Contains(string(data), `"pages"`) {
		t.Error("file summary contains old matches or PDF page details")
	}
	if strings.Contains(string(data), `"sensitivity"`) {
		t.Error("file metadata includes sensitivity")
	}

	decoded, err := (&accessAnalyzerClient{}).parseDLPFindingData(`{"dlp_scan":` + string(data) + `}`)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, decoded, cmp.AllowUnexported(bucketDLPScan{})); diff != "" {
		t.Errorf("stored dlp_scan mismatch (-want +got):\n%s", diff)
	}

	next := scanDLPFiles(t.Context(), scanner, "example.test", objects, decoded, started.Add(time.Hour)).withSummary(objectHost)
	if opens != 1 {
		t.Errorf("opened %d files after unchanged scan, want 1", opens)
	}
	if next.TotalFiles != len(wantFiles) {
		t.Errorf("total_files after unchanged scan = %d, want %d", next.TotalFiles, len(wantFiles))
	}
	if diff := cmp.Diff(wantFiles, next.SensitiveObjects); diff != "" {
		t.Errorf("previous file decisions mismatch (-want +got):\n%s", diff)
	}
}

func TestBucketDLPScanStoresOnlySensitiveFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		decision    ai.Sensitivity
		want        *bool
		wantObjects int
	}{
		{name: "sensitive", decision: ai.Sensitivity_SENSITIVITY_TRUE, want: new(true), wantObjects: 1},
		{name: "not sensitive", decision: ai.Sensitivity_SENSITIVITY_FALSE, want: new(false)},
		{name: "unknown", decision: ai.Sensitivity_SENSITIVITY_UNKNOWN},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			updated := time.Unix(1700000000, 0).UTC()
			opens := 0
			objects := []dlpObject{{
				Name: "sample.csv", Updated: updated,
				Open: func(context.Context) (io.ReadCloser, error) {
					opens++
					return io.NopCloser(strings.NewReader("name,amount\nsample,100")), nil
				},
			}}
			scanner := dlp.NewScanner(bucketDLPTestClassifier{decision: test.decision}, &dlp.Config{})
			started := updated.Add(time.Hour)
			const objectHost = "s3.us-east-1.amazonaws.com"
			result := scanDLPFiles(t.Context(), scanner, "example", objects, nil, started).withSummary(objectHost)
			if opens != 1 || result.TotalFiles != test.wantObjects || len(result.SensitiveObjects) != test.wantObjects {
				t.Fatalf("opened %d files, total_files = %d, sensitive_objects length = %d, want 1 opened and %d stored",
					opens, result.TotalFiles, len(result.SensitiveObjects), test.wantObjects)
			}
			if diff := cmp.Diff(test.want, result.Sensitive); diff != "" {
				t.Errorf("sensitive (-want +got):\n%s", diff)
			}

			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var saved bucketDLPScan
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			next := scanDLPFiles(t.Context(), scanner, "example", objects, &saved, started.Add(time.Hour)).withSummary(objectHost)
			if opens != 1 || next.TotalFiles != test.wantObjects || len(next.SensitiveObjects) != test.wantObjects {
				t.Errorf("after unchanged scan, opened %d files, total_files = %d, sensitive_objects length = %d",
					opens, next.TotalFiles, len(next.SensitiveObjects))
			}
			if diff := cmp.Diff(test.want, next.Sensitive); diff != "" {
				t.Errorf("sensitive for unchanged bucket (-want +got):\n%s", diff)
			}
		})
	}
}

type bucketDLPTestClassifier struct {
	decision ai.Sensitivity
}

func (c bucketDLPTestClassifier) ClassifySensitiveContent(context.Context, *ai.ClassifySensitiveContentRequest, ...grpc.CallOption) (*ai.ClassifySensitiveContentResponse, error) {
	return &ai.ClassifySensitiveContentResponse{Sensitivity: c.decision}, nil
}
