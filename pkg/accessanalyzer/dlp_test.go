package accessanalyzer

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ca-risken/common/pkg/dlp"
	"github.com/ca-risken/common/pkg/logging"
	"github.com/ca-risken/core/proto/finding"
	"github.com/ca-risken/core/proto/finding/mocks"
	"github.com/stretchr/testify/mock"
)

type awsTestTransport func(*http.Request) (*http.Response, error)

func (f awsTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFullDLPScanReplacesPreviousResultsOnlyAfterListing(t *testing.T) {
	t.Parallel()

	const previous = `{"dlp_scan":{"resource_name":"example-bucket","scan_time":1700000000,"sensitive_objects":[{"object":"old.wav","complete":false,"content_kind":"UNSPECIFIED","content_type":["PII"]}]}}`
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantOld    bool
	}{
		{
			name:       "successful list removes the previous detection for an excluded object",
			statusCode: http.StatusOK,
			body: `<ListBucketResult><IsTruncated>false</IsTruncated><Contents>
				<Key>old.wav</Key><LastModified>2023-11-14T22:13:20Z</LastModified><Size>16</Size>
			</Contents></ListBucketResult>`,
		},
		{
			name:       "failed list keeps the saved result",
			statusCode: http.StatusForbidden,
			body:       `<Error><Code>AccessDenied</Code></Error>`,
			wantOld:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			findings := mocks.NewFindingServiceClient(t)
			if test.wantOld {
				findings.On("ListFinding", mock.Anything, mock.Anything).Return(&finding.ListFindingResponse{FindingId: []uint64{1}}, nil).Once()
				findings.On("GetFinding", mock.Anything, &finding.GetFindingRequest{ProjectId: 1, FindingId: 1}).
					Return(&finding.GetFindingResponse{Finding: &finding.Finding{Data: previous}}, nil).Once()
			}
			client := accessAnalyzerClient{
				S3: s3.New(s3.Options{
					Region:      "us-east-1",
					Credentials: aws.AnonymousCredentials{},
					HTTPClient: &http.Client{Transport: awsTestTransport(func(req *http.Request) (*http.Response, error) {
						if req.URL.Query().Get("list-type") != "2" {
							t.Fatalf("unexpected S3 call %s", req.URL)
						}
						return &http.Response{StatusCode: test.statusCode, Body: io.NopCloser(strings.NewReader(test.body))}, nil
					})},
				}),
				FindingClient: findings,
				dlpScanner:    dlp.NewScanner(nil, &dlp.Config{ExcludeFilePatterns: []string{".wav"}}),
				logger:        logging.NewLogger(),
			}
			got, err := client.dlpScan(t.Context(), "arn:aws:s3:::example-bucket", 1, true)
			if (err != nil) != test.wantOld || got == nil {
				t.Fatalf("unexpected result: scan=%v err=%v", got, err)
			}
			withPrevious := got.ScanTime == 1700000000 && len(got.SensitiveObjects) == 1 && got.SensitiveObjects[0].Object == "old.wav"
			if withPrevious != test.wantOld || (!test.wantOld && len(got.SensitiveObjects) != 0) {
				t.Errorf("full scan has %d sensitive objects, time %d, want previous=%t", len(got.SensitiveObjects), got.ScanTime, test.wantOld)
			}
		})
	}
}

func TestPublicObjectReadIsAnonymous(t *testing.T) {
	t.Parallel()

	updated := time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)
	client := &accessAnalyzerClient{
		publicS3: s3.New(s3.Options{
			Region:      "us-east-1",
			Credentials: aws.AnonymousCredentials{},
			HTTPClient: &http.Client{Transport: awsTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "" || req.URL.Query().Has("X-Amz-Credential") {
					t.Error("public object read was signed")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Last-Modified": {updated.Format(http.TimeFormat)}},
					Body:       io.NopCloser(strings.NewReader("id,name")),
				}, nil
			})},
		}),
	}
	object := client.publicDLPObject("test-bucket", "customers.csv", 7, updated)
	body, err := object.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}
