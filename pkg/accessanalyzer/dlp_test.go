package accessanalyzer

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type awsTestTransport func(*http.Request) (*http.Response, error)

func (f awsTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
