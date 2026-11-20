package accessanalyzer

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

func TestListAvailableRegionResolvesEC2Endpoint(t *testing.T) {
	t.Parallel()

	client := &accessAnalyzerClient{
		EC2: ec2.New(ec2.Options{
			Region:      "us-east-1",
			Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""),
			HTTPClient: &http.Client{Transport: awsTestTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "ec2.us-east-1.amazonaws.com" {
					t.Errorf("unexpected EC2 endpoint %q", req.URL.Host)
				}
				const body = `<DescribeRegionsResponse>
					<regionInfo><item><regionName>us-east-1</regionName></item></regionInfo>
				</DescribeRegionsResponse>`
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(body)),
				}, nil
			})},
		}),
	}

	regions, err := client.listAvailableRegion(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if regions == nil || len(*regions) != 1 || aws.ToString((*regions)[0].RegionName) != "us-east-1" {
		t.Fatalf("listAvailableRegion() = %+v, want us-east-1", regions)
	}
}

func TestGetQueueURLFromArn(t *testing.T) {
	tests := []struct {
		name     string
		queueArn string
		want     string
	}{
		{
			"OK",
			"arn:aws:sqs:us-west-2:123456789012:my-queue",
			"https://sqs.us-west-2.amazonaws.com/123456789012/my-queue",
		},
		{
			"Invalid ARN with less parts",
			"arn:aws:sqs:us-west-2:123456789012",
			"",
		},
		{
			"Invalid ARN with wrong format",
			"invalid:format",
			"",
		},
		{
			"Empty string",
			"",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getQueueURLFromArn(tt.queueArn); got != tt.want {
				t.Errorf("getQueueNameFromArn(%q) = %q, want %q", tt.queueArn, got, tt.want)
			}
		})
	}
}

func TestIsSupportedAnalyzerType(t *testing.T) {
	tests := []struct {
		name         string
		analyzerType types.Type
		want         bool
	}{
		{name: "account", analyzerType: types.TypeAccount, want: true},
		{name: "organization", analyzerType: types.TypeOrganization, want: true},
		{name: "account unused access", analyzerType: types.Type("ACCOUNT_UNUSED_ACCESS"), want: false},
		{name: "organization unused access", analyzerType: types.Type("ORGANIZATION_UNUSED_ACCESS"), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSupportedAnalyzerType(tt.analyzerType); got != tt.want {
				t.Errorf("isSupportedAnalyzerType(%q) = %t, want %t", tt.analyzerType, got, tt.want)
			}
		})
	}
}
