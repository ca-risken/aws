package main

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/accessanalyzer"
)

func TestScoreAccessAnalyzerFinding(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		isPublic bool
		actions  []*string
		want     float32
	}{
		{
			name:     "Not active status score",
			status:   accessanalyzer.FindingStatusArchived,
			isPublic: true,
			actions:  []*string{aws.String("s3:ListBucket")},
			want:     0.1,
		},
		{
			name:     "Not public resource score",
			status:   accessanalyzer.FindingStatusActive,
			isPublic: false,
			actions:  []*string{aws.String("s3:ListBucket")},
			want:     0.3,
		},
		{
			name:     "Public (readable)",
			status:   accessanalyzer.FindingStatusActive,
			isPublic: true,
			actions: []*string{
				aws.String("s3:ListBucket"),
				aws.String("s3:ListObject"),
				aws.String("s3:DescribeBucketPolicy"),
			},
			want: 0.7,
		},
		{
			name:     "Public (writable)",
			status:   accessanalyzer.FindingStatusActive,
			isPublic: true,
			actions: []*string{
				aws.String("s3:PutObject"),
				aws.String("s3:DeleteBucket"),
			},
			want: 0.9,
		},
		{
			name:     "Public (readable / writable)",
			status:   accessanalyzer.FindingStatusActive,
			isPublic: true,
			actions: []*string{
				aws.String("s3:ListBucket"),
				aws.String("s3:GetObject"),
				aws.String("s3:PutObject"),
			},
			want: 1.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAccessAnalyzerFinding(c.status, c.isPublic, c.actions)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
