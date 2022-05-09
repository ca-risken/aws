package main

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

func TestScoreAccessAnalyzerFinding(t *testing.T) {
	cases := []struct {
		name     string
		status   types.FindingStatus
		isPublic bool
		actions  []string
		want     float32
	}{
		{
			name:     "Not active status score",
			status:   types.FindingStatusArchived,
			isPublic: true,
			actions:  []string{"s3:ListBucket"},
			want:     0.1,
		},
		{
			name:     "Not public resource score",
			status:   types.FindingStatusActive,
			isPublic: false,
			actions:  []string{"s3:ListBucket"},
			want:     0.3,
		},
		{
			name:     "Public (readable)",
			status:   types.FindingStatusActive,
			isPublic: true,
			actions: []string{
				"s3:ListBucket",
				"s3:ListObject",
				"s3:DescribeBucketPolicy",
			},
			want: 0.7,
		},
		{
			name:     "Public (writable)",
			status:   types.FindingStatusActive,
			isPublic: true,
			actions: []string{
				"s3:PutObject",
				"s3:DeleteBucket",
			},
			want: 0.9,
		},
		{
			name:     "Public (readable / writable)",
			status:   types.FindingStatusActive,
			isPublic: true,
			actions: []string{
				"s3:ListBucket",
				"s3:GetObject",
				"s3:PutObject",
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
