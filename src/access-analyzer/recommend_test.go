package main

import (
	"reflect"
	"testing"
)

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *recommend
	}{
		{
			name:  "Exists",
			input: "s3",
			want: &recommend{
				Risk: `Amazon S3 Bucket access control
		- If a bucket policy grants access to another account or allows public access, Access Analyzer generates a high score finding.
		- In that case, your data in the S3 bucket may be leaked, destroyed, or tampered with.`,
				Recommendation: `Update bucket policy or ACL settings or 'S3 block public access' settings override the bucket policies applied to the bucket.
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-alternatives-guidelines.html
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html`,
			},
		},
		{
			name:  "Uppercase",
			input: "S3",
			want: &recommend{
				Risk: `Amazon S3 Bucket access control
		- If a bucket policy grants access to another account or allows public access, Access Analyzer generates a high score finding.
		- In that case, your data in the S3 bucket may be leaked, destroyed, or tampered with.`,
				Recommendation: `Update bucket policy or ACL settings or 'S3 block public access' settings override the bucket policies applied to the bucket.
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-alternatives-guidelines.html
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html`,
			},
		},
		{
			name:  "Unknown",
			input: "unknown",
			want: &recommend{
				Risk:           "",
				Recommendation: "",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
