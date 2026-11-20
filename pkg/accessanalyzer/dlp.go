package accessanalyzer

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func extractBucketNameFromArn(bucketArn string) string {
	parts := strings.Split(bucketArn, ":")
	if len(parts) >= 6 && parts[2] == "s3" {
		return parts[5]
	}
	return ""
}

func (a *accessAnalyzerClient) dlpScan(ctx context.Context, bucketArn string, projectID uint32, fullScan bool) (*bucketDLPScan, error) {
	bucketName := extractBucketNameFromArn(bucketArn)
	if bucketName == "" {
		return nil, fmt.Errorf("failed to extract bucket name from ARN: %s", bucketArn)
	}

	var previous *bucketDLPScan
	if !fullScan {
		var err error
		previous, err = a.getPreviousDLPFindings(ctx, bucketName, projectID)
		if err != nil {
			a.logger.Warnf(ctx, "Failed to get previous DLP findings: %v", err)
		}
	}
	started := time.Now()
	objects, err := a.collectDLPObjects(ctx, bucketName)
	if err != nil {
		return previous, err
	}

	return scanDLPFiles(ctx, a.dlpScanner, bucketName, objects, previous, started), nil
}

func (a *accessAnalyzerClient) collectDLPObjects(ctx context.Context, bucket string) ([]dlpObject, error) {
	pager := s3.NewListObjectsV2Paginator(a.S3, &s3.ListObjectsV2Input{
		Bucket:  &bucket,
		MaxKeys: aws.Int32(1000),
	})
	var objects []dlpObject
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
		}
		for _, item := range page.Contents {
			key := aws.ToString(item.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}
			objects = append(objects, a.publicDLPObject(bucket, key, aws.ToInt64(item.Size), aws.ToTime(item.LastModified)))
		}
	}
	return objects, nil
}

func (a *accessAnalyzerClient) publicDLPObject(bucket, key string, size int64, updated time.Time) dlpObject {
	return dlpObject{
		Name: key, Size: size, Updated: updated,
		Open: func(ctx context.Context) (io.ReadCloser, error) {
			result, err := a.publicS3.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
			if err != nil {
				return nil, err
			}
			if !updated.IsZero() && !updated.Equal(aws.ToTime(result.LastModified)) {
				_ = result.Body.Close()
				return nil, fmt.Errorf("object changed since listing")
			}
			return result.Body, nil
		},
	}
}
