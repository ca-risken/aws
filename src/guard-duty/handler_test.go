package main

import (
	"fmt"
	"testing"

	"github.com/CyberAgent/mimosa-aws/pkg/common"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
)

func TestGetResourceName(t *testing.T) {
	cases := []struct {
		name  string
		input *guardduty.Finding
		want  string
	}{
		{
			name: "Empty",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource:  &guardduty.Resource{},
			},
			want: resourceUnknown,
		},
		{
			name: "EC2 INSTANCE",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:    aws.String("Instance"),
					InstanceDetails: &guardduty.InstanceDetails{InstanceId: aws.String("i-xxx")},
				},
			},
			want: fmt.Sprintf(common.EC2ResourceTemplate, "123456789012", "i-xxx"),
		},
		{
			name: "EC2 INSTANCE Unknown",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType: aws.String("Instance"),
				},
			},
			want: ec2InstanceUnknown,
		},
		{
			name: "IAM ACCESSKEY",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:     aws.String("AccessKey"),
					AccessKeyDetails: &guardduty.AccessKeyDetails{UserType: aws.String("IAMUser"), UserName: aws.String("user-name")},
				},
			},
			want: fmt.Sprintf(common.IAMResourceTemplate, "123456789012", "user-name"),
		},
		{
			name: "IAM Unknown user type",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:     aws.String("AccessKey"),
					AccessKeyDetails: &guardduty.AccessKeyDetails{UserType: aws.String("UnknownType"), UserName: aws.String("user-name")},
				},
			},
			want: userTypeUnknown,
		},
		{
			name: "IAM User unkonwn",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:     aws.String("AccessKey"),
					AccessKeyDetails: &guardduty.AccessKeyDetails{UserType: aws.String("IAMUser")},
				},
			},
			want: iamUserUnknown,
		},
		{
			name: "S3 BUCKET 1",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:    aws.String("S3Bucket"),
					S3BucketDetails: []*guardduty.S3BucketDetail{{Name: aws.String("bucket")}},
				},
			},
			want: fmt.Sprintf(common.S3ResourceTemplate, "123456789012", "bucket"),
		},
		{
			name: "S3 BUCKET 2",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:    aws.String("S3Bucket"),
					S3BucketDetails: []*guardduty.S3BucketDetail{{Name: aws.String("bucket-1")}, {Name: aws.String("bucket-2")}},
				},
			},
			want: fmt.Sprintf(common.S3ResourceTemplate, "123456789012", "bucket-1,bucket-2"),
		},
		{
			name: "S3 No bucket name",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:    aws.String("S3Bucket"),
					S3BucketDetails: []*guardduty.S3BucketDetail{{Arn: aws.String("arn")}},
				},
			},
			want: fmt.Sprintf(common.S3ResourceTemplate, "123456789012", ""),
		},
		{
			name: "S3 Unkown bucket",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType:    aws.String("S3Bucket"),
					S3BucketDetails: []*guardduty.S3BucketDetail{},
				},
			},
			want: fmt.Sprintf(common.S3ResourceTemplate, "123456789012", s3BucketUnknown),
		},
		{
			name: "Unknown resource type",
			input: &guardduty.Finding{
				AccountId: aws.String("123456789012"),
				Resource: &guardduty.Resource{
					ResourceType: aws.String("UnkonwnResource"),
				},
			},
			want: resourceTypeUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getResourceName(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
