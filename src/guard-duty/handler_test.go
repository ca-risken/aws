package main

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/guardduty"
)

func TestParseMessage(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    *message.AWSQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: `{"aws_id":1, "aws_data_source_id":1, "data_source":"aws:guard-duty", "project_id":1, "account_id":"123456789012", "assume_role_arn":"", "external_id":""}`,
			want:  &message.AWSQueueMessage{AWSID: 1, AWSDataSourceID: 1, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "", ExternalID: ""},
		},
		{
			name:    "NG Json parse erroro",
			input:   `{"parse...: error`,
			wantErr: true,
		},
		{
			name:    "NG Invalid mmessage(required parammeter)",
			input:   `{}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseMessage(c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("Unexpected error occured, wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpaeted response, want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

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
			want: fmt.Sprintf(ec2ResourceTemplate, "123456789012", "i-xxx"),
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
			want: fmt.Sprintf(iamResourceTemplate, "123456789012", "user-name"),
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
			want: fmt.Sprintf(s3ResourceTemplate, "123456789012", "bucket"),
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
			want: fmt.Sprintf(s3ResourceTemplate, "123456789012", "bucket-1,bucket-2"),
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
			want: fmt.Sprintf(s3ResourceTemplate, "123456789012", ""),
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
			want: fmt.Sprintf(s3ResourceTemplate, "123456789012", s3BucketUnknown),
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
