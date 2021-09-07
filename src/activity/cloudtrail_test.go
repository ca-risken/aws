package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/ca-risken/aws/proto/activity"
)

func TestGenerateLookupEventInput(t *testing.T) {
	nowUnix := time.Now().Unix()
	now := time.Unix(nowUnix, 0)
	cases := []struct {
		name  string
		input *activity.ListCloudTrailRequest
		want  *cloudtrail.LookupEventsInput
	}{
		{
			name: "OK minimum",
			input: &activity.ListCloudTrailRequest{
				ProjectId: 1,
				AwsId:     1,
				Region:    "ap-northeast-1",
				StartTime: nowUnix,
				EndTime:   nowUnix,
			},
			want: &cloudtrail.LookupEventsInput{
				StartTime:        aws.Time(now),
				EndTime:          aws.Time(now),
				MaxResults:       aws.Int64(30),
				LookupAttributes: []*cloudtrail.LookupAttribute{},
			},
		},
		{
			name: "OK maximum",
			input: &activity.ListCloudTrailRequest{
				ProjectId:      1,
				AwsId:          1,
				Region:         "ap-northeast-1",
				StartTime:      nowUnix,
				EndTime:        nowUnix,
				AttributeKey:   activity.AttributeKey_EVENT_ID,
				AttributeValue: "id",
				NextToken:      "dG9rZW4=", // base64("token")
			},
			want: &cloudtrail.LookupEventsInput{
				StartTime:  aws.Time(now),
				EndTime:    aws.Time(now),
				MaxResults: aws.Int64(30),
				LookupAttributes: []*cloudtrail.LookupAttribute{
					{AttributeKey: aws.String(cloudtrail.LookupAttributeKeyEventId), AttributeValue: aws.String("id")},
				},
				NextToken: aws.String("token"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := generateLookupEventInput(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestConvertTrailResource(t *testing.T) {
	cases := []struct {
		name  string
		input []*cloudtrail.Resource
		want  []*activity.Resource
	}{
		{
			name: "OK",
			input: []*cloudtrail.Resource{
				{ResourceType: aws.String("type-1"), ResourceName: aws.String("name-a")},
				{ResourceType: aws.String("type-2"), ResourceName: aws.String("name-b")},
			},
			want: []*activity.Resource{
				{ResourceType: "type-1", ResourceName: "name-a"},
				{ResourceType: "type-2", ResourceName: "name-b"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertTrailResource(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
