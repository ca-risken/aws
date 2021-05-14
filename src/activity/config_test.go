package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/CyberAgent/mimosa-aws/proto/activity"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/configservice"
)

func TestConvertConfigTag(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]*string
		want  []*activity.Tag
	}{
		{
			name: "OK",
			input: map[string]*string{
				"k": aws.String("v"),
			},
			want: []*activity.Tag{
				{Key: "k", Value: "v"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertConfigTag(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestConvertStringSlice(t *testing.T) {
	cases := []struct {
		name  string
		input []*string
		want  []string
	}{
		{
			name: "OK",
			input: []*string{
				aws.String("something"),
			},
			want: []string{
				"something",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertStringSlice(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestConvertSupplementaryConfiguration(t *testing.T) {
	cases := []struct {
		name  string
		input map[string]*string
		want  []*activity.SupplementaryConfiguration
	}{
		{
			name: "OK",
			input: map[string]*string{
				"k": aws.String("v"),
			},
			want: []*activity.SupplementaryConfiguration{
				{Key: "k", Value: "v"},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertSupplementaryConfiguration(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}

func TestGenerateGetResourceConfigHistoryInput(t *testing.T) {
	nowUnix := time.Now().Unix()
	now := time.Unix(nowUnix, 0)
	cases := []struct {
		name  string
		input *activity.ListConfigHistoryRequest
		want  *configservice.GetResourceConfigHistoryInput
	}{
		{
			name: "OK minimum",
			input: &activity.ListConfigHistoryRequest{
				ProjectId:    1,
				AwsId:        1,
				Region:       "ap-northeast-1",
				ResourceType: "AWS::S3::Bucket",
				ResourceId:   "some-bucket",
				EarlierTime:  nowUnix,
				LaterTime:    nowUnix,
			},
			want: &configservice.GetResourceConfigHistoryInput{
				ResourceType: aws.String("AWS::S3::Bucket"),
				ResourceId:   aws.String("some-bucket"),
				EarlierTime:  aws.Time(now),
				LaterTime:    aws.Time(now),
				Limit:        aws.Int64(30),
			},
		},
		{
			name: "OK maximum",
			input: &activity.ListConfigHistoryRequest{
				ProjectId:          1,
				AwsId:              1,
				Region:             "ap-northeast-1",
				ResourceType:       "AWS::S3::Bucket",
				ResourceId:         "some-bucket",
				EarlierTime:        nowUnix,
				LaterTime:          nowUnix,
				ChronologicalOrder: "Forward",  // Reverse
				StartingToken:      "dG9rZW4=", // base64("token")
			},
			want: &configservice.GetResourceConfigHistoryInput{
				ResourceType:       aws.String("AWS::S3::Bucket"),
				ResourceId:         aws.String("some-bucket"),
				EarlierTime:        aws.Time(now),
				LaterTime:          aws.Time(now),
				Limit:              aws.Int64(30),
				ChronologicalOrder: aws.String("Forward"),
				NextToken:          aws.String("token"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := generateGetResourceConfigHistoryInput(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
