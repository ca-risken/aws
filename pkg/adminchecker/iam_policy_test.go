package adminchecker

import (
	"net/url"
	"reflect"
	"testing"
)

func TestConvertPolicyDocument(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    *policyDocument
		wantErr bool
	}{
		{
			name: "OK 1",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "ListYourObjects",
						"Effect": "Allow",
						"Action": "s3:ListBucket",
						"Resource": [
							"arn:aws:s3:::bucket-name"
						],
						"Condition": {
							"StringLike": {
								"s3:prefix": ["cognito/application-name/${cognito-identity.amazonaws.com:sub}"]
							}
						}
					},
					{
						"Sid": "ReadWriteDeleteYourObjects",
						"Effect": "Allow",
						"Action": [
							"s3:GetObject",
							"s3:PutObject",
							"s3:DeleteObject"
						],
						"Resource": [
							"arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}",
							"arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}/*"
						]
					}
				]
			}`,
			want: &policyDocument{
				Version: "2012-10-17",
				Statement: []statementEntry{
					{
						Effect:   "Allow",
						Action:   []string{"s3:ListBucket"},
						Resource: []string{"arn:aws:s3:::bucket-name"},
					},
					{
						Effect: "Allow",
						Action: []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
						Resource: []string{
							"arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}",
							"arn:aws:s3:::bucket-name/cognito/application-name/${cognito-identity.amazonaws.com:sub}/*",
						},
					},
				},
			},
		},
		{
			name: "OK 2",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:*",
						"Resource": "*"
					}
				]
			}`,
			want: &policyDocument{
				Version: "2012-10-17",
				Statement: []statementEntry{
					{
						Effect:   "Allow",
						Action:   []string{"s3:*"},
						Resource: []string{"*"},
					},
				},
			},
		},
		{
			name: "OK 3",
			input: `{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Action": "s3:*",
					"Resource": [
						"arn:aws:s3:::some-bucket/*",
						"arn:aws:s3:::some-bucket"
					]
				}
			}`,
			want: &policyDocument{
				Version: "2012-10-17",
				Statement: []statementEntry{
					{
						Effect: "Allow",
						Action: []string{"s3:*"},
						Resource: []string{
							"arn:aws:s3:::some-bucket/*",
							"arn:aws:s3:::some-bucket",
						},
					},
				},
			},
		},
		{
			name: "NG not supported charactor type(int)",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "ErrorPolicy",
						"Effect": "Allow",
						"Action": 123,
						"Resource": 456,
						}
					},
				]
			}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := url.QueryEscape(c.input)
			got, err := convertPolicyDocument(&in)
			// t.Logf("got=%+v, err=%+v", got, err)
			if (c.wantErr && err == nil) || (!c.wantErr && err != nil) {
				t.Fatalf("Unexpected error occured, err=%+v", err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
