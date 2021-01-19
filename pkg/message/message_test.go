package message

import (
	"reflect"
	"testing"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   *AWSQueueMessage
		wantErr bool
	}{
		{
			name:  "OK (guard-duty)",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
		},
		{
			name:  "OK (access-analyzer)",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:access-analyzer", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
		},
		{
			name:  "OK (admin-checker)",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:access-analyzer", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
		},
		{
			name:  "OK (cloudsploit)",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:cloudsploit", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
		},
		{
			name:  "OK (portscan)",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:portscan", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
		},
		{
			name:    "NG Required(AWSID)",
			input:   &AWSQueueMessage{AWSID: 0, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Required(AWSDataSourceID)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 0, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Required(DataSource)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Unknown(DataSource)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty-x", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Required(ProjectID)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 0, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Required(AccountID)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 0, AccountID: "", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Invalid Length(AccountID) 1",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 0, AccountID: "12345678901", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
		{
			name:    "NG Invalid Length(AccountID) 2",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 0, AccountID: "1234567890123", AssumeRoleArn: "role", ExternalID: ""},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.Validate()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}

func TestParseMessage(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    *AWSQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: `{"aws_id":1, "aws_data_source_id":1, "data_source":"aws:guard-duty", "project_id":1, "account_id":"123456789012", "assume_role_arn":"", "external_id":""}`,
			want:  &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 1, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "", ExternalID: ""},
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
			got, err := ParseMessage(c.input)
			if err != nil && !c.wantErr {
				t.Fatalf("Unexpected error occured, wantErr=%t, err=%+v", c.wantErr, err)
			}
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpaeted response, want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
