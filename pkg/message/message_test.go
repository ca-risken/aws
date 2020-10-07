package message

import "testing"

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		input   *AWSQueueMessage
		wantErr bool
	}{
		{
			name:  "OK",
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, DataSource: "aws:guard-duty", ProjectID: 1, AccountID: "123456789012", AssumeRoleArn: "role", ExternalID: ""},
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
