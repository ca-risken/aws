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
			input: &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2, ProjectID: 3},
		},
		{
			name:    "NG Required(AWSID)",
			input:   &AWSQueueMessage{AWSDataSourceID: 2, ProjectID: 3},
			wantErr: true,
		},
		{
			name:    "NG Required(AWSDataSourceID)",
			input:   &AWSQueueMessage{AWSID: 1, ProjectID: 3},
			wantErr: true,
		},
		{
			name:    "NG Required(ProjectID)",
			input:   &AWSQueueMessage{AWSID: 1, AWSDataSourceID: 2},
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
