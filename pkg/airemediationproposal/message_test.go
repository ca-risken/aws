package airemediationproposal

import "testing"

func TestParseQueueMessage(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    *QueueMessage
		wantErr bool
	}{
		{
			name: "OK",
			body: `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"data_source":"aws:cloudsploit","aws_id":1001,"account_id":"123456789012","assume_role_arn":"arn:aws:iam::123456789012:role/test","external_id":"external"}`,
			want: &QueueMessage{
				RemediationProposalID: 1001,
				FindingID:             2001,
				ProjectID:             1001,
				DataSource:            "aws:cloudsploit",
				AWSID:                 1001,
				AccountID:             "123456789012",
				AssumeRoleArn:         "arn:aws:iam::123456789012:role/test",
				ExternalID:            "external",
			},
		},
		{
			name:    "NG invalid JSON",
			body:    `{`,
			wantErr: true,
		},
		{
			name:    "NG missing remediation_proposal_id",
			body:    `{"finding_id":2001,"project_id":1001,"data_source":"aws:cloudsploit","aws_id":1001,"account_id":"123456789012","assume_role_arn":"arn:aws:iam::123456789012:role/test"}`,
			wantErr: true,
		},
		{
			name:    "NG missing assume_role_arn",
			body:    `{"remediation_proposal_id":1001,"finding_id":2001,"project_id":1001,"data_source":"aws:cloudsploit","aws_id":1001,"account_id":"123456789012"}`,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseQueueMessage(c.body)
			if err != nil && !c.wantErr {
				t.Fatalf("unexpected error: %+v", err)
			}
			if err == nil && c.wantErr {
				t.Fatal("expected error but got nil")
			}
			if c.wantErr {
				return
			}
			if *got != *c.want {
				t.Fatalf("unexpected message: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
