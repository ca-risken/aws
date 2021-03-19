package aws

import (
	"testing"
)

const (
	stringLength65  = "12345678901234567890123456789012345678901234567890123456789012345"
	stringLength256 = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789=12345678901234567890123456789012345678901234567890123456"
)

func TestValidate_ListAWSRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListAWSRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &ListAWSRequest{ProjectId: 111, AwsId: 1001, AwsAccountId: "123456789012"},
			wantErr: false,
		},
		{
			name:    "NG required(project_id)",
			input:   &ListAWSRequest{AwsId: 1001, AwsAccountId: "123456789012"},
			wantErr: true,
		},
		{
			name:    "NG length(aws_account_id)",
			input:   &ListAWSRequest{ProjectId: 111, AwsId: 1001, AwsAccountId: "12345678901"},
			wantErr: true,
		},
		{
			name:    "NG isDigit(aws_account_id)",
			input:   &ListAWSRequest{ProjectId: 111, AwsId: 1001, AwsAccountId: "12345678901x"},
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

func TestValidate_PutAWSRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *PutAWSRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &PutAWSRequest{ProjectId: 1, Aws: &AWSForUpsert{Name: "nm", ProjectId: 1, AwsAccountId: "123456789012"}},
			wantErr: false,
		},
		{
			name:    "NG Required(Aws)",
			input:   &PutAWSRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(ProjectId)",
			input:   &PutAWSRequest{Aws: &AWSForUpsert{Name: "nm", ProjectId: 1, AwsAccountId: "123456789012"}},
			wantErr: true,
		},
		{
			name:    "NG Not match(ProjectId)",
			input:   &PutAWSRequest{ProjectId: 999, Aws: &AWSForUpsert{Name: "nm", ProjectId: 1, AwsAccountId: "123456789012"}},
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

func TestValidate_DeleteAWSRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *DeleteAWSRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &DeleteAWSRequest{ProjectId: 111, AwsId: 1001},
			wantErr: false,
		},
		{
			name:    "NG Required(project_id)",
			input:   &DeleteAWSRequest{AwsId: 1001},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_id)",
			input:   &DeleteAWSRequest{ProjectId: 111},
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

func TestValidate_ListDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *ListDataSourceRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &ListDataSourceRequest{ProjectId: 111, AwsId: 1001, DataSource: "ds"},
			wantErr: false,
		},
		{
			name:    "NG Length(aws_id)",
			input:   &ListDataSourceRequest{ProjectId: 111, DataSource: "ds"},
			wantErr: true,
		},
		{
			name:    "NG Length(data_source)",
			input:   &ListDataSourceRequest{ProjectId: 111, AwsId: 1001, DataSource: stringLength65},
			wantErr: true,
		},
		{
			name:    "NG Length(project_id)",
			input:   &ListDataSourceRequest{AwsId: 1001, DataSource: "ds"},
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

func TestValidate_AttachDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *AttachDataSourceRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &AttachDataSourceRequest{ProjectId: 1, AttachDataSource: &DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "assume-role", ExternalId: "12345678"}},
			wantErr: false,
		},
		{
			name:    "NG Required(attach_data_source)",
			input:   &AttachDataSourceRequest{ProjectId: 1},
			wantErr: true,
		},
		{
			name:    "NG Required(ProjectID)",
			input:   &AttachDataSourceRequest{AttachDataSource: &DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "assume-role", ExternalId: "12345678"}},
			wantErr: true,
		},
		{
			name:    "NG Invalid ProjectID",
			input:   &AttachDataSourceRequest{ProjectId: 999, AttachDataSource: &DataSourceForAttach{AwsId: 1, AwsDataSourceId: 1, ProjectId: 1, AssumeRoleArn: "assume-role", ExternalId: "12345678"}},
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

func TestValidate_DetachDataSourceRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *DetachDataSourceRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &DetachDataSourceRequest{ProjectId: 111, AwsId: 1001, AwsDataSourceId: 1001},
			wantErr: false,
		},
		{
			name:    "NG Required(project_id)",
			input:   &DetachDataSourceRequest{AwsId: 1001, AwsDataSourceId: 1001},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_id)",
			input:   &DetachDataSourceRequest{ProjectId: 111, AwsDataSourceId: 1001},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_data_source_id)",
			input:   &DetachDataSourceRequest{ProjectId: 111, AwsId: 1001},
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

func TestValidate_InvokeScanRequest(t *testing.T) {
	cases := []struct {
		name    string
		input   *InvokeScanRequest
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &InvokeScanRequest{ProjectId: 111, AwsId: 1001, AwsDataSourceId: 1001},
			wantErr: false,
		},
		{
			name:    "NG Required(project_id)",
			input:   &InvokeScanRequest{AwsId: 1001, AwsDataSourceId: 1001},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_id)",
			input:   &InvokeScanRequest{ProjectId: 111, AwsDataSourceId: 1001},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_data_source)",
			input:   &InvokeScanRequest{ProjectId: 111, AwsId: 1001},
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

func TestValidate_AWSForUpsert(t *testing.T) {
	cases := []struct {
		name    string
		input   *AWSForUpsert
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &AWSForUpsert{Name: "name", ProjectId: 111, AwsAccountId: "123456789012"},
			wantErr: false,
		},
		{
			name:    "NG Length(name)",
			input:   &AWSForUpsert{Name: stringLength256, ProjectId: 111, AwsAccountId: "123456789012"},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &AWSForUpsert{Name: "name", AwsAccountId: "123456789012"},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_account_id)",
			input:   &AWSForUpsert{Name: "name", ProjectId: 111},
			wantErr: true,
		},
		{
			name:    "NG isDigit(aws_account_id)",
			input:   &AWSForUpsert{Name: "name", ProjectId: 111, AwsAccountId: "12345678901x"},
			wantErr: true,
		},
		{
			name:    "NG length(aws_account_id)",
			input:   &AWSForUpsert{Name: "name", ProjectId: 111, AwsAccountId: "1234567890123"},
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

func TestValidate_DataSourceForAttach(t *testing.T) {
	cases := []struct {
		name    string
		input   *DataSourceForAttach
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: false,
		},
		{
			name:    "NG Required(aws_id)",
			input:   &DataSourceForAttach{AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_data_source_id)",
			input:   &DataSourceForAttach{AwsId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(assume_role_arn)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length(assume_role_arn)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: stringLength256, ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length MAX(external_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: stringLength256, Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length(Status Detail)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Range1(ScanAt)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: -1},
			wantErr: true,
		},
		{
			name:    "NG Range2(ScanAt)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: 253402268400},
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

func TestValidateForUser_DataSourceForAttach(t *testing.T) {
	cases := []struct {
		name    string
		input   *DataSourceForAttach
		wantErr bool
	}{
		{
			name:    "OK",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: false,
		},
		{
			name:    "NG Required(aws_id)",
			input:   &DataSourceForAttach{AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(aws_data_source_id)",
			input:   &DataSourceForAttach{AwsId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(project_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, AssumeRoleArn: "role", ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(assume_role_arn)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length(assume_role_arn)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: stringLength256, ExternalId: "12345678", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Required(external_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length MIN(external_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "1234567", Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length MAX(external_id)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: stringLength256, Status: Status_OK, StatusDetail: "", ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Length(Status Detail)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: 0},
			wantErr: true,
		},
		{
			name:    "NG Range1(ScanAt)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: -1},
			wantErr: true,
		},
		{
			name:    "NG Range2(ScanAt)",
			input:   &DataSourceForAttach{AwsId: 1001, AwsDataSourceId: 1001, ProjectId: 111, AssumeRoleArn: "role", ExternalId: "", Status: Status_OK, StatusDetail: stringLength256, ScanAt: 253402268400},
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.input.ValidateForUser()
			if c.wantErr && err == nil {
				t.Fatal("Unexpected no error")
			} else if !c.wantErr && err != nil {
				t.Fatalf("Unexpected error occured: wantErr=%t, err=%+v", c.wantErr, err)
			}
		})
	}
}
