package common

import (
	"time"

	"github.com/CyberAgent/mimosa-aws/pkg/message"
	"github.com/CyberAgent/mimosa-aws/proto/aws"
)

// InitScanStatus return init aws.AttachDataSourceRequest data
func InitScanStatus(message *message.AWSQueueMessage) aws.AttachDataSourceRequest {
	return aws.AttachDataSourceRequest{
		ProjectId: message.ProjectID,
		AttachDataSource: &aws.DataSourceForAttach{
			AwsId:           message.AWSID,
			AwsDataSourceId: message.AWSDataSourceID,
			ProjectId:       message.ProjectID,
			AssumeRoleArn:   message.AssumeRoleArn,
			ExternalId:      message.ExternalID,
			ScanAt:          time.Now().Unix(),
			// to be updated below, after the scan
			Status:       aws.Status_UNKNOWN,
			StatusDetail: "",
		},
	}
}
