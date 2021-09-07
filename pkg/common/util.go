package common

import (
	"strings"
	"time"

	"github.com/ca-risken/aws/pkg/message"
	"github.com/ca-risken/aws/proto/aws"
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

func IsMatchAccountIDArn(accountID, arn string) bool {
	if strings.Index(arn, "::") < 0 {
		return false
	}
	tmp := strings.Split(arn, "::")[1]
	return strings.HasPrefix(tmp, accountID)
}
