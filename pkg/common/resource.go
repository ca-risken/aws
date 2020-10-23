package common

import "fmt"

const (
	// Resource Name template

	// UnknownResourceTemplate resource name for unknown service
	UnknownResourceTemplate = "unknown/%s/%s"
	// EC2ResourceTemplate resource name for ec2 (ec2/{account-id}/{resource})
	EC2ResourceTemplate = "ec2/%s/%s"
	// IAMResourceTemplate resource name for iam (iam/{account-id}/{resource})
	IAMResourceTemplate = "iam/%s/%s"
	// S3ResourceTemplate resource name for s3 (s3/{account-id}/{bucket-name})
	S3ResourceTemplate = "s3/%s/%s"
	// SQSResourceTemplate resource name for sqs(sqs/{account-id}/{resource})
	SQSResourceTemplate = "sqs/%s/%s"
	// LambdaResourceTemplate resource name for lambda(lambda/{account-id}/{resource})
	LambdaResourceTemplate = "lambda/%s/%s"
	// KMSResourceTemplate resource name for kms(kms/{account-id}/{resource})
	KMSResourceTemplate = "kms/%s/%s"
)

// GetResourceName return formated resource name
func GetResourceName(svc AWSService, accountID, resourceName string) string {
	switch svc {
	case EC2:
		return fmt.Sprintf(EC2ResourceTemplate, accountID, resourceName)
	case IAM:
		return fmt.Sprintf(IAMResourceTemplate, accountID, resourceName)
	case S3:
		return fmt.Sprintf(S3ResourceTemplate, accountID, resourceName)
	case SQS:
		return fmt.Sprintf(SQSResourceTemplate, accountID, resourceName)
	case Lambda:
		return fmt.Sprintf(LambdaResourceTemplate, accountID, resourceName)
	case KMS:
		return fmt.Sprintf(KMSResourceTemplate, accountID, resourceName)
	default:
		return fmt.Sprintf(UnknownResourceTemplate, accountID, resourceName)
	}
}
