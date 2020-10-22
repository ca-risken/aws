package common

const (
	// Resource Name template

	// EC2ResourceTemplate resource name for ec2
	EC2ResourceTemplate = "ec2/%s/%s" // ec2/{account-id}/{instance-id}
	// IAMResourceTemplate resource name for iam
	IAMResourceTemplate = "iam/%s/%s" // iam/{account-id}/{user-name}
	// S3ResourceTemplate resource name for s3
	S3ResourceTemplate = "s3/%s/%s" // s3/{account-id}/{bucket-name}
)
