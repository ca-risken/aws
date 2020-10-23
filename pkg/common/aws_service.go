package common

// AWSService type
type AWSService int

const (
	// EC2 service
	EC2 AWSService = iota
	// IAM service
	IAM
	// S3 service
	S3
	// SQS service
	SQS
	// Lambda service
	Lambda
	// KMS service
	KMS
)
