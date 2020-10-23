package common

// AWSService type
type AWSService int

const (
	// Unknown service
	Unknown AWSService = iota
	// EC2 service
	EC2
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
