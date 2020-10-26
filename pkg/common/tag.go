package common

import "strings"

const (
	// TagAWS aws tag
	TagAWS = "aws"
	// TagGuardduty guard-duty tag
	TagGuardduty = "guard-duty"
	// TagAccessAnalyzer access-analyzer tag
	TagAccessAnalyzer = "access-analyzer"
	// TagAdminChecker admin-checker tag
	TagAdminChecker = "admin-checker"

	// AWS Services

	// TagUnknown unknown service tag
	TagUnknown = "unknown-aws-service"
	// TagEC2 ec2 tag
	TagEC2 = "ec2"
	// TagIAM iam tag
	TagIAM = "iam"
	// TagS3 s3 tag
	TagS3 = "s3"
	// TagSQS sqs tag
	TagSQS = "sqs"
	// TagLambda lambda tag
	TagLambda = "lambda"
	// TagKMS kms tag
	TagKMS = "kms"
)

// GetAWSServiceTagByResourceName return tag name by resource
func GetAWSServiceTagByResourceName(resourceName string) string {
	if strings.HasPrefix(strings.ToLower(resourceName), TagEC2) {
		return TagEC2
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagIAM) {
		return TagIAM
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagS3) {
		return TagS3
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagEC2) {
		return TagEC2
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagSQS) {
		return TagSQS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagLambda) {
		return TagLambda
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagKMS) {
		return TagKMS
	}
	return TagUnknown
}
