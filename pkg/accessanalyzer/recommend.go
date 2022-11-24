package accessanalyzer

import "strings"

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(resourceType string) *recommend {
	r := recommendMap[strings.ToLower(resourceType)]
	return &r
}

// recommendMap maps risk and recommendation details to plugins.
// The recommendations are based on https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html
// key: resourceType, value: recommend{}
var recommendMap = map[string]recommend{
	"s3": {
		Risk: `Amazon S3 Bucket access control
		- If a bucket policy grants access to another account or allows public access, Access Analyzer generates a high score finding.
		- In that case, your data in the S3 bucket may be leaked, destroyed, or tampered with.`,
		Recommendation: `Update bucket policy or ACL settings or 'S3 block public access' settings override the bucket policies applied to the bucket.
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-policy-alternatives-guidelines.html
		- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html`,
	},
	"iam": {
		Risk: `AWS IAM Role trust policy
		- If a role trust policy grants access to an external entity, Access Analyzer generates a finding in each enabled Region.
		- Untrusted entities(principal) should not be allowed to access their IAM roles.`,
		Recommendation: `Update IAM role's trust policy or principal setting in the permissions.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html`,
	},
	"kms": {
		Risk: `AWS KMS key reource access control
		- For example, if you use the 'kms:CallerAccount' condition key in a policy statement to allow access to all users in a specific AWS account, and you specify an account other than the current account (the zone of trust for the current analyzer), Access Analyzer generates a finding.
		- Untrusted entities should not be allowed to access their keys`,
		Recommendation: `Update 'key access policy' in AWS KMS
		- https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html`,
	},
	"lambda": {
		Risk: `AWS Lambda functions and layers
		- If you grant access to theLambda function, Access Analyzer generates a finding.
		- The Lambda function execution policy should not allow public invocation of the function.`,
		Recommendation: `Update the Lambda policy to prevent access from the public.
		- https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html`,
	},
	"sqs": {
		Risk: `SQS access control
		- For Amazon SQS queues, Access Analyzer analyzes policies, including condition statements in a policy, that allow an external entity access to a queue.
		- SQS queues should be not be publicly accessible to prevent unauthorized actions.`,
		Recommendation: `Update the SQS queue policy to prevent public access.
		- http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html`,
	},
	"secretsmanager": {
		Risk: `AWS Secrets Manager access control
		- For AWS Secrets Manager secrets, Access Analyzer analyzes policies, including condition statements in a policy, that allow an external entity to access a secret.
		- Untrusted entities should not be allowed to access their secret resources.`,
		Recommendation: `Update the Secret Manager policy to prevent untrusted enetities.
		- https://docs.aws.amazon.com/mediapackage/latest/ug/iam-policy-examples-asm-secrets.html.`,
	},
}
