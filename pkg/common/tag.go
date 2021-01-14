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
	// TagCloudsploit cloudsploit tag
	TagCloudsploit = "cloudsploit"

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
	// TagACM acm tag
	TagACM = "acm"
	// TagAPIGateway apigateway tag
	TagAPIGateway = "apigateway"
	// TagAthena athena tag
	TagAthena = "athena"
	// TagAutoScaling autoscaling tag
	TagAutoScaling = "autoscaling"
	// TagCloudFormation cloudformation tag
	TagCloudFormation = "cloudformation"
	// TagCloudFront cloudfront tag
	TagCloudFront = "cloudfront"
	// TagCloudTrail cloudtrail tag
	TagCloudTrail = "cloudtrail"
	// TagCloudWatchLogs cloudwatchlogs tag
	TagCloudWatchLogs = "cloudwatchlogs"
	// TagComprehend comprehend tag
	TagComprehend = "comprehend"
	// TagConfigService configservice tag
	TagConfigService = "configservice"
	// TagDMS dms tag
	TagDMS = "dms"
	// TagDynamoDB dynamodb tag
	TagDynamoDB = "dynamodb"
	// TagECR ecr tag
	TagECR = "ecr"
	// TagEFS efs tag
	TagEFS = "efs"
	// TagEKS eks tag
	TagEKS = "eks"
	// TagElasticBeanstalk elasticbeanstalk tag
	TagElasticBeanstalk = "elasticbeanstalk"
	// TagELB elb tag
	TagELB = "elb"
	// TagELBv2 elbv2 tag
	TagELBv2 = "elbv2"
	// TagEMR emr tag
	TagEMR = "emr"
	// TagES es tag
	TagES = "es"
	// TagFirehose firehose tag
	TagFirehose = "firehose"
	// TagGuardDuty guardduty tag
	TagGuardDuty = "guardduty"
	// TagKinesis kinesis tag
	TagKinesis = "kinesis"
	// TagOrganizations organizations tag
	TagOrganizations = "organizations"
	// TagRDS rds tag
	TagRDS = "rds"
	// TagRedshift redshift tag
	TagRedshift = "redshift"
	// TagRoute53 route53 tag
	TagRoute53 = "route53"
	// TagSageMaker sagemaker tag
	TagSageMaker = "sagemaker"
	// TagSES ses tag
	TagSES = "ses"
	// TagShield shield tag
	TagShield = "shield"
	// TagSNS sns tag
	TagSNS = "sns"
	// TagSSM ssm tag
	TagSSM = "ssm"
	// TagTransfer transfer tag
	TagTransfer = "transfer"
	// TagXRay xray tag
	TagXRay = "xray"
	// TagVPC vpc tag
	TagVPC = "vpc"
)

// GetAWSServiceTagByARN retrun aws service tag from ARN
func GetAWSServiceTagByARN(arn string) string {
	// ARN format: (e.g.) `arn:partition:service:region:account-id:resource...`
	// source https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	splited := strings.Split(arn, ":")
	if len(splited) < 3 {
		return TagUnknown
	}
	return strings.TrimSpace(strings.ToLower(splited[2]))
}
