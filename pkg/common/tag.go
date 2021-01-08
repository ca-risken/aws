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
	if strings.HasPrefix(strings.ToLower(resourceName), TagACM) {
		return TagACM
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagAPIGateway) {
		return TagAPIGateway
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagAthena) {
		return TagAthena
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagAutoScaling) {
		return TagAutoScaling
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagCloudFormation) {
		return TagCloudFormation
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagCloudFront) {
		return TagCloudFront
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagCloudTrail) {
		return TagCloudTrail
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagCloudWatchLogs) {
		return TagCloudWatchLogs
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagComprehend) {
		return TagComprehend
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagConfigService) {
		return TagConfigService
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagDMS) {
		return TagDMS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagDynamoDB) {
		return TagDynamoDB
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagECR) {
		return TagECR
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagEFS) {
		return TagEFS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagEKS) {
		return TagEKS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagElasticBeanstalk) {
		return TagElasticBeanstalk
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagELBv2) {
		return TagELBv2
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagELB) {
		return TagELB
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagEMR) {
		return TagEMR
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagES) {
		return TagES
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagFirehose) {
		return TagFirehose
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagGuardDuty) {
		return TagGuardDuty
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagKinesis) {
		return TagKinesis
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagOrganizations) {
		return TagOrganizations
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagRDS) {
		return TagRDS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagRedshift) {
		return TagRedshift
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagRoute53) {
		return TagRoute53
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagSageMaker) {
		return TagSageMaker
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagSES) {
		return TagSES
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagShield) {
		return TagShield
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagSNS) {
		return TagSNS
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagSSM) {
		return TagSSM
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagTransfer) {
		return TagTransfer
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagXRay) {
		return TagXRay
	}
	if strings.HasPrefix(strings.ToLower(resourceName), TagVPC) {
		return TagVPC
	}

	return TagUnknown
}
