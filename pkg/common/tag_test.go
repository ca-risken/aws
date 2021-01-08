package common

import (
	"testing"
)

func TestGetAWSServiceTagByResourceName(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "EC2",
			input: "ec2/any",
			want:  TagEC2,
		},
		{
			name:  "EC2 upper case",
			input: "EC2/any",
			want:  TagEC2,
		},
		{
			name:  "IAM",
			input: "iam/any",
			want:  TagIAM,
		},
		{
			name:  "IAM upper case",
			input: "IAM/any",
			want:  TagIAM,
		},
		{
			name:  "S3",
			input: "s3/any",
			want:  TagS3,
		},
		{
			name:  "S3 upper",
			input: "S3/any",
			want:  TagS3,
		},
		{
			name:  "SQS",
			input: "sqs/any",
			want:  TagSQS,
		},
		{
			name:  "SQS upper",
			input: "SQS/any",
			want:  TagSQS,
		},
		{
			name:  "Lambda",
			input: "Lambda/any",
			want:  TagLambda,
		},
		{
			name:  "Lambda upper",
			input: "lambda/any",
			want:  TagLambda,
		},
		{
			name:  "KMS",
			input: "kms/any",
			want:  TagKMS,
		},
		{
			name:  "KMS upper",
			input: "KMS/any",
			want:  TagKMS,
		},
		{
			name:  "ACM",
			input: "acm/any",
			want:  TagACM,
		},
		{
			name:  "ACM upper case",
			input: "ACM/any",
			want:  TagACM,
		},
		{
			name:  "APIGateway",
			input: "apigateway/any",
			want:  TagAPIGateway,
		},
		{
			name:  "APIGateway upper case",
			input: "APIGATEWAY/any",
			want:  TagAPIGateway,
		},
		{
			name:  "Athena",
			input: "athena/any",
			want:  TagAthena,
		},
		{
			name:  "Athena upper case",
			input: "ATHENA/any",
			want:  TagAthena,
		},
		{
			name:  "AutoScaling",
			input: "autoscaling/any",
			want:  TagAutoScaling,
		},
		{
			name:  "AutoScaling upper case",
			input: "AUTOSCALING/any",
			want:  TagAutoScaling,
		},
		{
			name:  "CloudFormation",
			input: "cloudformation/any",
			want:  TagCloudFormation,
		},
		{
			name:  "CloudFormation upper case",
			input: "CLOUDFORMATION/any",
			want:  TagCloudFormation,
		},
		{
			name:  "CloudFront",
			input: "cloudfront/any",
			want:  TagCloudFront,
		},
		{
			name:  "CloudFront upper case",
			input: "CLOUDFRONT/any",
			want:  TagCloudFront,
		},
		{
			name:  "CloudTrail",
			input: "cloudtrail/any",
			want:  TagCloudTrail,
		},
		{
			name:  "CloudTrail upper case",
			input: "CLOUDTRAIL/any",
			want:  TagCloudTrail,
		},
		{
			name:  "CloudWatchLogs",
			input: "cloudwatchlogs/any",
			want:  TagCloudWatchLogs,
		},
		{
			name:  "CloudWatchLogs upper case",
			input: "CLOUDWATCHLOGS/any",
			want:  TagCloudWatchLogs,
		},
		{
			name:  "Comprehend",
			input: "comprehend/any",
			want:  TagComprehend,
		},
		{
			name:  "Comprehend upper case",
			input: "COMPREHEND/any",
			want:  TagComprehend,
		},
		{
			name:  "ConfigService",
			input: "configservice/any",
			want:  TagConfigService,
		},
		{
			name:  "ConfigService upper case",
			input: "CONFIGSERVICE/any",
			want:  TagConfigService,
		},
		{
			name:  "DMS",
			input: "dms/any",
			want:  TagDMS,
		},
		{
			name:  "DMS upper case",
			input: "DMS/any",
			want:  TagDMS,
		},
		{
			name:  "DynamoDB",
			input: "dynamodb/any",
			want:  TagDynamoDB,
		},
		{
			name:  "DynamoDB upper case",
			input: "DYNAMODB/any",
			want:  TagDynamoDB,
		},
		{
			name:  "ECR",
			input: "ecr/any",
			want:  TagECR,
		},
		{
			name:  "ECR upper case",
			input: "ECR/any",
			want:  TagECR,
		},
		{
			name:  "EFS",
			input: "efs/any",
			want:  TagEFS,
		},
		{
			name:  "EFS upper case",
			input: "EFS/any",
			want:  TagEFS,
		},
		{
			name:  "EKS",
			input: "eks/any",
			want:  TagEKS,
		},
		{
			name:  "EKS upper case",
			input: "EKS/any",
			want:  TagEKS,
		},
		{
			name:  "ElasticBeanstalk",
			input: "elasticbeanstalk/any",
			want:  TagElasticBeanstalk,
		},
		{
			name:  "ElasticBeanstalk upper case",
			input: "ELASTICBEANSTALK/any",
			want:  TagElasticBeanstalk,
		},
		{
			name:  "ELB",
			input: "elb/any",
			want:  TagELB,
		},
		{
			name:  "ELB upper case",
			input: "ELB/any",
			want:  TagELB,
		},
		{
			name:  "ELBv2",
			input: "elbv2/any",
			want:  TagELBv2,
		},
		{
			name:  "ELBv2 upper case",
			input: "ELBv2/any",
			want:  TagELBv2,
		},
		{
			name:  "EMR",
			input: "emr/any",
			want:  TagEMR,
		},
		{
			name:  "EMR upper case",
			input: "EMR/any",
			want:  TagEMR,
		},
		{
			name:  "ES",
			input: "es/any",
			want:  TagES,
		},
		{
			name:  "ES upper case",
			input: "ES/any",
			want:  TagES,
		},
		{
			name:  "Firehose",
			input: "firehose/any",
			want:  TagFirehose,
		},
		{
			name:  "Firehose upper case",
			input: "FIREHOSE/any",
			want:  TagFirehose,
		},
		{
			name:  "GuardDuty",
			input: "guardduty/any",
			want:  TagGuardDuty,
		},
		{
			name:  "GuardDuty upper case",
			input: "GUARDDUTY/any",
			want:  TagGuardDuty,
		},
		{
			name:  "Kinesis",
			input: "kinesis/any",
			want:  TagKinesis,
		},
		{
			name:  "Kinesis upper case",
			input: "KINESIS/any",
			want:  TagKinesis,
		},
		{
			name:  "Organizations",
			input: "organizations/any",
			want:  TagOrganizations,
		},
		{
			name:  "Organizations upper case",
			input: "ORGANIZATIONS/any",
			want:  TagOrganizations,
		},
		{
			name:  "RDS",
			input: "rds/any",
			want:  TagRDS,
		},
		{
			name:  "RDS upper case",
			input: "RDS/any",
			want:  TagRDS,
		},
		{
			name:  "Redshift",
			input: "redshift/any",
			want:  TagRedshift,
		},
		{
			name:  "Redshift upper case",
			input: "REDSHIFT/any",
			want:  TagRedshift,
		},
		{
			name:  "Route53",
			input: "route53/any",
			want:  TagRoute53,
		},
		{
			name:  "Route53 upper case",
			input: "ROUTE53/any",
			want:  TagRoute53,
		},
		{
			name:  "SageMaker",
			input: "sagemaker/any",
			want:  TagSageMaker,
		},
		{
			name:  "SageMaker upper case",
			input: "SAGEMAKER/any",
			want:  TagSageMaker,
		},
		{
			name:  "SES",
			input: "ses/any",
			want:  TagSES,
		},
		{
			name:  "SES upper case",
			input: "SES/any",
			want:  TagSES,
		},
		{
			name:  "Shield",
			input: "shield/any",
			want:  TagShield,
		},
		{
			name:  "Shield upper case",
			input: "SHIELD/any",
			want:  TagShield,
		},
		{
			name:  "SNS",
			input: "sns/any",
			want:  TagSNS,
		},
		{
			name:  "SNS upper case",
			input: "SNS/any",
			want:  TagSNS,
		},
		{
			name:  "SSM",
			input: "ssm/any",
			want:  TagSSM,
		},
		{
			name:  "SSM upper case",
			input: "SSM/any",
			want:  TagSSM,
		},
		{
			name:  "Transfer",
			input: "transfer/any",
			want:  TagTransfer,
		},
		{
			name:  "Transfer upper case",
			input: "TRANSFER/any",
			want:  TagTransfer,
		},
		{
			name:  "XRay",
			input: "xray/any",
			want:  TagXRay,
		},
		{
			name:  "XRay upper case",
			input: "XRAY/any",
			want:  TagXRay,
		},
		{
			name:  "unkonwn",
			input: "any",
			want:  TagUnknown,
		},
		{
			name:  "blank",
			input: "",
			want:  TagUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := GetAWSServiceTagByResourceName(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%s, got=%s", c.want, got)
			}
		})
	}
}
