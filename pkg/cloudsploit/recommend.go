package cloudsploit

import "fmt"

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(category, plugin string) recommend {
	return recommendMap[fmt.Sprintf("%s/%s", category, plugin)]
}

// recommendMap maps risk and recommendation details to plugins.
// The recommendations are based on https://github.com/aquasecurity/cloudsploit/tree/master/plugins/aws
// key: category/plugin, value: recommend{}
var recommendMap = map[string]recommend{
	categoryACM + "/acmCertificateExpiry": {
		Risk: `ACM Certificate Expiry
		- Detect upcoming expiration of ACM certificates
		- Certificates that have expired will trigger warnings in all major browsers. AWS will attempt to automatically renew the certificate but may be unable to do so if email or DNS validation cannot be confirmed.`,
		Recommendation: `Ensure AWS is able to renew the certificate via email or DNS validation of the domain.
		- https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html`,
	},
	categoryACM + "/acmValidation": {
		Risk: `ACM Certificate Validation
		- ACM certificates should be configured to use DNS validation.
		- With DNS validation, ACM will automatically renew certificates before they expire, as long as the DNS CNAME record is in place.`,
		Recommendation: `Configure ACM managed certificates to use DNS validation.
		- https://aws.amazon.com/blogs/security/easier-certificate-validation-using-dns-with-aws-certificate-manager/
		- https://cloudsploit.com/remediations/aws/acm/acm-certificate-validation`,
	},
	categoryAPIGateway + "/apigatewayWafEnabled": {
		Risk: `API Gateway WAF Enabled
		- Ensures that API Gateway APIs are associated with a Web Application Firewall.
		- API Gateway APIs should be associated with a Web Application Firewall to ensure API security.`,
		Recommendation: `Associate API Gateway API with Web Application Firewall
		- https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html`,
	},
	categoryAthena + "/workgroupEncrypted": {
		Risk: `Workgroup Encrypted
		- Ensures Athena workgroups are configured to encrypt all data at rest.
		- Athena workgroups support full server-side encryption for all data at rest which should be enabled.`,
		Recommendation: `Enable encryption at rest for all Athena workgroups.
		- https://docs.aws.amazon.com/athena/latest/ug/encryption.html`,
	},
	categoryAthena + "/workgroupEnforceConfiguration": {
		Risk: `Workgroup Enforce Configuration
		- Ensures Athena workgroups do not allow clients to override configuration options.
		- Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates.`,
		Recommendation: `Disable the ability for clients to override Athena workgroup configuration options.
		- https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings.html`,
	},
	categoryAutoScaling + "/appTierAsgCloudwatchLogs": {
		Risk: `App-Tier Auto Scaling Group CloudWatch Logs Enabled
		- Ensures that App-Tier Auto Scaling Groups are using CloudWatch logs agent.
		- EC2 instance available within app-tier Auto Scaling Group (ASG) should use an AWS CloudWatch Logs agent to monitor, store and access log files.`,
		Recommendation: `Update app-tier Auto Scaling Group to use CloudWatch Logs agent
		- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html'`,
	},
	categoryAutoScaling + "/appTierIamRole": {
		Risk: `App-Tier Launch Configurations IAM Roles
		- Ensures that App-Tier Auto Scaling launch configuration is configured to use a customer created IAM role.
		- App-Tier Auto Scaling launch configuration should have a customer created App-Tier IAM role to provide necessary credentials to access AWS services.`,
		Recommendation: `Update App-Tier Auto Scaling launch configuration and attach a customer created App-Tier IAM role
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html`,
	},
	categoryAutoScaling + "/asgActiveNotifications": {
		Risk: `Auto Scaling Notifications Active
		- Ensures auto scaling groups have notifications active.
		- Notifications can be sent to an SNS endpoint when scaling actions occur, which should be set to ensure all scaling activity is recorded.`,
		Recommendation: `Add a notification endpoint to the auto scaling group.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/ASGettingNotifications.html`,
	},
	categoryAutoScaling + "/asgMissingELB": {
		Risk: `Auto Scaling Group Missing ELB
		- Ensures all Auto Scaling groups are referencing active load balancers.
		- Each Auto Scaling group with a load balancer configured should reference an active ELB.`,
		Recommendation: `Ensure that the Auto Scaling group load balancer has not been deleted. If so, remove it from the ASG.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html`,
	},
	categoryAutoScaling + "/asgMissingSecurityGroups": {
		Risk: `Launch Configuration Referencing Missing Security Groups
		- Ensures that Auto Scaling launch configurations are not utilizing missing security groups.
		- Auto Scaling launch configuration should utilize an active security group to ensure safety of managed instances.`,
		Recommendation: `Ensure that the launch configuration security group has not been deleted. If so, remove it from launch configurations
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/GettingStartedTutorial.html`,
	},
	categoryAutoScaling + "/asgMultiAz": {
		Risk: `ASG Multiple AZ
		- Ensures that ASGs are created to be cross-AZ for high availability.
		- ASGs can easily be configured to allow instances to launch in multiple availability zones. This ensures that the ASG can continue to scale, even when AWS is experiencing downtime in one or more zones.`,
		Recommendation: `Modify the autoscaling instance to enable scaling across multiple availability zones.
		- http://docs.aws.amazon.com/autoscaling/latest/userguide/AutoScalingGroup.html`,
	},
	categoryAutoScaling + "/asgSuspendedProcesses": {
		Risk: `Suspended AutoScaling Groups
		- Ensures that there are no Amazon AutoScaling groups with suspended processes.
		- AutoScaling groups should not have any suspended processes to avoid disrupting the AutoScaling workflow.`,
		Recommendation: `Update the AutoScaling group to resume the suspended processes.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html`,
	},
	categoryAutoScaling + "/elbHealthCheckActive": {
		Risk: `ELB Health Check Active
		- Ensures all Auto Scaling groups have ELB health check active.
		- Auto Scaling groups should have ELB health checks active to replace unhealthy instances in time.`,
		Recommendation: `Enable ELB health check for the Auto Scaling groups.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-elb-healthcheck.html`,
	},
	categoryAutoScaling + "/emptyASG": {
		Risk: `Empty AutoScaling Group
		- Ensures all autoscaling groups contain at least 1 instance.
		- AutoScaling groups that are no longer in use should be deleted to prevent accidental use.`,
		Recommendation: `Delete the unused AutoScaling group.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/AutoScalingGroup.html`,
	},
	categoryAutoScaling + "/sameAzElb": {
		Risk: `AutoScaling ELB Same Availability Zone
		- Ensures all autoscaling groups with attached ELBs are operating in the same availability zone.
		- To work properly and prevent orphaned instances, ELBs must be created in the same availability zones as the backend instances in the autoscaling group.`,
		Recommendation: `Update the ELB to use the same availability zones as the autoscaling group.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html`,
	},
	categoryAutoScaling + "/webTierAsgAssociatedElb": {
		Risk: `Web-Tier Auto Scaling Group Associated ELB
		- Ensures that Web-Tier Auto Scaling Group has an associated Elastic Load Balancer
		- Web-Tier Auto Scaling groups should have an ELB associated to distribute incoming traffic across EC2 instances.`,
		Recommendation: `Update Web-Tier Auto Scaling group to associate ELB to distribute incoming traffic.
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html`,
	},
	categoryAutoScaling + "/webTierAsgCloudwatchLogs": {
		Risk: `Web-Tier Auto Scaling Group CloudWatch Logs Enabled
		- Ensures that Web-Tier Auto Scaling Groups are using CloudWatch Logs agent.
		- EC2 instance available within web-tier Auto Scaling Group (ASG) should use an AWS CloudWatch Logs agent to monitor, store and access log files.`,
		Recommendation: `Update web-tier Auto Scaling Group to use CloudWatch Logs agent
		- https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html`,
	},
	categoryAutoScaling + "/webTierIamRole": {
		Risk: `Web-Tier Launch Configurations IAM Roles
		- Ensures that Web-Tier Auto Scaling launch configuration is configured to use a customer created IAM role.
		- Web-Tier Auto Scaling launch configuration should have a customer created Web-Tier IAM role to provide necessary credentials to access AWS services.`,
		Recommendation: `Update Web-Tier Auto Scaling launch configuration and attach a customer created Web-Tier IAM role
		- https://docs.aws.amazon.com/autoscaling/ec2/userguide/us-iam-role.html`,
	},
	categoryCloudFormation + "/plainTextParameters": {
		Risk: `CloudFormation Plaintext Parameters
		- Ensures CloudFormation parameters that reference sensitive values are configured to use NoEcho.
		- CloudFormation supports the NoEcho property for sensitive values, which should be used to ensure secrets are not exposed in the CloudFormation UI and APIs.`,
		Recommendation: `Update the sensitive parameters to use the NoEcho property.
		- https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html`,
	},
	categoryCloudFront + "/cloudfrontHttpsOnly": {
		Risk: `CloudFront HTTPS Only
		- Ensures CloudFront distributions are configured to redirect non-HTTPS traffic to HTTPS.
		- For maximum security, CloudFront distributions can be configured to only accept HTTPS connections or to redirect HTTP connections to HTTPS.`,
		Recommendation: `Remove HTTP-only listeners from distributions.
		- http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/CloudFront.html`,
	},
	categoryCloudFront + "/cloudfrontLoggingEnabled": {
		Risk: `CloudFront Logging Enabled
		- Ensures CloudFront distributions have request logging enabled.
		- Logging requests to CloudFront distributions is a helpful way of detecting and investigating potential attacks, malicious activity, or misuse of backend resources. Logs can be sent to S3 and processed for further analysis.`,
		Recommendation: `Enable CloudFront request logging.
		- http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html`,
	},
	categoryCloudFront + "/cloudfrontWafEnabled": {
		Risk: `CloudFront WAF Enabled
		- Ensures CloudFront distributions have WAF enabled.
		- Enabling WAF allows control over requests to the Cloudfront Distribution, allowing or denying traffic based off rules in the Web ACL`,
		Recommendation: `1. Enter the WAF service. 
		2. Enter Web ACLs and filter by global. 
		3. If no Web ACL is found, Create a new global Web ACL and in Resource type to associate with web ACL, select the Cloudfront Distribution. 
		- https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-cloudfront-distribution.html`,
	},
	categoryCloudFront + "/insecureProtocols": {
		Risk: `Insecure CloudFront Protocols
		- Detects the use of insecure HTTPS SSL/TLS protocols for use with HTTPS traffic between viewers and CloudFront
		- CloudFront supports SSLv3 and TLSv1 protocols for use with HTTPS traffic, but only TLSv1.1 or higher should be used unless there is a valid business justification to support the older, insecure SSLv3.`,
		Recommendation: `Ensure that traffic sent between viewers and CloudFront is passed over HTTPS and uses TLSv1.1 or higher.
		- http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html`,
	},
	categoryCloudFront + "/publicS3Origin": {
		Risk: `Public S3 CloudFront Origin
		- Detects the use of an S3 bucket as a CloudFront origin without an origin access identity
		- When S3 is used as an origin for a CloudFront bucket, the contents should be kept private and an origin access identity should allow CloudFront access. This prevents someone from bypassing the caching benefits that CloudFront provides, repeatedly loading objects directly from S3, and amassing a large access bill.`,
		Recommendation: `Create an origin access identity for CloudFront, then make the contents of the S3 bucket private.
		- http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html`,
	},
	categoryCloudFront + "/secureOrigin": {
		Risk: `Secure CloudFront Origin
		- Detects the use of secure web origins with secure protocols for CloudFront.
		- Traffic passed between the CloudFront edge nodes and the backend resource should be sent over HTTPS with modern protocols for all web-based origins.`,
		Recommendation: `Ensure that traffic sent between CloudFront and its origin is passed over HTTPS and uses TLSv1.1 or higher. Do not use the match-viewer option.
		- http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web.html`,
	},
	categoryCloudTrail + "/cloudtrailBucketAccessLogging": {
		Risk: `CloudTrail Bucket Access Logging
		- Ensures CloudTrail logging bucket has access logging enabled to detect tampering of log files
		- CloudTrail buckets should utilize access logging for an additional layer of auditing. If the log files are deleted or modified in any way, the additional access logs can help determine who made the changes.`,
		Recommendation: `Enable access logging on the CloudTrail bucket from the S3 console
		- http://docs.aws.amazon.com/AmazonS3/latest/UG/ManagingBucketLogging.html`,
	},
	categoryCloudTrail + "/cloudtrailBucketDelete": {
		Risk: `CloudTrail Bucket Delete Policy
		- Ensures CloudTrail logging bucket has a policy to prevent deletion of logs without an MFA token
		- To provide additional security, CloudTrail logging buckets should require an MFA token to delete objects`,
		Recommendation: `Enable MFA delete on the CloudTrail bucket
		- http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html#MultiFactorAuthenticationDelete`,
	},
	categoryCloudTrail + "/cloudtrailBucketPrivate": {
		Risk: `CloudTrail Bucket Private
		- Ensures CloudTrail logging bucket is not publicly accessible
		- CloudTrail buckets contain large amounts of sensitive account data and should only be accessible by logged in users.`,
		Recommendation: `Set the S3 bucket access policy for all CloudTrail buckets to only allow known users to access its files.
		- http://docs.aws.amazon.com/AmazonS3/latest/dev/example-bucket-policies.html`,
	},
	categoryCloudTrail + "/cloudtrailDataEvents": {
		Risk: `CloudTrail Data Events
		- Ensure Data events are included into Amazon CloudTrail trails configuration.
		- AWS CloudTrail trails should be configured to enable Data Events in order to log S3 object-level API operations.`,
		Recommendation: `Update CloudTrail to enable data events.
		- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html`,
	},
	categoryCloudTrail + "/cloudtrailDeliveryFailing": {
		Risk: `CloudTrail Delivery Failing
		- Ensures that Amazon CloudTrail trail log files are delivered to destination S3 bucket.
		- Amazon CloudTrail trail logs should be delivered to destination S3 bucket to be used for security audits.`,
		Recommendation: `Modify CloudTrail trail configurations so that logs are being delivered
		- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-cloudtrail-works.html`,
	},
	categoryCloudTrail + "/cloudtrailEnabled": {
		Risk: `CloudTrail Enabled
		- Ensures CloudTrail is enabled for all regions within an account
		- CloudTrail should be enabled for all regions in order to detect suspicious activity in regions that are not typically used.`,
		Recommendation: `Enable CloudTrail for all regions and ensure that at least one region monitors global service events
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html`,
	},
	categoryCloudTrail + "/cloudtrailEncryption": {
		Risk: `CloudTrail Encryption
		- Ensures CloudTrail encryption at rest is enabled for logs
		- CloudTrail log files contain sensitive information about an account and should be encrypted at rest for additional protection.`,
		Recommendation: `Enable CloudTrail log encryption through the CloudTrail console or API
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html`,
	},
	categoryCloudTrail + "/cloudtrailFileValidation": {
		Risk: `CloudTrail File Validation
		- Ensures CloudTrail file validation is enabled for all regions within an account
		- CloudTrail file validation is essentially a hash of the file which can be used to ensure its integrity in the case of an account compromise.`,
		Recommendation: `Enable CloudTrail file validation for all regions
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html`,
	},
	categoryCloudTrail + "/cloudtrailObjectLock": {
		Risk: `Object Lock Enabled
		- Ensures that AWS CloudTrail S3 buckets use Object Lock for data protection and regulatory compliance.'
		- CloudTrail buckets should be configured to have object lock enabled. You can use it to prevent an object from being deleted or overwritten for a fixed amount of time or indefinitely.`,
		Recommendation: `Edit trail to use a bucket with object locking enabled.
		- https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lock-managing.html`,
	},
	categoryCloudTrail + "/cloudtrailS3Bucket": {
		Risk: `CloudTrail S3 Bucket
		- Ensure that AWS CloudTrail trail uses the designated Amazon S3 bucket.
		- Ensure that your Amazon CloudTrail trail is configured to use the appropriated S3 bucket in order to meet regulatory compliance requirements within your organization.`,
		Recommendation: `Modify ClouTrail trails to configure designated S3 bucket
		- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-update-a-trail-console.html`,
	},
	categoryCloudTrail + "/cloudtrailToCloudwatch": {
		Risk: `CloudTrail To CloudWatch
		- Ensures CloudTrail logs are being properly delivered to CloudWatch
		- Sending CloudTrail logs to CloudWatch enables easy integration with AWS CloudWatch alerts, as well as an additional backup log storage location.`,
		Recommendation: `Enable CloudTrail CloudWatch integration for all regions
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html`,
	},
	categoryCloudTrail + "/globalLoggingDuplicated": {
		Risk: `CloudTrail Global Services Logging Duplicated
		- Ensures that AWS CloudTrail trails are not duplicating global services events in log files.
		- Only one trail should have Include Global Services feature enabled to avoid duplication of global services events in log files.`,
		Recommendation: `Update CloudTrail trails to log global services events enabled for only one trail
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html`,
	},
	categoryCloudWatchLogs + "/monitoringMetrics": {
		Risk: `CloudWatch Monitoring Metrics
		- Ensures metric filters are setup for CloudWatch logs to detect security risks from CloudTrail.
		- Sending CloudTrail logs to CloudWatch is only useful if metrics are setup to detect risky activity from those logs. There are numerous metrics that should be used. For the exact filter patterns, please see this plugin on GitHub: https://github.com/cloudsploit/scans/blob/master/plugins/aws/cloudwatchlogs/monitoringMetrics.js`,
		Recommendation: `Enable metric filters to detect malicious activity in CloudTrail logs sent to CloudWatch.
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html`,
	},
	categoryComprehend + "/outputResultEncryption": {
		Risk: `Amazon Comprehend Output Result Encryption
		- Ensures the Comprehend service is using encryption for all result output.
		- Comprehend supports using KMS keys to result output, which should be enabled.`,
		Recommendation: `Enable output result encryption for the Comprehend job
		- https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html`,
	},
	categoryComprehend + "/volumeEncryption": {
		Risk: `Amazon Comprehend Volume Encryption
		- Ensures the Comprehend service is using encryption for all volumes storing data at rest.
		- Comprehend supports using KMS keys to encrypt data at rest, which should be enabled.`,
		Recommendation: `Enable volume encryption for the Comprehend job
		- https://docs.aws.amazon.com/comprehend/latest/dg/kms-in-comprehend.html`,
	},
	categoryConfigService + "/configServiceEnabled": {
		Risk: `Config Service Enabled
		- Ensures the AWS Config Service is enabled to detect changes to account resources
		- The AWS Config Service tracks changes to a number of resources in an AWS account and is invaluable in determining how account changes affect other resources and in recovery in the event of an account intrusion or accidental configuration change.`,
		Recommendation: `Enable the AWS Config Service for all regions and resources in an account. Ensure that it is properly recording and delivering logs.
		- https://aws.amazon.com/config/details/`,
	},
	categoryDMS + "/dmsEncryptionEnabled": {
		Risk: `DMS Encryption Enabled
		- Ensures DMS encryption is enabled using a CMK
		- Data sent through the data migration service is encrypted using KMS. Encryption is enabled by default, but it is recommended to use customer managed keys.`,
		Recommendation: `Enable encryption using KMS CMKs for all DMS replication instances.
		- https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html`,
	},
	categoryDynamoDB + "/daxClusterEncryption": {
		Risk: `DynamoDB Accelerator Cluster Encryption
		- Ensures DynamoDB Cluster Accelerator DAX clusters have encryption enabled.
		- DynamoDB Clusters Accelerator DAX clusters should have encryption at rest enabled to secure data from unauthorized access.`,
		Recommendation: `Enable encryption for DAX cluster.
		- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html`,
	},
	categoryDynamoDB + "/dynamoKmsEncryption": {
		Risk: `DynamoDB KMS Encryption
		- Ensures DynamoDB tables are encrypted using a customer-owned KMS key.
		- DynamoDB tables can be encrypted using AWS-owned or customer-owned KMS keys. Customer keys should be used to ensure control over the encryption seed data.`,
		Recommendation: `Create a new DynamoDB table using a CMK KMS key.
		- https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html`,
	},
	categoryEC2 + "/allowedCustomPorts": {
		Risk: `Allowed Custom Ports
		- Ensures that security groups does not allow public access to any port.
		- Security groups should be used to restrict access to ports from known networks.`,
		Recommendation: `Modify the security group to ensure the ports are not exposed publicly
		- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html`,
	},
	categoryEC2 + "/appTierInstanceIamRole": {
		Risk: `App-Tier EC2 Instance IAM Role
		- Ensure IAM roles attached with App-Tier EC2 instances have IAM policies attached.
		- EC2 instances should have IAM roles configured with necessary permission to access other AWS services`,
		Recommendation: `Modify EC2 instances to attach IAM roles with required IAM policies
		- https://aws.amazon.com/blogs/security/new-attach-an-aws-iam-role-to-an-existing-amazon-ec2-instance-by-using-the-aws-cli/`,
	},
	categoryEC2 + "/classicInstances": {
		Risk: `Detect EC2 Classic Instances
		- Ensures AWS VPC is being used for instances instead of EC2 Classic
		- VPCs are the latest and more secure method of launching AWS resources. EC2 Classic should not be used.`,
		Recommendation: `Migrate instances from EC2 Classic to VPC
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Introduction.html`,
	},
	categoryEC2 + "/crossVpcPublicPrivate": {
		Risk: `Cross VPC Public Private Communication
		- Ensures communication between public and private VPC tiers is not enabled.
		- Communication between the public tier of one VPC and the private tier of other VPCs should never be allowed. Instead, VPC peerings with proper NACLs and gateways should be used`,
		Recommendation: `Remove the NACL rules allowing communication between the public and private tiers of different VPCs
		- https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html`,
	},
	categoryEC2 + "/defaultSecurityGroup": {
		Risk: `Default Security Group
		- Ensure the default security groups block all traffic by default
		- The default security group is often used for resources launched without a defined security group. For this reason, the default rules should be to block all traffic to prevent an accidental exposure.`,
		Recommendation: `Update the rules for the default security group to deny all traffic by default
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group`,
	},
	categoryEC2 + "/defaultVpcExists": {
		Risk: `Default VPC Exists
		- Determines whether the default VPC exists.
		- The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity. Each application, or network tier, should use its own VPC.`,
		Recommendation: `Move resources from the default VPC to a new VPC created for that application or resource group.
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html`,
	},
	categoryEC2 + "/defaultVpcInUse": {
		Risk: `Default VPC In Use
		- Determines whether the default VPC is being used for launching EC2 instances.
		- The default VPC should not be used in order to avoid launching multiple services in the same network which may not require connectivity. Each application, or network tier, should use its own VPC.`,
		Recommendation: `Move resources from the default VPC to a new VPC created for that application or resource group.
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/default-vpc.html`,
	},
	categoryEC2 + "/ebsEncryptedSnapshots": {
		Risk: `EBS Encrypted Snapshots
		- Ensures EBS snapshots are encrypted at rest
		- EBS snapshots should have at-rest encryption enabled through AWS using KMS. If the volume was not encrypted and a snapshot was taken the snapshot will be unencrypted.`,
		Recommendation: `Configure volume encryption and delete unencrypted EBS snapshots.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html#encryption-support`,
	},
	categoryEC2 + "/ebsEncryptionEnabled": {
		Risk: `EBS Encryption Enabled
		- Ensures EBS volumes are encrypted at rest
		- EBS volumes should have at-rest encryption enabled through AWS using KMS. If the volume is used for a root volume, the instance must be launched from an AMI that has been encrypted as well.`,
		Recommendation: `Enable encryption for EBS volumes.
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html`,
	},
	categoryEC2 + "/ebsOldSnapshots": {
		Risk: `EBS Volumes Too Old Snapshots
		- Ensure that EBS volume snapshots are deleted after defined time period.
		- EBS volume snapshots older than indicated should be deleted after defined time period for cost optimization.`,
		Recommendation: `Delete the EBS snapshots past their defined expiration date
		- https://docs.amazonaws.cn/en_us/AWSEC2/latest/UserGuide/ebs-deleting-snapshot.html`,
	},
	categoryEC2 + "/ebsSnapshotLifecycle": {
		Risk: `Automate EBS Snapshot Lifecycle
		- Ensure DLM is used to automate EBS volume snapshots management.
		- Amazon Data Lifecycle Manager (DLM) service enables you to manage the lifecycle of EBS volume snapshots.
		- Using DLM helps in enforcing regular backup schedule, retaining backups, deleting outdated EBS snapshots`,
		Recommendation: `Create lifecycle policy for EBS volumes.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html`,
	},
	categoryEC2 + "/ebsSnapshotPrivate": {
		Risk: `EBS Volume Snapshot Public
		- Ensures EBS volume snapshots are private
		- EBS volumes often contain sensitive data from running EC2 instances and should be set to private so they cannot be accidentally shared with other accounts.`,
		Recommendation: `Ensure that each EBS snapshot has its permissions set to private.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html`,
	},
	categoryEC2 + "/ebsSnapshotPublic": {
		Risk: `Amazon EBS Public Snapshots
		- Ensure that Amazon EBS volume snapshots are not shared to all AWS accounts.
		- AWS Elastic Block Store (EBS) volume snapshots should not be not publicly shared with other AWS account to avoid data exposure.`,
		Recommendation: `Modify the permissions of public snapshots to remove public access.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html`,
	},
	categoryEC2 + "/ebsUnusedVolumes": {
		Risk: `Unused EBS Volumes
		- Ensures EBS volumes are in use and attached to EC2 instances
		- EBS volumes should be deleted if the parent instance has been deleted to prevent accidental exposure of data.`,
		Recommendation: `Delete the unassociated EBS volume.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-deleting-volume.html`,
	},
	categoryEC2 + "/ec2MetadataOptions": {
		Risk: `Insecure EC2 Metadata Options
		- Ensures EC2 instance metadata is updated to require HttpTokens or disable HttpEndpoint
		- The new EC2 metadata service prevents SSRF attack escalations from accessing the sensitive instance metadata endpoints.`,
		Recommendation: `Update instance metadata options to use IMDSv2
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#configuring-instance-metadata-service`,
	},
	categoryEC2 + "/elasticIpLimit": {
		Risk: `Elastic IP Limit
		- Determine if the number of allocated EIPs is close to the AWS per-account limit
		- AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.`,
		Recommendation: `Contact AWS support to increase the number of EIPs available
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit`,
	},
	categoryEC2 + "/encryptedAmi": {
		Risk: `Encrypted AMI
		- Ensures EBS-backed AMIs are configured to use encryption
		- AMIs with unencrypted data volumes can be used to launch unencrypted instances that place data at risk.`,
		Recommendation: `Ensure all AMIs have encrypted EBS volumes.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIEncryption.html`,
	},
	categoryEC2 + "/excessiveSecurityGroups": {
		Risk: `Excessive Security Groups
		- Determine if there are an excessive number of security groups in the account
		- Keeping the number of security groups to a minimum helps reduce the attack surface of an account.
		- Rather than creating new groups with the same rules for each project, common rules should be grouped under the same security groups. For example, instead of adding port 22 from a known IP to every group, create a single "SSH" security group which can be used on multiple instances.`,
		Recommendation: `Limit the number of security groups to prevent accidental authorizations
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/flowLogsEnabled": {
		Risk: `VPC Flow Logs Enabled
		- Ensures VPC flow logs are enabled for traffic logging
		- VPC flow logs record all traffic flowing in to and out of a VPC. These logs are critical for auditing and review after security incidents.`,
		Recommendation: `Enable VPC flow logs for each VPC
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/flow-logs.html`,
	},
	categoryEC2 + "/instanceIamRole": {
		Risk: `Instance IAM Role
		- Ensures EC2 instances are using an IAM role instead of hard-coded AWS credentials
		- IAM roles should be assigned to all instances to enable them to access AWS resources. Using an IAM role is more secure than hard-coding AWS access keys into application code.`,
		Recommendation: `Attach an IAM role to the EC2 instance
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html`,
	},
	categoryEC2 + "/instanceKeyBasedLogin": {
		Risk: `EC2 Instance Key Based Login
		- Ensures EC2 instances have associated keys for password-less SSH login
		- AWS allows EC2 instances to be launched with a specified PEM key for SSH login which should be used instead of user and password login.`,
		Recommendation: `Ensure each EC2 instance has an associated SSH key and disable password login.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html`,
	},
	categoryEC2 + "/instanceLimit": {
		Risk: `Instance Limit
		- Determine if the number of EC2 instances is close to the AWS per-account limit
		- AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.`,
		Recommendation: `Contact AWS support to increase the number of instances available
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit`,
	},
	categoryEC2 + "/instanceMaxCount": {
		Risk: `EC2 Max Instances
		- Ensures the total number of EC2 instances does not exceed a set threshold.
		- The number of running EC2 instances should be carefully audited, especially in unused regions, to ensure only approved applications are consuming compute resources.
		- Many compromised AWS accounts see large numbers of EC2 instances launched.`,
		Recommendation: `Ensure that the number of running EC2 instances matches the expected count.
		- If instances are launched above the threshold, investigate to ensure they are legitimate.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring_ec2.html`,
	},
	categoryEC2 + "/instanceVcpusLimit": {
		Risk: `Instance vCPU On-Demand Based Limits
		- Determine if the number of EC2 On-Demand instances is close to the regional vCPU based limit.
		- AWS limits accounts to certain numbers of resources per region. Exceeding those limits could prevent resources from launching.`,
		Recommendation: `EC2 automatically increases On Demand Instance limits based on usage, limit increases can be requested via the Limits Page on Amazon EC2 console, the EC2 service page on the Service Quotas console, or the Service Quotas API/CLI.
		- https://aws.amazon.com/ec2/faqs/#EC2_On-Demand_Instance_limits`,
	},
	categoryEC2 + "/launchWizardSecurityGroups": {
		Risk: `EC2 LaunchWizard Security Groups
		- Ensures security groups created by the EC2 launch wizard are not used
		- The EC2 launch wizard frequently creates insecure security groups that are exposed publicly. 
		- These groups should not be used and custom security groups should be created instead.`,
		Recommendation: `Delete the launch wizard security group and replace it with a custom security group.
		- https://docs.aws.amazon.com/launchwizard/latest/userguide/launch-wizard-sap-security-groups.html`,
	},
	categoryEC2 + "/managedNatGateway": {
		Risk: `Managed NAT Gateway In Use
		- Ensure AWS VPC Managed NAT (Network Address Translation) Gateway service is enabled for high availability (HA).
		- VPCs should use highly available Managed NAT Gateways in order to enable EC2 instances to connect to the internet or with other AWS components.`,
		Recommendation: `Update VPCs to use Managed NAT Gateways instead of NAT instances
		- https://aws.amazon.com/blogs/aws/new-managed-nat-network-address-translation-gateway-for-aws/`,
	},
	categoryEC2 + "/multipleSubnets": {
		Risk: `VPC Multiple Subnets
		- Ensures that VPCs have multiple subnets to provide a layered architecture
		- VPCs should be designed to have separate public and private subnets, ideally across availability zones, enabling a DMZ-style architecture.`,
		Recommendation: `Create at least two subnets in each VPC, utilizing one for public traffic and the other for private traffic.
		- https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#SubnetSecurity`,
	},
	categoryEC2 + "/natMultiAz": {
		Risk: `NAT Multiple AZ
		- Ensures managed NAT instances exist in at least 2 AZs for availability purposes
		- Creating NAT instances in a single AZ creates a single point of failure for all systems in the VPC. 
		- All managed NAT instances should be created in multiple AZs to ensure proper failover.`,
		Recommendation: `Launch managed NAT instances in multiple AZs.
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-nat-gateway.html`,
	},
	categoryEC2 + "/openAllPortsProtocols": {
		Risk: `Open All Ports Protocols
		- Determine if security group has all ports or protocols open to the public
		- Security groups should be created on a per-service basis and avoid allowing all ports or protocols.`,
		Recommendation: `Modify the security group to specify a specific port and protocol to allow.
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openCIFS": {
		Risk: `Open CIFS
		- Determine if UDP port 445 for CIFS is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as CIFS should be restricted to known IP addresses.`,
		Recommendation: `Restrict UDP port 445 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openCustomPorts": {
		Risk: `Open Custom Ports
		- Ensure that defined custom ports are not open to public.
		- Security groups should restrict access to ports from known networks.`,
		Recommendation: `Modify the security group to ensure the defined custom ports are not exposed publicly
		- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html`,
	},
	categoryEC2 + "/openDNS": {
		Risk: `Open DNS
		- Determine if TCP or UDP port 53 for DNS is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as DNS should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP and UDP port 53 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openDocker": {
		Risk: `Open Docker
		- Determine if Docker port 2375 or 2376 is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Docker should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP ports 2375 and 2376 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openElasticsearch": {
		Risk: `Open Elasticsearch
		- Determine if TCP port 9200 for Elasticsearch is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Elasticsearch should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 9200 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openFTP": {
		Risk: `Open FTP
		- Determine if TCP port 20 or 21 for FTP is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as FTP should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP ports 20 and 21 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openHadoopNameNode": {
		Risk: `Open Hadoop HDFS NameNode Metadata Service
		- Determine if TCP port 8020 for HDFS NameNode metadata service is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Hadoop/HDFS should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 8020 to known IP addresses for Hadoop/HDFS
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openHadoopNameNodeWebUI": {
		Risk: `Open Hadoop HDFS NameNode WebUI
		- Determine if TCP port 50070 and 50470 for Hadoop/HDFS NameNode WebUI service is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Hadoop/HDFS should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 50070 and 50470 to known IP addresses for Hadoop/HDFS
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openKibana": {
		Risk: `Open Kibana
		- Determine if TCP port 5601 for Kibana is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Kibana should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 5601 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openMySQL": {
		Risk: `Open MySQL
		- Determine if TCP port 4333 or 3306 for MySQL is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as MySQL should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP ports 4333 and 3306 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openNetBIOS": {
		Risk: `Open NetBIOS
		- Determine if UDP port 137 or 138 for NetBIOS is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as NetBIOS should be restricted to known IP addresses.`,
		Recommendation: `Restrict UDP ports 137 and 138 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openOracle": {
		Risk: `Open Oracle
		- Determine if TCP port 1521 for Oracle is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Oracle should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP ports 1521 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openOracleAutoDataWarehouse": {
		Risk: `Open Oracle Auto Data Warehouse
		- Determine if TCP port 1522 for Oracle Auto Data Warehouse is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Oracle Auto Data Warehouse should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP ports 1522 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openPostgreSQL": {
		Risk: `Open PostgreSQL
		- Determine if TCP port 5432 for PostgreSQL is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as PostgreSQL should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 5432 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openRDP": {
		Risk: `Open RDP
		- Determine if TCP port 3389 for RDP is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RDP should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 3389 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openRPC": {
		Risk: `Open RPC
		- Determine if TCP port 135 for RPC is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as RPC should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 135 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openSalt": {
		Risk: `Open Salt
		- Determine if TCP ports 4505 or 4506 for the Salt master are open to the public
		- Active Salt vulnerabilities, CVE-2020-11651 and CVE-2020-11652 are exploiting Salt instances exposed to the internet. These ports should be closed immediately.`,
		Recommendation: `Restrict TCP ports 4505 and 4506 to known IP addresses
		- https://help.saltstack.com/hc/en-us/articles/360043056331-New-SaltStack-Release-Critical-Vulnerability`,
	},
	categoryEC2 + "/openSMBoTCP": {
		Risk: `Open SMBoTCP
		- Determine if TCP port 445 for Windows SMB over TCP is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMB should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 445 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openSMTP": {
		Risk: `Open SMTP
		- Determine if TCP port 25 for SMTP is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SMTP should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 25 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openSQLServer": {
		Risk: `Open SQL Server
		- Determine if TCP port 1433 or UDP port 1434 for SQL Server is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SQL server should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 1433 and UDP port 1434 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openSSH": {
		Risk: `Open SSH
		- Determine if TCP port 22 for SSH is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as SSH should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 22 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openTelnet": {
		Risk: `Open Telnet
		- Determine if TCP port 23 for Telnet is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as Telnet should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 23 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openVNCClient": {
		Risk: `Open VNC Client
		- Determine if TCP port 5500 for VNC Client is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Client should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 5500 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/openVNCServer": {
		Risk: `Open VNC Server
		- Determine if TCP port 5900 for VNC Server is open to the public
		- While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as VNC Server should be restricted to known IP addresses.`,
		Recommendation: `Restrict TCP port 5900 to known IP addresses
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/overlappingSecurityGroups": {
		Risk: `Overlapping Security Groups
		- Determine if EC2 instances have security groups that share the same rules
		- Overlapping security group rules make managing EC2 instance access much more difficult.
		- If a rule is removed from one security group, the access may still remain in another resulting in unintended access to the instance.`,
		Recommendation: `Structure security groups to provide a single category of access and do not duplicate rules across groups used by the same instances.
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	categoryEC2 + "/publicAmi": {
		Risk: `Public AMI
		- Checks for publicly shared AMIs
		- Accidentally sharing AMIs allows any AWS user to launch an EC2 instance using the image as a base. This can potentially expose sensitive information stored on the host.`,
		Recommendation: `Convert the public AMI a private image.
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html`,
	},
	categoryEC2 + "/publicIpAddress": {
		Risk: `Public IP Address EC2 Instances
		- Ensures that EC2 instances do not have public IP address attached.
		- EC2 instances should not have a public IP address attached in order to block public access to the instances.`,
		Recommendation: `Remove the public IP address from the EC2 instances to block public access to the instance
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html`,
	},
	categoryEC2 + "/securityGroupRfc1918": {
		Risk: `Open RFC 1918
		- Ensures EC2 security groups are configured to deny inbound traffic from RFC-1918 CIDRs
		- RFC-1918 IP addresses are considered reserved private addresses and should not be used in security groups.`,
		Recommendation: `Modify the security group to deny private reserved addresses for inbound traffic
		- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html`,
	},
	categoryEC2 + "/subnetIpAvailability": {
		Risk: `Subnet IP Availability
		- Determine if a subnet is at risk of running out of IP addresses
		- Subnets have finite IP addresses. Running out of IP addresses could prevent resources from launching.`,
		Recommendation: `Add a new subnet with larger CIDR block and migrate resources.
		- http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html`,
	},
	categoryEC2 + "/unassociatedElasticIp": {
		Risk: `Unassociated Elastic IP Addresses
		- Ensures all EIPs are allocated to a resource to avoid accidental usage or reuse and to save costs
		- EIPs should be deleted if they are not in use to avoid extra charges.`,
		Recommendation: `Delete the unassociated Elastic IP
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html`,
	},
	categoryEC2 + "/unusedAmi": {
		Risk: `Unused Amazon Machine Images
		- Ensures that all Amazon Machine Images are in use to ensure cost optimization.
		- All unused/deregistered Amazon Machine Images should be deleted to avoid extraneous cost.`,
		Recommendation: `Delete the unused/deregistered AMIs
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html`,
	},
	categoryEC2 + "/unusedEni": {
		Risk: `Unused Elastic Network Interfaces
		- Ensures that unused AWS Elastic Network Interfaces (ENIs) are removed.
		- Unused AWS ENIs should be removed to follow best practices and to avoid reaching the service limit.`,
		Recommendation: `Delete the unused AWS Elastic Network Interfaces
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html`,
	},
	categoryEC2 + "/unusedVirtualPrivateGateway": {
		Risk: `Unused Virtual Private Gateway
		- Ensures that unused Virtual Private Gateways (VGWs) are removed.
		- Unused VGWs should be remove to follow best practices and to avoid reaching the service limit.`,
		Recommendation: `Remove the unused Virtual Private Gateways (VGWs)
		- https://docs.aws.amazon.com/vpn/latest/s2svpn/delete-vpn.html`,
	},
	categoryEC2 + "/unusedVpcInternetGateways": {
		Risk: `Unused VPC Internet Gateways
		- Ensures that unused VPC Internet Gateways and Egress-Only Internet Gateways are removed.
		- Unused VPC Internet Gateways and Egress-Only Internet Gateways must be removed to avoid reaching the internet gateway limit.`,
		Recommendation: `Remove the unused/detached Internet Gateways and Egress-Only Internet Gateways
		- https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html`,
	},
	categoryEC2 + "/vpcElasticIpLimit": {
		Risk: `VPC Elastic IP Limit
		- Determine if the number of allocated VPC EIPs is close to the AWS per-account limit
		- AWS limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.`,
		Recommendation: `Contact AWS support to increase the number of EIPs available
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-limit`,
	},
	categoryEC2 + "/vpcEndpointAcceptance": {
		Risk: `VPC PrivateLink Endpoint Acceptance Required
		- Ensures VPC PrivateLink endpoints require acceptance
		- VPC PrivateLink endpoints should be configured to require acceptance so that access to the endpoint is controlled on a case-by-case basis.`,
		Recommendation: `Update the VPC PrivateLink endpoint to require acceptance
		- https://docs.aws.amazon.com/vpc/latest/userguide/accept-reject-endpoint-requests.html`,
	},
	categoryEC2 + "/vpcEndpointExposed": {
		Risk: `VPC Endpoint Exposed
		- Ensure Amazon VPC endpoints are not publicly exposed.
		- VPC endpoints should not be publicly accessible in order to avoid any unsigned requests made to the services inside VPC.`,
		Recommendation: `Update VPC endpoint access policy in order to stop any unsigned requests
		- https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html`,
	},
	categoryEC2 + "/webTierInstanceIamRole": {
		Risk: `Web-Tier EC2 Instance IAM Role
		- Ensure IAM roles attached with Web-Tier EC2 instances have IAM policies attached.
		- EC2 instances should have IAM roles configured with necessary permission to access other AWS services`,
		Recommendation: `Modify EC2 instances to attach IAM roles with required IAM policies
		- https://aws.amazon.com/blogs/security/new-attach-an-aws-iam-role-to-an-existing-amazon-ec2-instance-by-using-the-aws-cli/`,
	},
	categoryECR + "/ecrRepositoryPolicy": {
		Risk: `ECR Repository Policy
		- Ensures ECR repository policies do not enable global or public access to images
		- ECR repository policies should limit access to images to known IAM entities and AWS accounts and avoid the use of account-level wildcards.`,
		Recommendation: `Update the repository policy to limit access to known IAM entities.
		- https://docs.aws.amazon.com/AmazonECR/latest/userguide/RepositoryPolicyExamples.html`,
	},
	categoryECR + "/ecrRepositoryTagImmutability": {
		Risk: `ECR Repository Tag Immutability
		- Ensures ECR repository image tags cannot be overwritten
		- ECR repositories should be configured to prevent overwriting of image tags to avoid potentially-malicious images from being deployed to live environments.`,
		Recommendation: `Update ECR registry configurations to ensure image tag mutability is set to immutable.
		- https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html`,
	},
	categoryEFS + "/efsCmkEncrypted": {
		Risk: `EFS CMK Encrypted
		- Ensure EFS file systems are encrypted using Customer Master Keys (CMKs).
		- EFS file systems should use KMS Customer Master Keys (CMKs) instead of AWS managed keys for encryption in order to have full control over data encryption and decryption.`,
		Recommendation: `Encryption at rest key can only be configured during file system creation. Encryption of data in transit is configured when mounting your file system. 1. Backup your data in not encrypted efs 2. Recreate the EFS and use KMS CMK for encryption of data at rest.
		- https://docs.aws.amazon.com/efs/latest/ug/encryption-at-rest.html`,
	},
	categoryEFS + "/efsEncryptionEnabled": {
		Risk: `EFS Encryption Enabled
		- Ensures that EFS volumes are encrypted at rest
		- EFS offers data at rest encryption using keys managed through AWS Key Management Service (KMS).`,
		Recommendation: `Encryption of data at rest can only be enabled during file system creation.
		Encryption of data in transit is configured when mounting your file system. 
		
		1. Backup your data in not encrypted efs 
		2. Recreate the EFS and select 'Enable encryption of data at rest'`,
	},
	categoryEKS + "/eksKubernetesVersion": {
		Risk: `EKS Kubernetes Version
		- Ensures the latest version of Kubernetes is installed on EKS clusters
		- EKS supports provisioning clusters from several versions of Kubernetes. Clusters should be kept up to date to ensure Kubernetes security patches are applied.`,
		Recommendation: `Upgrade the version of Kubernetes on all EKS clusters to the latest available version.
		- https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html`,
	},
	categoryEKS + "/eksLoggingEnabled": {
		Risk: `EKS Logging Enabled
		- Ensures all EKS cluster logs are being sent to CloudWatch
		- EKS supports routing of cluster event and audit logs to CloudWatch, including control plane logs.
		- All logs should be sent to CloudWatch for security analysis.`,
		Recommendation: `Enable all EKS cluster logs to be sent to CloudWatch with proper log retention limits.
		- https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html`,
	},
	categoryEKS + "/eksPrivateEndpoint": {
		Risk: `EKS Private Endpoint
		- Ensures the private endpoint setting is enabled for EKS clusters
		- EKS private endpoints can be used to route all traffic between the Kubernetes worker and control plane nodes over a private VPC endpoint rather than across the public internet.`,
		Recommendation: `Enable the private endpoint setting for all EKS clusters.
		- https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html`,
	},
	categoryEKS + "/eksSecurityGroups": {
		Risk: `EKS Security Groups
		- Ensures the EKS control plane only allows inbound traffic on port 443.
		- The EKS control plane only requires port 443 access. Security groups for the control plane should not add additional port access.`,
		Recommendation: `Configure security groups for the EKS control plane to allow access only on port 443.
		- https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html`,
	},
	categoryElasticBeanstalk + "/managedPlatformUpdates": {
		Risk: `ElasticBeanstalk Managed Platform Updates
		- Ensures ElasticBeanstalk applications are configured to use managed updates.
		- Environments for an application should be configured to allow platform managed updates.`,
		Recommendation: `Update the environment to enable managed updates.
		- https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html`,
	},
	categoryELB + "/elbHttpsOnly": {
		Risk: `ELB HTTPS Only
		- Ensures ELBs are configured to only accept connections on HTTPS ports.
		- For maximum security, ELBs can be configured to only accept HTTPS connections.
		- Standard HTTP connections will be blocked.
		- This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.`,
		Recommendation: `Remove non-HTTPS listeners from load balancer.
		- http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html`,
	},
	categoryELB + "/elbLoggingEnabled": {
		Risk: `ELB Logging Enabled
		- Ensures load balancers have request logging enabled.
		- Logging requests to ELB endpoints is a helpful way of detecting and investigating potential attacks, malicious activity, or misuse of backend resources.
		- Logs can be sent to S3 and processed for further analysis.`,
		Recommendation: `Enable ELB request logging
		- http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`,
	},
	categoryELB + "/elbNoInstances": {
		Risk: `ELB No Instances
		- Detects ELBs that have no backend instances attached
		- All ELBs should have backend server resources.
		- Those without any are consuming costs without providing any functionality. Additionally, old ELBs with no instances present a security concern if new instances are accidentally attached.`,
		Recommendation: `Delete old ELBs that no longer have backend resources.
		- http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-backend-instances.html`,
	},
	categoryELB + "/insecureCiphers": {
		Risk: `Insecure Ciphers
		- Detect use of insecure ciphers on ELBs
		- Various security vulnerabilities have rendered several ciphers insecure. Only the recommended ciphers should be used.`,
		Recommendation: `Update your ELBs to use the recommended cipher suites
		- http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html`,
	},
	categoryELBv2 + "/elbv2DeletionProtection": {
		Risk: `ELBv2 Deletion Protection
		- Ensures ELBv2 load balancers are configured with deletion protection.
		- ELBv2 load balancers should be configured with deletion protection to prevent accidental deletion of live resources in production environments.`,
		Recommendation: `Update ELBv2 load balancers to use deletion protection to prevent accidental deletion
		- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#deletion-protection`,
	},
	categoryELBv2 + "/elbv2HttpsOnly": {
		Risk: `ELBv2 HTTPS Only
		- Ensures ELBs are configured to only accept connections on HTTPS ports.
		- For maximum security, ELBs can be configured to only accept HTTPS connections.
		- Standard HTTP connections will be blocked. This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.`,
		Recommendation: `Remove non-HTTPS listeners from load balancer.
		- http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html`,
	},
	categoryELBv2 + "/elbv2LoggingEnabled": {
		Risk: `ELBv2 Logging Enabled
		- Ensures load balancers have request logging enabled.
		- Logging requests to ELB endpoints is a helpful way of detecting and investigating potential attacks, malicious activity, or misuse of backend resources.
        - Logs can be sent to S3 and processed for further analysis.`,
		Recommendation: `Enable ELB request logging
		- http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`,
	},
	categoryELBv2 + "/elbv2MinimumTargetInstances": {
		Risk: `ELBv2 Minimum Number of EC2 Target Instances
		- Ensures that there is a minimum number of two healthy target instances associated with each AWS ELBv2 load balancer.
		- There should be a minimum number of two healthy target instances associated with each AWS ELBv2 load balancer to ensure fault tolerance.`,
		Recommendation: `Associate at least two healthy target instances to AWS ELBv2 load balancer
		- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html`,
	},
	categoryELBv2 + "/elbv2NlbListenerSecurity": {
		Risk: `ELBv2 NLB Listener Security
		- Ensures that AWS Network Load Balancers have secured listener configured.
		- AWS Network Load Balancer should have TLS protocol listener configured to terminate TLS traffic.`,
		Recommendation: `Attach TLS listener to AWS Network Load Balancer
		- https://docs.amazonaws.cn/en_us/elasticloadbalancing/latest/network/create-tls-listener.html`,
	},
	categoryELBv2 + "/elbv2NoInstances": {
		Risk: `ELBv2 No Instances
		- Detects ELBs that have no target groups attached
		- All ELBs should have backend server resources.
        - Those without any are consuming costs without providing any functionality.
		- Additionally, old ELBs with no target groups present a security concern if new target groups are accidentally attached.`,
		Recommendation: `Delete old ELBs that no longer have backend resources.
		- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html`,
	},
	categoryELBv2 + "/elbv2WafEnabled": {
		Risk: `ELBv2 WAF Enabled
		- Ensure that all Application Load Balancers have WAF enabled.
		- Enabling WAF allows control over requests to the load balancer, allowing or denying traffic based off rules in the Web ACL.`,
		Recommendation: `1. Enter the WAF service. 
		2. Enter Web ACLs and filter by the region the Application Load Balancer is in. 
		3. If no Web ACL is found, Create a new Web ACL in the region the ALB resides and in Resource type to associate with web ACL, select the Load Balancer.
		- https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/`,
	},
	categoryEMR + "/emrClusterLogging": {
		Risk: `EMR Cluster Logging
		- Ensure AWS Elastic MapReduce (EMR) clusters capture detailed log data to Amazon S3.
		- EMR cluster logging should be enabled to save log files for troubleshooting purposes.`,
		Recommendation: `Modify EMR clusters to enable cluster logging
		- https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html`,
	},
	categoryEMR + "/emrEncryptionAtRest": {
		Risk: `EMR Encryption At Rest
		- Ensures encryption at rest for local disks is enabled for EMR clusters
		- EMR clusters should be configured to enable encryption at rest for local disks.`,
		Recommendation: `Update security configuration associated with EMR cluster to enable encryption at rest for local disks.
		- https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html`,
	},
	categoryEMR + "/emrEncryptionInTransit": {
		Risk: `EMR Encryption In Transit
		- Ensures encryption in transit is enabled for EMR clusters
		- EMR clusters should be configured to enable encryption in transit.`,
		Recommendation: `Update security configuration associated with EMR cluster to enable encryption in transit.
		- https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-data-encryption-options.html`,
	},
	categoryES + "/esAccessFromIps": {
		Risk: `ElasticSearch Access From IP Addresses
		- Ensure only whitelisted IP addresses can access Amazon Elasticsearch domains.
		- ElasticSearch domains should only be accessible only from whitelisted IP addresses to avoid unauthorized access.`,
		Recommendation: `Modify Elasticseach domain access policy to allow only known/whitelisted IP addresses.
		- https://aws.amazon.com/blogs/security/how-to-control-access-to-your-amazon-elasticsearch-service-domain/`,
	},
	categoryES + "/esEncryptedDomain": {
		Risk: `ElasticSearch Encrypted Domain
		- Ensures ElasticSearch domains are encrypted with KMS
		- ElasticSearch domains should be encrypted to ensure data at rest is secured.`,
		Recommendation: `Ensure encryption-at-rest is enabled for all ElasticSearch domains.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html`,
	},
	categoryES + "/esExposedDomain": {
		Risk: `ElasticSearch Exposed Domain
		- Ensures ElasticSearch domains are not publicly exposed to all AWS accounts
		- ElasticSearch domains should not be publicly exposed to all AWS accounts.`,
		Recommendation: `Update elasticsearch domain to set access control.
		- https://aws.amazon.com/blogs/database/set-access-control-for-amazon-elasticsearch-service/`,
	},
	categoryES + "/esHttpsOnly": {
		Risk: `ElasticSearch HTTPS Only
		- Ensures ElasticSearch domains are configured to enforce HTTPS connections
		- ElasticSearch domains should be configured to enforce HTTPS connections for all clients to ensure encryption of data in transit.`,
		Recommendation: `Ensure HTTPS connections are enforced for all ElasticSearch domains.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html`,
	},
	categoryES + "/esLoggingEnabled": {
		Risk: `ElasticSearch Logging Enabled
		- Ensures ElasticSearch domains are configured to log data to CloudWatch
		- ElasticSearch domains should be configured with logging enabled with logs sent to CloudWatch for analysis and long-term storage.`,
		Recommendation: `Ensure logging is enabled and a CloudWatch log group is specified for each ElasticSearch domain.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html#es-createdomain-configure-slow-logs`,
	},
	categoryES + "/esNodeToNodeEncryption": {
		Risk: `ElasticSearch Node To Node Encryption
		- Ensures ElasticSearch domain traffic is encrypted in transit between nodes
		- ElasticSearch domains should use node-to-node encryption to ensure data in transit remains encrypted using TLS 1.2.`,
		Recommendation: `Ensure node-to-node encryption is enabled for all ElasticSearch domains.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html`,
	},
	categoryES + "/esPublicEndpoint": {
		Risk: `ElasticSearch Public Service Domain
		- Ensures ElasticSearch domains are created with private VPC endpoint options
		- ElasticSearch domains can either be created with a public endpoint or with a VPC configuration that enables internal VPC communication.
		- Domains should be created without a public endpoint to prevent potential public access to the domain.`,
		Recommendation: `Configure the ElasticSearch domain to use a VPC endpoint for secure VPC communication.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html`,
	},
	categoryES + "/esRequireIAMAuth": {
		Risk: `ElasticSearch IAM Authentication
		- Ensures ElasticSearch domains require IAM Authentication
		- ElasticSearch domains can allow access without IAM authentication by having a policy that does not specify the principal or has a wildcard principal`,
		Recommendation: `Configure the ElasticSearch domain to have an access policy without a global principal or no principal
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-ac.html`,
	},
	categoryES + "/esUpgradeAvailable": {
		Risk: `ElasticSearch Upgrade Available
		- Ensures ElasticSearch domains are running the latest service software
		- ElasticSearch domains should be configured to run the latest service software which often contains security updates.`,
		Recommendation: `Ensure each ElasticSearch domain is running the latest service software and update out-of-date domains.
		- https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-version-migration.html`,
	},
	categoryFirehose + "/firehoseEncrypted": {
		Risk: `Firehose Delivery Streams Encrypted
		- Ensures Firehose Delivery Stream encryption is enabled
		- Data sent through Firehose Delivery Streams can be encrypted using KMS server-side encryption.
		- Existing delivery streams can be modified to add encryption with minimal overhead.`,
		Recommendation: `Enable encryption using KMS for all Firehose Delivery Streams.
		- https://docs.aws.amazon.com/firehose/latest/dev/encryption.html`,
	},
	categoryGlue + "/bookmarkEncryptionEnabled": {
		Risk: `AWS Glue Job Bookmark Encryption Enabled
		- Ensures that AWS Glue job bookmark encryption is enabled.
		- AWS Glue security configuration should have job bookmark encryption enabled in order to encrypt the bookmark data before it is sent to Amazon S3.`,
		Recommendation: `Recreate Glue security configurations and enable job bookmark encryption
		- https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html`,
	},
	categoryGuardDuty + "/guardDutyEnabled": {
		Risk: `GuardDuty is Enabled
		- GuardDuty provides threat intelligence by analyzing several AWS data sources for security risks and should be enabled in all accounts.`,
		Recommendation: `Enable GuardDuty for all AWS accounts.
		- https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html`,
	},
	categoryGuardDuty + "/guardDutyMaster": {
		Risk: `GuardDuty Master Account
		- Ensures GuardDuty master account is correct
		- Organizations with large numbers of AWS accounts should configure GuardDuty findings from all member accounts to be sent to a consistent master account.`,
		Recommendation: `Configure the member account to send GuardDuty findings to a known master account.
		- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html#guardduty_master`,
	},
	categoryIAM + "/accessKeysExtra": {
		Risk: `Access Keys Extra
		- Detects the use of more than one access key by any single user
		- Having more than one access key for a single user increases the chance of accidental exposure.
		- Each account should only have one key that defines the users permissions.`,
		Recommendation: `Remove the extra access key for the specified user.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html`,
	},
	categoryIAM + "/accessKeysLastUsed": {
		Risk: `Access Keys Last Used
		- Detects access keys that have not been used for a period of time and that should be decommissioned
		- Having numerous, unused access keys extends the attack surface. Access keys should be removed if they are no longer being used.`,
		Recommendation: `Log into the IAM portal and remove the offending access key.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html`,
	},
	categoryIAM + "/accessKeysRotated": {
		Risk: `Access Keys Rotated
		- Ensures access keys are not older than 180 days in order to reduce accidental exposures
		- Access keys should be rotated frequently to avoid having them accidentally exposed.`,
		Recommendation: `To rotate an access key, first create a new key, replace the key and secret throughout your app or scripts, then set the previous key to disabled. 
		- Once you ensure that no services are broken, then fully delete the old key.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html`,
	},
	categoryIAM + "/canaryKeysUsed": {
		Risk: `Canary Keys Used
		- Detects when a special canary-token access key has been used
		- Canary access keys can be created with limited permissions and then used to detect when a potential breach occurs.`,
		Recommendation: `Create a canary access token and provide its user to CloudSploit.
		- If CloudSploit detects that the account is in use, it will trigger a failure.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html`,
	},
	categoryIAM + "/certificateExpiry": {
		Risk: `Certificate Expiry
		- Detect upcoming expiration of certificates used with ELBs
		- Certificates that have expired will trigger warnings in all major browsers`,
		Recommendation: `Update your certificates before the expiration date
		- http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-update-ssl-cert.html`,
	},
	categoryIAM + "/crossAccountMfaExtIdAccess": {
		Risk: `Cross-Account Access External ID and MFA
		- Ensures that either MFA or external IDs are used to access AWS roles.
		- IAM roles should be configured to require either a shared external ID or use an MFA device when assuming the role.`,
		Recommendation: `Update the IAM role to either require MFA or use an external ID.
		- https://aws.amazon.com/blogs/aws/mfa-protection-for-cross-account-access/`,
	},
	categoryIAM + "/emptyGroups": {
		Risk: `Empty Groups
		- Ensures all groups have at least one member
		- While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.`,
		Recommendation: `Remove unused groups without users
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_WorkingWithGroupsAndUsers.html`,
	},
	categoryIAM + "/groupInlinePolicies": {
		Risk: `Group Inline Policies
		- Ensures that groups do not have any inline policies
		- Managed Policies are recommended over inline policies.`,
		Recommendation: `Remove inline policies attached to groups
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html`,
	},
	categoryIAM + "/iamRoleLastUsed": {
		Risk: `IAM Role Last Used
		- Ensures IAM roles that have not been used within the given time frame are deleted.
		- IAM roles that have not been used for a long period may contain old access policies that could allow unintended access to resources if accidentally attached to new services.
		- These roles should be deleted.`,
		Recommendation: `Delete IAM roles that have not been used within the expected time frame.
		- https://aws.amazon.com/about-aws/whats-new/2019/11/identify-unused-iam-roles-easily-and-remove-them-confidently-by-using-the-last-used-timestamp/`,
	},
	categoryIAM + "/iamRolePolicies": {
		Risk: `IAM Role Policies
		- Ensures IAM role policies are properly scoped with specific permissions
		- Policies attached to IAM roles should be scoped to least-privileged access and avoid the use of wildcards.`,
		Recommendation: `Ensure that all IAM roles are scoped to specific services and API calls.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html`,
	},
	categoryIAM + "/iamUserAdmins": {
		Risk: `IAM User Admins
		- Ensures the number of IAM admins in the account are minimized
		- While at least two IAM admin users should be configured, the total number of admins should be kept to a minimum.`,
		Recommendation: `Keep two users with admin permissions but ensure other IAM users have more limited permissions.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started_create-admin-group.html`,
	},
	categoryIAM + "/iamUserNameRegex": {
		Risk: `IAM Username Matches Regex
		- Ensures all IAM user names match the given regex
		- Many organizational policies require IAM user names to follow a common naming convention.
		- This check ensures these conventions are followed.`,
		Recommendation: `Rename the IAM user name to match the provided regex.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html`,
	},
	categoryIAM + "/iamUserUnauthorizedToEdit": {
		Risk: `IAM User Unauthorized to Edit
		- Ensures AWS IAM users that are not authorized to edit IAM access policies are decommissioned.
		- Only authorized IAM users should have permission to edit IAM access policies to prevent any unauthorized requests.`,
		Recommendation: `Update unauthorized IAM users to remove permissions to edit IAM access policies.
		- Update unauthorized IAM users to remove permissions to edit IAM access policies.`,
	},
	categoryIAM + "/maxPasswordAge": {
		Risk: `Maximum Password Age
		- Ensures password policy requires passwords to be reset every 180 days
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Descrease the maximum allowed age of passwords for the password policy
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/minPasswordLength": {
		Risk: `Minimum Password Length
		- Ensures password policy requires a password of at least a minimum number of characters
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Increase the minimum length requirement for the password policy
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/noUserIamPolicies": {
		Risk: `No User IAM Policies
		- Ensures IAM policies are not connected directly to IAM users
		- To reduce management complexity, IAM permissions should only be assigned to roles and groups. Users can then be added to those groups.
		- Policies should not be applied directly to a user.`,
		Recommendation: `Create groups with the required policies, move the IAM users to the applicable groups, and then remove the inline and directly attached policies from the IAM user.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions`,
	},
	categoryIAM + "/passwordExpiration": {
		Risk: `Password Expiration
		- Ensures password policy enforces a password expiration
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Enable password expiration for the account
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/passwordRequiresLowercase": {
		Risk: `Password Requires Lowercase
		- Ensures password policy requires at least one lowercase letter
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Update the password policy to require the use of lowercase letters
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/passwordRequiresNumbers": {
		Risk: `Password Requires Numbers
		- Ensures password policy requires the use of numbers
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Update the password policy to require the use of numbers
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/passwordRequiresSymbols": {
		Risk: `Password Requires Symbols
		- Ensures password policy requires the use of symbols
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Update the password policy to require the use of symbols
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/passwordRequiresUppercase": {
		Risk: `Password Requires Uppercase
		- Ensures password policy requires at least one uppercase letter
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Update the password policy to require the use of uppercase letters
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/passwordReusePrevention": {
		Risk: `Password Reuse Prevention
		- Ensures password policy prevents previous password reuse
		- A strong password policy enforces minimum length, expirations, reuse, and symbol usage`,
		Recommendation: `Increase the minimum previous passwords that can be reused to 24.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/rootAccessKeys": {
		Risk: `Root Access Keys
		- Ensures the root account is not using access keys
		- The root account should avoid using access keys.
		- Since the root account has full permissions across the entire account, creating access keys for it only increases the chance that they are compromised.
		- Instead, create IAM users with predefined roles.`,
		Recommendation: `Remove access keys for the root account and setup IAM users with limited permissions instead
		- http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html`,
	},
	categoryIAM + "/rootAccountInUse": {
		Risk: `Root Account In Use
		- Ensures the root account is not being actively used
		- The root account should not be used for day-to-day account management.
		- IAM users, roles, and groups should be used instead.`,
		Recommendation: `Create IAM users with appropriate group-level permissions for account access.
		- Create an MFA token for the root account, and store its password and token generation QR codes in a secure place.
		- http://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html`,
	},
	categoryIAM + "/rootHardwareMfa": {
		Risk: `Root Hardware MFA
		- Ensures the root account is using a hardware MFA device
		- The root account should use a hardware MFA device for added security, rather than a virtual device which could be more easily compromised.`,
		Recommendation: `Enable a hardware MFA device for the root account and disable any virtual devices
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html`,
	},
	categoryIAM + "/rootMfaEnabled": {
		Risk: `Root MFA Enabled
		- Ensures a multi-factor authentication device is enabled for the root account
		- The root account should have an MFA device setup to enable two-factor authentication.`,
		Recommendation: `Enable an MFA device for the root account and then use an IAM user for managing services
		- http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html`,
	},
	categoryIAM + "/rootSigningCertificate": {
		Risk: `Root Account Active Signing Certificates
		- Ensures the root user is not using x509 signing certificates
		- AWS supports using x509 signing certificates for API access, but these should not be attached to the root user, which has full access to the account.`,
		Recommendation: `Delete the x509 certificates associated with the root account.
		- https://docs.aws.amazon.com/whitepapers/latest/aws-overview-security-processes/x.509-certificates.html`,
	},
	categoryIAM + "/sshKeysRotated": {
		Risk: `SSH Keys Rotated
		- Ensures SSH keys are not older than 180 days in order to reduce accidental exposures
		- SSH keys should be rotated frequently to avoid having them accidentally exposed.`,
		Recommendation: `To rotate an SSH key, first create a new public-private key pair, then upload the public key to AWS and delete the old key.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_ssh-keys.html`,
	},
	categoryIAM + "/usersMfaEnabled": {
		Risk: `Users MFA Enabled
		- Ensures a multi-factor authentication device is enabled for all users within the account
		- User accounts should have an MFA device setup to enable two-factor authentication`,
		Recommendation: `Enable an MFA device for the user account
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html`,
	},
	categoryIAM + "/usersPasswordAndKeys": {
		Risk: `Users Password And Keys
		- Detects whether users with a console password are also using access keys
		- Access keys should only be assigned to machine users and should not be used for accounts that have console password access.`,
		Recommendation: `Remove access keys from all users with console access.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/ManagingCredentials.html`,
	},
	categoryIAM + "/usersPasswordLastUsed": {
		Risk: `Users Password Last Used
		- Detects users with password logins that have not been used for a period of time and that should be decommissioned
		- Having numerous, unused user accounts extends the attack surface.
		- If users do not log into their accounts for more than the defined period of time, the account should be deleted.`,
		Recommendation: `Delete old user accounts that allow password-based logins and have not been used recently.
		- http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html`,
	},
	categoryKinesis + "/kinesisEncrypted": {
		Risk: `Kinesis Streams Encrypted
		- Ensures Kinesis Streams encryption is enabled
		- Data sent to Kinesis Streams can be encrypted using KMS server-side encryption.
		- Existing streams can be modified to add encryption with minimal overhead.`,
		Recommendation: `Enable encryption using KMS for all Kinesis Streams.
		- https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html`,
	},
	categoryKMS + "/kmsAppTierCmk": {
		Risk: `App-Tier KMS Customer Master Key (CMK)
		- Ensures that there is one Amazon KMS Customer Master Key (CMK) present in the account for App-Tier resources.
		- Amazon KMS should have Customer Master Key (CMK) for App-Tier to protect data in transit.`,
		Recommendation: `Create a Customer Master Key (CMK) with App-Tier tag
		- https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html`,
	},
	categoryKMS + "/kmsDefaultKeyUsage": {
		Risk: `KMS Default Key Usage
		- Checks AWS services to ensure the default KMS key is not being used
		- It is recommended not to use the default key to avoid encrypting disparate sets of data with the same key.
		- Each application should have its own customer-managed KMS key`,
		Recommendation: `Avoid using the default KMS key
		- http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html`,
	},
	categoryKMS + "/kmsKeyPolicy": {
		Risk: `KMS Key Policy
		- Validates the KMS key policy to ensure least-privilege access.
		- KMS key policies should be designed to limit the number of users who can perform encrypt and decrypt operations.
		- Each application should use its own key to avoid over exposure.`,
		Recommendation: `Modify the KMS key policy to remove any wildcards and limit the number of users and roles that can perform encrypt and decrypt operations using the key.
		- http://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html`,
	},
	categoryKMS + "/kmsKeyRotation": {
		Risk: `KMS Key Rotation
		- Ensures KMS keys are set to rotate on a regular schedule
		- All KMS keys should have key rotation enabled.
		- AWS will handle the rotation of the encryption key itself, as well as storage of previous keys, so previous data does not need to be re-encrypted before the rotation occurs.`,
		Recommendation: `Enable yearly rotation for the KMS key
		- http://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html`,
	},
	categoryKMS + "/kmsScheduledDeletion": {
		Risk: `KMS Scheduled Deletion
		- Detects KMS keys that are scheduled for deletion
		- Deleting a KMS key will permanently prevent all data encrypted using that key from being decrypted.
		- Avoid deleting keys unless no encrypted data is in use.`,
		Recommendation: `Disable the key deletion before the scheduled deletion time.
		- http://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html`,
	},
	categoryLambda + "/lambdaLogGroups": {
		Risk: `Lambda Log Groups
		- Ensures each Lambda function has a valid log group attached to it
		- Every Lambda function created should automatically have a CloudWatch log group generated to handle its log streams.`,
		Recommendation: `Update the Lambda function permissions to allow CloudWatch logging.
		- https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs.html`,
	},
	categoryLambda + "/lambdaOldRuntimes": {
		Risk: `Lambda Old Runtimes
		- Ensures Lambda functions are not using out-of-date runtime environments.
		- Lambda runtimes should be kept current with recent versions of the underlying codebase.
		- Deprecated runtimes should not be used.`,
		Recommendation: `Upgrade the Lambda function runtime to use a more current version.
		- http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html`,
	},
	categoryLambda + "/lambdaPublicAccess": {
		Risk: `Lambda Public Access
		- Ensures Lambda functions are not accessible globally
		- The Lambda function execution policy should not allow public invocation of the function.`,
		Recommendation: `Update the Lambda policy to prevent access from the public.
		- https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html`,
	},
	categoryLambda + "/lambdaVpcConfig": {
		Risk: `Lambda VPC Config
		- Ensures Lambda functions are created in a VPC.
		- Lambda functions should be created in an AWS VPC to avoid exposure to the Internet and to enable communication with VPC resources through NACLs and security groups.`,
		Recommendation: `Update the Lambda function with a VPC configuration.
		- https://docs.aws.amazon.com/lambda/latest/dg/vpc.html`,
	},
	categoryOrganizations + "/enableAllFeatures": {
		Risk: `Enable All Organization Features
		- Ensures all Organization features are enabled
		- All AWS Organizations should be enabled to take advantage of all shared security controls and policies across all member accounts.`,
		Recommendation: `Enable all AWS Organizations features.
		- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html?icmpid=docs_orgs_console`,
	},
	categoryOrganizations + "/organizationInvite": {
		Risk: `Organization Invite
		- Ensure all Organization invites are accepted
		- AWS Organizations invites should be accepted or rejected quickly so that member accounts can take advantage of all Organization features.`,
		Recommendation: `Enable all AWS Organizations features
		- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html?icmpid=docs_orgs_console`,
	},
	categoryRDS + "/rdsAutomatedBackups": {
		Risk: `RDS Automated Backups
		- Ensures automated backups are enabled for RDS instances
		- AWS provides a simple method of backing up RDS instances at a regular interval.
		- This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.`,
		Recommendation: `Enable automated backups for the RDS instance
		- http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html`,
	},
	categoryRDS + "/rdsCmkEncryptionEnabled": {
		Risk: `RDS CMK Encryption
		- Ensures RDS instances are encrypted with KMS Customer Master Keys(CMKs).
		- RDS instances should be encrypted with Customer Master Keys in order to have full control over data encryption and decryption.`,
		Recommendation: `RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with KMS CMK encryption enabled.
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html`,
	},
	categoryRDS + "/rdsEncryptionEnabled": {
		Risk: `RDS Encryption Enabled
		- Ensures at-rest encryption is setup for RDS instances
		- AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.`,
		Recommendation: `RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.
		- http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html`,
	},
	categoryRDS + "/rdsLoggingEnabled": {
		Risk: `RDS Logging Enabled
		- Ensures logging is configured for RDS instances
		- Logging database level events enables teams to analyze events for the purpose diagnostics as well as audit tracking for compliance purposes.`,
		Recommendation: `Modify the RDS instance to enable logging as required.
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html`,
	},
	categoryRDS + "/rdsMinorVersionUpgrade": {
		Risk: `RDS DocumentDB Minor Version Upgrade
		- Ensures Auto Minor Version Upgrade is enabled on RDS and DocumentDB databases
		- RDS supports automatically upgrading the minor version of the database, which should be enabled to ensure security fixes are quickly deployed.`,
		Recommendation: `Enable automatic minor version upgrades on RDS and DocumentDB databases
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html#USER_UpgradeDBInstance.Upgrading.AutoMinorVersionUpgrades`,
	},
	categoryRDS + "/rdsMultiAz": {
		Risk: `RDS Multiple AZ
		- Ensures that RDS instances are created to be cross-AZ for high availability.
		- Creating RDS instances in a single AZ creates a single point of failure for all systems relying on that database.
		- All RDS instances should be created in multiple AZs to ensure proper failover.`,
		Recommendation: `Modify the RDS instance to enable scaling across multiple availability zones.
		- http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html`,
	},
	categoryRDS + "/rdsPubliclyAccessible": {
		Risk: `RDS Publicly Accessible
		- Ensures RDS instances are not launched into the public cloud
		- Unless there is a specific business requirement, RDS instances should not have a public endpoint and should be accessed from within a VPC only.`,
		Recommendation: `Remove the public endpoint from the RDS instance
		- http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html`,
	},
	categoryRDS + "/rdsRestorable": {
		Risk: `RDS Restorable
		- Ensures RDS instances can be restored to a recent point
		- AWS will maintain a point to which the database can be restored.
		- This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.`,
		Recommendation: `Ensure the instance is running and configured properly.
		- If the time drifts too far, consider opening a support ticket with AWS.
		- http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html`,
	},
	categoryRDS + "/rdsSnapshotEncryption": {
		Risk: `RDS Snapshot Encryption
		- Ensures encryption is enabled for RDS snapshots to ensure encryption of data at rest.
		- AWS provides encryption for RDS snapshots which should be enabled to ensure that all data at rest is encrypted.`,
		Recommendation: `Copy the snapshot to a new snapshot that is encrypted and delete the old snapshot.
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html`,
	},
	categoryRDS + "/rdsTransportEncryption": {
		Risk: `RDS Transport Encryption Enabled
		- Ensures RDS SQL Server instances have Transport Encryption enabled.
		- Parameter group associated with the RDS instance should have transport encryption enabled to handle encryption and decryption`,
		Recommendation: `Update the parameter group associated with the RDS instance to have rds.force_ssl set to true
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html`,
	},
	categoryRDS + "/sqlServerTLSVersion": {
		Risk: `SQL Server TLS Version
		- Ensures RDS SQL Servers do not allow outdated TLS certificate versions
		- TLS 1.2 or higher should be used for all TLS connections to RDS.
		- A parameter group can be used to enforce this connection type.`,
		Recommendation: `Create a parameter group that contains the TLS version restriction and limit access to TLS 1.2 or higher
		- https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-rds-for-sql-server-supports-disabling-old-versions-of-tls-and-ciphers/`,
	},
	categoryRedshift + "/auditLoggingEnabled": {
		Risk: `Redshift Cluster Audit Logging Enabled
		- Ensure audit logging is enabled for Redshift clusters for security and troubleshooting purposes.
		- Redshift clusters should be configured to enable audit logging to log cluster usage information.`,
		Recommendation: `Modify Redshift clusters to enable audit logging
		- https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing-console.html`,
	},
	categoryRedshift + "/redshiftAllowVersionUpgrade": {
		Risk: `Redshift Cluster Allow Version Upgrade
		- Ensure that version upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window.
		- Redshift clusters should be configured to allow version upgrades to get the newest features, bug fixes or the latest security patches released.`,
		Recommendation: `Modify Redshift clusters to allow version upgrade
		- https://docs.amazonaws.cn/en_us/redshift/latest/mgmt/redshift-mgmt.pdf`,
	},
	categoryRedshift + "/redshiftClusterCmkEncrypted": {
		Risk: `Redshift Cluster CMK Encryption
		- Ensures Redshift clusters are encrypted using KMS customer master keys (CMKs)
		- KMS CMKs should be used to encrypt redshift clusters in order to have full control over data encryption and decryption.`,
		Recommendation: `Update Redshift clusters encryption configuration to use KMS CMKs instead of AWS managed-keys.
		- http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html`,
	},
	categoryRedshift + "/redshiftEncryptionEnabled": {
		Risk: `Redshift Encryption Enabled
		- Ensures at-rest encryption is setup for Redshift clusters
		- AWS provides at-read encryption for Redshift clusters which should be enabled to ensure the integrity of data stored within the cluster.`,
		Recommendation: `Redshift does not currently allow modifications to encryption after the cluster has been launched, so a new cluster will need to be created with encryption enabled.
		- http://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html`,
	},
	categoryRedshift + "/redshiftPubliclyAccessible": {
		Risk: `Redshift Publicly Accessible
		- Ensures Redshift clusters are not launched into the public cloud
		- Unless there is a specific business requirement, Redshift clusters should not have a public endpoint and should be accessed from within a VPC only.`,
		Recommendation: `Remove the public endpoint from the Redshift cluster
		- http://docs.aws.amazon.com/redshift/latest/mgmt/getting-started-cluster-in-vpc.html`,
	},
	categoryRedshift + "/redshiftSSLEnabled": {
		Risk: `Redshift Parameter Group SSL Required
		- Ensures AWS Redshift non-default parameter group associated with Redshift cluster require SSL connection.
		- Redshift parameter group associated with Redshift cluster should be configured to require SSL to secure data in transit.`,
		Recommendation: `Update Redshift parameter groups to have require-ssl parameter set to true.
		- https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html`,
	},
	categoryRedshift + "/userActivityLoggingEnabled": {
		Risk: `Redshift User Activity Logging Enabled
		- Ensure that user activity logging is enabled for your Amazon Redshift clusters.
		- Redshift clusters associated parameter groups should have user activity logging enabled in order to log user activities performed.`,
		Recommendation: `Update Redshift parameter groups to enable user activity logging
		- https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html#db-auditing-enable-logging`,
	},
	categoryRoute53 + "/danglingDnsRecords": {
		Risk: `Route53 Dangling DNS Records
		- Ensures that AWS Route53 DNS records are not pointing to invalid/deleted EIPs.
		- AWS Route53 DNS records should not point to invalid/deleted EIPs to prevent malicious activities.`,
		Recommendation: `Delete invalid/dangling AWS Route53 DNS records
		- https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-aws-resources.html`,
	},
	categoryRoute53 + "/domainAutoRenew": {
		Risk: `Domain Auto Renew
		- Ensures domains are set to auto renew through Route53
		- Domains purchased through Route53 should be set to auto renew.
		- Domains that are not renewed can quickly be acquired by a third-party and cause loss of access for customers.`,
		Recommendation: `Enable auto renew for the domain
		- http://docs.aws.amazon.com/Route53/latest/APIReference/api-enable-domain-auto-renew.html`,
	},
	categoryRoute53 + "/domainExpiry": {
		Risk: `Domain Expiry
		- Ensures domains are not expiring too soon
		- Expired domains can be lost and reregistered by a third-party.`,
		Recommendation: `Reregister the expiring domain
		- http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/registrar.html`,
	},
	categoryRoute53 + "/domainTransferLock": {
		Risk: `Domain Transfer Lock
		- Ensures domains have the transfer lock set
		- To avoid having a domain maliciously transferred to a third-party, all domains should enable the transfer lock unless actively being transferred.`,
		Recommendation: `Enable the transfer lock for the domain
		- http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-transfer-from-route-53.html`,
	},
	categoryS3 + "/bucketAllUsersAcl": {
		Risk: `S3 Bucket All Users ACL
		- Ensures S3 buckets do not allow global write, delete, or read ACL permissions
		- S3 buckets can be configured to allow anyone, regardless of whether they are an AWS user or not, to write objects to a bucket or delete objects.
		- This option should not be configured unless there is a strong business requirement.`,
		Recommendation: `Disable global all users policies on all S3 buckets and ensure both the bucket ACL is configured with least privileges.
		- http://docs.aws.amazon.com/AmazonS3/latest/UG/EditingBucketPermissions.html`,
	},
	categoryS3 + "/bucketAllUsersPolicy": {
		Risk: `S3 Bucket All Users Policy
		- Ensures S3 bucket policies do not allow global write, delete, or read permissions
		- S3 buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to known users or accounts.`,
		Recommendation: `Remove wildcard principals from the bucket policy statements.
		- https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html`,
	},
	categoryS3 + "/bucketEncryption": {
		Risk: `S3 Bucket Encryption
		- Ensures object encryption is enabled on S3 buckets
		- S3 object encryption provides fully-managed encryption of all objects uploaded to an S3 bucket.`,
		Recommendation: `Enable CMK KMS-based encryption for all S3 buckets.
		- https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html`,
	},
	categoryS3 + "/bucketEncryptionInTransit": {
		Risk: `S3 Bucket Encryption In Transit
		- Ensures S3 buckets have bucket policy statements that deny insecure transport
		- S3 bucket policies can be configured to deny access to the bucket over HTTP.`,
		Recommendation: `Add statements to the bucket policy that deny all S3 actions when SecureTransport is false.
		- Resources must be list of bucket ARN and bucket ARN with wildcard.
		- https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/`,
	},
	categoryS3 + "/bucketEnforceEncryption": {
		Risk: `S3 Bucket Enforce Object Encryption
		- Ensures S3 bucket policies do not allow uploads of unencrypted objects
		- S3 bucket policies can be configured to block uploads of objects that are not encrypted.`,
		Recommendation: `Set the S3 bucket policy to deny uploads of unencrypted objects.
		- https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/`,
	},
	categoryS3 + "/bucketLogging": {
		Risk: `S3 Bucket Logging
		- Ensures S3 bucket logging is enabled for S3 buckets
		- S3 bucket logging helps maintain an audit trail of access that can be used in the event of a security incident.`,
		Recommendation: `Enable bucket logging for each S3 bucket.
		- http://docs.aws.amazon.com/AmazonS3/latest/dev/Logging.html`,
	},
	categoryS3 + "/bucketPublicAccessBlock": {
		Risk: `S3 Bucket Public Access Block
		- Ensures S3 public access block is enabled on all buckets or for AWS account
		- Blocking S3 public access at the account level or bucket-level ensures objects are not accidentally exposed.`,
		Recommendation: `Enable the S3 public access block on all S3 buckets or for AWS account.
		- https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html`,
	},
	categoryS3 + "/bucketSecureTransportEnabled": {
		Risk: `S3 Secure Transport Enabled
		- Ensure AWS S3 buckets enforce SSL to secure data in transit
		- S3 buckets should be configured to strictly require SSL connections to deny unencrypted HTTP requests when dealing with sensitive data.`,
		Recommendation: `Update S3 bucket policy to enforse SSL to secure data in transit.
		- https://aws.amazon.com/premiumsupport/knowledge-center/s3-bucket-policy-for-config-rule/`,
	},
	categoryS3 + "/bucketVersioning": {
		Risk: `S3 Bucket Versioning
		- Ensures object versioning is enabled on S3 buckets 
		- Object versioning can help protect against the overwriting of objects or data loss in the event of a compromise.`,
		Recommendation: `Enable object versioning for buckets with sensitive contents at a minimum and for all buckets ideally.
		- http://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html`,
	},
	categoryS3 + "/bucketWebsiteEnabled": {
		Risk: `S3 Bucket Website Enabled
		- Ensures S3 buckets are not configured with static website hosting
		- S3 buckets should not be configured with static website hosting with public objects.
		- Instead, a CloudFront distribution should be configured with an origin access identity.`,
		Recommendation: `Disable S3 bucket static website hosting in favor or CloudFront distributions.
		- https://aws.amazon.com/premiumsupport/knowledge-center/cloudfront-https-requests-s3/`,
	},
	categoryS3 + "/s3Encryption": {
		Risk: `S3 Bucket Encryption Enforcement
		- All statements in all S3 bucket policies must have a condition that requires encryption at a certain level
		- S3 buckets support numerous types of encryption, including AES-256, KMS using a default key, KMS with a CMK, or via HSM-based key.`,
		Recommendation: `Configure a bucket policy to enforce encryption.
		- https://aws.amazon.com/blogs/security/how-to-prevent-uploads-of-unencrypted-objects-to-amazon-s3/`,
	},
	categorySageMaker + "/notebookDataEncrypted": {
		Risk: `Notebook Data Encrypted
		- Ensure Notebook data is encrypted
		- An optional encryption key can be supplied during Notebook Instance creation.`,
		Recommendation: `An existing KMS key should be supplied during Notebook Instance creation.
		- https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax`,
	},
	categorySageMaker + "/notebookDirectInternetAccess": {
		Risk: `Notebook Direct Internet Access
		- Ensure Notebook Instance is not publicly available.
		- SageMaker notebooks should not be exposed to the Internet. Public availability can be configured via the DirectInternetAccess attribute.`,
		Recommendation: `Disable DirectInternetAccess for each SageMaker notebook.
		- https://docs.aws.amazon.com/sagemaker/latest/dg/appendix-additional-considerations.html#appendix-notebook-and-internet-access`,
	},
	categorySES + "/dkimEnabled": {
		Risk: `Email DKIM Enabled
		- Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES.
		- DKIM is a security feature that allows recipients of an email to veriy that the sender domain has authorized the message and that it has not been spoofed.`,
		Recommendation: `Enable DKIM for all domains and addresses in all regions used to send email through SES.
		- http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html`,
	},
	categoryShield + "/shieldAdvancedEnabled": {
		Risk: `Shield Advanced Enabled
		- Ensures AWS Shield Advanced is setup and properly configured
		- AWS Shield Advanced provides enhanced DDOS protection for all enrolled services within a subscribed account. Subscriptions should be active.`,
		Recommendation: `Enable AWS Shield Advanced for the account.
		- https://docs.aws.amazon.com/waf/latest/developerguide/ddos-overview.html#ddos-advanced`,
	},
	categoryShield + "/shieldEmergencyContacts": {
		Risk: `Shield Emergency Contacts
		- Ensures AWS Shield emergency contacts are configured
		- AWS Shield Emergency contacts should be configured so that AWS can contact an account representative in the event of a DDOS event.`,
		Recommendation: `Configure emergency contacts within AWS Shield for the account.
		- https://docs.aws.amazon.com/waf/latest/developerguide/ddos-edit-drt.html`,
	},
	categoryShield + "/shieldProtections": {
		Risk: `Shield Protections
		- Ensures AWS Shield Advanced is configured to protect account resources
		- Once AWS Shield Advanced is enabled, it can be applied to resources within the account including ELBs, CloudFront.`,
		Recommendation: `Enable AWS Shield Advanced on resources within the account.
		- https://docs.aws.amazon.com/waf/latest/developerguide/configure-new-protection.html`,
	},
	categorySNS + "/topicCmkEncrypted": {
		Risk: `SNS Topic CMK Encryption
		- Ensures Amazon SNS topics are encrypted with KMS Customer Master Keys (CMKs).
		- AWS SNS topics should be encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys in order to have a more granular control over the SNS data-at-rest encryption and decryption process.`,
		Recommendation: `Update SNS topics to use Customer Master Keys (CMKs) for Server-Side Encryption.
		- https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html`,
	},
	categorySNS + "/topicEncrypted": {
		Risk: `SNS Topic Encrypted
		- Ensures that Amazon SNS topics enforce Server-Side Encryption (SSE)
		- SNS topics should enforce Server-Side Encryption (SSE) to secure data at rest.
		- SSE protects the contents of messages in Amazon SNS topics using keys managed in AWS Key Management Service (AWS KMS).`,
		Recommendation: `Enable Server-Side Encryption to protect the content of SNS topic messages.
		- https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html`,
	},
	categorySNS + "/topicPolicies": {
		Risk: `SNS Topic Policies
		- Ensures SNS topics do not allow global send or subscribe.
		- SNS policies should not be configured to allow any AWS user to subscribe or send messages.
		- This could result in data leakage or financial DDoS.`,
		Recommendation: `Adjust the topic policy to only allow authorized AWS users in known accounts to subscribe.
		- http://docs.aws.amazon.com/sns/latest/dg/AccessPolicyLanguage.html`,
	},
	categorySQS + "/sqsCrossAccount": {
		Risk: `SQS Cross Account Access
		- Ensures SQS policies disallow cross-account access
		- SQS policies should be carefully restricted to prevent publishing or reading from the queue from unexpected sources.
		- Queue policies can be used to limit these privileges.`,
		Recommendation: `Update the SQS policy to prevent access from external accounts.
		- http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html`,
	},
	categorySQS + "/sqsEncrypted": {
		Risk: `SQS Encrypted
		- Ensures SQS encryption is enabled
		- Messages sent to SQS queues can be encrypted using KMS server-side encryption.
		- Existing queues can be modified to add encryption with minimal overhead.`,
		Recommendation: `Enable encryption using KMS for all SQS queues.
		- http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html`,
	},
	categorySQS + "/sqsPublicAccess": {
		Risk: `SQS Public Access
		- Ensures that SQS queues are not publicly accessible
		- SQS queues should be not be publicly accessible to prevent unauthorized actions.`,
		Recommendation: `Update the SQS queue policy to prevent public access.
		- http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-creating-custom-policies.html`,
	},
	categorySSM + "/ssmActiveOnAllInstances": {
		Risk: `SSM Agent Active All Instances
		- Ensures SSM agents are installed and active on all servers
		- SSM allows for centralized monitoring of all servers and should be activated on all EC2 instances.`,
		Recommendation: `Install SSM on all servers and ensure it is active.
		- https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-setting-up.html`,
	},
	categorySSM + "/ssmAgentAutoUpdateEnabled": {
		Risk: `SSM Agent Auto Update Enabled
		- Ensures the SSM agent is configured to automatically update to new versions
		- To ensure the latest version of the SSM agent is installed, it should be configured to consume automatic updates.`,
		Recommendation: `Update the SSM agent configuration for all managed instances to use automatic updates.
		- https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html`,
	},
	categorySSM + "/ssmAgentLatestVersion": {
		Risk: `SSM Agent Latest Version
		- Ensures SSM agents installed on Linux hosts are running the latest version
		- SSM agent software provides sensitive access to servers and should be kept up-to-date.`,
		Recommendation: `Update the SSM agent on all Linux hosts to the latest version.
		- https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-agent-automatic-updates.html`,
	},
	categorySSM + "/ssmEncryptedParameters": {
		Risk: `SSM Encrypted Parameters
		- Ensures SSM Parameters are encrypted
		- SSM Parameters should be encrypted.
		- This allows their values to be used by approved systems, while restricting access to other users of the account.`,
		Recommendation: `Recreate unencrypted SSM Parameters with Type set to SecureString.
		- https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring`,
	},
	categoryTransfer + "/transferLoggingEnabled": {
		Risk: `Transfer Logging Enabled
		- Ensures AWS Transfer servers have CloudWatch logging enabled.
		- AWS Transfer servers can log activity to CloudWatch if a proper IAM service role is provided.
		- This role should be configured for all servers to ensure proper access logging.`,
		Recommendation: `Provide a valid IAM service role for AWS Transfer servers.
		- https://docs.aws.amazon.com/transfer/latest/userguide/monitoring.html`,
	},
	categoryWorkspaces + "/workspacesIpAccessControl": {
		Risk: `Workspaces IP Access Control
		- Ensures enforced IP Access Control on Workspaces
		- Checking the existence of IP Access control on Workspaces and ensuring that no Workspaces are open`,
		Recommendation: `Enable proper IP Access Controls for all workspaces
		- https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-ip-access-control-groups.html`,
	},
	categoryXRay + "/xrayEncryptionEnabled": {
		Risk: `XRay Encryption Enabled
		- Ensures CMK-based encryption is enabled for XRay traces.
		- AWS XRay supports default encryption based on an AWS-managed KMS key as well as encryption using a customer managed key (CMK).
		- For maximum security, the CMK-based encryption should be used.`,
		Recommendation: `Update XRay encryption configuration to use a CMK.
		- https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html`,
	},
}
