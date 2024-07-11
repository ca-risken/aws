// TODO: delete
package cloudsploit

import "fmt"

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(category, plugin string) recommend {
	return RecommendMap[fmt.Sprintf("%s/%s", category, plugin)]
}

// recommendMap maps risk and recommendation details to plugins.
// The recommendations are based on https://github.com/aquasecurity/cloudsploit/tree/master/plugins/aws
// key: category/plugin, value: recommend{}
//
// ########### FORMAT ###########
//
//	category + "/plugin": {
//		Risk: `title
//	  - description
//	  - more_info
//	  `,
//		Recommendation: `recommended_action
//	  - link
//	  `,
//	 },
var RecommendMap = map[string]recommend{
	categoryIAM + "/accessAnalyzerActiveFindings": {
		Risk: `Access Analyzer Active Findings
		- Ensure that IAM Access analyzer findings are reviewed and resolved by taking all necessary actions.
		- IAM Access Analyzer helps you evaluate access permissions across your AWS cloud environment and gives insights into intended access to your resources. 
		- It can monitor the access policies associated with S3 buckets, KMS keys, SQS queues, IAM roles and Lambda functions for permissions changes. 
		- You can view IAM Access Analyzer findings at any time. 
		- Work through all of the findings in your account until you have zero active findings.
		`,
		Recommendation: `Investigate into active findings in your account and do the needful until you have zero active findings.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-work-with-findings.html
		`,
	},
	categoryIAM + "/accessAnalyzerEnabled": {
		Risk: `Access Analyzer Enabled
	 - Ensure that IAM Access analyzer is enabled for all regions.
	 - Access Analyzer allow you to determine if an unintended user is allowed, making it easier for administrators to monitor least privileges access. It analyzes only policies that are applied to resources in the same AWS region.
	 `,
		Recommendation: `Enable Access Analyzer for all regions
	 - https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html
	 `,
	},
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
	categoryACM + "/acmCertificateHasTags": {
		Risk: `ACM Certificate Has Tags
	 - Ensure that ACM Certificates have tags associated.
	 - Tags help you to group resources together that are related to or associated with each other. 
	 - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	 `,
		Recommendation: `Modify ACM certificate and add tags.
	 - https://docs.aws.amazon.com/acm/latest/userguide/tags.html
	 `,
	},
	categoryACM + "/acmSingleDomainNameCertificate": {
		Risk: `ACM Single Domain Name Certificates
	 - Ensure that ACM single domain name certificates are used instead of wildcard certificates within your AWS account.
	 - Using wildcard certificates can compromise the security of all sites i.e. domains and subdomains if the private key of a certificate is hacked. 
	 - So it is recommended to use ACM single domain name certificates instead of wildcard certificates.
	 `,
		Recommendation: `Configure ACM managed certificates to use single name domain instead of wildcards.
	 - https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate.html
	 `,
	},
	categoryAPIGateway + "/apigatewayWafEnabled": {
		Risk: `API Gateway WAF Enabled
		- Ensures that API Gateway APIs are associated with a Web Application Firewall.
		- API Gateway APIs should be associated with a Web Application Firewall to ensure API security.`,
		Recommendation: `Associate API Gateway API with Web Application Firewall
		- https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html`,
	},
	categoryAPIGateway + "/apigatewayCertificateRotation": {
		Risk: `API Gateway Certificate Rotation
	 - Ensures that Amazon API Gateway APIs have certificates with expiration date more than the rotation limit.
	 - API Gateway APIs should have certificates with long term expiry date to avoid API insecurity after certificate expiration.
	 `,
		Recommendation: `Rotate the certificate attached to API Gateway API
	 - https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html
	 `,
	},
	categoryAPIGateway + "/apigatewayClientCertificate": {
		Risk: `API Gateway Client Certificate
	  - Ensures that Amazon API Gateway API stages use client certificates.
	  - API Gateway API stages should use client certificates to ensure API security authorization.
	  `,
		Recommendation: `Attach client certificate to API Gateway API stages
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html
	  `,
	},
	categoryAPIGateway + "/apigatewayCloudwatchLogs": {
		Risk: `API Gateway CloudWatch Logs
	  - Ensures that Amazon API Gateway API stages have Amazon CloudWatch Logs enabled.
	  - API Gateway API stages should have Amazon CloudWatch Logs enabled to help debug issues related to request execution or client access to your API.
	  `,
		Recommendation: `Modify API Gateway API stages to enable CloudWatch Logs
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html
	  `,
	},
	categoryAPIGateway + "/apigatewayContentEncoding": {
		Risk: `API Gateway Content Encoding
	  - Ensures that Amazon API Gateway APIs have content encoding enabled.
	  - API Gateway API should have content encoding enabled to enable compression of response payload.
	  `,
		Recommendation: `Enable content encoding and set minimum compression size of API Gateway API response
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-gzip-compression-decompression.html
	  `,
	},
	categoryAPIGateway + "/apigatewayDefaultEndpointDisabled": {
		Risk: `API Gateway Default Endpoint Disabled
	  - Ensure default execute-api endpoint is disabled for your API Gateway.
	  - By default, clients can invoke your API by using the execute-api endpoint that API Gateway generates for your API. 
	  - To ensure that clients can access your API only by using a custom domain name, disable the default execute-api endpoint.
	  `,
		Recommendation: `Modify API Gateway to disable default execute-api endpoint.
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
	  `,
	},
	categoryAPIGateway + "/apigatewayPrivateEndpoints": {
		Risk: `API Gateway Private Endpoints
	  - Ensures that Amazon API Gateway APIs are only accessible through private endpoints.
	  - API Gateway APIs should be only accessible through private endpoints to ensure API security.
	  `,
		Recommendation: `Set API Gateway API endpoint configuration to private
	  - https://aws.amazon.com/blogs/compute/introducing-amazon-api-gateway-private-endpoints
	  `,
	},
	categoryAPIGateway + "/apigatewayResponseCaching": {
		Risk: `API Gateway Response Caching
	  - Ensure that response caching is enabled for your Amazon API Gateway REST APIs.
	  - A REST API in API Gateway is a collection of resources and methods that are integrated with backend HTTP endpoints, Lambda functions, or other AWS services.
	  - You can enable API caching in Amazon API Gateway to cache your endpoint responses.
	  - With caching, you can reduce the number of calls made to your endpoint and also improve the latency of requests to your API.
	  `,
		Recommendation: `Modify API Gateway API stages to enable API cache
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html
	  `,
	},
	categoryAPIGateway + "/apigatewayTracingEnabled": {
		Risk: `API Gateway Tracing Enabled
	  - Ensures that Amazon API Gateway API stages have tracing enabled for AWS X-Ray.
	  - API Gateway API stages should have tracing enabled to send traces to AWS X-Ray for enhanced distributed tracing.
	  `,
		Recommendation: `Enable tracing on API Gateway API stages
	  - https://docs.aws.amazon.com/xray/latest/devguide/xray-services-apigateway.html
	  `,
	},
	categoryAPIGateway + "/apiStageLevelCacheEncryption": {
		Risk: `API Stage-Level Cache Encryption
	  - Ensure that your Amazon API Gateway REST APIs are configured to encrypt API cached responses.
	  - It is strongly recommended to enforce encryption for API cached responses in order to protect your data from unauthorized access.
	  `,
		Recommendation: `Modify API Gateway API stages to enable encryption on cache data
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/data-protection-encryption.html
	  `,
	},
	categoryAPIGateway + "/customDomainTlsVersion": {
		Risk: `Custom Domain TLS Version
	  - Ensure API Gateway custom domains are using current minimum TLS version.
	  - A security policy is a predefined combination of minimum TLS version and cipher suite offered by Amazon API Gateway. 
	  - Choose either a TLS version 1.2 or TLS version 1.0 security policy.
	  `,
		Recommendation: `Modify API Gateway custom domain security policy and specify new TLS version.
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
	  `,
	},
	categoryAPIGateway + "/detailedCloudWatchMetrics": {
		Risk: `API Gateway Detailed CloudWatch Metrics
	  - Ensures that API Gateway API stages have detailed CloudWatch metrics enabled.
	  - API Gateway API stages should have detailed CloudWatch metrics enabled to monitor logs and events.
	  `,
		Recommendation: `Add CloudWatch role ARN to API settings and enabled detailed metrics for each stage
	  - https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html
	  `,
	},
	categoryAppFlow + "/flowEncrypted": {
		Risk: `AppFlow Flow Encrypted
	  - Ensure that your Amazon AppFlow flows are encrypted with desired encryption level.
	  - Amazon AppFlow encrypts your access tokens, secret keys, and data in transit and data at rest with AWS-manager keys by default. 
	  - Encrypt them using customer-managed keys in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create AppFlow flows with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/appflow/latest/userguide/data-protection.html
	  `,
	},
	categoryAppMesh + "/appmeshTLSRequired": {
		Risk: `App Mesh TLS Required
	  - Ensure that AWS App Mesh virtual gateway listeners only accepts TLS enabled connections.
	  - In App Mesh, Transport Layer Security (TLS) encrypts communication between the envoy proxies deployed on compute resources that are represented in App Mesh by mesh endpoints, such as Virtual nodes and Virtual gateways.
	  `,
		Recommendation: `Restrict AWS App Mesh virtual gateway listeners to accept only TLS enabled connections.
	  - https://docs.aws.amazon.com/app-mesh/latest/APIReference/API_ListenerTls.html
	  `,
	},
	categoryAppMesh + "/appmeshVGAccessLogging": {
		Risk: `App Mesh VG Access Logging
	  - Ensure that your Amazon App Mesh virtual gateways have access logging enabled.
	  - Enabling access logging feature for App Mesh virtual gateways lets you track application mesh user access, helps you meet compliance regulations, and gives insight into security audits and investigations. 
	  `,
		Recommendation: `To enable access logging, modify virtual gateway configuration settings and configure the file path to write access logs to.
	  - https://docs.aws.amazon.com/app-mesh/latest/userguide/envoy-logs.html
	  `,
	},
	categoryAppMesh + "/restrictExternalTraffic": {
		Risk: `App Mesh Restrict External Traffic
	  - Ensure that Amazon App Mesh virtual nodes have egress only access to other defined resources available within the service mesh.
	  - Amazon App Mesh gives you controls to choose whether or not to allow App Mesh services to communicate with outside world. 
	  - If you choose to deny external traffic, the proxies will not forward traffic to external services not defined in the mesh. 
	  - The traffic to the external services should be denied to adhere to cloud security best practices and minimize the security risks.
	  `,
		Recommendation: `Deny all traffic to the external services
	  - https://docs.aws.amazon.com/app-mesh/latest/userguide/security.html
	  `,
	},
	categoryAppRunner + "/serviceEncrypted": {
		Risk: `Service Encrypted
	  - Ensure that AWS App Runner service is encrypted using using desired encryption level.
	  - To protect your application\'s data at rest, App Runner encrypts all stored copies of your application source image or source bundle using AWS-managed key by default.
	  - Use customer-managed keys (CMKs) instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create App Runner Service with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/apprunner/latest/dg/security-data-protection-encryption.html
	  `,
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
	categoryAuditManager + "/auditmanagerDataEncrypted": {
		Risk: `Audit Manager Data Encrypted
	  - Ensure that all data in Audit Manager is encrypted with desired encryption level.
	  - All resource in AWS Audit Manager such as assessments, controls, frameworks, evidence are encrypted under a customer managed key or an AWS owned key, depending on your selected settings. 
	  - If you don’t provide a customer managed key, AWS Audit Manager uses an AWS owned key to encrypt your content.
	  - Encrypt these resources using customer-managed keys in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Modify Audit Manager data encryption settings and choose desired encryption key for data encryption
	  - https://docs.aws.amazon.com/audit-manager/latest/userguide/data-protection.html
	  `,
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
	categoryAutoScaling + "/appTierAsgApprovedAmi": {
		Risk: `App-Tier ASG Launch Configurations Approved AMIs
	  - Ensures that App-Tier Auto Scaling Group Launch Configurations are using approved AMIs.
	  - App-Tier Auto Scaling Group Launch Configurations should use approved AMIs only to launch EC2 instances within the ASG
	  `,
		Recommendation: `Update App-Tier ASG Launch Configurations to use approved AMIs only
	  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html
	  `,
	},
	categoryAutoScaling + "/asgCooldownPeriod": {
		Risk: `Auto Scaling Group Cooldown Period
	  - Ensure that your AWS Auto Scaling Groups are configured to use a cool down period.
	  - A scaling cool down helps you prevent your Auto Scaling group from launching or terminating additional instances before the effects of previous activities are visible.
	  `,
		Recommendation: `Implement proper cool down period for Auto Scaling groups to temporarily suspend any scaling actions.
	  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/Cooldown.html
	  `,
	},
	categoryAutoScaling + "/asgUnusedLaunchConfiguration": {
		Risk: `Auto Scaling Unused Launch Configuration
	  - Ensure that any unused Auto Scaling Launch Configuration templates are identified and removed from your account in order to adhere to AWS best practices.
	  - A launch configuration is an instance configuration template that an Auto Scaling group uses to launch EC2 instances. When you create a launch configuration, you specify information for the instances.
	  - Every unused Launch Configuration template should be removed for a better management of your AWS Auto Scaling components.
	  `,
		Recommendation: `Identify and remove any Auto Scaling Launch Configuration templates that are not associated anymore with ASGs available in the selected AWS region.
	  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html
	  `,
	},
	categoryAutoScaling + "/webTierAsgApprovedAmi": {
		Risk: `Web-Tier ASG Launch Configurations Approved AMIs
	  - Ensures that Web-Tier Auto Scaling Group Launch Configurations are using approved AMIs.
	  - Web-Tier Auto Scaling Group Launch Configurations should use approved AMIs only to launch EC2 instances within the ASG
	  `,
		Recommendation: `Update Web-Tier ASG Launch Configuration to use approved AMIs only
	  - https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html
	  `,
	},
	categoryBackup + "/backupDeletionProtection": {
		Risk: `Backup Deletion Protection Enabled
	  - Ensure that an Amazon Backup vault access policy is configured to prevent the deletion of AWS backups in the backup vault.
	  - With AWS Backup, you can assign policies to backup vaults and the resources they contain.
	  - Assigning policies allows you to do things like grant access to users to create backup plans and on-demand backups, but limit their ability to delete recovery points after they are created.
	  `,
		Recommendation: `Add a statement in Backup vault access policy which denies global access to action: backup:DeleteRecoveryPoint
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault-access-policy.html
	  `,
	},
	categoryBackup + "/backupInUseForRDSSnapshots": {
		Risk: `Backup In Use For RDS Snapshots
	  - Ensure that Amazon Backup is integrated with Amazon Relational Database Service in order to manage RDS database instance snapshots
	  - Amazon RDS creates and saves automated backups of your DB instance during the backup window of your DB instance. 
	  - With Amazon Backup, you can centrally configure backup policies and rules, and monitor backup activity for AWS RDS database instances.
	  `,
		Recommendation: `Enable RDS database instance snapshots to improve the reliability of your backup strategy.
	  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html
	  `,
	},
	categoryBackup + "/backupNotificationEnabled": {
		Risk: `Backup Failure Notification Enabled
	  - Ensure that Amazon Backup vaults send notifications via Amazon SNS for each failed backup job event.
	  - AWS Backup can take advantage of the robust notifications delivered by Amazon Simple Notification Service (Amazon SNS). 
	  - You can configure Amazon SNS to notify you of AWS Backup events from the Amazon SNS console.
	  `,
		Recommendation: `Configure Backup vaults to sent notifications alert for failed backup job events.
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/sns-notifications.html
	  `,
	},
	categoryBackup + "/backupResourceProtection": {
		Risk: `Backup Resource Protection
	  - Ensure that protected resource types feature is enabled and configured for Amazon Backup service within.
	  - Amazon Backup protected resource types feature allows you to choose which resource types are protected by backup plans on per-region basis.
	  `,
		Recommendation: `Enable protected resource type feature in order to meet compliance requirements.
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html
	  `,
	},
	categoryBackup + "/backupVaultEncrypted": {
		Risk: `Backup Vault Encrypted
	  - Ensure that your Amazon Backup vaults are using AWS KMS Customer Master Keys instead of AWS managed-keys (i.e. default encryption keys).
	  - When you encrypt AWS Backup using your own AWS KMS Customer Master Keys (CMKs) for enhanced protection, you have full control over who can use the encryption keys to access your backups.
	  `,
		Recommendation: `Encrypt Backup Vault with desired encryption level
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault.html
	  `,
	},
	categoryBackup + "/backupVaultHasTags": {
		Risk: `Backup Vault Has Tags
	  - Ensure that AWS Backup Vaults have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify Backup Vault and add tags.
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/creating-a-vault.html
	  `,
	},
	categoryBackup + "/compliantLifecyleConfigured": {
		Risk: `AWS Backup Compliant Lifecycle Configured
	  - Ensure that a compliant lifecycle configuration is enabled for your Amazon Backup plans in order to meet compliance requirements when it comes to security and cost optimization.
	  - The AWS Backup lifecycle configuration contains an array of transition objects specifying how long in days before a recovery point transitions to cold storage or is deleted.
	  `,
		Recommendation: `Enable compliant lifecycle configuration for your Amazon Backup plans
	  - https://docs.aws.amazon.com/aws-backup/latest/devguide/API_Lifecycle.html
	  `,
	},
	categoryCloudFormation + "/plainTextParameters": {
		Risk: `CloudFormation Plaintext Parameters
		- Ensures CloudFormation parameters that reference sensitive values are configured to use NoEcho.
		- CloudFormation supports the NoEcho property for sensitive values, which should be used to ensure secrets are not exposed in the CloudFormation UI and APIs.`,
		Recommendation: `Update the sensitive parameters to use the NoEcho property.
		- https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html`,
	},
	categoryCloudFormation + "/cloudformationAdminPriviliges": {
		Risk: `CloudFormation Admin Priviliges
	  - Ensures no AWS CloudFormation stacks available in your AWS account has admin privileges.
	  - A service role is an AWS Identity and Access Management (IAM) role that allows AWS CloudFormation to make calls to resources in a stack on your behalf. 
	  - You can specify an IAM role that allows AWS CloudFormation to create, update, or delete your stack resources
	  `,
		Recommendation: `Modify IAM role attached with AWS CloudFormation stack to provide the minimal amount of access required to perform its tasks
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html
	  `,
	},
	categoryCloudFormation + "/cloudformationInUse": {
		Risk: `AWS CloudFormation In Use
	  - Ensure that Amazon CloudFormation service is in use within your AWS account to automate your infrastructure management and deployment.
	  - AWS CloudFormation is a service that helps you model and set up your AWS resources so that you can spend less time managing those resources and more time focusing on your applications that run in AWS.
	  - A stack is a collection of AWS resources that you can manage as a single unit. 
	  - In other words, you can create, update, or delete a collection of resources by creating, updating, or deleting stacks.
	  `,
		Recommendation: `Check if CloudFormation is in use or not by observing the stacks
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/Welcome.html
	  `,
	},
	categoryCloudFormation + "/driftDetection": {
		Risk: `CloudFormation Drift Detection
	  - Ensures that AWS CloudFormation stacks are not in a drifted state.
	  - AWS CloudFormation stack should not be in drifted state to ensure that stack template is aligned with the resources.
	  `,
		Recommendation: `Resolve CloudFormation stack drift by importing drifted resource back to the stack.
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-resolve-drift.html
	  `,
	},
	categoryCloudFormation + "/stackFailedStatus": {
		Risk: `CloudFormation Stack Failed Status
	  - Ensures that AWS CloudFormation stacks are not in Failed mode for more than the maximum failure limit hours.
	  - AWS CloudFormation stacks should not be in failed mode to avoid application downtime.
	  `,
		Recommendation: `Remove or redeploy the CloudFormation failed stack.
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html
	  `,
	},
	categoryCloudFormation + "/stackNotifications": {
		Risk: `CloudFormation Stack SNS Notifications
	  - Ensures that AWS CloudFormation stacks have SNS topic associated.
	  - AWS CloudFormation stacks should have SNS topic associated to ensure stack events monitoring.
	  `,
		Recommendation: `Associate an Amazon SNS topic to all CloudFormation stacks
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-view-stack-data-resources.html
	  `,
	},
	categoryCloudFormation + "/stackTerminationProtection": {
		Risk: `CloudFormation Stack Termination Protection Enabled
	  - Ensures that AWS CloudFormation stacks have termination protection enabled.
	  - AWS CloudFormation stacks should have termination protection enabled to avoid accidental stack deletion.
	  `,
		Recommendation: `Enable termination protection for CloudFormation stack
	  - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html
	  `,
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
	categoryCloudFront + "/cloudfrontCustomOriginHttpsOnly": {
		Risk: `CloudFront Custom Origin HTTPS Only
	  - Ensures CloudFront Distribution Custom Origin is HTTPS Only.
	  - When you create a distribution, you specify the origin where CloudFront sends requests for the files. 
	  - You can use several different kinds of origins with CloudFront.
	  `,
		Recommendation: `Modify CloudFront distribution and update the Origin Protocol Policy setting to HTTPS Only.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html
	  `,
	},
	categoryCloudFront + "/cloudfrontFieldLevelEncryption": {
		Risk: `CloudFront Distribution Field-Level Encryption
	  - Ensure that field-level encryption is enabled for your Amazon CloudFront web distributions.
	  - With Amazon CloudFront, you can enforce secure end-to-end connections to origin servers by using HTTPS.
	  - Field-level encryption adds an additional layer of security that lets you protect specific data throughout system processing so that only certain applications can see it.
	  - Field-level encryption allows you to enable users to securely upload sensitive information to web servers.
	  `,
		Recommendation: `Enable field-level encryption for CloudFront distributions.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html
	  `,
	},
	categoryCloudFront + "/cloudfrontGeoRestriction": {
		Risk: `CloudFront Geo Restriction
	  - Ensure that geo-restriction feature is enabled for your CloudFront distribution to allow or block location-based access.
	  - AWS CloudFront geo restriction feature can be used to assist in mitigation of Distributed Denial of Service (DDoS) attacks.
	  - Also you have the ability to block IP addresses based on Geo IP from reaching your distribution and your web application content delivered by the distribution.
	  `,
		Recommendation: `Enable CloudFront geo restriction to whitelist or block location-based access.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html
	  `,
	},
	categoryCloudFront + "/cloudfrontInUse": {
		Risk: `CloudFront Enabled
	  - Ensure that AWS CloudFront service is used within your AWS account.
	  - Amazon CloudFront is a web service that speeds up distribution of your static and dynamic web content, such as .html, .css, .js, and image files, to your users.
	  - CloudFront delivers your content through a worldwide network of data centers called edge locations.
	  `,
		Recommendation: `Create CloudFront distributions as per requirement.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html
	  `,
	},
	categoryCloudFront + "/cloudfrontOriginTlsVersion": {
		Risk: `CloudFront Distribution Origins TLS Version
	  - Ensures CloudFront Distribution custom origin TLS version is not deprecated.
	  - The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology.
	  - Encryption should be set with the latest version of TLS where possible.
	  `,
		Recommendation: `Modify cloudFront distribution and update the TLS version.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
	  `,
	},
	categoryCloudFront + "/cloudfrontTlsDeprecatedProtocols": {
		Risk: `CloudFront TLS Deprecated Protocols
	  - Ensures AWS CloudFront distribution is not using deprecated TLS Version.
	  - Use latest TLS policy for CloudFront distribution to meet compliance and regulatory requirements within your organisation and to adhere to AWS security best policies.
	  `,
		Recommendation: `Modify cloudFront distribution and update the TLS version.
	  - https://aws.amazon.com/about-aws/whats-new/2020/07/cloudfront-tls-security-policy/
	  `,
	},
	categoryCloudFront + "/cloudfrontTlsInsecureCipher": {
		Risk: `CloudFront TLS Insecure Cipher
	  - Ensures CloudFront distribution TLS Version is not using insecure cipher.
	  - The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology.
	  - Encryption should be set with the latest version of TLS where possible.
	  `,
		Recommendation: `Modify cloudFront distribution and update the TLS version.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html
	  `,
	},
	categoryCloudFront + "/compressObjectsAutomatically": {
		Risk: `CloudFront Compress Objects Automatically
	  - Ensure that your Amazon Cloudfront distributions are configured to automatically compress files(object).
	  - Cloudfront data transfer is based on the total amount of data served, sending compressed files to the viewers is much less expensive than sending uncompressed files.
	  - To optimise your AWS cloud costs and speed up your web applications, configure your Cloudfront distributions to compress the web content served with compression enabled.
	  `,
		Recommendation: `Ensures that CloudFront is configured to automatically compress files
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/ServingCompressedFiles.html
	  `,
	},
	categoryCloudFront + "/enableOriginFailOver": {
		Risk: `CloudFront Enable Origin Failover
	  - Ensure that Origin Failover feature is enabled for your CloudFront distributions in order to improve the availability of the content delivered to your end users.
	  - With Origin Failover capability, you can setup two origins for your CloudFront web distributions primary and secondary. In the event of primary origin failure, your content is automatically served from the secondary origin, maintaining the distribution high reliability.
	  `,
		Recommendation: `Modify CloudFront distributions and configure origin group instead of a single origin
	  - https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_OriginGroupFailoverCriteria.html
	  `,
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
	categoryCloudTrail + "/cloudtrailHasTags": {
		Risk: `CloudTrail Has Tags
	  - Ensure that AWS CloudTrail trails have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify CloudTrail trails and add tags.
	  - https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AddTags.html
	  `,
	},
	categoryCloudTrail + "/cloudtrailManagementEvents": {
		Risk: `CloudTrail Management Events
	  - Ensures that AWS CloudTrail trails are configured to log management events.
	  - AWS CloudTrail trails should be configured to log management events to record management operations that are performed on resources in your AWS account.
	  `,
		Recommendation: `Update CloudTrail to enable management events logging
	  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html
	  `,
	},
	categoryCloudTrail + "/cloudtrailNotificationsEnabled": {
		Risk: `CloudTrail Notifications Enabled
	  - Ensure that Amazon CloudTrail trails are using active Simple Notification Service (SNS) topics to deliver notifications.
	  - CloudTrail trails should reference active SNS topics to notify for log files delivery to S3 buckets. 
	  - Otherwise, you will lose the ability to take immediate actions based on log information.
	  `,
		Recommendation: `Make sure that CloudTrail trails are using active SNS topics and that SNS topics have not been deleted after trail creation.
	  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html
	  `,
	},
	categoryCloudWatch + "/vpcFlowLogsMetricAlarm": {
		Risk: `VPC Flow Logs Metric Alarm
	  - Ensure that an AWS CloudWatch alarm exists and configured for metric filter attached with VPC flow logs CloudWatch group.
	  - A metric alarm watches a single CloudWatch metric or the result of a math expression based on CloudWatch metrics.
	  - The alarm performs one or more actions based on the value of the metric or expression relative to a threshold over a number of time periods.
	  - The action can be sending a notification to an Amazon SNS topic.
	  `,
		Recommendation: `Create a CloudWatch group, attached metric filter to log VPC flow logs changes and create an CloudWatch alarm for the metric filter.
	  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
	  `,
	},
	categoryCloudWatchLogs + "/monitoringMetrics": {
		Risk: `CloudWatch Monitoring Metrics
		- Ensures metric filters are setup for CloudWatch logs to detect security risks from CloudTrail.
		- Sending CloudTrail logs to CloudWatch is only useful if metrics are setup to detect risky activity from those logs. There are numerous metrics that should be used. For the exact filter patterns, please see this plugin on GitHub: https://github.com/cloudsploit/scans/blob/master/plugins/aws/cloudwatchlogs/monitoringMetrics.js`,
		Recommendation: `Enable metric filters to detect malicious activity in CloudTrail logs sent to CloudWatch.
		- http://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html`,
	},
	categoryCloudWatchLogs + "/logGroupsEncrypted": {
		Risk: `CloudWatch Log Groups Encrypted
	  - Ensure that the CloudWatch Log groups are encrypted using desired encryption level.
	  - Log group data is always encrypted in CloudWatch Logs. You can optionally use AWS Key Management Service for this encryption. 
	  - After you associate a customer managed key with a log group, all newly ingested data for the log group is encrypted using this key.
	  - This data is stored in encrypted format throughout its retention period. CloudWatch Logs decrypts this data whenever it is requested.
	  `,
		Recommendation: `Ensure CloudWatch Log groups have encryption enabled with desired AWS KMS key
	  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
	  `,
	},
	categoryCloudWatchLogs + "/logRetentionPeriod": {
		Risk: `CloudWatch Log Retention Period
	  - Ensures that the CloudWatch Log retention period is set above a specified length of time.
	  - Retention settings can be used to specify how long log events are kept in CloudWatch Logs.
	  - Expired log events get deleted automatically.
	  `,
		Recommendation: `Ensure CloudWatch logs are retained for at least 90 days.
	  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Working-with-log-groups-and-streams.html
	  `,
	},
	categoryCodeArtifact + "/codeartifactDomainEncrypted": {
		Risk: `CodeArtifact Domain Encrypted
	  - Ensures that AWS CodeArtifact domains have encryption enabled with desired encryption level.
	  - CodeArtifact domains make it easier to manage multiple repositories across an organization.
	  - By default, domain assets are encrypted with AWS-managed KMS key.
	  `,
		Recommendation: `Encrypt CodeArtifact domains with desired encryption level
	  - https://docs.aws.amazon.com/codeartifact/latest/ug/domain-create.html
	  `,
	},
	categoryCodeBuild + "/codebuildValidSourceProviders": {
		Risk: `CodeBuild Valid Source Providers
	  - Ensure that CodeBuild projects are using only valid source providers.
	  - CodeBuild should use only desired source providers in order to follow your organizations\'s security and compliance requirements.
	  `,
		Recommendation: `Edit CodeBuild project source provider information and remove disallowed source providers
	  - https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html
	  `,
	},
	categoryCodeBuild + "/projectArtifactsEncrypted": {
		Risk: `Project Artifacts Encrypted
	  - Ensure that your AWS CodeBuild project artifacts are encrypted with desired encryption level.
	  - AWS CodeBuild encrypts artifacts such as a cache, logs, exported raw test report data files, and build results by default using AWS managed keys.
	  - Use customer-managed key instead, in order to to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt them using customer-managed keys to gain more control over data encryption and decryption process.
	  - https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html
	  `,
	},
	categoryCodePipeline + "/pipelineArtifactsEncrypted": {
		Risk: `Pipeline Artifacts Encrypted
	  - Ensure that AWS CodePipeline is using desired encryption level to encrypt pipeline artifacts being stored in S3.
	  - CodePipeline creates an S3 artifact bucket and default AWS managed key when you create a pipeline.
	  - By default, these artifacts are encrypted using default AWS-managed S3 key. Use customer-managed key for encryption in order to to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Ensure customer-manager keys (CMKs) are being used for CodePipeline pipeline artifacts.
	  - https://docs.aws.amazon.com/codepipeline/latest/userguide/S3-artifact-encryption.html
	  `,
	},
	categoryCodeStar + "/codestarValidRepoProviders": {
		Risk: `CodeStar Valid Repository Providers
	  - Ensure that CodeStar projects are not using undesired repository providers.
	  - CodeStar should use only allowed repository providers in order to follow your organizations\'s security and compliance requirements.
	  `,
		Recommendation: `Ensure diallowed repository providers are not being used for CodeStar projects
	  - https://docs.aws.amazon.com/codestar/latest/userguide/getting-started.html#getting-started-create
	  `,
	},
	categoryCognito + "/cognitoHasWafEnabled": {
		Risk: `Cognito User Pool WAF Enabled
	  - Ensure that Cognito User Pool has WAF enabled.
	  - Enabling WAF allows control over unwanted requests to your hosted UI and Amazon Cognito API service endpoints, allowing or denying traffic based off rules in the Web ACL.
	  `,
		Recommendation: `1. Enter the Cognito service. 
		2. Enter user pools and enable WAF from properties.
	  - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html
	  `,
	},
	categoryCognito + "/cognitoMFAEnabled": {
		Risk: `Cognito User Pool MFA enabled
	  - Ensure that Cognito user pool has MFA enabled.
	  - Enabling Multi-factor authentication (MFA) increases security for your app.
	  - You can choose SMS text messages or time-based one-time passwords (TOTP) as second factors to sign in your users.
	  `,
		Recommendation: `1. Enter the Cognito service. 
		2. Enter user pools and enable MFA from sign in experience.
	  - https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html
	  `,
	},
	categoryComputeOptimizer + "/asgOptimized": {
		Risk: `Auto Scaling Group Optimized
	  - Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized Auto Scaling groups.
	  - An Auto Scaling group is considered optimized when Compute Optimizer determines that the group is correctly provisioned to run your workload, based on the chosen instance type. 
	  - For optimized Auto Scaling groups, Compute Optimizer might sometimes recommend a new generation instance type.
	  `,
		Recommendation: `Resolve Compute Optimizer recommendations for Auto Scaling groups.
	  - https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-asg-recommendations.html
	  `,
	},
	categoryComputeOptimizer + "/ebsVolumesOptimized": {
		Risk: `EBS Volumes Optimized
	  - Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized EBS Volumes.
	  - An EBS volume is considered optimized when Compute Optimizer determines that the volume is correctly provisioned to run your workload, based on the chosen volume type, volume size, and IOPS specification. 
	  - For optimized resources, Compute Optimizer might sometimes recommend a new generation volume type.
	  `,
		Recommendation: `Resolve Compute Optimizer recommendations for EBS volumes.
	  - https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ebs-recommendations.html
	  `,
	},
	categoryComputeOptimizer + "/ec2InstancesOptimized": {
		Risk: `EC2 Instances Optimized
	  - Ensure that Compute Optimizer does not have active recommendation summaries for over-provisioned or under-provisioned EC2 instances.
	  - An EC2 instance is considered optimized when all specifications of an instance, such as CPU, memory, and network, meet the performance requirements of your workload, and the instance is not over-provisioned. 
	  - For optimized instances, Compute Optimizer might sometimes recommend a new generation instance type.
	  `,
		Recommendation: `Resolve Compute Optimizer recommendations for EC2 instances.
	  - https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-ec2-recommendations.html
	  `,
	},
	categoryComputeOptimizer + "/lambdaFunctionsOptimized": {
		Risk: `Lambda Function Optimized
	  - Ensure that Compute Optimizer does not have active recommendation summaries for unoptimized Lambda Functions.
	  - AWS Compute Optimizer generates memory size recommendations for AWS Lambda functions. 
	  - A Lambda function is considered optimized when Compute Optimizer determines that its configured memory or CPU power (which is proportional to the configured memory) is correctly provisioned to run your workload.
	  `,
		Recommendation: `Resolve Compute Optimizer recommendations for Lambda functions.
	  - https://docs.aws.amazon.com/compute-optimizer/latest/ug/view-lambda-recommendations.html
	  `,
	},
	categoryComputeOptimizer + "/optimizerRecommendationsEnabled": {
		Risk: `Compute Optimizer Recommendations Enabled
	  - Ensure that Compute Optimizer is enabled for your AWS account.
	  - AWS Compute Optimizer is a service that analyzes the configuration and utilization metrics of your AWS resources.
	  - It reports whether your resources are optimal, and generates optimization recommendations to reduce the cost and improve the performance of your workloads.
	  `,
		Recommendation: `Enable Compute Optimizer Opt In options for current of all AWS account in your organization.
	  - https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html
	  `,
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
	categoryConfigService + "/configComplaintRules": {
		Risk: `AWS Config Complaint Rules
	  - Ensures that all the evaluation results returned from the Amazon Config rules created within your AWS account are compliant.
	  - AWS Config provides AWS managed rules, which are predefined customizable rules that AWS Config uses to evaluate whether your AWS resources comply with common best practices.
	  `,
		Recommendation: `Enable the AWS Config Service rules for compliance checks and close security gaps.
	  - https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules.html
	  `,
	},
	categoryConfigService + "/configDeliveryFailing": {
		Risk: `Config Delivery Failing
	  - Ensure that the AWS Config log files are delivered to the S3 bucket in order to store logging data for auditing purposes without any failures.
	  - Amazon Config keep record of the changes within the configuration of your AWS resources and it regularly stores this data to log files that are send to an S3 bucket specified by you.
	  `,
		Recommendation: `Configure AWS Config log files to be delivered without any failures to designated S3 bucket.
	  - https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html
	  `,
	},
	categoryConfigService + "/configServiceMissingBucket": {
		Risk: `Config Service Missing Bucket
	  - Ensure that Amazon Config service is pointing an S3 bucket that is active in your account in order to save configuration information
	  - Amazon Config tracks changes within the configuration of your AWS resources and it regularly sends updated configuration details to an S3 bucket that you specify.
	  - When AWS Config is not referencing an active S3 bucket, the service is unable to send the recorded information to the designated bucket, therefore you lose the ability to audit later the configuration changes made within your AWS account.
	  `,
		Recommendation: `Ensure that Amazon Config service is referencing an active S3 bucket in order to save configuration information.
	  - https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html
	  `,
	},
	categoryConfigService + "/servicesInUse": {
		Risk: `AWS Services In Use
	  - Ensures that only permitted services are being used in you AWS cloud account.
	  - Use only permitted AWS services in your cloud account in order to meet security and compliance requirements within your organization.
	  `,
		Recommendation: `Delete resources from unpermitted services within your AWS cloud account.
	  - https://docs.aws.amazon.com/config/latest/developerguide/how-does-config-work.html
	  `,
	},
	categoryConnect + "/customerProfilesDomainEncrypted": {
		Risk: `Connect Customer Profiles Domain Encrypted
	  - Ensure that AWS Connect Customer Profiles domains are using desired encryption level.
	  - Customer profiles domain is a container for all data, such as customer profiles, object types, profile keys, and encryption keys.
	  - To encrypt this data, use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Enabled data encryption feature for Connect Customer Profiles
	  - https://docs.aws.amazon.com/connect/latest/adminguide/enable-customer-profiles.html
	  `,
	},
	categoryConnect + "/instanceAttachmentsEncrypted": {
		Risk: `Connect Instance Attachments Encrypted
	  - Ensure that Amazon Connect instances have encryption enabled for attachments being saved on S3.
	  - You can configure Amazon Connect instance to save attachments on S3. When you save such data on S3, enable encryption for the data and use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Connect instance data storage configuration and enable encryption for  attachments
	  - https://docs.aws.amazon.com/connect/latest/adminguide/set-up-recordings.html
	  `,
	},
	categoryConnect + "/instanceCallRecordingEncrypted": {
		Risk: `Connect Instance Call Recording Encrypted
	  - Ensure that Amazon Connect instances have encryption enabled for call recordgins being saved on S3.
	  - You can configure Amazon Connect instance to save recordings for incoming call to be saved on S3. 
	  - When you save such data on S3, enable encryption for the data and use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Connect instance data storage configuration and enable encryption for call recordings
	  - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
	  `,
	},
	categoryConnect + "/instanceMediaStreamsEncrypted": {
		Risk: `Connect Instance Media Streams Encrypted
	  - Ensure that Amazon Connect instances have encryption enabled for media streams being saved on Kinesis Video Stream.
	  - In Amazon Connect, you can capture customer audio during an interaction with your contact center by sending the audio to a Kinesis video stream. 
	  - All data put into a Kinesis video stream is encrypted at rest using AWS-managed KMS keys. 
	  - Use customer-managed keys instead, in order to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Connect instance data storage configuration and enable encryption for media streams
	  - https://docs.aws.amazon.com/connect/latest/adminguide/enable-live-media-streams.html
	  `,
	},
	categoryConnect + "/instanceReportsEncrypted": {
		Risk: `Connect Instance Exported Reports Encrypted
	  - Ensure that Amazon Connect instances have encryption enabled for exported reports being saved on S3.
	  - You can configure Amazon Connect instance to save exported reports on S3. 
	  - When you save such data on S3, enable encryption for the data and use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Connect instance data storage configuration and enable encryption for exported reports
	  - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
	  `,
	},
	categoryConnect + "/instanceTranscriptsEncrypted": {
		Risk: `Connect Instance Chat Transcripts Encrypted
	  - Ensure that Amazon Connect instances have encryption enabled for chat transcripts being saved on S3.
	  - You can configure Amazon Connect instance to save transcripts for chats to be saved on S3. 
	  - When you save such data on S3, enable encryption for the data and use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Connect instance data storage configuration and enable encryption for chat transcripts
	  - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
	  `,
	},
	categoryConnect + "/voiceIdDomainEncrypted": {
		Risk: `Connect Voice ID Domain Encrypted
	  - Ensure that Voice domains created under Amazon Connect instances are using desired KMS encryption level.
	  - All user data stored in Amazon Connect Voice ID is encrypted at rest using encryption keys stored in AWS Key Management Service.
	  - Additionally, you can provide customer managed KMS keys in order to gain more control over encryption/decryption processes.
	  `,
		Recommendation: `Ensure that Amazon Voice ID domains have encryption enabled.
	  - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
	  `,
	},
	categoryConnect + "/wisdomDomainEncrypted": {
		Risk: `Connect Wisdom Domain Encrypted
	  - Ensure that Wisdom domains created under Amazon Connect instances are using desired KMS encryption level.
	  - All user data stored in Amazon Connect Wisdom is encrypted at rest using encryption keys stored in AWS Key Management Service.
	  - Additionally, you can provide customer managed KMS keys in order to gain more control over encryption/decryption processes.
	  `,
		Recommendation: `Ensure that Amazon Connect Wisdom domains have encryption enabled.
	  - https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html
	  `,
	},
	categoryDevOpsGuru + "/devOpsGuruNotificationEnabled": {
		Risk: `DevOps Guru Notifications Enabled
	  - Ensures SNS topic is set up for Amazon DevOps Guru.
	  - Amazon DevOps Guru uses an SNS topic to notify you about important DevOps Guru events.
	  `,
		Recommendation: `Add a notification channel to DevOps Guru
	  - https://docs.aws.amazon.com/devops-guru/latest/userguide/setting-up.html
	  `,
	},
	categoryDMS + "/dmsEncryptionEnabled": {
		Risk: `DMS Encryption Enabled
		- Ensures DMS encryption is enabled using a CMK
		- Data sent through the data migration service is encrypted using KMS. Encryption is enabled by default, but it is recommended to use customer managed keys.`,
		Recommendation: `Enable encryption using KMS CMKs for all DMS replication instances.
		- https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html`,
	},
	categoryDMS + "/autoMinorVersionUpgrade": {
		Risk: `DMS Auto Minor Version Upgrade
	  - Ensure that your Amazon Database Migration Service (DMS) replication instances have the Auto Minor Version Upgrade feature enabled
	  - AWS Database Migration Service (AWS DMS) helps you migrate databases to AWS quickly and securely.
	  - The DMS service releases engine version upgrades regularly to introduce new software features, bug fixes, security patches and performance improvements.
	  `,
		Recommendation: `Enable Auto Minor Version Upgrade feature in order to automatically receive minor engine upgrades for improved performance and security
	  - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.Modifying.html
	  `,
	},
	categoryDMS + "/dmsMultiAZFeatureEnabled": {
		Risk: `DMS Multi-AZ Feature Enabled
	  - Ensure that your Amazon Database Migration Service (DMS) replication instances are using Multi-AZ deployment configurations.
	  - AWS Database Migration Service (AWS DMS) helps you migrate databases to AWS quickly and securely. 
	  - In a Multi-AZ deployment, AWS DMS automatically provisions and maintains a synchronous standby replica of the replication instance in a different Availability Zone.
	  `,
		Recommendation: `Enable Multi-AZ deployment feature in order to get high availability and failover support
	  - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.html
	  `,
	},
	categoryDMS + "/dmsPubliclyAccessibleInstances": {
		Risk: `DMS Publicly Accessible Instances
	  - Ensure that Amazon Database Migration Service (DMS) instances are not publicly accessible.
	  - An AWS DMS replication instance can have one public IP address and one private IP address.
	  - If you uncheck (disable) the box for Publicly accessible, then the replication instance has only a private IP address.
	  - that prevents from exposure of data to other users
	  `,
		Recommendation: `Ensure that DMS replication instances have only private IP address and not public IP address
	  - https://docs.aws.amazon.com/dms/latest/userguide/CHAP_ReplicationInstance.PublicPrivate.html
	  `,
	},
	categoryDocumentDB + "/docdbClusterBackupRetention": {
		Risk: `DocumentDB Cluster Backup Retention
	  - Ensure that your Amazon DocumentDB clusters have set a minimum backup retention period.
	  - DocumentDB cluster provides feature to retain incremental backups between 1 and 35 allowing you to quickly restore to any point within the backup retention period. 
	  - Ensure that you have sufficient backup retention period configured in order to restore your data in the event of failure.
	  `,
		Recommendation: `Modify DocumentDB cluster to configure sufficient backup retention period.
	  - https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-modify.html
	  `,
	},
	categoryDocumentDB + "/docdbClusterEncrypted": {
		Risk: `DocumentDB Cluster Encrypted
	  - Ensure that data at-rest in encrypted in AWS DocumentDB clusters using desired encryption level.
	  - Amazon DocumentDB integrates with AWS KMS and uses a method known as envelope encryption to protect your data. 
	  - This gives you an extra layer of data security and help meet security compliance and regulations within your organization.
	  `,
		Recommendation: `Modify DocumentDB cluster at-rest encryption configuration to use desired encryption key
	  - https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html
	  `,
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
	categoryDynamoDB + "/dynamoContinuousBackups": {
		Risk: `DynamoDB Continuous Backups
	  - Ensures that Amazon DynamoDB tables have continuous backups enabled.
	  - DynamoDB tables should have Continuous Backups and Point-In-Time Recovery (PITR) features enabled to protect DynamoDB data against accidental data writes.
	  `,
		Recommendation: `Enable Continuous Backups and Point-In-Time Recovery (PITR) features.
	  - https://aws.amazon.com/blogs/aws/new-amazon-dynamodb-continuous-backups-and-point-in-time-recovery-pitr/
	  `,
	},
	categoryDynamoDB + "/dynamoTableBackupExists": {
		Risk: `DynamoDB Table Backup Exists
	  - Ensures that Amazon DynamoDB tables are using on-demand backups.
	  - With AWS Backup, you can configure backup policies and monitor activity for your AWS resources and on-premises workloads in one place. 
	  - Using DynamoDB with AWS Backup, you can copy your on-demand backups across AWS accounts and regions, add cost allocation tags to on-demand backups, and transition on-demand backups to cold storage for lower costs.
	  `,
		Recommendation: `Create on-demand backups for DynamoDB tables.
	  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/BackupRestore.html
	  `,
	},
	categoryDynamoDB + "/dynamoTableHasTags": {
		Risk: `DynamoDB Table Has Tags
	  - Ensure that DynamoDB tables have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify DynamoDB table and add tags.
	  - https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Tagging.html
	  `,
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
	categoryEC2 + "/amiHasTags": {
		Risk: `AMI Has Tag
	  - Ensure that AMIs have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify AMI and add tags.
	  - https://aws.amazon.com/about-aws/whats-new/2020/12/amazon-machine-images-support-tag-on-create-tag-based-access-control/
	  `,
	},
	categoryEC2 + "/defaultSecurityGroupInUse": {
		Risk: `Default Security Group In Use
	  - Ensure that AWS EC2 Instances are not associated with default security group.
	  - The default security group allows all traffic inbound and outbound, which can make your resources vulnerable to attacks. 
	  - Ensure that the Amazon EC2 instances are not associated with the default security groups.
	  `,
		Recommendation: `Modify EC2 instances and change security group.
	  - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html#default-security-group
	  `,
	},
	categoryEC2 + "/ebsBackupEnabled": {
		Risk: `EBS Backup Enabled
	  - Checks whether EBS Backup is enabled
	  - EBS volumes should have backups in the form of snapshots.
	  `,
		Recommendation: `Ensure that each EBS volumes contain at least .
	  - https://docs.aws.amazon.com/prescriptive-guidance/latest/backup-recovery/new-ebs-volume-backups.html
	  `,
	},
	categoryEC2 + "/ebsDefaultEncryptionEnabled": {
		Risk: `EBS Encryption Enabled By Default
	  - Ensure the setting for encryption by default is enabled
	  - AWS account should be configured to enable encryption for new EBS volumes and snapshots for all regions.
	  `,
		Recommendation: `Enable EBS Encryption by Default
	  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default
	  `,
	},
	categoryEC2 + "/ebsSnapshotHasTags": {
		Risk: `EBS Snapshot Has Tags
	  - Ensure that EBS snapshots have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify EBS snapshots and add tags.
	  - https://aws.amazon.com/blogs/compute/tag-amazon-ebs-snapshots-on-creation-and-implement-stronger-security-policies/
	  `,
	},
	categoryEC2 + "/ebsVolumeHasTags": {
		Risk: `EBS Volume has tags
	  - Ensure that EBS Volumes have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify EBS volumes and add tags
	  - https://aws.amazon.com/blogs/aws/new-tag-ec2-instances-ebs-volumes-on-creation/
	  `,
	},
	categoryEC2 + "/ec2HasTags": {
		Risk: `EC2 has Tags
	  - Ensure that AWS EC2 Instances have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify EC2 instances and add tags.
	  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html
	  `,
	},
	categoryEC2 + "/enableDetailedMonitoring": {
		Risk: `Instance Detailed Monitoring
	  - Ensure that EC2 instances have detailed monitoring feature enabled.
	  - By default, your instance is enabled for basic monitoring. 
	  - After you enable detailed monitoring, EC2 console displays monitoring graphs with a 1-minute period.
	  `,
		Recommendation: `Modify EC2 instance to enable detailed monitoring.
	  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html
	  `,
	},
	categoryEC2 + "/internetGatewayInVpc": {
		Risk: `Internet Gateways In VPC
	  - Ensure Internet Gateways are associated with at least one available VPC.
	  - Internet Gateways allow communication between instances in VPC and the internet.
	  - They provide a target in VPC route tables for internet-routable traffic and also perform network address translation (NAT) for instances that have been assigned public IPv4 addresses.
	  - Make sure they are always associated with a VPC to meet security and compliance requirements within your organization.
	  `,
		Recommendation: `Ensure Internet Gateways have VPC attached to them.
	  - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html
	  `,
	},
	categoryEC2 + "/networkAclHasTags": {
		Risk: `Network ACL has Tags
	  - Ensure that Amazon Network ACLs have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify Network ACL and add tags.
	  - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
	  `,
	},
	categoryEC2 + "/networkAclInboundTraffic": {
		Risk: `Unrestricted Network ACL Inbound Traffic
	  - Ensures that no Amazon Network ACL allows inbound/ingress traffic to remote administration ports.
	  - Amazon Network ACL should not allow inbound/ingress traffic to remote administration ports to avoid unauthorized access at the subnet level.
	  `,
		Recommendation: `Update Network ACL to allow inbound/ingress traffic to specific port ranges only
	  - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
	  `,
	},
	categoryEC2 + "/networkAclOutboundTraffic": {
		Risk: `Unrestricted Network ACL Outbound Traffic
	  - Ensures that no Amazon Network ACL allows outbound/egress traffic to all ports.
	  - Amazon Network ACL should not allow outbound/egress traffic to all ports to avoid unauthorized access at the subnet level.
	  `,
		Recommendation: `Update Network ACL to allow outbound/egress traffic to specific port ranges only
	  - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
	  `,
	},
	categoryEC2 + "/openAllPortsProtocolsEgress": {
		Risk: `Open All Ports Protocols Egress
	  - Determine if security group has all outbound ports or protocols open to the public
	  - Security groups should be created on a per-service basis and avoid allowing all ports or protocols in order to implement the Principle of Least Privilege (POLP) and reduce the attack surface.
	  `,
		Recommendation: `Modify the security group tp restrict access to only those IP addresses and/or IP ranges that require it.
	  - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
	  `,
	},
	categoryEC2 + "/openHTTP": {
		Risk: `Open HTTP
	  - Determine if TCP port 80 for HTTP is open to the public
	  - While some ports are required to be open to the public to function properly, more sensitive services such as HTTP should be restricted to known IP addresses.
	  `,
		Recommendation: `Restrict TCP port 80 to known IP addresses
	  - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
	  `,
	},
	categoryEC2 + "/openHTTPS": {
		Risk: `Open HTTPS
	  - Determine if TCP port 443 for HTTPS is open to the public
	  - While some ports are required to be open to the public to function properly, more sensitive services such as HTTPS should be restricted to known IP addresses.
	  `,
		Recommendation: `Restrict TCP port 443 to known IP addresses.
	  - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
	  `,
	},
	categoryEC2 + "/openMongoDB": {
		Risk: `Open MongoDB
	  - Determine if TCP port 27017 or 27018 or 27019 for MongoDB is open to the public
	  - While some ports such as HTTP and HTTPS are required to be open to the public to function properly, more sensitive services such as MongoDB should be restricted to known IP addresses.
	  `,
		Recommendation: `Restrict TCP port 27017 or 27018 or 27019 to known IP addresses
	  - http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
	  `,
	},
	categoryEC2 + "/outdatedAmiInUse": {
		Risk: `Outdated Amazon Machine Images
	  - Ensures that deprecated Amazon Machine Images are not in use.
	  - Deprecated Amazon Machine Images should not be used to make an instance.
	  `,
		Recommendation: `Delete the instances using deprecated AMIs
	  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html
	  `,
	},
	categoryEC2 + "/securityGroupsHasTags": {
		Risk: `Security Group Has Tags
	  - Ensure that AWS Security Groups have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Update Security Group and add Tags
	  - https://aws.amazon.com/about-aws/whats-new/2021/07/amazon-ec2-adds-resource-identifiers-tags-vpc-security-groups-rules/
	  `,
	},
	categoryEC2 + "/unusedSecurityGroups": {
		Risk: `Unused Security Groups
	  - Identify and remove unused EC2 security groups.
	  - Keeping the number of security groups to a minimum makes the management easier and helps to avoid reaching the service limit.
	  `,
		Recommendation: `Remove security groups that are not being used.
	  - https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html
	  `,
	},
	categoryEC2 + "/vpcEndpointCrossAccount": {
		Risk: `VPC Endpoint Cross Account Access
	  - Ensures that Amazon VPC endpoints do not allow unknown cross account access.
	  - VPC endpoints should not allow unknown cross account access to avoid any unsigned requests made to the services inside VPC.
	  `,
		Recommendation: `Update VPC endpoint access policy in order to remove untrusted cross account access
	  - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html
	  `,
	},
	categoryEC2 + "/vpcHasTags": {
		Risk: `VPC Has Tags
	  - Ensure that AWS VPC have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify VPCs and add new tags
	  - https://aws.amazon.com/about-aws/whats-new/2020/07/amazon-vpc-resources-support-tag-on-create/
	  `,
	},
	categoryEC2 + "/vpcPeeringConnections": {
		Risk: `Cross Organization VPC Peering Connections
	  - Ensures that VPC peering communication is only between AWS accounts, members of the same AWS Organization.
	  `,
		Recommendation: `Update VPC peering connections to allow connections to AWS Accounts, members of the same organization
	  - https://docs.aws.amazon.com/vpc/latest/peering/working-with-vpc-peering.html
	  `,
	},
	categoryEC2 + "/vpcSubnetInstancesPresent": {
		Risk: `VPC Subnet Instances Present
	  - Ensures that there are instances attached to every subnet.
	  - All subnets should have instances associated and unused subnets should be removed to avoid reaching the limit.
	  `,
		Recommendation: `Update VPC subnets and attach instances to it or remove the unused VPC subnets
	  - https://docs.aws.amazon.com/vpc/latest/userguide/vpc-endpoints-access.html
	  `,
	},
	categoryEC2 + "/vpnGatewayInVpc": {
		Risk: `Virtual Private Gateway In VPC
	  - Ensure Virtual Private Gateways are associated with at least one VPC.
	  - Virtual Private Gateways allow communication between cloud infrastructure and the remote customer network.
	  - They help in establishing VPN connection between VPC and the customer gateway.
	  - Make sure virtual private gateways are always associated with a VPC to meet security and regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Check if virtual private gateways have vpc associated
	  - https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html
	  `,
	},
	categoryEC2 + "/vpnTunnelState": {
		Risk: `VPN Tunnel State
	  - Ensures that each AWS Virtual Private Network (VPN) connection has all tunnels up.
	  - AWS Virtual Private Network (VPN) should have tunnels up to ensure network traffic flow over Virtual Private Network.
	  `,
		Recommendation: `Establish a successful VPN connection using IKE or IPsec configuration'
	  - https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html
	  `,
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
	categoryECR + "/ecrRepositoryEncrypted": {
		Risk: `ECR Repository Encrypted
	  - Ensure that the images in ECR repository are encrypted using desired encryption level.
	  - By default, Amazon ECR uses server-side encryption with Amazon S3-managed encryption keys which encrypts your data at rest using an AES-256 encryption algorithm. 
	  - Use customer-managed keys instead, in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create ECR Repository with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/Repositories.html
	  `,
	},
	categoryECR + "/ecrRepositoryHasTags": {
		Risk: `ECR Repository Has Tags
	  - Ensure that Amazon ECR repositories have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify ECR repository and add tags.
	  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/ecr-using-tags.html
	  `,
	},
	categoryECS + "/ecsClusterActiveService": {
		Risk: `ECS Cluster Active Services
	  - Ensure that AWS ECS clusters have active services.
	  - Amazon ECS service allows you to run and maintain a specified number of instances of a task definition simultaneously in an Amazon ECS cluster.
	  - It is recommended to have clusters with the active services to avoid any container attack surface.
	  `,
		Recommendation: `Modify Cluster and create new service.
	  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html
	  `,
	},
	categoryECS + "/ecsClustersHaveTags": {
		Risk: `ECS Cluster Has Tags
	  - Ensure that AWS ECS Clusters have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify ECS Cluster and add tags.
	  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-using-tags.html
	  `,
	},
	categoryECS + "/ecsClusterWithActiveTask": {
		Risk: `ECS Cluster Service Active Tasks
	  - Ensure ECS clusters have services with running tasks.
	  - A task is the instantiation of a task definition within a cluster.
	  - Amazon ECS service instantiates and maintains the specified number of tasks simultaneously in a cluster.
	  - As a best practice, ensure you always have running tasks in a cluster.
	  `,
		Recommendation: `Modify Cluster services and add tasks
	  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs_services.html
	  `,
	},
	categoryECS + "/ecsContainerInsightsEnabled": {
		Risk: `Container Insights Enabled
	  - Ensure that ECS clusters have CloudWatch Container Insights feature enabled.
	  - CloudWatch Container Insights provides monitoring and troubleshooting solution for containerized applications and microservices that collects, aggregates and summarizes resource utilization such as CPU, memory, disk, and network.
	  `,
		Recommendation: `Enabled container insights feature for ECS clusters.
	  - https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html
	  `,
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
	categoryEFS + "/efsHasTags": {
		Risk: `EFS Has Tags
	  - Ensure that AWS EFS file systems have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify EFS file systems to add tags.
	  - https://docs.aws.amazon.com/efs/latest/ug/manage-fs-tags.html
	  `,
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
	categoryEKS + "/eksClusterHasTags": {
		Risk: `EKS Cluster Has Tags
	  - Ensure that AWS EKS Clusters have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify EKS Cluster and add tags.
	  - https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html
	  `,
	},
	categoryEKS + "/eksLatestPlatformVersion": {
		Risk: `EKS Latest Platform Version
	  - Ensure that EKS clusters are using latest platform version.
	  - Amazon EKS platform versions represent the capabilities of the Amazon EKS cluster control plane, such as which Kubernetes API server flags are enabled, as well as the current Kubernetes patch version.
	  - Clusters should be kept up to date of latest platforms to ensure Kubernetes security patches are applied.
	  `,
		Recommendation: `Check for the version on all EKS clusters to be the latest platform version.
	  - https://docs.aws.amazon.com/eks/latest/userguide/platform-versions.html
	  `,
	},
	categoryEKS + "/eksSecretsEncrypted": {
		Risk: `EKS Secrets Encrypted
	  - Ensures EKS clusters are configured to enable envelope encryption of Kubernetes secrets using KMS.
	  - Amazon EKS clusters should be configured to enable envelope encryption for Kubernetes secrets to adhere to security best practice for applications that store sensitive data.
	  `,
		Recommendation: `Modify EKS clusters to enable envelope encryption for Kubernetes secrets
	  - https://aws.amazon.com/about-aws/whats-new/2020/03/amazon-eks-adds-envelope-encryption-for-secrets-with-aws-kms/
	  `,
	},
	categoryElastiCache + "/elasticacheClusterInVpc": {
		Risk: `ElastiCache Cluster In VPC
	  - Ensure that your ElastiCache clusters are provisioned within the AWS VPC platform.
	  - Creating Amazon ElastiCache clusters inside Amazon VPC can bring multiple advantages such as better networking infrastructure and flexible control over access security .
	  `,
		Recommendation: `Create ElastiCache clusters within VPC network
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VPCs.EC.html
	  `,
	},
	categoryElastiCache + "/elasticacheDefaultPorts": {
		Risk: `ElastiCache Default Ports
	  - Ensure AWS ElastiCache clusters are not using the default ports set for Redis and Memcached cache engines.
	  - ElastiCache clusters should be configured not to use the default assigned port value for Redis (6379) and Memcached (11211).
	  `,
		Recommendation: `Configure ElastiCache clusters to use the non-default ports.
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/accessing-elasticache.html
	  `,
	},
	categoryElastiCache + "/elasticacheInstanceGeneration": {
		Risk: `ElastiCache Instance Generation
	  - Ensure that all ElastiCache clusters provisioned within your AWS account are using the latest generation of instances
	  - Using the latest generation of Amazon ElastiCache instances instances will benefit clusters for higher hardware performance, better support for latest Memcached and Redis in-memory engines versions and lower costs.
	  `,
		Recommendation: `Upgrade ElastiCache instance generaion to the latest available generation.
	  - https://aws.amazon.com/elasticache/previous-generation/
	  `,
	},
	categoryElastiCache + "/elasticacheNodesCount": {
		Risk: `ElastiCache Nodes Count
	  - Ensure that the number of ElastiCache cluster cache nodes has not reached the limit quota established by your organization.
	  - Defining limits for the maximum number of ElastiCache cluster nodes that can be created within your AWS account will help you to better manage your ElastiCache compute resources and prevent unexpected charges on your AWS bill.
	  `,
		Recommendation: `Enable limit for ElastiCache cluster nodes count
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.html
	  `,
	},
	categoryElastiCache + "/elasticacheRedisMultiAZ": {
		Risk: `ElastiCache Redis Cluster Have Multi-AZ
	  - Ensure that your ElastiCache Redis Cache clusters are using a Multi-AZ deployment configuration to enhance High Availability.
	  - Enabling the Multi-AZ feature for your Redis Cache clusters will improve the fault tolerance in case the read/write primary node becomes unreachable due to loss of network connectivity, loss of availability in the primary’s AZ, etc.
	  `,
		Recommendation: `Enable Redis Multi-AZ for ElastiCache clusters
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html#AutoFailover.Enable
	  `,
	},
	categoryElastiCache + "/elasticaheDesiredNodeType": {
		Risk: `ElastiCache Desired Node Type
	  - Ensure that the Amazon ElastiCache cluster nodes provisioned in your AWS account have the desired node type established within your organization based on the workload deployed.
	  - Setting limits for the type of Amazon ElastiCache cluster nodes will help you address internal compliance requirements and prevent unexpected charges on your AWS bill.
	  `,
		Recommendation: `Create ElastiCache clusters with desired node types
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html
	  `,
	},
	categoryElastiCache + "/elasticCacheClusterHasTags": {
		Risk: `ElastiCache Cluster Has Tags
	  - Ensure that ElastiCache clusters have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify ElastiCache cluster and add tags.
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Tagging-Resources.html
	  `,
	},
	categoryElastiCache + "/idleElastiCacheNode": {
		Risk: `ElastiCache idle Cluster Status.
	  - Identify ElastiCache clusters having CPU utilization below defined threshold within last 24 hours (idle clusters).
	  - Idle Amazon ElastiCache cache cluster nodes represent a good candidate to reduce your monthly AWS costs and avoid accumulating unnecessary usage charges.
	  `,
		Recommendation: `Identify and remove idle ElastiCache clusters
	  - https://aws.amazon.com/elasticache/features/
	  `,
	},
	categoryElastiCache + "/redisClusterEncryptionAtRest": {
		Risk: `ElastiCache Redis Cluster Encryption At-Rest
	  - Ensure that your Amazon ElastiCache Redis clusters are encrypted to increase data security.
	  - Amazon ElastiCache provides an optional feature to encrypt your data saved to persistent media.
	  - Enable this feature and use customer-managed keys In order to protect it from unauthorized access and fulfill compliance requirements within your organization.
	  `,
		Recommendation: `Enable encryption for ElastiCache cluster data-at-rest
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html
	  `,
	},
	categoryElastiCache + "/redisClusterEncryptionInTransit": {
		Risk: `ElastiCache Redis Cluster Encryption In-Transit
	  - Ensure that your AWS ElastiCache Redis clusters have encryption in-transit enabled.
	  - Amazon ElastiCache in-transit encryption is an optional feature that allows you to increase the security of your data at its most vulnerable points—when it is in transit from one location to another.
	  `,
		Recommendation: `Enable in-transit encryption for ElastiCache clusters
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html
	  `,
	},
	categoryElastiCache + "/redisEngineVersions": {
		Risk: `ElastiCache Engine Versions for Redis
	  - Ensure that Amazon ElastiCache clusters are using the stable latest version of Redis cache engine.
	  - ElastiCache clusters with the latest version of Redis cache engine, You will benefit from new features and enhancements, Using engines prior to version 3.2.6 will not be benefited with Encryption Options, support for HIPAA compliance and much more.
	  - Also engine version 3.2.10 does not support Encryption options.
	  `,
		Recommendation: `Upgrade the version of Redis on all ElastiCache clusters to the latest available version.
	  - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/supported-engine-versions.html
	  `,
	},
	categoryElastiCache + "/reservedNodeLeaseExpiration": {
		Risk: `ElastiCache Reserved Cache Node Lease Expiration
	  - Ensure that your AWS ElastiCache Reserved Cache Nodes are renewed before expiration in order to get a significant discount.
	  - Reserved Cache Nodes can optimize your Amazon ElastiCache costs based on your expected usage.
	  - Since RCNs are not renewed automatically, purchasing another reserved ElastiCache nodes before expiration will guarantee their billing at a discounted hourly rate.
	  `,
		Recommendation: `Enable ElastiCache reserved cache nodes expiration days alert
	  - https://aws.amazon.com/elasticache/reserved-cache-nodes/
	  `,
	},
	categoryElastiCache + "/reservedNodePaymentFailed": {
		Risk: `ElastiCache Reserved Cache Node Payment Failed
	  - Ensure that payments for ElastiCache Reserved Cache Nodes available within your AWS account has been processed completely.
	  - When using ElastiCache Reserved Cache Nodes over standard On-Demand Cache Nodes savings are up to max that they give when used in steady state, therefore in order to receive this benefit you need to make sure that all your ElastiCache reservation purchases have been fully successful.
	  `,
		Recommendation: `Identify any failed payments for ElastiCache reserved cache nodes
	  - https://aws.amazon.com/elasticache/reserved-cache-nodes/
	  `,
	},
	categoryElastiCache + "/reservedNodePaymentPending": {
		Risk: `ElastiCache Reserved Cache Node Payment Pending
	  - Ensure that payments for ElastiCache Reserved Cache Nodes available within your AWS account has been processed completely.
	  - When using ElastiCache Reserved Cache Nodes over standard On-Demand Cache Nodes savings are up to max that they give when used in steady state, therefore in order to receive this benefit you need to make sure that all your ElastiCache reservation purchases have been fully successful.
	  `,
		Recommendation: `Identify any pending payments for ElastiCache reserved cache nodes
	  - https://aws.amazon.com/elasticache/reserved-cache-nodes/
	  `,
	},
	categoryElastiCache + "/unusedElastiCacheReservedNode": {
		Risk: `Unused ElastiCache Reserved Cache Nodes
	  - Ensure that all your AWS ElastiCache reserved nodes have corresponding cache nodes running within the same account of an AWS Organization.
	  - Creating cache nodes for your unused reserved cache clusters will prevent your investment having a negative return.
	  - When an Amazon ElastiCache RCN is not in use the investment made is not properly exploited.
	  `,
		Recommendation: `Enable prevention of unused reserved nodes for ElastiCache clusters
	  - https://aws.amazon.com/elasticache/reserved-cache-nodes/
	  `,
	},
	categoryElasticBeanstalk + "/managedPlatformUpdates": {
		Risk: `ElasticBeanstalk Managed Platform Updates
		- Ensures ElasticBeanstalk applications are configured to use managed updates.
		- Environments for an application should be configured to allow platform managed updates.`,
		Recommendation: `Update the environment to enable managed updates.
		- https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-platform-update-managed.html`,
	},
	categoryElasticBeanstalk + "/enhancedHealthReporting": {
		Risk: `Enhanced Health Reporting
	  - Ensure that Amazon Elastic Beanstalk (EB) environments have enhanced health reporting feature enabled.
	  - Enhanced health reporting is a feature that you can enable on your environment to allow AWS Elastic Beanstalk to gather additional information about resources in your environment.
	  - Elastic Beanstalk analyzes the information gathered to provide a better picture of overall environment health and aid in the identification of issues that can cause your application to become unavailable.
	  `,
		Recommendation: `Modify Elastic Beanstalk environmentsand enable enhanced health reporting.
	  - https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/health-enhanced.html
	  `,
	},
	categoryElasticBeanstalk + "/environmentAccessLogs": {
		Risk: `Environment Access Logs
	  - Ensure that your Amazon Elastic Beanstalk environment is configured to save logs for load balancer associated with the application environment.
	  - Elastic Load Balancing provides access logs that capture detailed information about requests sent to your load balancer.
	  - Each log contains information such as the time the request was received, the client\'s IP address, latencies, request paths, and server responses.
	  - You can use these access logs to analyze traffic patterns and troubleshoot issues.
	  `,
		Recommendation: `Go to specific environment, select Configuration, edit Load Balancer category, and enable Store logs
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
	  `,
	},
	categoryElasticBeanstalk + "/environmentPersistentLogs": {
		Risk: `Environment Persistent Logs
	  - Ensure that AWS Elastic Beanstalk environment logs are retained and saved on S3.
	  - Elastic Beanstalk environment logs should be retained in order to keep the logging data for future audits, historical purposes or to track and analyze the EB application environment behavior for a long period of time.
	  `,
		Recommendation: `Go to specific environment, select Configuration, edit Software category, and enable Log streaming
	  - https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/AWSHowTo.cloudwatchlogs.html
	  `,
	},
	categoryElasticTranscoder + "/jobOutputsEncrypted": {
		Risk: `Elastic Transcoder Job Outputs Encrypted
	  - Ensure that Elastic Transcoder jobs have encryption enabled to encrypt your data before saving on S3.
	  - Amazon Elastic Transcoder jobs saves th result output on S3. 
	  - If you don\'t configure encryption parameters, these job will save the file unencrypted. 
	  - You should enabled encryption for output files and use customer-managed keys for encryption in order to gain more granular control over encryption/decryption process
	  `,
		Recommendation: `Enable encryption for Elastic Transcoder job outputs
	  - https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/encryption.html
	  `,
	},
	categoryElasticTranscoder + "/pipelineDataEncrypted": {
		Risk: `Elastic Transcoder Pipeline Data Encrypted
	  - Ensure that Elastic Transcoder pipelines have encryption enabled with desired encryption level to encrypt your data.
	  - Amazon Elastic Transcoder pipelines use AWS-managed KMS keys to encrypt your data.
	  - You should use customer-managed keys in order to gain more granular control over encryption/decryption process
	  `,
		Recommendation: `Modify Elastic Transcoder pipelines encryption settings to use custom KMS key
	  - https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/encryption.html
	  `,
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
	categoryELB + "/appTierElbSecurity": {
		Risk: `App-Tier ELB Security Policy
	  - Ensures that AWS App-Tier ELBs are using the latest predefined security policies.
	  - AWS App-Tier ELBs should use the latest predefined security policies to secure the connection between client and ELB.
	  `,
		Recommendation: `Update App-Tier ELB reference security policy to latest predefined security policy to secure the connection between client and ELB
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html
	  `,
	},
	categoryELB + "/classicELBInUse": {
		Risk: `Classic Load Balancers In Use
	  - Ensures that HTTP/HTTPS applications are using Application Load Balancer instead of Classic Load Balancer.
	  - HTTP/HTTPS applications should use Application Load Balancer instead of Classic Load Balancer for cost and web traffic distribution optimization.
	  `,
		Recommendation: `Detach Classic Load balancer from HTTP/HTTPS applications and attach Application Load Balancer to those applications
	  - https://aws.amazon.com/elasticloadbalancing/features/
	  `,
	},
	categoryELB + "/connectionDrainingEnabled": {
		Risk: `ELB Connection Draining Enabled
	  - Ensures that AWS ELBs have connection draining enabled.
	  - Connection draining should be used to ensure that a Classic Load Balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open.
	  `,
		Recommendation: `Update ELBs to enable connection draining
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html
	  `,
	},
	categoryELB + "/crosszoneLoadBalancing": {
		Risk: `ELB Cross-Zone Load Balancing
	  - Ensures that AWS ELBs have cross-zone load balancing enabled.
	  - AWS ELBs should have cross-zone load balancing enabled to distribute the traffic evenly across the registered instances in all enabled Availability Zones.
	  `,
		Recommendation: `Update AWS ELB to enable cross zone load balancing
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-crosszone-lb.html
	  `,
	},
	categoryELB + "/elbHasTags": {
		Risk: `ELB Has Tags
	  - Ensure that ELBs have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify ELB and add tags.
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html
	  `,
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
	categoryELBv2 + "/elbv2DeprecatedSslPolicies": {
		Risk: `ELBv2 Deprecated SSL Policies
	  - Ensure that Elbv2 listeners are configured to use the latest predefined security policies.
	  - Insecure or deprecated security policies can expose the client and the load balancer to various vulnerabilities.
	  `,
		Recommendation: `Modify ELBv2 listeners with the latest predefined AWS security policies.
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html
	  `,
	},
	categoryELBv2 + "/ELBv2 Deregistration Delay": {
		Risk: `ELBv2 Deregistration Delay
	  - Ensures that AWS ELBv2 target groups have deregistration delay configured.
	  - AWS ELBv2 target groups should have deregistration delay configured to help in-flight requests to the target to complete.
	  `,
		Recommendation: `Update ELBv2 target group attributes and set the deregistration delay value
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#deregistration-delay
	  `,
	},
	categoryELBv2 + "/elbv2HasTags": {
		Risk: `ELBv2 Has Tags
	  - Ensure that ELBv2 load balancers have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify ELBv2 and add tags.
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html
	  `,
	},
	categoryELBv2 + "/elbv2InsecureCiphers": {
		Risk: `ELBv2 Insecure Ciphers
	  - Ensure that Elbv2 listeners are configured to use the predefined security policies containing secure ciphers.
	  - A security policy is a combination of protocols and ciphers. 
	  - The protocol establishes a secure connection between a client and a server and ensures that all data passed between the client and your load balancer is private.
	  `,
		Recommendation: `Modify ELBv2 listeners with the predefined AWS security policies containing secure ciphers.
	  - https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html
	  `,
	},
	categoryELBv2 + "/elbv2SslTermination": {
		Risk: `ELB SSL Termination
	  - Ensure that Load Balancers has SSL certificate configured for SSL terminations.
	  - SSL termination or SSL offloading decrypts and verifies data on the load balancer instead of the application server which spares the server of having to organize incoming connections and prioritize on other tasks like loading web pages. 
	  - This helps increase server speed.
	  `,
		Recommendation: `Attach SSL certificate with the listener to AWS Elastic Load Balancer
	  - https://aws.amazon.com/blogs/aws/elastic-load-balancer-support-for-ssl-termination/
	  `,
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
	categoryEMR + "/emrClusterInVPC": {
		Risk: `EMR Cluster In VPC
	  - Ensure that your Amazon Elastic MapReduce (EMR) clusters are provisioned using the AWS VPC platform instead of EC2-Classic platform.
	  - AWS EMR clusters using VPC platform instead of EC2-Classic can bring multiple advantages such as better networking infrastructure, much more flexible control over access security .
	  `,
		Recommendation: `EMR clusters Available in VPC
	  - https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-vpc-launching-job-flows.html
	  `,
	},
	categoryEMR + "/emrDesiredInstanceType": {
		Risk: `EMR Cluster Desired Instance Type
	  - Ensure AWS Elastic MapReduce (EMR) clusters are using desired instance type.
	  - EMR cluster desired instance should be enabled  to get the desired instance type.
	  `,
		Recommendation: `Modify EMR clusters to enable cluster logging
	  - https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-debugging.html
	  `,
	},
	categoryEMR + "/emrInstanceCount": {
		Risk: `EMR Instances Counts
	  - Ensure that the number of EMR cluster instances provisioned in your AWS account has not reached the desired threshold established by your organization.
	  - Setting threshold for the number of EMR cluster instances provisioned within your AWS account will help to manage EMR compute resources and prevent unexpected charges on your AWS bill.
	  `,
		Recommendation: `Ensure that the number of running EMR cluster instances matches the expected count. 
	  - If instances are launched above the threshold, investigate to ensure they are legitimate.
	  - https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-manage-view-clusters.html
	  `,
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
	categoryES + "/esClusterStatus": {
		Risk: `ElasticSearch Cluster Status
	  - Ensure that ElasticSearch clusters are healthy, i.e status is green.
	  - Unhealthy Amazon ES clusters with the status set to "Red" is crucial for availability of ElasticSearch applications.
	  `,
		Recommendation: `Configure alarms to send notification if cluster status remains red for more than a minute.
	  - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/cloudwatch-alarms.html
	  `,
	},
	categoryES + "/esCrossAccountAccess": {
		Risk: `ElasticSearch Domain Cross Account access
	  - Ensures that only trusted accounts have access to ElasticSearch domains.
	  - Allowing unrestricted access of ES clusters will cause data leaks and data loss. 
	  - This can be prevented by restricting access only to the trusted entities by implementing the appropriate access policies.
	  `,
		Recommendation: `Restrict the access to ES clusters to allow only trusted accounts.
	  - http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-gsg-configure-access.html
	  `,
	},
	categoryES + "/esDedicatedMasterEnabled": {
		Risk: `ElasticSearch Dedicated Master Enabled
	  - Ensure that Amazon Elasticsearch domains are using dedicated master nodes.
	  - Using Elasticsearch dedicated master nodes to separate management tasks from index and search requests will improve the clusters ability to manage easily different types of workload and make them more resilient in production.
	  `,
		Recommendation: `Update the domain to use dedicated master nodes.
	  - http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html
	  `,
	},
	categoryES + "/esDesiredInstanceTypes": {
		Risk: `ElasticSearch Desired Instance Type
	  - Ensure that all your Amazon Elasticsearch cluster instances are of given instance types.
	  - Limiting the type of Amazon Elasticsearch cluster instances that can be provisioned will help address compliance requirements and prevent unexpected charges on the AWS bill.
	  `,
		Recommendation: `Reconfigure the domain to have the desired instance types.
	  - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createupdatedomains.html
	  `,
	},
	categoryES + "/esDomainEncryptionEnabled": {
		Risk: `ElasticSearch Encryption Enabled
	  - Ensure that AWS ElasticSearch domains have encryption enabled.
	  - ElasticSearch domains should be encrypted to ensure that data is secured.
	  `,
		Recommendation: `Ensure encryption-at-rest is enabled for all ElasticSearch domains.
	  - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html
	  `,
	},
	categoryES + "/esTlsVersion": {
		Risk: `ElasticSearch TLS Version
	  - Ensure ElasticSearch domain is using the latest security policy to only allow TLS v1.2
	  - ElasticSearch domains should be configured to enforce TLS version 1.2 for all clients to ensure encryption of data in transit with updated features.
	  `,
		Recommendation: `Update elasticsearch domain to set TLSSecurityPolicy to contain TLS version 1.2.
	  - https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/infrastructure-security.html
	  `,
	},
	categoryEventBridge + "/eventBusCrossAccountAccess": {
		Risk: `Event Bus Cross Account Access
	  - Ensure that EventBridge event bus is configured to allow access to whitelisted AWS account principals.
	  - EventBridge event bus policy should be configured to allow access only to whitelisted/trusted cross-account principals.
	  `,
		Recommendation: `Configure EventBridge event bus policies that allow access to whitelisted/trusted cross-account principals.
	  - https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-bus-perms.html
	  `,
	},
	categoryEventBridge + "/eventBusPublicAccess": {
		Risk: `Event Bus Public Access
	  - Ensure that EventBridge event bus is configured to prevent exposure to public access.
	  - The default event bus in your Amazon account only allows events from one account.
	  - You can grant additional permissions to an event bus by attaching a resource-based policy to it.
	  `,
		Recommendation: `Configure EventBridge event bus policies that allow access to whitelisted/trusted account principals but not public access.
	  - https://docs.amazonaws.cn/en_us/eventbridge/latest/userguide/eb-event-bus-perms.html
	  `,
	},
	categoryEventBridge + "/eventsInUse": {
		Risk: `EventBridge Event Rules In Use
	  - Ensure that Amazon EventBridge Events service is in use in order to enable you to react selectively and efficiently to system events.
	  - Amazon EventBridge Events delivers a near real-time stream of system events that describe changes in Amazon Web Services (AWS) resources. Using simple rules that you can quickly set up, you can match events and route them to one or more target functions or streams.
	  `,
		Recommendation: `Create EventBridge event rules to meet regulatory and compliance requirement within your organization.
	  - https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html
	  `,
	},
	categoryFinSpace + "/finspaceEnvironmentEncrypted": {
		Risk: `FinSpace Environment Encrypted
	  - Ensure that AWS FinSpace Environments are using desired encryption level.
	  - Amazon FinSpace is a fully managed data management and analytics service that makes it easy to store, catalog, and prepare financial industry data at scale.
	  - To encrypt this data, use a KMS key with desired encrypted level to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Create FinSpace Environment with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/finspace/latest/userguide/data-encryption.html
	  `,
	},
	categoryFirehose + "/firehoseEncrypted": {
		Risk: `Firehose Delivery Streams Encrypted
		- Ensures Firehose Delivery Stream encryption is enabled
		- Data sent through Firehose Delivery Streams can be encrypted using KMS server-side encryption.
		- Existing delivery streams can be modified to add encryption with minimal overhead.`,
		Recommendation: `Enable encryption using KMS for all Firehose Delivery Streams.
		- https://docs.aws.amazon.com/firehose/latest/dev/encryption.html`,
	},
	categoryFirehose + "/deliveryStreamEncrypted": {
		Risk: `Firehose Delivery Streams CMK Encrypted
	  - Ensures Firehose delivery stream are encrypted using AWS KMS key of desired encryption level.
	  - Data sent through Firehose delivery streams can be encrypted using KMS server-side encryption.
	  - Existing delivery streams can be modified to add encryption with minimal overhead. 
	  - Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Enable encryption using desired level for all Firehose Delivery Streams.
	  - https://docs.aws.amazon.com/firehose/latest/dev/encryption.html
	  `,
	},
	categoryForecast + "/datasetExportEncrypted": {
		Risk: `Forecast Dataset Export Encrypted
	  - Ensure that AWS Forecast exports have encryption enabled before they are being saved on S3.
	  - In AWS Forecast, you can save forecast reports on S3 in CSV format.
	  - Make sure to encrypt these export before writing them to the bucket in order to follow your organizations\'s security and compliance requirements.
	  `,
		Recommendation: `Create Forecast exports with encryption enabled
	  - https://docs.aws.amazon.com/forecast/latest/dg/howitworks-forecast.html
	  `,
	},
	categoryForecast + "/forecastDatasetEncrypted": {
		Risk: `Forecast Dataset Encrypted
	  - Ensure that AWS Forecast datasets are using desired KMS key for data encryption.
	  - Datasets contain the data used to train a predictor. 
	  - You create one or more Amazon Forecast datasets and import your training data into them. 
	  - Make sure to enable encryption for these datasets using customer-managed keys (CMKs) in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create Forecast datasets using customer-manager KMS keys (CMKs).
	  - https://docs.aws.amazon.com/forecast/latest/dg/API_CreateDataset.html
	  `,
	},
	categoryFraudDetector + "/fraudDetectorDataEncrypted": {
		Risk: `Fraud Detector Data Encrypted
	  - Ensure that Amazon Fraud Detector has encryption enabled for data at rest with desired KMS encryption level.
	  - Amazon Fraud Detector encrypts your data at rest with AWS-managed KMS key. Use customer-manager KMS keys (CMKs) instead in order to follow your organizations\'s security and compliance requirements.
	  `,
		Recommendation: `Enable encryption for data at rest using PutKMSEncryptionKey API
	  - https://docs.aws.amazon.com/frauddetector/latest/ug/encryption-at-rest.html
	  `,
	},
	categoryFSx + "/fsxFileSystemEncrypted": {
		Risk: `FSx File System Encrypted
	  - Ensure that Amazon FSx for Windows File Server file systems are encrypted using desired KMS encryption level.
	  - If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, AWS recommends creating encrypted file systems.
	  `,
		Recommendation: `Enable encryption for file systems created under Amazon FSx for Windows File Server
	  - https://docs.aws.amazon.com/fsx/latest/WindowsGuide/encryption.html
	  `,
	},
	categoryGlue + "/bookmarkEncryptionEnabled": {
		Risk: `AWS Glue Job Bookmark Encryption Enabled
		- Ensures that AWS Glue job bookmark encryption is enabled.
		- AWS Glue security configuration should have job bookmark encryption enabled in order to encrypt the bookmark data before it is sent to Amazon S3.`,
		Recommendation: `Recreate Glue security configurations and enable job bookmark encryption
		- https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html`,
	},
	categoryGlue + "/dataCatalogCmkEncrypted": {
		Risk: `AWS Glue Data Catalog CMK Encrypted
	  - Ensures that AWS Glue has data catalog encryption enabled with KMS Customer Master Key (CMK).
	  - AWS Glue should have data catalog encryption enabled with KMS Customer Master Key (CMK) instead of AWS-managed Key in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Modify Glue data catalog to use CMK instead of AWS-managed Key to encrypt Metadata
	  - https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html
	  `,
	},
	categoryGlue + "/dataCatalogEncryptionEnabled": {
		Risk: `AWS Glue Data Catalog Encryption Enabled
	  - Ensures that AWS Glue Data Catalogs has encryption at-rest enabled.
	  - Encryption should be enabled for metadata objects stored in your AWS Glue Data Catalog to secure sensitive data.
	  `,
		Recommendation: `Modify Glue data catalog settings and enable metadata encryption
	  - https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html
	  `,
	},
	categoryGlue + "/glueCloudwatchLogsEncrypted": {
		Risk: `AWS Glue CloudWatch Encrypted Logs
	  - Ensures that encryption at-rest is enabled when writing AWS Glue logs to Amazon CloudWatch.
	  - AWS Glue should have encryption at-rest enabled for AWS Glue logs to ensure security of AWS Glue logs.
	  `,
		Recommendation: `Modify Glue Security Configurations to enable CloudWatch logs encryption at-rest
	  - https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html
	  `,
	},
	categoryGlue + "/glueS3EncryptionEnabled": {
		Risk: `AWS Glue S3 Encryption Enabled
	  - Ensures that encryption at-rest is enabled when writing AWS Glue data to Amazon S3.
	  - AWS Glue should have encryption at-rest enabled for Amazon S3 to ensure security of data at rest and to prevent unauthorized access.
	  `,
		Recommendation: `Recreate AWS Glue Security Configuration to enable Amazon S3 encryption at-rest
	  - https://docs.aws.amazon.com/glue/latest/dg/console-security-configurations.html
	  `,
	},
	categoryGlueDataBrew + "/databrewJobOutputEncrypted": {
		Risk: `AWS Glue DataBrew Job Output Encrypted
	  - Ensure that AWS Glue DataBrew jobs have encryption enabled for output files with desired encryption level.
	  - AWS Glue DataBrew jobs should have encryption enabled to encrypt S3 targets i.e. output files to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Modify Glue DataBrew jobs to set desired encryption configuration
	  - https://docs.aws.amazon.com/databrew/latest/dg/encryption-security-configuration.html
	  `,
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
	categoryGuardDuty + "/exportedFindingsEncrypted": {
		Risk: `Exported Findings Encrypted
	  - Ensure that GuardDuty findings export is encrypted using desired KMS encryption level.
	  - GuardDuty data, such as findings, is encrypted at rest using AWS owned customer master keys (CMK).
	  - Additionally, you can use your use key (CMKs) in order to gain more control over data encryption/decryption process.
	  `,
		Recommendation: `Encrypt GuardDuty Export Findings with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html
	  `,
	},
	categoryGuardDuty + "/noActiveFindings": {
		Risk: `GuardDuty No Active Findings
	  - Ensure that GurardDuty active/current findings does not exist in your AWS account.
	  - Amazon GuardDuty is a threat detection service that continuously monitors your AWS accounts and workloads for malicious activity and delivers detailed security findings for visibility and remediation.
	  - These findings should be acted upon and archived after they have been remediated in order to follow security best practices.
	  `,
		Recommendation: `Resolve the GuardDuty findings and archive them
	  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings.html
	  `,
	},
	categoryHealthLake + "/dataStoreEncrypted": {
		Risk: `HealthLake Data Store Encrypted
	  - Ensure that AWS HealthLake Data Store is using desired encryption level.
	  - Amazon HealthLake is a Fast Healthcare Interoperability Resources (FHIR)-enabled patient Data Store that uses AWS-managed KMS keys for encryption. 
	  - Encrypt these data stores using customer-managed keys (CMKs) in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create HealthLake Data Store with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/healthlake/latest/devguide/data-protection.html
	  `,
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
	categoryIAM + "/iamMasterManagerRoles": {
		Risk: `IAM Master and IAM Manager Roles
	  - Ensure IAM Master and IAM Manager roles are active within your AWS account.
	  - IAM roles should be split into IAM Master and IAM Manager roles to work in two-person rule manner for best prectices.
	  `,
		Recommendation: `Create the IAM Master and IAM Manager roles for an efficient IAM administration and permission management within your AWS account
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
	  `,
	},
	categoryIAM + "/iamPoliciesPresent": {
		Risk: `IAM Policies Present
	  - Ensure that required policies are present in all IAM roles.
	  - Validate the presence of required policies in IAM roles in order to follow your organizations\'s security and compliance requirements.
	  `,
		Recommendation: `Modify IAM roles to attach required policies
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
	  `,
	},
	categoryIAM + "/iamRoleHasTags": {
		Risk: `IAM Role Has Tags
	  - Ensure that AWS IAM Roles have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify Roles to add tags.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html
	  `,
	},
	categoryIAM + "/iamSupportPolicy": {
		Risk: `IAM Support Policy
	  - Ensures that an IAM role, group or user exists with specific permissions to access support center.
	  - AWS provides a support center that can be used for incident notification and response, as well as technical support and customer services.
	  - An IAM Role should be present to allow authorized users to manage incidents with AWS Support.
	  `,
		Recommendation: `Ensure that an IAM role has permission to access support center.
	  - https://docs.aws.amazon.com/awssupport/latest/user/accessing-support.html
	  `,
	},
	categoryIAM + "/iamUserHasTags": {
		Risk: `IAM User Has Tags
	  - Ensure that AWS IAM Users have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify IAM User and add tags
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags_users.html
	  `,
	},
	categoryIAM + "/iamUserInUse": {
		Risk: `IAM User Account In Use
	  - Ensure that IAM user accounts are not being actively used.
	  - IAM users, roles, and groups should not be used for day-to-day account management.
	  `,
		Recommendation: `Delete IAM user accounts which are being actively used.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html
	  `,
	},
	categoryIAM + "/iamUserNotInUse": {
		Risk: `IAM User Account Not In Use
	  - Ensure that IAM user accounts are being actively used.
	  - To increase the security of your AWS account, remove IAM user accounts that have not been used over a certain period of time.
	  `,
		Recommendation: `Delete IAM user accounts which are not being actively used or change the password or deactivate the access keys so they no longer have access.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html
	  `,
	},
	categoryIAM + "/iamUserPresent": {
		Risk: `IAM User Present
	  - Ensure that at least one IAM user exists so that access to your AWS services and resources is made only through IAM users instead of the root account.
	  - To protect your AWS root account and adhere to IAM security best practices, create individual IAM users to access your AWS environment.
	  `,
		Recommendation: `Create IAM user(s) and use them to access AWS services and resources.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
	  `,
	},
	categoryIAM + "/iamUserWithoutPermissions": {
		Risk: `IAM User Without Permissions
	  - Ensure that no IAM user exists without any permissions.
	  - IAM users are created to perform any Console, CLI or API based operations on AWS cloud accounts. 
	  - They are associated with policies that grant them permissions to perform required operations. 
	  - An IAM user without any permission is a security risk, it is recommended to either add required permissions or delete them to adhere to compliance standards.
	  `,
		Recommendation: `Modify IAM user and attach new permissions or delete the user.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
	  `,
	},
	categoryIAM + "/policyAllowsToChangePassword": {
		Risk: `Password Policy Allows To Change Password
	  - Ensure IAM password policy allows users to change their passwords.
	  - Password policy should allow users to rotate their passwords as a security best practice.
	  `,
		Recommendation: `Update the password policy for users to change their passwords
	  - http://docs.aws.amazon.com/IAM/latest/UserGuide/Using_ManagingPasswordPolicies.html
	  `,
	},
	categoryIAM + "/rolePolicyUnusedServices": {
		Risk: `IAM Role Policy Unused Services
	  - Ensure that IAM role policies are scoped properly as to not provide access to unused AWS services.
	  - AM role policies should only contain actions for resource types which are being used in your account i.e. dynamodb:ListTables permission should only be given when there are DynamoDB tables to adhere to security best practices and to follow principal of least-privilege.
	  `,
		Recommendation: `Ensure that all IAM roles are scoped to specific services and resource types.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html
	  `,
	},
	categoryIAM + "/trustedCrossAccountRoles": {
		Risk: `Trusted Cross Account Roles
	  - Ensures that only trusted cross-account IAM roles can be used.
	  - IAM roles should be configured to allow access to trusted account IDs.
	  `,
		Recommendation: `Delete the IAM roles that are associated with untrusted account IDs.
	  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_aws-accounts.html
	  `,
	},
	categoryImageBuilder + "/dockerfileTemplateEncrypted": {
		Risk: `Dockerfile Template Encrypted
	  - Ensure that Image Recipe dockerfile templates are encrypted.
	  - Image Builder now offers a managed service for building Docker images. 
	  - With Image Builder, you can automatically produce new up-to-date container images and publish them to specified Amazon Elastic Container Registry (Amazon ECR) repositories after running stipulated tests. 
	  - Custom components are encrypted with your KMS key or a KMS key owned by Image Builder.
	  `,
		Recommendation: `Ensure that container recipe docker file templates are encrypted using AWS keys or customer managed keys in Imagebuilder service
	  - https://docs.aws.amazon.com/imagebuilder/latest/userguide/data-protection.html
	  `,
	},
	categoryImageBuilder + "/enhancedMetadataEnabled": {
		Risk: `Enhanced Metadata Collection Enabled
	  - Ensure that enhanced metadata collection is enabled for image pipelines.
	  - EC2 Image Builder is a fully managed AWS service that makes it easier to automate the creation, management, and deployment of customized, secure, and up-to-date server images that are pre-installed and pre-configured with software and settings to meet specific IT standards.
	  `,
		Recommendation: `Enable enhanced metadata collection for image pipeline.
	  - https://docs.aws.amazon.com/imagebuilder/latest/userguide/start-build-image-pipeline.html
	  `,
	},
	categoryImageBuilder + "/imageRecipeVolumeEncrypted": {
		Risk: `Image Recipe Storage Volumes Encrypted
	  - Ensure that Image Recipe storage ebs volumes are encrypted.
	  - EC2 Image Builder is a fully managed AWS service that makes it easier to automate the creation, management, and deployment of customized, secure, and up-to-date server images that are pre-installed and pre-configured with software and settings to meet specific IT standards.
	  `,
		Recommendation: `Ensure that storage volumes for ebs are encrypted using AWS keys or customer managed keys in Image recipe
	  - https://docs.aws.amazon.com/imagebuilder/latest/userguide/data-protection.html
	  `,
	},
	categoryImageBuilder + "/imgBuilderComponentsEncrypted": {
		Risk: `Image Builder Components Encrypted
	  - Ensure that Image Builder components are encrypted.
	  - Build components contain software, settings, and configurations that are installed or applied during the process of building custom images. 
	  - Tests are run after a custom image is built to validate functionality, security, performance, etc. Custom components are encrypted with your KMS key or a KMS key owned by Image Builder.
	  `,
		Recommendation: `Ensure that components are encrypted using AWS keys or customer managed keys in Image Builder service
	  - https://docs.aws.amazon.com/imagebuilder/latest/userguide/data-protection.html
	  `,
	},
	categoryImageBuilder + "/infraConfigNotificationEnabled": {
		Risk: `Infrastructure Configuration Notification Enabled
	  - Ensure that Image Builder infrastructure configurations have SNS notifications enabled.
	  - Infrastructure configurations allow you to specify the infrastructure within which to build and test your EC2 Image Builder image.
	  `,
		Recommendation: `Enable SNS notification in EC2 Image Builder infrastructure configurations to get notified of any changes in the service.
	  - https://docs.aws.amazon.com/imagebuilder/latest/userguide/manage-infra-config.html
	  `,
	},
	categoryIoTSiteWise + "/iotsitewiseDataEncrypted": {
		Risk: `IoT SiteWise Data Encrypted
	  - Ensure that AWS IoT SiteWise is using desired encryption level for data at-rest.
	  - AWS IoT SiteWise encrypts data such as your asset property values and aggregate values by default.
	  - It is recommended to use customer managed keys in order to gain more control over data encryption/decryption process.
	  `,
		Recommendation: `Update IoT SiteWise encryption configuration to use a CMK.
	  - https://docs.aws.amazon.com/iot-sitewise/latest/userguide/encryption-at-rest.html
	  `,
	},
	categoryKendra + "/kendraIndexEncrypted": {
		Risk: `Kendra Index Encrypted
	  - Ensure that the Kendra index is encrypted using desired encryption level.
	  - Amazon Kendra encrypts your data at rest with AWS-manager keys by default. 
	  - Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create Kendra Index with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/kendra/latest/dg/encryption-at-rest.html
	  `,
	},
	categoryKinesis + "/kinesisEncrypted": {
		Risk: `Kinesis Streams Encrypted
		- Ensures Kinesis Streams encryption is enabled
		- Data sent to Kinesis Streams can be encrypted using KMS server-side encryption.
		- Existing streams can be modified to add encryption with minimal overhead.`,
		Recommendation: `Enable encryption using KMS for all Kinesis Streams.
		- https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html`,
	},
	categoryKinesis + "/kinesisDataStreamsEncrypted": {
		Risk: `Kinesis Data Streams Encrypted
	  - Ensures Kinesis data streams are encrypted using AWS KMS key of desired encryption level.
	  - Data sent to Kinesis data streams can be encrypted using KMS server-side encryption. 
	  - Existing streams can be modified to add encryption with minimal overhead.
	  - Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Enable encryption using desired level for all Kinesis streams
	  - https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html
	  `,
	},
	categoryKinesisVideoStreams + "/videostreamDataEncrypted": {
		Risk: `Video Stream Data Encrypted
	  - Ensure that Amazon Kinesis Video Streams is using desired encryption level for Data at-rest.
	  - Server-side encryption is always enabled on Kinesis video streams data. 
	  - If a user-provided key is not specified when the stream is created, the default key (provided by Kinesis Video Streams) is used.
	  - It is recommended to use customer-managed keys (CMKs) for encryption in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt Kinesis Video Streams data with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/how-kms.html
	  `,
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
	categoryKMS + "/kmsDuplicateGrants": {
		Risk: `KMS Duplicate Grants
	  - Ensure that AWS KMS keys does not have duplicate grants to adhere to AWS security best practices.
	  - Duplicate grants have the same key ARN, API actions, grantee principal, encryption context, and name.
	  - If you retire or revoke the original grant but leave the duplicates, the leftover duplicate grants constitute unintended escalations of privilege.
	  `,
		Recommendation: `Delete duplicate grants for AWS KMS keys
	  - https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
	  `,
	},
	categoryKMS + "/kmsGrantLeastPrivilege": {
		Risk: `KMS Grant Least Privilege
	  - Ensure that AWS KMS key grants use the principle of least privileged access.
	  - AWS KMS key grants should be created with minimum set of permissions required by grantee principal to adhere to AWS security best practices.
	  `,
		Recommendation: `Create KMS grants with minimum permission required
	  - https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
	  `,
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
	categoryLambda + "/envVarsClientSideEncryption": {
		Risk: `Lambda Environment Variables Client Side Encryption
	  - Ensure that all sensitive AWS Lambda environment variable values are client side encrypted.
	  - Environment variables are often used to store sensitive information such as passwords. Such variable valuesshould be encrypted for security best practices.
	  `,
		Recommendation: `Encrypt environment variables that store sensitive information
	  - https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
	  `,
	},
	categoryLambda + "/lambdaAdminPrivileges": {
		Risk: `Lambda Admin Privileges
	  - Ensures no Lambda function available in your AWS account has admin privileges.
	  - AWS Lambda Function should have most-restrictive IAM permissions for Lambda security best practices.
	  `,
		Recommendation: `Modify IAM role attached with Lambda function to provide the minimal amount of access required to perform its tasks
	  - link
	  `,
	},
	categoryLambda + "/lambdaHasTags": {
		Risk: `Lambda Has Tags
	  - Ensure that AWS Lambda functions have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify Lambda function configurations and  add new tags
	  - https://docs.aws.amazon.com/lambda/latest/dg/configuration-tags.html
	  `,
	},
	categoryLambda + "/lambdaTracingEnabled": {
		Risk: `Lambda Tracing Enabled
	  - Ensures AWS Lambda functions have active tracing for X-Ray.
	  - AWS Lambda functions should have active tracing in order to gain visibility into the functions execution and performance.
	  `,
		Recommendation: `Modify Lambda functions to activate tracing
	  - https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html
	  `,
	},
	categoryLambda + "/lambdaUniqueExecutionRole": {
		Risk: `Lambda Unique Execution Role
	  - Ensure that AWS Lambda functions do not share the same execution role.
	  - An execution role grants required permission to Lambda function to access AWS services and resources. 
	  - It is recommended to associate the unique IAM role for each Lambda function to follow the principle of least privilege access.
	  `,
		Recommendation: `Modify Lambda function and add new execution role.
	  - https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
	  `,
	},
	categoryLex + "/lexAudioLogsEncrypted": {
		Risk: `Audio Logs Encrypted
	  - Ensure that Amazon Lex audio logs are encrypted using desired KMS encryption level
	  - For audio logs you use default encryption on your S3 bucket or specify an AWS KMS key to encrypt your audio objects. 
	  - Even if your S3 bucket uses default encryption you can still specify a different AWS KMS key to encrypt your audio objects for enhanced security.
	  `,
		Recommendation: `Encrypt Lex audio logs with customer-manager keys (CMKs) present in your account
	  - https://docs.aws.amazon.com/lex/latest/dg/conversation-logs-encrypting.html
	  `,
	},
	categoryLocation + "/geoCollectionDataEncrypted": {
		Risk: `Geoference Collection Data Encrypted
	  - Ensure that Amazon Location geoference collection data is encrypted using desired KMS encryption level.
	  - Amazon Location Service provides encryption by default to protect sensitive customer data at rest using AWS owned encryption keys.
	  - It is recommended to use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt Amazon Location geoference collection with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/location/latest/developerguide/encryption-at-rest.html
	  `,
	},
	categoryLocation + "/trackerDataEncrypted": {
		Risk: `Tracker Data Encrypted
	  - Ensure that Amazon Location tracker data is encrypted using desired KMS encryption level
	  - Amazon Location Service provides encryption by default to protect sensitive customer data at rest using AWS owned encryption keys. 
	  - It is recommended to use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt Amazon Location tracker with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/location/latest/developerguide/encryption-at-rest.html
	  `,
	},
	categoryLookoutMetrics + "/anomalyDetectorEncrypted": {
		Risk: `LookoutMetrics Anomaly Detector Encrypted
	  - Ensure that Amazon LookoutMetrics Anomaly Detector is encrypted using desired KMS encryption level
	  - Amazon Lookout for Metrics encrypts your data at rest with your choice of an encryption key. 
	  - If you do not specify an encryption key, your data is encrypted with AWS owned key by default.
	  - So use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt Amazon LookoutMetrics Anomaly Detector with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/lookoutmetrics/latest/dev/security-dataprotection.html#security-privacy-atrest
	  `,
	},
	categoryLookoutEquipment + "/equipmentdatasetEncrypted": {
		Risk: `LookoutEquipment Dataset Encrypted
	  - Ensure that Amazon Lookout for Equipment datasets are encrypted using desired KMS encryption level
	  - Amazon Lookout for Equipment encrypts your data at rest with AWS owned KMS key by default.
	  - It is recommended to use customer-managed keys instead you will gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt Amazon LookoutEquipment Dataset with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/encryption-at-rest.html
	  `,
	},
	categoryLookout + "/modelDataEncrypted": {
		Risk: `Model Data Encrypted
	  - Ensure that Lookout for Vision model data is encrypted using desired KMS encryption level
	  - By default, trained models and manifest files are encrypted in Amazon S3 using server-side encryption with KMS keys stored in AWS Key Management Service (SSE-KMS).
	  - You can also use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Encrypt LookoutVision model with customer-manager keys (CMKs) present in your account
	  - https://docs.aws.amazon.com/lookout-for-vision/latest/developer-guide/security-data-encryption.html
	  `,
	},
	categoryManagedBlockchain + "/networkMemberDataEncrypted": {
		Risk: `Managed Blockchain Network Member Data Encrypted
	  - Ensure that members created in Amazon Managed Blockchain are encrtypted using desired encryption level.
	  - Amazon Managed Blockchain encrypts the network member data at-rest by default with AWS-managed keys.
	  - Use your own key (CMK) to encrypt this data to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Ensure members in Managed Blockchain are using desired encryption level for encryption
	  - https://docs.aws.amazon.com/managed-blockchain/latest/hyperledger-fabric-dev/managed-blockchain-encryption-at-rest.html
	  `,
	},
	categoryMemoryDB + "/memorydbClusterEncrypted": {
		Risk: `MemoryDB Cluster Encrypted
	  - Ensure that your Amazon MemoryDB cluster is encrypted with desired encryption level.
	  - To help keep your data secure, MemoryDB at-rest encryption is always enabled to increase data security by encrypting persistent data using AWS-managed KMS keys. 
	  - Use AWS customer-managed Keys (CMKs) instead in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements.
	  `,
		Recommendation: `Modify MemoryDB cluster encryption configuration to use desired encryption key
	  - https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html
	  `,
	},
	categoryMQ + "/mqAutoMinorVersionUpgrade": {
		Risk: `MQ Auto Minor Version Upgrade
	  - Ensure that Amazon MQ brokers have the Auto Minor Version Upgrade feature enabled.
	  - As AWS MQ deprecates minor engine version periodically and provides new versions for upgrade, it is highly recommended that Auto Minor Version Upgrade feature is enabled to apply latest upgrades.
	  `,
		Recommendation: `Enabled Auto Minor Version Upgrade feature for MQ brokers
	  - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/broker.html
	  `,
	},
	categoryMQ + "/mqBrokerEncrypted": {
		Risk: `MQ Broker Encrypted
	  - Ensure that Amazon MQ brokers have data ecrypted at-rest feature enabled.
	  - Amazon MQ encryption at rest provides enhanced security by encrypting your data using encryption keys stored in the AWS Key Management Service (KMS).
	  `,
		Recommendation: `Enabled data at-rest encryption feature for MQ brokers
	  - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/data-protection.html#data-protection-encryption-at-rest
	  `,
	},
	categoryMQ + "/mqDeploymentMode": {
		Risk: `MQ Deployment Mode
	  - Ensure that for high availability, your AWS MQ brokers are using the active/standby deployment mode instead of single-instance
	  - With the active/standby deployment mode as opposed to the single-broker mode (enabled by default), you can achieve high availability for your Amazon MQ brokers as the service provides failure proof no risk.
	  `,
		Recommendation: `Enabled Deployment Mode feature for MQ brokers
	  - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/active-standby-broker-deployment.html
	  `,
	},
	categoryMQ + "/mqDesiredInstanceType": {
		Risk: `MQ Desired Broker Instance Type
	  - Ensure that the Amazon MQ broker instances are created with desired instance types.
	  - Set limits for the type of Amazon MQ broker instances created in your AWS account to address internal compliance requirements and prevent unexpected charges on your AWS bill.
	  `,
		Recommendation: `Create MQ broker with desired instance types
	  - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/amazon-mq-broker-architecture.html
	  `,
	},
	categoryMQ + "/mqLogExports": {
		Risk: `MQ Log Exports Enabled
	  - Ensure that Amazon MQ brokers have the Log Exports feature enabled.
	  - Amazon MQ has a feature of AWS CloudWatch Logs, a service of storing, accessing and monitoring your log files from different sources within your AWS account.
	  `,
		Recommendation: `Enable Log Exports feature for MQ brokers
	  - https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/security-logging-monitoring.html
	  `,
	},
	categoryMSK + "/mskClusterCBEncryption": {
		Risk: `MSK Cluster Client Broker Encryption
	  - Ensure that only TLS encryption between the client and broker feature is enabled for your Amazon MSK clusters.
	  - Amazon MSK in-transit encryption is an optional feature which encrypts data in transit between the client and brokers. 
	  - Select the Transport Layer Security (TLS) protocol to encrypt data as it travels between brokers and clients within the cluster.
	  `,
		Recommendation: `Enable only TLS encryption between the client and broker for all MSK clusters
	  - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
	  `,
	},
	categoryMSK + "/mskClusterEncryptionAtRest": {
		Risk: `MSK Cluster Encryption At-Rest
	  - Ensure that Amazon Managed Streaming for Kafka (MSK) clusters are using desired encryption key for at-rest encryption.
	  - Amazon MSK encrypts all data at rest using AWS-managed KMS keys by default. Use AWS customer-managed Keys (CMKs) instead in order to have a fine-grained control over data-at-rest encryption/decryption process and meet compliance requirements.
	  `,
		Recommendation: `Modify MSK cluster encryption configuration to use desired encryption key
	  - https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-security.html
	  `,
	},
	categoryMSK + "/mskClusterEncryptionInTransit": {
		Risk: `MSK Cluster Encryption In-Transit
	  - Ensure that TLS encryption within the cluster feature is enabled for your Amazon MSK clusters.
	  - Amazon MSK in-transit encryption is an optional feature which encrypts data in transit within your MSK cluster. 
	  - You can override this default at the time you create the cluster.
	  `,
		Recommendation: `Enable TLS encryption within the cluster for all MSK clusters
	  - https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html
	  `,
	},
	categoryMSK + "/mskClusterPublicAccess": {
		Risk: `MSK Cluster Public Access
	  - Ensure that public access feature within the cluster is disabled for your Amazon MSK clusters.
	  - Amazon MSK gives you the option to turn on public access to the brokers of MSK clusters running Apache Kafka 2.6.0 or later versions. For security reasons, you cannot turn on public access while creating an MSK cluster. However, you can update an existing cluster to make it publicly accessible.
	  `,
		Recommendation: `Check for public access feature within the cluster for all MSK clusters
	  - https://docs.aws.amazon.com/msk/latest/developerguide/public-access.html
	  `,
	},
	categoryMSK + "/mskClusterUnauthAccess": {
		Risk: `MSK Cluster Unauthenticated Access
	  - Ensure that unauthenticated access feature is disabled for your Amazon MSK clusters.
	  - Amazon MSK authenticates clients to allow or deny Apache Kafka actions. Alternatively, TLS or SASL/SCRAM can be used to authenticate clients, and Apache Kafka ACLs to allow or deny actions.
	  `,
		Recommendation: `Ensure that MSK clusters does not have unauthenticated access enabled.
	  - https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html
	  `,
	},
	categoryMWAA + "/environmentAdminPrivileges": {
		Risk: `Environment Admin Privileges
	  - Ensures no Amazon MWAA environment available in your AWS account has admin privileges.
	  - Amazon MWAA environments should have most-restrictive IAM permissions for security best practices.
	  `,
		Recommendation: `Modify IAM role attached with MWAA environment to provide the minimal amount of access required to perform its tasks
	  - https://docs.aws.amazon.com/mwaa/latest/userguide/manage-access.html
	  `,
	},
	categoryMWAA + "/environmentDataEncrypted": {
		Risk: `Environment Data Encrypted
	  - Ensure that AWS MWAA environment data is encrypted
	  - Amazon MWAA encrypts data saved to persistent media with AWS-manager keys by default.
	  - Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create MWAA environments with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/mwaa/latest/userguide/encryption-at-rest.html
	  `,
	},
	categoryMWAA + "/webServerPublicAccess": {
		Risk: `Web Server Public Access
	  - Ensures web access to the Apache Airflow UI in your MWAA environment is not public.
	  - To restrict access to the Apache Airflow UI, environment should be configured to be accessible only from within the VPC selected.
	  `,
		Recommendation: `Modify Amazon MWAA environments to set web server access mode to be private only
	  - https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-create.html
	  `,
	},
	categoryNeptune + "/neptuneDBInstanceEncrypted": {
		Risk: `Neptune Database Instance Encrypted
	  - Ensure that your AWS Neptune database instances are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys.
	  - Neptune encrypted instances provide an additional layer of data protection by helping to secure your data from unauthorized access to the underlying storage.
	  - You can use Neptune encryption to increase data protection of your applications that are deployed in the cloud.
	  - You can also use it to fulfill compliance requirements for data-at-rest encryption.
	  `,
		Recommendation: `Encrypt Neptune database with desired encryption level
	  - https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html
	  `,
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
	categoryProton + "/environmentTemplateEncrypted": {
		Risk: `Environment Template Encrypted
	  - Ensure that AWS Proton environment template is encrypted with desired level.
	  - AWS Proton encrypts sensitive data in your template bundles at rest in the S3 bucket where you store your template bundles using AWS-managed keys. 
	  - Use customer-managed keys (CMKs) in order to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Create Proton environment template with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/proton/latest/adminguide/data-protection.html
	  `,
	},
	categoryQLDB + "/ledgerEncrypted": {
		Risk: `Ledger Encrypted
	  - Ensure that AWS QLDB ledger is encrypted using desired encryption level
	  - QLDB encryption at rest provides enhanced security by encrypting all ledger data at rest using encryption keys in AWS Key Management Service (AWS KMS).
	  - Use customer-managed keys (CMKs) instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create QLDB ledger with customer-manager keys (CMKs)
	  - https://docs.aws.amazon.com/qldb/latest/developerguide/encryption-at-rest.html
	  `,
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
	categoryRDS + "/iamDbAuthenticationEnabled": {
		Risk: `RDS IAM Database Authentication Enabled
	  - Ensures IAM Database Authentication is enabled for RDS database instances to manage database access
	  - AWS Identity and Access Management (IAM) can be used to authenticate to your RDS DB instances.
	  `,
		Recommendation: `Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication.
	  - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
	  `,
	},
	categoryRDS + "/rdsDeletionProtectionEnabled": {
		Risk: `RDS Deletion Protection Enabled
	  - Ensures deletion protection is enabled for RDS database instances.
	  - Deletion protection prevents Amazon RDS instances from being deleted accidentally by any user.
	  `,
		Recommendation: `Modify the RDS instances to enable deletion protection.
	  - https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/
	  `,
	},
	categoryRDS + "/rdsInstanceHasTags": {
		Risk: `RDS Instance Has Tags
	  - Ensure that AWS RDS instance have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify the RDS instance to add tags.
	  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html
	  `,
	},
	categoryRDS + "/rdsSnapshotPubliclyAccessible": {
		Risk: `RDS Snapshot Publicly Accessible
	  - Ensure that Amazon RDS database snapshots are not publicly exposed.
	  - If an RDS snapshot is exposed to the public, any AWS account can copy the snapshot and create a new database instance from it.
	  - It is a best practice to ensure RDS snapshots are not exposed to the public to avoid any accidental leak of sensitive information.
	  `,
		Recommendation: `Ensure Amazon RDS database snapshot is not publicly accessible and available for any AWS account to copy or restore it.
	  - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
	  `,
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
	categoryRedshift + "/redshiftClusterDefaultPort": {
		Risk: `Redshift Cluster Default Port
	  - Ensures that Amazon Redshift clusters are not using port "5439" (default port) for database access.
	  - Amazon Redshift clusters should not use the default port for database access to ensure cluster security.
	  `,
		Recommendation: `Update Amazon Redshift cluster endpoint port.
	  - https://docs.amazonaws.cn/en_us/redshift/latest/gsg/rs-gsg-launch-sample-cluster.html
	  `,
	},
	categoryRedshift + "/redshiftClusterInVpc": {
		Risk: `Redshift Cluster In VPC
	  - Ensures that Amazon Redshift clusters are launched within a Virtual Private Cloud (VPC).
	  - Amazon Redshift clusters should be launched within a Virtual Private Cloud (VPC) to ensure cluster security.
	  `,
		Recommendation: `Update Amazon Redshift cluster and attach it to VPC
	  - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#cluster-platforms
	  `,
	},
	categoryRedshift + "/redshiftClusterMasterUsername": {
		Risk: `Redshift Cluster Default Master Username
	  - Ensures that Amazon Redshift clusters are not using "awsuser" (default master username) for database access.
	  - Amazon Redshift clusters should not use default master username for database access to ensure cluster security.
	  `,
		Recommendation: `Update Amazon Redshift cluster master username.
	  - https://docs.amazonaws.cn/en_us/redshift/latest/gsg/rs-gsg-launch-sample-cluster.html
	  `,
	},
	categoryRedshift + "/redshiftDesiredNodeType": {
		Risk: `Redshift Desired Node Type
	  - Ensures that Amazon Redshift cluster nodes are of given types.
	  - Amazon Redshift clusters nodes should be of the given types to ensure the internal compliance and prevent unexpected billing charges.
	  `,
		Recommendation: `Take snapshot of the Amazon Redshift cluster and launch a new cluster of the desired node type using the snapshot.
	  - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview
	  `,
	},
	categoryRedshift + "/redshiftNodesCount": {
		Risk: `Redshift Nodes Count
	  - Ensures that each AWS region has not reached the limit set for the number of Redshift cluster nodes.
	  - The number of provisioned Amazon Redshift cluster nodes must be less than the provided nodes limit to avoid reaching the limit and exceeding the set budget.
	  `,
		Recommendation: `Remove Redshift clusters over defined limit
	  - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html#working-with-clusters-overview
	  `,
	},
	categoryRedshift + "/redshiftUnusedReservedNodes": {
		Risk: `Redshift Unused Reserved Nodes
	  - Ensures that Amazon Redshift Reserved Nodes are being utilized.
	  - Amazon Redshift reserved nodes must be utilized to avoid unnecessary billing.
	  `,
		Recommendation: `Provision new Redshift clusters matching the criteria of reserved nodes
	  - https://docs.aws.amazon.com/redshift/latest/mgmt/purchase-reserved-node-instance.html
	  `,
	},
	categoryRedshift + "/snapshotRetentionPeriod": {
		Risk: `Redshift Automated Snapshot Retention Period
	  - Ensures that retention period is set for Amazon Redshift automated snapshots.
	  - Amazon Redshift clusters should have retention period set for automated snapshots for data protection and to avoid unexpected failures.
	  `,
		Recommendation: `Modify Amazon Redshift cluster to set snapshot retention period
	  - https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html
	  `,
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
	categoryRoute53 + "/privacyProtection": {
		Risk: `Domain Privacy Protection
	  - Ensure that Privacy Protection feature is enabled for your Amazon Route 53 domains.
	  - Enabling the Privacy Protection feature protects against receiving spams and sharing contact information in response of WHOIS queries.
	  `,
		Recommendation: `Enable Privacy Protection for Domain
	  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-privacy-protection.html
	  `,
	},
	categoryRoute53 + "/senderPolicyFwInUse": {
		Risk: `Sender Policy Framework In Use
	  - Ensure that Sender Policy Framework (SPF) is used to stop spammers from spoofing your AWS Route 53 domain.
	  - The Sender Policy Framework enables AWS Route 53 registered domain to publicly state the mail servers that are authorized to send emails on its behalf.
	  `,
		Recommendation: `Updated the domain records to have SPF.
	  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/rrsets-working-with.html
	  `,
	},
	categoryRoute53 + "/senderPolicyFwRecordPresent": {
		Risk: `Sender Privacy Framework Record Present
	  - Ensure that Route 53 hosted zones have a DNS record containing Sender Policy Framework (SPF) value set for each MX record available.
	  - The SPF record enables Route 53 registered domains to publicly state the mail servers that are authorized to send emails on its behalf.
	  `,
		Recommendation: `Add SPF records to the DNS records.
	  - https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-creating.html
	  `,
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
	categoryS3 + "/bucketDnsCompliantName": {
		Risk: `S3 DNS Compliant Bucket Names
	  - Ensures that S3 buckets have DNS complaint bucket names.
	  - S3 bucket names must be DNS-compliant and not contain period "." to enable S3 Transfer Acceleration and to use buckets over SSL.
	  `,
		Recommendation: `Recreate S3 bucket to use "-" instead of "." in S3 bucket names.
	  - https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html
	  `,
	},
	categoryS3 + "/bucketLifecycleConfiguration": {
		Risk: `S3 Bucket Lifecycle Configuration
	  - Ensures that S3 buckets have lifecycle configuration enabled to automatically transition S3 bucket objects.
	  - S3 bucket should have lifecycle configuration enabled to automatically downgrade the storage class for your objects.
	  `,
		Recommendation: `Update S3 bucket and create lifecycle rule configuration
	  - https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-set-lifecycle-configuration-intro.html
	  `,
	},
	categoryS3 + "/bucketMFADeleteEnabled": {
		Risk: `S3 Bucket MFA Delete Status
	  - Ensures MFA delete is enabled on S3 buckets.
	  - Adding MFA delete adds another layer of security while changing the version state in the event of security credentials being compromised or unauthorized access being granted.
	  `,
		Recommendation: `Enable MFA Delete on S3 buckets.
	  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html
	  `,
	},
	categoryS3 + "/bucketPolicyCloudFrontOac": {
		Risk: `S3 Bucket Policy CloudFront OAC
	  - Ensures S3 bucket is origin to only one distribution and allows only that distribution.
	  - Access to CloudFront origins should only happen via ClouFront URL and not from S3 URL or any source in order to restrict access to private data.
	  - 
	  `,
		Recommendation: `Review the access policy for S3 bucket which is an origin to a CloudFront distribution. Make sure the S3 bucket is origin to only one distribution. 
	  - Modify the S3 bucket access policy to allow CloudFront OAC for only the associated CloudFront distribution and restrict access from any other source.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
	  `,
	},
	categoryS3 + "/bucketPolicyCloudFrontOai": {
		Risk: `S3 Bucket Policy CloudFront OAI
	  - Ensures S3 bucket is origin to only one distribution and allows only that distribution.
	  - Access to CloudFront origins should only happen via ClouFront URL and not from S3 URL or any source in order to restrict access to private data.
	  `,
		Recommendation: `Review the access policy for S3 bucket which is an origin to a CloudFront distribution. Make sure the S3 bucket is origin to only one distribution.
	  - Modify the S3 bucket access policy to allow CloudFront OAI for only the associated CloudFront distribution and restrict access from any other source.
	  - https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
	  `,
	},
	categoryS3 + "/bucketTransferAcceleration": {
		Risk: `S3 Transfer Acceleration Enabled
	  - Ensures that S3 buckets have transfer acceleration enabled to increase the speed of data transfers.
	  - S3 buckets should have transfer acceleration enabled to increase the speed of data transfers in and out of Amazon S3 using AWS edge network.
	  `,
		Recommendation: `Modify S3 bucket to enable transfer acceleration.
	  - https://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html
	  `,
	},
	categoryS3 + "/S3 Bucket Has Tags": {
		Risk: `Ensure that AWS S3 Bucket have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify S3 buckets and add tags.
	  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/CostAllocTagging.html
	  `,
	},
	categoryS3 + "/versionedBucketsLC": {
		Risk: `S3 Versioned Buckets Lifecycle Configuration
	  - Ensure that S3 buckets having versioning enabled also have liecycle policy configured for non-current objects.
	  - When object versioning is enabled on a bucket, every modification/update to an object results in a new version of the object that will be stored indefinitely. 
	  - Enable a lifecycle policy, so that non-current object versions are removed or transitioned in a predictable manner.
	  `,
		Recommendation: `Configure lifecycle rules for buckets which have versioning enabled
	  - https://docs.aws.amazon.com/AmazonS3/latest/dev/how-to-set-lifecycle-configuration-intro.html
	  `,
	},
	categoryS3Glacier + "/vaultPublicAccess": {
		Risk: `S3 Glacier Vault Public Access
	  - Ensure that S3 Glacier Vault public access block is enabled for the account.
	  - Blocking S3 Glacier Vault public access at the account level ensures objects are not accidentally exposed.
	  `,
		Recommendation: `Add access policy for the S3 Glacier Vault to block public access for the AWS account.
	  - https://docs.aws.amazon.com/amazonglacier/latest/dev/access-control-overview.html
	  `,
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
	categorySageMaker + "/notebookInstanceInVpc": {
		Risk: `Notebook instance in VPC
	  - Ensure that Amazon SageMaker Notebook instances are launched within a VPC.
	  - Launching instances can bring multiple advantages such as better networking infrastructure, much more flexible control over access security. 
	  - Also it makes it possible to access VPC-only resources such as EFS file systems.
	  `,
		Recommendation: `Migrate Notebook instances to exist within a VPC
	  - https://docs.aws.amazon.com/sagemaker/latest/dg/API_CreateNotebookInstance.html#API_CreateNotebookInstance_RequestSyntax
	  `,
	},
	categorySecretsManager + "/secretHasTags": {
		Risk: `Secret Has Tags
	  - Ensure that AWS Secrets Manager secrets have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other.
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Update Secrets and add tags.
	  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets_tagging.html
	  `,
	},
	categorySecretsManager + "/secretRotationEnabled": {
		Risk: `Secrets Manager Secret Rotation Enabled
	  - Ensures AWS Secrets Manager is configured to automatically rotate the secret for a secured service or database.
	  - Secrets Manager rotation makes access to your databases and third-party services secure by automatically rotating secrets used to access these resources.
	  `,
		Recommendation: `Enable secret rotation for your secrets
	  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
	  `,
	},
	categorySecretsManager + "/secretsManagerEncrypted": {
		Risk: `Secrets Manager Encrypted Secrets
	  - Ensures Secrets Manager Secrets are encrypted
	  - Secrets Manager Secrets should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.
	  `,
		Recommendation: `Encrypt Secrets Manager Secrets
	  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/data-protection.html
	  `,
	},
	categorySecretsManager + "/Secrets Manager In Use": {
		Risk: `Secrets Manager In Use
	  - Ensure that Amazon Secrets Manager service is being used in your account to manage all the credentials.
	  - Amazon Secrets Manager helps you protect sensitive information needed to access your cloud applications, services and resources. 
	  - Users and apps can use secrets manager to get the secrets stored with a call to Secrets Manager API, enhancing access security.
	  `,
		Recommendation: `Use Secrets Manager service to store sensitive information in your AWS account.
	  - https://docs.aws.amazon.com/secretsmanager/latest/userguide/asm_access.html
	  `,
	},
	categorySES + "/dkimEnabled": {
		Risk: `Email DKIM Enabled
		- Ensures DomainKeys Identified Mail (DKIM) is enabled for domains and addresses in SES.
		- DKIM is a security feature that allows recipients of an email to veriy that the sender domain has authorized the message and that it has not been spoofed.`,
		Recommendation: `Enable DKIM for all domains and addresses in all regions used to send email through SES.
		- http://docs.aws.amazon.com/ses/latest/DeveloperGuide/easy-dkim.html`,
	},
	categorySES + "/emailMessagesEncrypted": {
		Risk: `SES Email Messages Encrypted
	  - Ensure that Amazon SES email messages are encrypted before delivering them to specified buckets.
	  - Amazon SES email messages should be encrypted in case they are being delivered to S3 bucket to meet regulatory compliance requirements within your organization.
	  `,
		Recommendation: `Enable encryption for SES email messages if they are being delivered to S3 in active rule-set .
	  - https://docs.aws.amazon.com/kms/latest/developerguide/services-ses.html
	  `,
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
	categorySNS + "/snsCrossAccount": {
		Risk: `SNS Cross Account Access
	  - Ensures SNS policies disallow cross-account access
	  - SNS topic policies should be carefully restricted to to subscribe or send messages.
	  - Topic policies can be used to limit these privileges.
	  `,
		Recommendation: `Update the SNS policy to prevent access from external accounts.
	  - https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html
	  `,
	},
	categorySNS + "/snsTopicHasTags": {
		Risk: `SNS Topic Has Tags
	  - Ensure that Amazon SNS topics have tags associated.
	  - Tags help you to group resources together that are related to or associated with each other. 
	  - It is a best practice to tag cloud resources to better organize and gain visibility into their usage.
	  `,
		Recommendation: `Modify SNS topic and add tags.
	  - https://docs.aws.amazon.com/sns/latest/dg/sns-tags.html
	  `,
	},
	categorySNS + "/snsValidSubscribers": {
		Risk: `SNS Valid Subscribers
	  - Ensure that Amazon SNS subscriptions are valid and there are no unwanted subscribers.
	  - Amazon Simple Notification Service (Amazon SNS) is a managed service that provides message delivery from publishers to subscribers. 
	  - So check for appropriate subsribers in order to improve access security to your SNS topics.
	  `,
		Recommendation: `Check for unwanted SNS subscriptions periodically
	  - https://docs.aws.amazon.com/sns/latest/dg/sns-create-subscribe-endpoint-to-topic.html
	  `,
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
	categorySQS + "/queueUnprocessedMessages": {
		Risk: `SQS Queue Unprocessed Messages
	  - Ensures that Amazon SQS queue has not reached unprocessed messages limit.
	  - Amazon SQS queues should have unprocessed messages less than the limit to be highly available and responsive.
	  `,
		Recommendation: `Set up appropriate message polling time and set up dead letter queue for Amazon SQS queue to handle messages in time
	  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/working-with-messages.html
	  `,
	},
	categorySQS + "/sqsDeadLetterQueue": {
		Risk: `SQS Dead Letter Queue
	  - Ensures that each Amazon SQS queue has Dead Letter Queue configured.
	  - Amazon SQS queues should have dead letter queue configured to avoid data loss for unprocessed messages.
	  `,
		Recommendation: `Update Amazon SQS queue and configure dead letter queue.
	  - https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
	  `,
	},
	categorySQS + "/sqsEncryptionEnabled": {
		Risk: `SQS Encryption Enabled
	  - Ensure SQS queues are encrypted using keys of desired encryption level
	  - Messages sent to SQS queues can be encrypted using KMS server-side encryption.
	  - Existing queues can be modified to add encryption with minimal overhead.
	  - Use customer-managed keys instead in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Enable encryption using KMS Customer Master Keys (CMKs) for all SQS queues.
	  - http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
	  `,
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
	categorySSM + "/ssmDocumentPublicAccess": {
		Risk: `SSM Documents Public Access
	  - Ensure that SSM service has block public sharing setting enabled.
	  - Public documents can be viewed by all AWS accounts. 
	  - To prevent unwanted access to your documents, turn on the block public access sharing setting.
	  `,
		Recommendation: `Enable block public sharing setting under SSM  documents preferences.
	  - https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-share-block.html
	  `,
	},
	categorySSM + "/ssmManagedInstances": {
		Risk: `SSM Managed Instances
	  - Ensure that all Amazon EC2 instances are managed by AWS Systems Manager (SSM).
	  - Systems Manager simplifies AWS cloud resource management, quickly detects and resolve operational problems, and makes it easier to operate and manage your instances securely at large scale.
	  `,
		Recommendation: `Configure AWS EC2 instance as SSM Managed Instances
	  - https://docs.aws.amazon.com/systems-manager/latest/userguide/managed_instances.html
	  `,
	},
	categorySSM + "/ssmSessionDuration": {
		Risk: `SSM Session Duration
	  - Ensure that all active sessions in the AWS Session Manager do not exceed the duration set in the settings.
	  - The session manager gives users the ability to either open a shell in a EC2 instance or execute commands in a ECS task. 
	  - This can be useful for when debugging issues in a container or instance.
	  `,
		Recommendation: `Terminate all the sessions which exceed the specified duration mentioned in settings.
	  - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-max-timeout.html
	  `,
	},
	categoryTimestream + "/timestreamDatabaseEncrypted": {
		Risk: `Timestream Database Encrypted
	  - Ensure that AWS Timestream databases are encrypted with KMS Customer Master Keys (CMKs) instead of AWS managed-keys.
	  - Timestream encryption at rest provides enhanced security by encrypting all your data at rest using encryption keys.
	  - This functionality helps reduce the operational burden and complexity involved in protecting sensitive data. 
	  - With encryption at rest using customer-managed keys, you can build security-sensitive applications that meet strict encryption compliance and regulatory requirements. 
	  `,
		Recommendation: `Modify Timestream database encryption configuration to use desired encryption key
	  - https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html
	  `,
	},
	categoryTransfer + "/transferLoggingEnabled": {
		Risk: `Transfer Logging Enabled
		- Ensures AWS Transfer servers have CloudWatch logging enabled.
		- AWS Transfer servers can log activity to CloudWatch if a proper IAM service role is provided.
		- This role should be configured for all servers to ensure proper access logging.`,
		Recommendation: `Provide a valid IAM service role for AWS Transfer servers.
		- https://docs.aws.amazon.com/transfer/latest/userguide/monitoring.html`,
	},
	categoryTransfer + "/transferPrivateLinkInUse": {
		Risk: `PrivateLink in Use for Transfer for SFTP Server Endpoints
	  - Ensure that AWS Transfer for SFTP server endpoints are configured to use VPC endpoints powered by AWS PrivateLink.
	  - PrivateLink provides secure and private connectivity between VPCs and other AWS resources using a dedicated network.
	  `,
		Recommendation: `Configure the SFTP server endpoints to use endpoints powered by PrivateLink.
	  - https://docs.aws.amazon.com/transfer/latest/userguide/update-endpoint-type-vpc.html
	  `,
	},
	categoryTranslate + "/translateJobOutputEncrypted": {
		Risk: `Translate Job Output Encrypted
	  - Ensure that your Amazon Translate jobs have CMK encryption enabled for output data residing on S3.
	  - Amazon Translate encrypts your output data with AWS-manager keys by default.
	  - Encrypt your files using customer-managed keys in order to gain more granular control over encryption/decryption process.
	  `,
		Recommendation: `Create Translate jobs with customer-manager keys (CMKs).
	  - https://docs.aws.amazon.com/translate/latest/dg/encryption-at-rest.html
	  `,
	},
	categoryWAF + "/wafInUse": {
		Risk: `AWS WAF In Use
	  - Ensure that AWS Web Application Firewall (WAF) is in use to achieve availability and security for AWS-powered web applications.
	  - Using WAF for your web application running in AWS environment can help against common web-based attacks, SQL injection attacks, DDOS attacks and more.
	  `,
		Recommendation: `Create one or more WAF ACLs with proper actions and rules
	  - https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html
	  `,
	},
	categoryWAF + "/wafv2InUse": {
		Risk: `AWS WAFV2 In Use
	  - Ensure that AWS Web Application Firewall V2 (WAFV2) is in use to achieve availability and security for AWS-powered web applications.
	  - Using WAF for your web application running in AWS environment can help you against common web-based attacks, SQL injection attacks, DDOS attacks and more.
	  `,
		Recommendation: `Create one or more WAF ACLs with proper actions and rules
	  - https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html
	  `,
	},
	categoryWorkspaces + "/workspacesIpAccessControl": {
		Risk: `Workspaces IP Access Control
		- Ensures enforced IP Access Control on Workspaces
		- Checking the existence of IP Access control on Workspaces and ensuring that no Workspaces are open`,
		Recommendation: `Enable proper IP Access Controls for all workspaces
		- https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-ip-access-control-groups.html`,
	},
	categoryWorkspaces + "/unusedWorkspaces": {
		Risk: `Unused WorkSpaces
	  - Ensure that there are no unused AWS WorkSpaces instances available within your AWS account.
	  - An AWS WorkSpaces instance is considered unused if it has 0 known user connections registered within the past 30 days. Remove these instances to avoid unnecessary billing.
	  `,
		Recommendation: `Identify and remove unused Workspaces instance
	  - https://aws.amazon.com/workspaces/pricing/
	  `,
	},
	categoryWorkspaces + "/workspacesDesiredBundleType": {
		Risk: `WorkSpaces Desired Bundle Type
	  - Ensure that AWS WorkSpaces bundles are of desired types.
	  - A bundle in AWS WorkSpaces defines the hardware and software for AWS WorkSpaces. 
	  - You can create a WorkSpaces instance using a predefined or custom bundle. 
	  - Setting a limit to the types that can be used will help you control billing and address internal compliance requirements.
	  `,
		Recommendation: `Ensure that WorkSpaces instances are using desired bundle types
	  - https://docs.aws.amazon.com/workspaces/latest/adminguide/amazon-workspaces-bundles.html
	  `,
	},
	categoryWorkspaces + "/workspacesInstanceCount": {
		Risk: `WorkSpaces Instance Count
	  - Ensure that the number of Amazon WorkSpaces provisioned in your AWS account has not reached set limit.
	  - In order to manage your WorkSpaces compute resources efficiently and prevent unexpected charges on your AWS bill, monitor and configure limits for the maximum number of WorkSpaces instances provisioned within your AWS account.
	  `,
		Recommendation: `Ensure that number of WorkSpaces created within your AWS account is within set limit
	  - https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-limits.html
	  `,
	},
	categoryWorkspaces + "/workspacesVolumeEncryption": {
		Risk: `WorkSpaces Volume Encryption
	  - Ensures volume encryption on WorkSpaces for data protection.
	  - AWS WorkSpaces should have volume encryption enabled in order to protect data from unauthorized access.
	  `,
		Recommendation: `Modify WorkSpaces to enable volume encryption
	  - https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html
	  `,
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
