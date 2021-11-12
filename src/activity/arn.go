package main

import (
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/ca-risken/aws/proto/activity"
)

// Parse from arn to resource details
func ParseARN(arnString string) (*activity.ARN, error) {
	parsed, err := arn.Parse(arnString)
	if err != nil {
		return nil, err
	}
	r := &activity.ARN{
		Partition: parsed.Partition,
		Service:   parsed.Service,
		Region:    parsed.Region,
		AccountId: parsed.AccountID,
		Resource:  parsed.Resource,
	}
	colonSplited := strings.Split(r.Resource, ":")
	slashSplited := strings.Split(colonSplited[len(colonSplited)-1], "/")
	r.ResourceId = slashSplited[len(slashSplited)-1]

	typeKey := r.Service
	if r.Service == "s3" || r.Service == "sqs" || r.Service == "sns" || r.Service == "codepipeline" {
		typeKey += "/"
	} else if r.Service == "elasticloadbalancing" && strings.Contains(r.Resource, "loadbalancer/app") {
		typeKey += "/loadbalancer/app"
	} else if r.Service == "elasticloadbalancing" && strings.Contains(r.Resource, "loadbalancer/net") {
		typeKey += "/loadbalancer/net"
	} else if r.Service == "apigateway" && strings.Contains(r.Resource, "/restapis/") && strings.Contains(r.Resource, "/stages/") {
		typeKey += "/restapis/stages"
	} else if r.Service == "apigateway" && strings.Contains(r.Resource, "/restapis/") && !strings.Contains(r.Resource, "/stages/") {
		typeKey += "/restapis"
	} else if r.Service == "apigateway" && strings.Contains(r.Resource, "/apis/") && strings.Contains(r.Resource, "/stages/") {
		typeKey += "/apis/stages"
	} else if r.Service == "apigateway" && strings.Contains(r.Resource, "/apis/") && !strings.Contains(r.Resource, "/stages/") {
		typeKey += "/apis"
	} else if len(colonSplited) > 1 {
		typeKey += "/" + colonSplited[0]
	} else {
		typeKey += "/" + slashSplited[0]
	}

	r.ResourceType = ResourceTypeMap[typeKey]
	return r, nil
}

// ResourceTypeMap return ResourceType value from service + type pattern.
//   key   : {service}/{type}
//   value : {resource-type}
// Supported resource-type : https://docs.aws.amazon.com/cli/latest/reference/configservice/get-resource-config-history.html#options
// Supported ARN format    : https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html#context_keys_table
var ResourceTypeMap = map[string]string{
	"{service}/{type}": "{resource-type}", // ARN format

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonec2.html
	"ec2/customer-gateway":  "AWS::EC2::CustomerGateway",  // arn:aws:ec2:region:account-id:customer-gateway/cgw-id
	"ec2/eip":               "AWS::EC2::EIP",              // arn:aws:ec2:region:account-id:eip/eipalloc-id
	"ec2/dedicated-host":    "AWS::EC2::Host",             // arn:aws:ec2:region:account-id:dedicated-host/host-id
	"ec2/instance":          "AWS::EC2::Instance",         // arn:aws:ec2:region:account-id:instance/instance-id
	"ec2/internet-gateway":  "AWS::EC2::InternetGateway",  // arn:aws:ec2:region:account-id:internet-gateway/igw-id
	"ec2/network-acl":       "AWS::EC2::NetworkAcl",       // arn:aws:ec2:region:account-id:network-acl/nacl-id
	"ec2/network-interface": "AWS::EC2::NetworkInterface", // arn:aws:ec2:region:account-id:network-interface/eni-id
	"ec2/route-table":       "AWS::EC2::RouteTable",       // arn:aws:ec2:region:account-id:route-table/route-table-id
	"ec2/security-group":    "AWS::EC2::SecurityGroup",    // arn:aws:ec2:region:account-id:security-group/security-group-id
	"ec2/subnet":            "AWS::EC2::Subnet",           // arn:aws:ec2:region:account-id:subnet/subnet-id
	"cloudtrail/trail":      "AWS::CloudTrail::Trail",     // arn:aws:cloudtrail:region:account-id:trail/trailname
	"ec2/volume":            "AWS::EC2::Volume",           // arn:aws:ec2:region:account-id:volume/volume-id
	"ec2/vpc":               "AWS::EC2::VPC",              // arn:aws:ec2:region:account-id:vpc/vpc-id
	"ec2/vpn-connection":    "AWS::EC2::VPNConnection",    // arn:aws:ec2:region:account-id:vpn-connection/vpn-id
	"ec2/vpn-gateway":       "AWS::EC2::VPNGateway",       // arn:aws:ec2:region:account-id:vpn-gateway/vgw-id
	// "ec2/type": "AWS::EC2::RegisteredHAInstance", //
	"ec2/natgateway":                   "AWS::EC2::NatGateway",                // arn:aws:ec2:region:account-id:natgateway/id
	"ec2/egress-only-internet-gateway": "AWS::EC2::EgressOnlyInternetGateway", // arn:aws:ec2:region:account-id:egress-only-internet-gateway/id
	"ec2/vpc-endpoint":                 "AWS::EC2::VPCEndpoint",               // arn:aws:ec2:region:account-id:vpc-endpoint/id
	"ec2/vpc-endpoint-service":         "AWS::EC2::VPCEndpointService",        // arn:aws:ec2:region:account-id:vpc-endpoint-service/id
	"ec2/vpc-flow-log":                 "AWS::EC2::FlowLog",                   // arn:aws:ec2:region:account-id:vpc-flow-log/id
	"ec2/vpc-peering-connection":       "AWS::EC2::VPCPeeringConnection",      // arn:aws:ec2:region:account-id:vpc-peering-connection/id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonelasticsearchservice.html
	"es/domain": "AWS::Elasticsearch::Domain", // arn:aws:es:region:account-id:domain/domain-name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_identityandaccessmanagement.html#identityandaccessmanagement-resources-for-iam-policies
	"iam/group":  "AWS::IAM::Group",  // arn:aws:iam::account-id:group/group-name
	"iam/policy": "AWS::IAM::Policy", // arn:aws:iam::account-id:policy/policy-name
	"iam/role":   "AWS::IAM::Role",   // arn:aws:iam::account-id:role/role-name
	"iam/user":   "AWS::IAM::User",   // arn:aws:iam::account-id:user/user-name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_elasticloadbalancing.html#elasticloadbalancing-resources-for-iam-policies
	"elasticloadbalancing/loadbalancer": "AWS::ElasticLoadBalancing::LoadBalancer", // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_elasticloadbalancingv2.html#elasticloadbalancingv2-resources-for-iam-policies
	"elasticloadbalancing/loadbalancer/app": "AWS::ElasticLoadBalancingV2::LoadBalancer", // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/app/.../load-balancer-id
	"elasticloadbalancing/loadbalancer/net": "AWS::ElasticLoadBalancingV2::LoadBalancer", // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/net/.../load-balancer-id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscertificatemanager.html#awscertificatemanager-resources-for-iam-policies
	"acm/certificate": "AWS::ACM::Certificate", // arn:aws:acm:region:account-id:certificate/certificate-id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonrds.html#amazonrds-resources-for-iam-policies
	"rds/db":               "AWS::RDS::DBInstance",        // arn:aws:rds:region:account-id:db:db-instance-name
	"rds/subgrp":           "AWS::RDS::DBSubnetGroup",     // arn:aws:rds:region:account-id:subgrp:subnet-group-name
	"rds/secgrp":           "AWS::RDS::DBSecurityGroup",   // arn:aws:rds:region:account-id:secgrp:security-group-name
	"rds/snapshot":         "AWS::RDS::DBSnapshot",        // arn:aws:rds:region:account-id:snapshot:snapshot-name
	"rds/cluster":          "AWS::RDS::DBCluster",         // arn:aws:rds:region:account-id:cluster:cluster-name
	"rds/cluster-snapshot": "AWS::RDS::DBClusterSnapshot", // arn:aws:rds:region:account-id:cluster-snapshot:snapshot-name
	"rds/es":               "AWS::RDS::EventSubscription", // arn:aws:rds:region:account-id:es:name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html#amazons3-resources-for-iam-policies
	"s3/": "AWS::S3::Bucket", // arn:aws:s3:::bucket_name
	// "s3/type": "AWS::S3::AccountPublicAccessBlock", //

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonredshift.html#amazonredshift-resources-for-iam-policies
	"redshift/cluster":           "AWS::Redshift::Cluster",               // arn:aws:redshift:region:account-id:cluster:cluster-name
	"redshift/snapshot":          "AWS::Redshift::ClusterSnapshot",       // arn:aws:redshift:region:account-id:snapshot:cluster-name/snapshot-name
	"redshift/parametergroup":    "AWS::Redshift::ClusterParameterGroup", // arn:aws:redshift:region:account-id:parametergroup:parameter-group-name
	"redshift/securitygroup":     "AWS::Redshift::ClusterSecurityGroup",  // arn:aws:redshift:region:account-id:securitygroup:security-group-name
	"redshift/subnetgroup":       "AWS::Redshift::ClusterSubnetGroup",    // arn:aws:redshift:region:account-id:subnetgroup:name
	"redshift/eventsubscription": "AWS::Redshift::EventSubscription",     // arn:aws:redshift:region:account-id:eventsubscription:name

	"cloudwatch/alarm": "AWS::CloudWatch::Alarm",     // arn:aws:cloudwatch:region:account-id:alarm:alarm-name
	"service/stack":    "AWS::CloudFormation::Stack", // arn:aws:cloudformation:region:account-id:stack/stackname/additionalidentifier

	"autoscaling/autoScalingGroup":    "AWS::AutoScaling::AutoScalingGroup",    // arn:aws:autoscaling:region:account-id:autoScalingGroup:uuid:autoScalingGroupName/asg-name
	"autoscaling/launchConfiguration": "AWS::AutoScaling::LaunchConfiguration", // arn:aws:autoscaling:region:account-id:launchConfiguration:uuid:launchConfigurationName/lc-name
	"autoscaling/scalingPolicy":       "AWS::AutoScaling::ScalingPolicy",       // arn:aws:autoscaling:region:account-id:scalingPolicy:uuid:...
	// "autoscaling/type": "AWS::AutoScaling::ScheduledAction", //
	"dynamodb/table":         "AWS::DynamoDB::Table",    // arn:aws:dynamodb:region:account-id:table/tablename
	"codebuild/resourcetype": "AWS::CodeBuild::Project", // arn:aws:codebuild:region:account-id:resourcetype/resource

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awswaf.html
	"waf/ratebasedrule": "AWS::WAF::RateBasedRule", //　arn:aws:waf:region:account:ratebasedrule/ID
	"waf/rule":          "AWS::WAF::Rule",          //　arn:aws:waf:region:account:rule/resource/ID
	"waf/rulegroup":     "AWS::WAF::RuleGroup",     //　arn:aws:waf:region:account:rulegroup/resource/ID
	"waf/webacl":        "AWS::WAF::WebACL",        //　arn:aws:waf:region:account:webacl/resource/ID

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awswafregional.html
	"waf-regional/ratebasedrule": "AWS::WAFRegional::RateBasedRule", // arn:aws:waf-regional:region:account:ratebasedrule/ID
	"waf-regional/rule":          "AWS::WAFRegional::Rule",          // arn:aws:waf-regional:region:account:rule/resource/ID
	"waf-regional/rulegroup":     "AWS::WAFRegional::RuleGroup",     // arn:aws:waf-regional:region:account:rulegroup/ID
	"waf-regional/webacl":        "AWS::WAFRegional::WebACL",        // arn:aws:waf-regional:region:account:webacl/ID

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awswafv2.html
	"wafv2/webacl":          "AWS::WAFv2::WebACL",          // arn:aws:wafv2:region:account-id:scope/webacl/name/id
	"wafv2/rulegroup":       "AWS::WAFv2::RuleGroup",       // arn:aws:wafv2:region:account-id:scope/rulegroup/name/id
	"wafv2/ipset":           "AWS::WAFv2::IPSet",           // arn:aws:wafv2:region:account-id:scope/ipset/name/id
	"wafv2/regexpatternset": "AWS::WAFv2::RegexPatternSet", // arn:aws:wafv2:region:account-id:scope/regexpatternset/name/id
	"wafv2/managedruleset":  "AWS::WAFv2::ManagedRuleSet",  // arn:aws:wafv2:region:account-id:scope/managedruleset/name/id

	"cloudfront/distribution":              "AWS::CloudFront::Distribution",          // arn:aws:cloudfront::account-id:distribution/...
	"cloudfront/streaming-distribution":    "AWS::CloudFront::StreamingDistribution", // arn:aws:cloudfront::account-id:streaming-distribution/...
	"lambda/function":                      "AWS::Lambda::Function",                  // arn:aws:lambda:region:account-id:function:function-name
	"network-firewall/firewall":            "AWS::NetworkFirewall::Firewall",         // arn:aws:network-firewall:region:account-id:firewall/name
	"network-firewall/firewall-policy":     "AWS::NetworkFirewall::FirewallPolicy",   // arn:aws:network-firewall:region:account-id:firewall-policy/name
	"network-firewall/stateful-rulegroup":  "AWS::NetworkFirewall::RuleGroup",        // arn:aws:network-firewall:region:account-id:stateful-rulegroup/name
	"network-firewall/stateless-rulegroup": "AWS::NetworkFirewall::RuleGroup",        // arn:aws:network-firewall:region:account-id:stateless-rulegroup/name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awselasticbeanstalk.html#awselasticbeanstalk-resources-for-iam-policies
	"elasticbeanstalk/application":        "AWS::ElasticBeanstalk::Application",        // arn:aws:elasticbeanstalk:region:account-id:application/applicationname
	"elasticbeanstalk/applicationversion": "AWS::ElasticBeanstalk::ApplicationVersion", // arn:aws:elasticbeanstalk:region:account-id:applicationversion/name/label
	"elasticbeanstalk/environment":        "AWS::ElasticBeanstalk::Environment",        // arn:aws:elasticbeanstalk:region:account-id:environment/appname/env

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsx-ray.html#awsx-ray-resources-for-iam-policies
	// "xray/type": "AWS::XRay::EncryptionConfig",                           //

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssystemsmanager.html#awssystemsmanager-resources-for-iam-policies
	"ssm/managed-instance-inventory": "AWS::SSM::ManagedInstanceInventory", // arn:aws:ssm:region:account-id:managed-instance-inventory/id
	"ssm/association":                "AWS::SSM::AssociationCompliance",    // ? arn:aws:ssm:region:account-id:association/id
	"ssm/patchbaseline":              "AWS::SSM::PatchCompliance",          // ? arn:aws:ssm:region:account-id:patchbaseline/id
	// "ssm/type": "AWS::SSM::FileData",                                    //

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsshield.html#awsshield-resources-for-iam-policies
	"shield/protection": "AWS::Shield::Protection", // arn:aws:shield::account-id:protection/id
	// "service/type": "AWS::ShieldRegional::Protection",                       //

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsconfig.html#awsconfig-resources-for-iam-policies
	"config/conformance-pack": "AWS::Config::ConformancePackCompliance", // arn:aws:config:region:account-id:conformance-pack/name/id
	// "config/type": "AWS::Config::ResourceCompliance",                       //

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonapigatewaymanagement.html#amazonapigatewaymanagement-resources-for-iam-policies
	"apigateway/restapis":        "AWS::ApiGateway::RestApi", // arn:aws:apigateway:region::/restapis/id
	"apigateway/restapis/stages": "AWS::ApiGateway::Stage",   // arn:aws:apigateway:region::/restapis/id/stages/name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonapigatewaymanagementv2.html#amazonapigatewaymanagementv2-resources-for-iam-policies
	"apigateway/apis":        "AWS::ApiGatewayV2::Api",   // arn:aws:apigateway:region::/apis/id
	"apigateway/apis/stages": "AWS::ApiGatewayV2::Stage", // arn:aws:apigateway:region::/apis/id/stages/name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscodepipeline.html#awscodepipeline-resources-for-iam-policies
	"codepipeline/": "AWS::CodePipeline::Pipeline", // arn:aws:codepipeline:region:account-id:name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsservicecatalog.html#awsservicecatalog-resources-for-iam-policies
	// "catalog/type": "AWS::ServiceCatalog::CloudFormationProvisionedProduct", //
	"catalog/product":   "AWS::ServiceCatalog::CloudFormationProduct", // arn:aws:catalog:region:account-id:product/id
	"catalog/portfolio": "AWS::ServiceCatalog::Portfolio",             // arn:aws:catalog:region:account-id:portfolio/id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonsqs.html#amazonsqs-resources-for-iam-policies
	"sqs/": "AWS::SQS::Queue", // arn:aws:sqs:region:account-id:name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awskeymanagementservice.html#awskeymanagementservice-resources-for-iam-policies
	"kms/key": "AWS::KMS::Key", // arn:aws:kms:region:account-id:key/id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonqldb.html#amazonqldb-resources-for-iam-policies
	"qldb/ledger": "AWS::QLDB::Ledger", // arn:aws:qldb:region:account-id:ledger/name

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecretsmanager.html#awssecretsmanager-resources-for-iam-policies
	"secretsmanager/secret": "AWS::SecretsManager::Secret", // arn:aws:secretsmanager:region:account-id:secret:id

	// https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonsns.html#amazonsns-resources-for-iam-policies
	"sns/": "AWS::SNS::Topic", // arn:aws:sns:region:account-id:name
}
