package main

import "strings"

const (
	categoryNmap              = "Nmap"
	categoryManyOpen          = "ManyOpen"
	typeSecurityGroup         = "SecurityGroup"
	typeLightSail             = "LightSail"
	typeManyOpenSecurityGroup = "SecurityGroupPortManyOpen"
	typeManyOpenLightSail     = "LightSailPortManyOpen"
	urlReferenceEC2           = "http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html"
	urlReferenceELB           = "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html"
	urlReferenceRDS           = "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"
	urlReferenceLightSail     = "https://lightsail.aws.amazon.com/ls/docs/en_us/articles/amazon-lightsail-editing-firewall-rules"
	urlReferenceDefault       = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html"
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommendType(category, service string) string {
	switch category {
	case categoryNmap:
		switch service {
		case "lightsail":
			return typeLightSail
		default:
			return typeSecurityGroup
		}
	case categoryManyOpen:
		switch service {
		case "lightsail":
			return typeManyOpenLightSail
		default:
			return typeManyOpenSecurityGroup
		}
	default:
		return ""
	}
}

func getRecommend(recommendType, service string) recommend {
	r := recommendMap[recommendType]
	r.Recommendation = strings.Replace(r.Recommendation, "{{url}}", getReferenceURL(service), 1)
	return r
}

func getReferenceURL(service string) string {
	switch service {
	case "ec2":
		return urlReferenceEC2
	case "elasticloadbalancing":
		return urlReferenceELB
	case "rds":
		return urlReferenceRDS
	case "lightsail":
		return urlReferenceLightSail
	}
	return urlReferenceDefault
}

var recommendMap = map[string]recommend{
	typeSecurityGroup: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports  are required to be open to the public to function properly, Restrict to known IP addresses if not necessary.`,
		Recommendation: `Restrict target TCP and UDP port to known IP addresses.
			- {{url}}`,
	},
	typeLightSail: {
		Risk: `Port opens to pubilc
		- Determine if target TCP or UDP port is open to the public
		- While some ports  are required to be open to the public to function properly, Restrict to known IP addresses if not necessary.`,
		Recommendation: `Restrict target TCP and UDP port to known IP addresses.
		- {{url}}`,
	},
	typeManyOpenSecurityGroup: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to known IP addresses if not necessary.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to known IP addresses.
		- {{url}}`,
	},
	typeManyOpenLightSail: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to known IP addresses if not necessary.`,
		Recommendation: `Enable encryption at rest for all Athena workgroups.
		- {{url}}`,
	},
}
