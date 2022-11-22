package portscan

const (
	categoryNmap                 = "Nmap"
	categoryManyOpen             = "ManyOpen"
	typeSecurityGroup            = "SecurityGroup"
	typeSecurityGroupEC2         = "SecurityGroup/EC2"
	typeSecurityGroupELB         = "SecurityGroup/ELB"
	typeSecurityGroupRDS         = "SecurityGroup/RDS"
	typeLightSail                = "LightSail"
	typeManyOpenSecurityGroup    = "SecurityGroupPortManyOpen"
	typeManyOpenSecurityGroupEC2 = "SecurityGroupPortManyOpen/EC2"
	typeManyOpenSecurityGroupELB = "SecurityGroupPortManyOpen/ELB"
	typeManyOpenSecurityGroupRDS = "SecurityGroupPortManyOpen/RDS"
	typeManyOpenLightSail        = "LightSailPortManyOpen"
)

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommendType(category, service string) string {
	switch category {
	case categoryNmap:
		switch service {
		case "ec2":
			return typeSecurityGroupEC2
		case "elasticloadbalancing":
			return typeSecurityGroupELB
		case "rds":
			return typeSecurityGroupRDS
		case "lightsail":
			return typeLightSail
		default:
			return typeSecurityGroup
		}
	case categoryManyOpen:
		switch service {
		case "ec2":
			return typeManyOpenSecurityGroupEC2
		case "elasticloadbalancing":
			return typeManyOpenSecurityGroupELB
		case "rds":
			return typeManyOpenSecurityGroupRDS
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
	return recommendMap[recommendType]
}

var recommendMap = map[string]recommend{
	typeSecurityGroupEC2: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	typeSecurityGroupELB: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html`,
	},
	typeSecurityGroupRDS: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html`,
	},
	typeLightSail: {
		Risk: `Port opens to pubilc
		- Determine if target TCP or UDP port is open to the public
		- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
		- https://lightsail.aws.amazon.com/ls/docs/en_us/articles/amazon-lightsail-editing-firewall-rules`,
	},
	typeSecurityGroup: {
		Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
		Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html`,
	},
	typeManyOpenSecurityGroupEC2: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to trusted IP addresses.
		- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
	},
	typeManyOpenSecurityGroupELB: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to trusted IP addresses.
		- https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-update-security-groups.html`,
	},
	typeManyOpenSecurityGroupRDS: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to trusted IP addresses.
		- https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html`,
	},
	typeManyOpenLightSail: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Enable encryption at rest for all Athena workgroups.
		- https://lightsail.aws.amazon.com/ls/docs/en_us/articles/amazon-lightsail-editing-firewall-rules`,
	},
	typeManyOpenSecurityGroup: {
		Risk: `Open Many Ports
		- Determine if security group has many ports open to the public
		- Security groups should be created on a per-service basis and restrict to trusted IP addresses.`,
		Recommendation: `Modify the security group to specify a specific port and and restrict to trusted IP addresses.
		- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html`,
	},
}
