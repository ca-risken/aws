package adminchecker

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
	typeAdmin: {
		Risk: `IAM user has 'Administrator' role (or administrator equivalent role)
		- Due to the risk of access keys and secrets being leaked, IAM users should follow the principle of least privilege.
		- https://en.wikipedia.org/wiki/Principle_of_least_privilege`,
		Recommendation: `Should consider whether 'IAM Role' can be a workaround
		- Or Update permissions to the minimum required.
		- Or Restricted to requests from trusted entities.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html`,
	},
	typeAccessReport: {
		Risk: `IAM Access Report
		- Access reports allows you to see which IAM resources(User/Role) have been granted too many privileges.`,
		Recommendation: `Remove unused resources, or update permissions to the minimum required.
		- You can get the IAM last activities
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_access-advisor-view-data.html
		- You can get a detailed report to see which services are not being used by IAM resources.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
		- Update the IAM resource when you are sure it is safe to do so 
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html`,
	},
}
