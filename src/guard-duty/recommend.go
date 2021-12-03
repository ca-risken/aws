package main

import "fmt"

type recommend struct {
	Risk           string `json:"risk,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

func getRecommend(findingType string) *recommend {
	return &recommend{
		Risk: fmt.Sprintf(`%s
- The risk & recommend informations for Amazon GuardDuty is maintained in the AWS documentation.
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html`, findingType),
		Recommendation: fmt.Sprintf(`Please go to the following page, and search by '%s' keyword.
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html`, findingType),
	}
}
