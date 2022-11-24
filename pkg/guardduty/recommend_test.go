package guardduty

import (
	"reflect"
	"testing"
)

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  *recommend
	}{
		{
			name:  "OK",
			input: "Backdoor:EC2/C&CActivity.B",
			want: &recommend{
				Risk: `Backdoor:EC2/C&CActivity.B
- The risk & recommend informations for Amazon GuardDuty is maintained in the AWS documentation.
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html`,
				Recommendation: `Please go to the following page, and search by 'Backdoor:EC2/C&CActivity.B' keyword.
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html`,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
