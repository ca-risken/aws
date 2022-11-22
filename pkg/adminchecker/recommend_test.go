package adminchecker

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
			name:  "Exists",
			input: "admin",
			want: &recommend{
				Risk: `IAM user has 'Administrator' role (or administrator equivalent role)
		- Due to the risk of access keys and secrets being leaked, IAM users should follow the principle of least privilege.
		- https://en.wikipedia.org/wiki/Principle_of_least_privilege`,
				Recommendation: `Should consider whether 'IAM Role' can be a workaround
		- Or Update permissions to the minimum required.
		- Or Restricted to requests from trusted entities.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html`,
			},
		},
		{
			name:  "Uppercase",
			input: "ADMIN",
			want: &recommend{
				Risk: `IAM user has 'Administrator' role (or administrator equivalent role)
		- Due to the risk of access keys and secrets being leaked, IAM users should follow the principle of least privilege.
		- https://en.wikipedia.org/wiki/Principle_of_least_privilege`,
				Recommendation: `Should consider whether 'IAM Role' can be a workaround
		- Or Update permissions to the minimum required.
		- Or Restricted to requests from trusted entities.
		- https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html`,
			},
		},
		{
			name:  "Unknown",
			input: "unknown",
			want: &recommend{
				Risk:           "",
				Recommendation: "",
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
