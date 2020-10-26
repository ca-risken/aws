package main

import (
	"testing"
)

func TestScoreAdminUser(t *testing.T) {
	cases := []struct {
		name  string
		input *iamUser
		want  float32
	}{
		{
			name: "Not admin user",
			input: &iamUser{
				UserName:     "alice",
				IsUserAdmin:  false,
				IsGroupAdmin: false,
			},
			want: 0.3,
		}, {
			name: "User admin",
			input: &iamUser{
				UserName:     "alice",
				IsUserAdmin:  true,
				IsGroupAdmin: false,
			},
			want: 0.9,
		},
		{
			name: "Group admin",
			input: &iamUser{
				UserName:     "alice",
				IsUserAdmin:  false,
				IsGroupAdmin: true,
			},
			want: 0.9,
		},
		{
			name: "Admin user, but enabled PermissionBoundory",
			input: &iamUser{
				UserName:                  "alice",
				IsUserAdmin:               true,
				IsGroupAdmin:              true,
				EnabledPermissionBoundory: true,
			},
			want: 0.7,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAdminUser(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
