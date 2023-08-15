package adminchecker

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
			name: "Admin user, but enabled PermissionBoundary",
			input: &iamUser{
				UserName:                  "alice",
				IsUserAdmin:               true,
				IsGroupAdmin:              true,
				EnabledPermissionBoundary: true,
			},
			want: 0.7,
		},
		{
			name: "Admin user, but enabled Physical MFA",
			input: &iamUser{
				UserName:           "Physical MFA",
				IsUserAdmin:        true,
				EnabledPhysicalMFA: true,
			},
			want: 0.5,
		},
		{
			name: "Admin user, but enabled Virtual MFA",
			input: &iamUser{
				UserName:          "Virtual MFA",
				IsUserAdmin:       true,
				EnabledVirtualMFA: true,
			},
			want: 0.5,
		},
		{
			name: "enabled MFA but access key is activated",
			input: &iamUser{
				UserName:          "Virtual MFA",
				IsUserAdmin:       true,
				EnabledVirtualMFA: true,
				ActiveAccessKeyID: []string{"key-id"},
			},
			want: 0.9,
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

func TestScoreAccessReport(t *testing.T) {
	cases := []struct {
		name  string
		input *serviceAccessedReport
		want  float32
	}{
		{
			name: "Too many policies",
			input: &serviceAccessedReport{
				AccessRate: 0.1,
			},
			want: 0.6,
		},
		{
			name: "Many many policies",
			input: &serviceAccessedReport{
				AccessRate: 0.3,
			},
			want: 0.5,
		},
		{
			name: "Many policies",
			input: &serviceAccessedReport{
				AccessRate: 0.5,
			},
			want: 0.4,
		},
		{
			name: "Many policies",
			input: &serviceAccessedReport{
				AccessRate: 0.7,
			},
			want: 0.3,
		},
		{
			name: "Many policies",
			input: &serviceAccessedReport{
				AccessRate: 1.0,
			},
			want: 0.1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scoreAccessReport(c.input)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
