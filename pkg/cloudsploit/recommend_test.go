package cloudsploit

import (
	"reflect"
	"testing"
)

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input [2]string
		want  recommend
	}{
		{
			name:  "Exists plugin",
			input: [2]string{"ACM", "acmCertificateExpiry"},
			want: recommend{
				Risk: `ACM Certificate Expiry
		- Detect upcoming expiration of ACM certificates
		- Certificates that have expired will trigger warnings in all major browsers. AWS will attempt to automatically renew the certificate but may be unable to do so if email or DNS validation cannot be confirmed.`,
				Recommendation: `Ensure AWS is able to renew the certificate via email or DNS validation of the domain.
		- https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html`,
			},
		},
		{
			name:  "Unknown plugin",
			input: [2]string{"unknown", "unknown"},
			want: recommend{
				Risk:           "",
				Recommendation: "",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommend(c.input[0], c.input[1])
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}
