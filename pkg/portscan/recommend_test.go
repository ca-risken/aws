package portscan

import (
	"reflect"
	"testing"
)

func TestGetRecommendType(t *testing.T) {
	cases := []struct {
		name  string
		input [2]string
		want  string
	}{
		{
			name:  "Exists category type Nmap",
			input: [2]string{"Nmap", "ec2"},
			want:  "SecurityGroup/EC2",
		},
		{
			name:  "Exists category type ManyOpen",
			input: [2]string{"ManyOpen", "lightsail"},
			want:  "LightSailPortManyOpen",
		},
		{
			name:  "Unknown category type",
			input: [2]string{"hogefuga", ""},
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getRecommendType(c.input[0], c.input[1])
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetRecommend(t *testing.T) {
	cases := []struct {
		name  string
		input [2]string
		want  recommend
	}{
		{
			name:  "Exists recommend",
			input: [2]string{"SecurityGroup/EC2", "ec2"},
			want: recommend{
				Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports are required to be open to the public to function properly, Restrict to trusted IP addresses.`,
				Recommendation: `Restrict target TCP and UDP port to trusted IP addresses.
			- http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html`,
			},
		},
		{
			name:  "Unknown recommend",
			input: [2]string{"typeUnknown", "unknown"},
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
