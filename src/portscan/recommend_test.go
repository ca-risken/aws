package main

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
			want:  "SecurityGroup",
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

func TestGetReferenceURL(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Exists service type",
			input: "ec2",
			want:  "http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html",
		},
		{
			name:  "Unknown service type",
			input: "hogefuga",
			want:  "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getReferenceURL(c.input)
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
			input: [2]string{"SecurityGroup", "ec2"},
			want: recommend{
				Risk: `Port opens to pubilc
			- Determine if target TCP or UDP port is open to the public
			- While some ports  are required to be open to the public to function properly, Restrict to known IP addresses if not necessary.`,
				Recommendation: `Restrict target TCP and UDP port to known IP addresses.
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
