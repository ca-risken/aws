package main

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/elbv2"
)

func TestSetELBv2(t *testing.T) {
	cases := []struct {
		name  string
		input *elbv2.DescribeLoadBalancersOutput
		want  []*target
	}{
		{
			name: "OK",
			input: &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []*elbv2.LoadBalancer{
					{
						LoadBalancerArn: aws.String("arn"),
						DNSName:         aws.String("dns"),
						SecurityGroups:  []*string{aws.String("sg-1"), aws.String("sg-2")},
					},
				},
			},
			want: []*target{
				{
					Arn:           "arn",
					Target:        "dns",
					FromPort:      80,
					ToPort:        80,
					Protocol:      "http",
					SecurityGroup: "sg-1",
					Category:      "elbv2",
				},
			},
		},
		{
			name:  "Nil",
			input: nil,
			want:  nil,
		},
		{
			name: "No Arn & DNS",
			input: &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []*elbv2.LoadBalancer{
					{
						LoadBalancerArn: nil,
						DNSName:         nil,
						SecurityGroups:  []*string{aws.String("sg-1"), aws.String("sg-2")},
					},
				},
			},
			want: []*target{
				{
					Arn:           "",
					Target:        "",
					FromPort:      80,
					ToPort:        80,
					Protocol:      "http",
					SecurityGroup: "sg-1",
					Category:      "elbv2",
				},
			},
		},
		{
			name: "No DNSName",
			input: &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []*elbv2.LoadBalancer{
					{
						LoadBalancerArn: aws.String("arn"),
						DNSName:         nil,
						SecurityGroups:  []*string{aws.String("sg-1"), aws.String("sg-2")},
					},
				},
			},
			want: []*target{
				{
					Arn:           "arn",
					Target:        "",
					FromPort:      80,
					ToPort:        80,
					Protocol:      "http",
					SecurityGroup: "sg-1",
					Category:      "elbv2",
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// init
			p := portscanClient{
				SecurityGroups: []*targetSG{
					{
						fromPort:  80,
						toPort:    80,
						protocol:  "http",
						groupID:   "sg-1",
						groupName: "gName",
					},
				},
			}
			p.setELBv2(c.input)
			for i, target := range p.target {
				t.Logf("%d: %+v", i, target)
			}
			if !reflect.DeepEqual(c.want, p.target) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, p.target)
			}
		})
	}
}

func TestConvertNilString(t *testing.T) {
	cases := []struct {
		name  string
		input *string
		want  string
	}{
		{
			name:  "OK",
			input: aws.String("test"),
			want:  "test",
		},
		{
			name:  "Nil",
			input: nil,
			want:  "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := convertNilString(c.input)
			if !reflect.DeepEqual(c.want, got) {
				t.Fatalf("Unexpected data: want=%+v, got=%+v", c.want, got)
			}
		})
	}
}
