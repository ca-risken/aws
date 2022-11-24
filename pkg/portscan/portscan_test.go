package portscan

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
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
				LoadBalancers: []elbv2types.LoadBalancer{
					{
						LoadBalancerArn: aws.String("arn"),
						DNSName:         aws.String("dns"),
						SecurityGroups:  []string{"sg-1", "sg-2"},
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
				LoadBalancers: []elbv2types.LoadBalancer{
					{
						LoadBalancerArn: nil,
						DNSName:         nil,
						SecurityGroups:  []string{"sg-1", "sg-2"},
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
				LoadBalancers: []elbv2types.LoadBalancer{
					{
						LoadBalancerArn: aws.String("arn"),
						DNSName:         nil,
						SecurityGroups:  []string{"sg-1", "sg-2"},
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

func TestExcludeScan(t *testing.T) {
	cases := []struct {
		name                  string
		scanExcludePortNumber int
		targets               []*target
		wantTarget            []*target
		wantExclude           []*excludeResult
	}{
		{
			name:                  "OK All Excluded",
			scanExcludePortNumber: -1,
			targets:               []*target{{Arn: "a1", Target: "t1", Protocol: "tcp", ToPort: 80, FromPort: 80, Category: "ec2", SecurityGroup: "sg1"}},
			wantTarget:            []*target{},
			wantExclude:           []*excludeResult{{Protocol: "tcp", FromPort: 80, ToPort: 80, Target: "t1", Arn: "a1", SecurityGroup: "sg1", Category: "ec2"}},
		},
		{
			name:                  "OK All Included",
			scanExcludePortNumber: 0,
			targets:               []*target{{Arn: "t1", Target: "t1", ToPort: 80, FromPort: 80, Category: "ec2", SecurityGroup: "t1"}},
			wantTarget:            []*target{{Arn: "t1", Target: "t1", ToPort: 80, FromPort: 80, Category: "ec2", SecurityGroup: "t1"}},
			wantExclude:           []*excludeResult{},
		},
		{
			name:                  "OK one Excluded",
			scanExcludePortNumber: 0,
			targets: []*target{{Arn: "a1", Target: "t1", Protocol: "tcp", ToPort: 80, FromPort: 80, Category: "ec2", SecurityGroup: "sg1"},
				{Arn: "a2", Target: "t2", Protocol: "tcp", ToPort: 81, FromPort: 80, Category: "ec2", SecurityGroup: "sg2"}},
			wantTarget:  []*target{{Arn: "t1", Target: "t1", ToPort: 80, FromPort: 80, Category: "ec2", SecurityGroup: "t1"}},
			wantExclude: []*excludeResult{{Protocol: "tcp", FromPort: 80, ToPort: 81, Target: "t2", Arn: "a2", SecurityGroup: "sg2", Category: "ec2"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotTarget, gotExclude := excludeScan(c.scanExcludePortNumber, c.targets)
			if len(c.wantTarget) != len(gotTarget) {
				t.Fatalf("Unexpected target: want=%+v, got=%+v", c.wantTarget, gotTarget)
			}
			if len(c.wantExclude) != len(gotExclude) {
				t.Fatalf("Unexpected exclude: want=%+v, got=%+v", c.wantExclude, gotExclude)
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
