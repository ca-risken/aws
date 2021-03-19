package main

import (
	"testing"
)

func TestGetScore(t *testing.T) {
	cases := []struct {
		name   string
		result *nmapResult
		want   float32
	}{
		{
			name: "tcp critical port",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     3306,
				Status:   "open",
			},
			want: 8.0,
		},
		{
			name: "tcp http/https port not 401,403",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     443,
				Status:   "open",
				ScanDetail: map[string]interface{}{
					"status": "200 OK",
				},
			},
			want: 6.0,
		},
		{
			name: "tcp http/https port 401,403",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     443,
				Status:   "open",
				ScanDetail: map[string]interface{}{
					"status": "401 Unauthorized",
				},
			},
			want: 1.0,
		},
		{
			name: "tcp unknown port",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     38080,
				Status:   "open",
			},
			want: 6.0,
		},
		{
			name: "tcp closed critical port",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     3306,
				Status:   "closed",
			},
			want: 1.0,
		},
		{
			name: "tcp filtered critical port",
			result: &nmapResult{
				Protocol: "tcp",
				Port:     5432,
				Status:   "filtered",
			},
			want: 1.0,
		},
		{
			name: "udp open port",
			result: &nmapResult{
				Protocol: "udp",
				Port:     80,
				Status:   "open",
			},
			want: 6.0,
		},
		{
			name: "udp open/filtered critical port",
			result: &nmapResult{
				Protocol: "udp",
				Status:   "open/filtered",
				Port:     53,
			},
			want: 6.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getScore(c.result)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
