package main

import (
	"testing"
)

func TestGetScore(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		protocol string
		port     int
		want     float32
	}{
		{
			name:     "tcp critical port",
			state:    "open",
			protocol: "tcp",
			port:     3306,
			want:     8.0,
		},
		{
			name:     "tcp http/https port",
			state:    "open",
			protocol: "tcp",
			port:     443,
			want:     1.0,
		},
		{
			name:     "tcp unknown port",
			state:    "open",
			protocol: "tcp",
			port:     38080,
			want:     3.0,
		},
		{
			name:     "tcp closed critical port",
			state:    "closed",
			protocol: "tcp",
			port:     3306,
			want:     1.0,
		},
		{
			name:     "tcp filtered critical port",
			state:    "filtered",
			protocol: "tcp",
			port:     5432,
			want:     1.0,
		},
		{
			name:     "udp open port",
			state:    "open",
			protocol: "udp",
			port:     80,
			want:     3.0,
		},
		{
			name:     "udp open/filtered critical port",
			state:    "open/filtered",
			protocol: "udp",
			port:     53,
			want:     1.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getScore(c.state, c.protocol, c.port)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
