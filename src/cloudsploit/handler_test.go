package main

import (
	"testing"
)

func TestGetScore(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		resource string
		want     float32
	}{
		{
			name:     "OK",
			status:   "OK",
			resource: "hoge",
			want:     0.0,
		}, {
			name:     "Fail Unknwon",
			status:   "Fail",
			resource: "Unknown",
			want:     1.0,
		},
		{
			name:     "Fail N/A",
			status:   "Fail",
			resource: "N/A",
			want:     1.0,
		},
		{
			name:     "Fail Other",
			status:   "Fail",
			resource: "other resource",
			want:     3.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getScore(c.status, c.resource)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
