package main

import (
	"strings"
	"testing"
)

func TestGetScore(t *testing.T) {
	cases := []struct {
		name     string
		status   string
		category string
		plugin   string
		want     float32
	}{
		{
			name:     "OK",
			status:   "OK",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     0.0,
		}, {
			name:     "WARN",
			status:   "WARN",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     3.0,
		},
		{
			name:     "UNKNOWN",
			status:   "UNKNOWN",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     1.0,
		},
		{
			name:     "Fail match Map",
			status:   "FAIL",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     6.0,
		},
		{
			name:     "Fail not match Map",
			status:   "FAIL",
			category: "ACM",
			plugin:   "hogehogehogehoge",
			want:     3.0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getScore(c.status, c.category, c.plugin)
			if c.want != got {
				t.Fatalf("Unexpected category name: want=%v, got=%v", c.want, got)
			}
		})
	}
}

func TestGetComplianceTag(t *testing.T) {
	cases := []struct {
		name     string
		category string
		plugin   string
		want     []string
	}{
		{
			name:     "match Map Exist Tag",
			category: "ACM",
			plugin:   "acmCertificateExpiry",
			want:     []string{"pci"},
		}, {
			name:     "match Map Not Exist Tag",
			category: "RDS",
			plugin:   "sqlServerTLSVersion",
			want:     []string{},
		},
		{
			name:     "not match Map",
			category: "ACM",
			plugin:   "hogehogehoge",
			want:     []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := getComplianceTags(c.category, c.plugin)
			if strings.Join(c.want, ",") != strings.Join(got, ",") {
				t.Fatalf("Unexpected category name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
