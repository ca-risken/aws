package common

import (
	"testing"

	"github.com/ca-risken/core/proto/finding"
)

func TestSetAWSProvider(t *testing.T) {
	f := &finding.FindingForUpsert{}

	SetAWSProvider(f, "123456789012")

	if f.Provider != ProviderAWS {
		t.Errorf("Provider = %q, want %q", f.Provider, ProviderAWS)
	}
	if f.ProviderTarget != "123456789012" {
		t.Errorf("ProviderTarget = %q, want %q", f.ProviderTarget, "123456789012")
	}
}
