package common

import "github.com/ca-risken/core/proto/finding"

const ProviderAWS = "aws"

func SetAWSProvider(f *finding.FindingForUpsert, accountID string) {
	f.Provider = ProviderAWS
	f.ProviderTarget = accountID
}
