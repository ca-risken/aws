package common

import (
	"testing"
)

func TestIsMatchAccountIDArn(t *testing.T) {
	cases := []struct {
		name      string
		arn       string
		accountID string
		want      bool
	}{
		{
			name:      "OK Match AccountID ARN",
			arn:       "arn:aws:iam::111111111111:role/mimosa",
			accountID: "111111111111",
			want:      true,
		},
		{
			name:      "NG Doesn't match AccountID ARN",
			arn:       "arn:aws:iam::111111111111:role/mimosa",
			accountID: "123456789012",
			want:      false,
		},
		{
			name:      "NG name likes accountID",
			arn:       "arn:aws:iam::111111111111:role/123456789012",
			accountID: "123456789012",
			want:      false,
		},
		{
			name:      "NG invalid arn",
			arn:       "arn:aws:iam111111111111:role/mimosa",
			accountID: "111111111111",
			want:      false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsMatchAccountIDArn(c.accountID, c.arn)
			if c.want != got {
				t.Fatalf("Unexpected resource name: want=%v, got=%v", c.want, got)
			}
		})
	}
}
