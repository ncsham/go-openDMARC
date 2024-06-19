// Lookup Forked From https://github.com/emersion/go-msgauth/tree/master/dmarc, With More RFC Oriented.

package lookup

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLookupWithOptions(t *testing.T) {
	testCases := []struct {
		name    string
		domain  string
		want    *Record
		shouldError bool
	}{
		{
			name:   "non-existent dmarc record",
			domain: "ncsham.in",
			want: nil,
			shouldError: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LookupWithOptions(tc.domain, nil)
			if tc.shouldError {
				require.Error(t, err, "expected error for domain %s", tc.domain)
			} else {
				require.NoError(t, err, "unexpected error for domain %s", tc.domain)
				require.Equal(t, tc.want, got, "unexpected record for domain %s", tc.domain)
			}
		})
	}
}
