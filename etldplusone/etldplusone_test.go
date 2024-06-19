package etldplusone

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// TestFindETLDPlusOne tests the FindETLDPlusOne function with various cases.
func TestFindETLDPlusOne(t *testing.T) {
	suffixes, wildcards, exceptions, err := FetchPublicSuffixList(publicSuffixListURL)
	require.NoError(t, err, "Error fetching public suffix list")

	testCases := []struct {
		domain       string
		expectedETLD string
		shouldError  bool
	}{
		{"a.nom.ad", "a.nom.ad", false},
		{"a.gov.uk", "a.gov.uk", false},
		{"a.b.gov.uk", "b.gov.uk", false},
		{"sa.gov.au", "sa.gov.au", false},
		{"gov.in", "gov.in", false},
		{"app.stupid.email", "stupid.email", false},
		{"stupid.email", "stupid.email", false},
		{"a.b.c.stupid.email", "stupid.email", false},
		{"a.stupid.email", "stupid.email", false},
		{"a.v.gov.in", "v.gov.in", false},
		{"OUTLOOK.COM.BR", "OUTLOOK.COM.BR", false},
		{"App.stupid.Email", "stupid.Email", false},
		{"a.hi.yokohama.jp", "a.hi.yokohama.jp", false},
		{"a.city.yokohama.jp", "city.yokohama.jp", false},
		{"a.com.pg", "a.com.pg", false},
		{"a.com.kh", "a.com.kh", false},
	}

	for _, tc := range testCases {
		t.Run(tc.domain, func(t *testing.T) {
			eTLDPlusOne, err := FindETLDPlusOne(tc.domain, suffixes, wildcards, exceptions)
			if tc.shouldError {
				require.Error(t, err, "expected error for domain %s", tc.domain)
			} else {
				require.NoError(t, err, "unexpected error for domain %s", tc.domain)
				require.Equal(t, tc.expectedETLD, eTLDPlusOne, "unexpected eTLD+1 for domain %s", tc.domain)
			}
		})
	}
}

// BenchmarkFindETLDPlusOne benchmarks the FindETLDPlusOne function.
func BenchmarkFindETLDPlusOne(b *testing.B) {
	suffixes, wildcards, exceptions, err := FetchPublicSuffixList(publicSuffixListURL)
	require.NoError(b, err, "Error fetching public suffix list")

	domain := "a.com.kh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := FindETLDPlusOne(domain, suffixes, wildcards, exceptions)
		require.NoError(b, err, "unexpected error for domain %s", domain)
	}
}
