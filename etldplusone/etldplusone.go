package etldplusone

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

const publicSuffixListURL = "https://publicsuffix.org/list/public_suffix_list.dat"

// FetchPublicSuffixList fetches the Public Suffix List from the provided URL.
func FetchPublicSuffixList(url string) ([]string, []string, []string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	var suffixes, wildcards, exceptions []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if len(line) == 0 || strings.HasPrefix(line, "//") {
			continue // Skip comments and empty lines
		}

		if strings.HasPrefix(line, "*.") {
			wildcards = append(wildcards, line[2:]) // Remove "*."
		} else if strings.HasPrefix(line, "!") {
			exceptions = append(exceptions, line[1:]) // Remove "!"
		} else {
			suffixes = append(suffixes, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, nil, err
	}
	return suffixes, wildcards, exceptions, nil
}

// FindETLDPlusOne determines the eTLD+1 for a given domain using the suffix list.
func FindETLDPlusOne(domain string, suffixes, wildcards, exceptions []string) (string, error) {
	domainParts := strings.Split(domain, ".")
	for i := 0; i < len(domainParts); i++ {
		candidate := strings.Join(domainParts[i:], ".")

		// Check exact matches
		for _, suffix := range suffixes {
			if strings.EqualFold(candidate, suffix) {
				if i == 0 {
					return domain, nil
				}
				return strings.Join(domainParts[i-1:], "."), nil
			}
		}

		// Check wildcard matches
		for _, wildcard := range wildcards {
			if strings.HasSuffix(candidate, wildcard) {
				// Check if there is any exception that matches this candidate
				for _, exception := range exceptions {
					if strings.Contains(strings.Join(domainParts[i:], "."), exception) {
						return exception, nil
					}
				}
				if i == 0 {
					return domain, nil
				}
				return strings.Join(domainParts[i-1:], "."), nil
			}
		}

	}
	return "", fmt.Errorf("no eTLD+1 found for domain: %s", domain)
}