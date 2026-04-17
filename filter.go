package main

import (
	"strings"
)

type Match struct {
	Domain string
	Type   string // "apex", "org", "keyword"
}

// filterCert returns the relevant domains from a cert result.
// Each domain is checked individually — a cert with both tesla.com and
// cloudflare.com in its SANs only keeps tesla.com.
// Keywords must already be lowercased.
func filterCert(cert CertResult, apex string, targetOrg string, keywords []string) []Match {
	apexLower := strings.ToLower(apex)
	isOrgMatch := targetOrg != "" && orgMatches(cert.Org, targetOrg)

	var matches []Match
	for _, domain := range cert.Domains {
		d := strings.ToLower(strings.TrimSpace(domain))
		if d == "" {
			continue
		}

		switch {
		case d == apexLower || strings.HasSuffix(d, "."+apexLower):
			matches = append(matches, Match{d, "apex"})
		case keywordMatch(d, keywords):
			matches = append(matches, Match{d, "keyword"})
		case isOrgMatch:
			matches = append(matches, Match{d, "org"})
		}
	}
	return matches
}

func keywordMatch(domain string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(domain, kw) {
			return true
		}
	}
	return false
}

func orgMatches(certOrgs []string, targetOrg string) bool {
	for _, org := range certOrgs {
		if strings.EqualFold(org, targetOrg) {
			return true
		}
	}
	return false
}
