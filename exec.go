package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// runRecon runs subfinder to get subdomains, then resolves each to IPs
// in parallel and truncates to /24.
func runRecon(ctx context.Context, domain string) (subdomains []string, cidrs []string, err error) {
	cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-silent")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("subfinder: %w", err)
	}

	// Collect unique subdomains
	seenSubs := make(map[string]bool)
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if sub := strings.TrimSpace(sc.Text()); sub != "" && !seenSubs[sub] {
			seenSubs[sub] = true
			subdomains = append(subdomains, sub)
		}
	}

	if len(subdomains) == 0 {
		return nil, nil, nil
	}

	// Resolve all subdomains in parallel, collect unique /24s
	var mu sync.Mutex
	seenCIDRs := make(map[string]bool)
	var wg sync.WaitGroup

	resolver := &net.Resolver{}
	sem := make(chan struct{}, 50) // limit concurrent DNS lookups

	for _, sub := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ips, err := resolver.LookupHost(ctx, host)
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, ip := range ips {
				// IPv4 only
				octets := strings.Split(ip, ".")
				if len(octets) != 4 {
					continue
				}
				cidr := octets[0] + "." + octets[1] + "." + octets[2] + ".0/24"
				if !seenCIDRs[cidr] {
					seenCIDRs[cidr] = true
					cidrs = append(cidrs, cidr)
				}
			}
		}(sub)
	}
	wg.Wait()

	return subdomains, cidrs, nil
}

type CertResult struct {
	OriginIP   string   `json:"originip"`
	Org        []string `json:"org"`
	CommonName string   `json:"commonName"`
	SAN        []string `json:"san"`
	Domains    []string `json:"domains"`
}

func scanAndFilter(ctx context.Context, cidrs []string, apex, targetOrg string, keywords []string, concurrency int, ports string, timeout int, wildcards bool, silent bool) ([]Result, error) {
	// Write CIDRs to temp file to avoid ARG_MAX limits
	tmp, err := os.CreateTemp("", "certsweep-cidrs-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	for _, c := range cidrs {
		fmt.Fprintln(tmp, c)
	}
	tmp.Close()

	args := []string{
		"-i", tmp.Name(),
		"-j",
		"-c", fmt.Sprintf("%d", concurrency),
		"-p", ports,
		"-t", fmt.Sprintf("%d", timeout),
	}
	if wildcards {
		args = append(args, "-wc")
	}
	cmd := exec.CommandContext(ctx, "caduceus", args...)
	if silent {
		cmd.Stderr = nil
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var results []Result
	certCount := 0
	lastLog := 0

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for sc.Scan() {
		var cert CertResult
		if err := json.Unmarshal(sc.Bytes(), &cert); err != nil {
			continue
		}
		certCount++

		if !silent && certCount-lastLog >= 500 {
			fmt.Printf("\r  [+] %d certs scanned, %d relevant domains found...", certCount, len(results))
			lastLog = certCount
		}

		for _, m := range filterCert(cert, apex, targetOrg, keywords) {
			if !seen[m.Domain] {
				seen[m.Domain] = true
				results = append(results, Result{
					Domain:   m.Domain,
					SourceIP: cert.OriginIP,
					Org:      strings.Join(cert.Org, ", "),
					Match:    m.Type,
				})
			}
		}
	}

	if !silent && certCount > 0 {
		fmt.Printf("\r  [+] %d certs scanned, %d relevant domains found   \n", certCount, len(results))
	}

	if err := cmd.Wait(); err != nil && len(results) == 0 {
		return nil, fmt.Errorf("caduceus: %w", err)
	}
	return results, nil
}
