package main

import (
	"context"
	"fmt"
)

type Config struct {
	Domain      string
	Keywords    []string // pre-lowercased
	OutputFile  string
	Concurrency int
	Ports       string
	Timeout     int
	Wildcards   bool
	Silent      bool
	JSONOutput  bool
}

func (c *Config) log(format string, args ...any) {
	if !c.Silent {
		fmt.Printf(format, args...)
	}
}

func run(ctx context.Context, cfg *Config) error {
	// Grab target cert org for org-based matching
	cfg.log("[*] Grabbing target cert org... ")
	targetOrg, err := grabCertOrg(cfg.Domain, cfg.Ports)
	if err != nil {
		cfg.log("unavailable — continuing with apex/keyword matching only\n")
	} else {
		cfg.log("\"%s\"\n", targetOrg)
	}

	// Subfinder with IP resolution → truncate to /24
	cfg.log("[*] Running subfinder on %s...\n", cfg.Domain)
	subdomains, cidrs, err := runRecon(ctx, cfg.Domain)
	if err != nil {
		return fmt.Errorf("recon: %w", err)
	}
	if len(cidrs) == 0 {
		return fmt.Errorf("no CIDR ranges found")
	}
	cfg.log("[+] %d subdomains → %d unique /24 ranges (%d IPs)\n", len(subdomains), len(cidrs), len(cidrs)*256)

	// Certificate scanning + filtering
	cfg.log("[*] Scanning certificates across %d ranges...\n", len(cidrs))
	results, err := scanAndFilter(ctx, cidrs, cfg.Domain, targetOrg, cfg.Keywords, cfg.Concurrency, cfg.Ports, cfg.Timeout, cfg.Wildcards, cfg.Silent)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Write output
	if err := writeResults(results, cfg); err != nil {
		return fmt.Errorf("output: %w", err)
	}

	cfg.log("[*] Complete: %d unique relevant domains from %d ranges\n", len(results), len(cidrs))
	cfg.log("[*] Written to %s\n", cfg.OutputFile)
	return nil
}
