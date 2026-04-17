package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
)

func main() {
	domain := flag.String("d", "", "Target domain (required)")
	domainList := flag.String("dL", "", "File containing target domains (one per line)")
	keywords := flag.String("k", "", "Extra brand keywords, comma-separated")
	output := flag.String("o", "", "Output file path (default: {domain}-certsweep.txt)")
	concurrency := flag.Int("c", 100, "Caduceus scan concurrency")
	ports := flag.String("p", "443", "TLS ports to scan, comma-separated")
	timeout := flag.Int("t", 3, "TLS handshake timeout in seconds")
	wildcards := flag.Bool("wc", true, "Include wildcard domains in results")
	silent := flag.Bool("silent", false, "Suppress progress output")
	jsonOut := flag.Bool("json", false, "Output results as JSON")
	flag.Parse()

	if *domain == "" && *domainList == "" {
		fmt.Fprintln(os.Stderr, "certsweep: -d <domain> or -dL <file> is required")
		flag.Usage()
		os.Exit(1)
	}

	for _, tool := range []string{"subfinder", "caduceus"} {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Fprintf(os.Stderr, "certsweep: %s not found in PATH\n", tool)
			os.Exit(1)
		}
	}

	// Normalize keywords once — all lowercase, trimmed
	var kw []string
	for _, k := range splitCSV(*keywords) {
		kw = append(kw, strings.ToLower(k))
	}

	// Build domain list from -dL file and/or -d flag
	var domains []string
	if *domainList != "" {
		data, err := os.ReadFile(*domainList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "certsweep: %v\n", err)
			os.Exit(1)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				domains = append(domains, line)
			}
		}
	}
	domains = append(domains, splitCSV(*domain)...)

	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "certsweep: no valid domains provided")
		os.Exit(1)
	}

	// Cancel child processes on ctrl+c
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for i, d := range domains {
		outFile := *output
		if outFile == "" {
			outFile = d + "-certsweep.txt"
		}

		cfg := &Config{
			Domain:      d,
			Keywords:    kw,
			OutputFile:  outFile,
			Concurrency: *concurrency,
			Ports:       *ports,
			Timeout:     *timeout,
			Wildcards:   *wildcards,
			Silent:      *silent,
			JSONOutput:  *jsonOut,
		}

		if err := run(ctx, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "certsweep: %s: %v\n", d, err)
		}
		if i < len(domains)-1 {
			fmt.Println()
		}
	}
}

// splitCSV splits a comma-separated string, trims whitespace, drops empties.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
