# certsweep

IP neighborhood certificate discovery. Takes a domain, finds its subdomains, resolves them to IPs, then scans the /24 neighborhood of each IP for TLS certificates related to the target.

Discovers domains that share IP space with your target — staging servers, internal tools, acquisitions, and infrastructure that doesn't appear in DNS or certificate transparency logs.

## How it works

```
target domain
  → subfinder          find subdomains via passive sources
  → DNS resolution     resolve each subdomain to its IP
  → /24 truncation     compute the /24 block for each unique IP
  → caduceus           TLS cert scan every IP in those /24 blocks
  → relevance filter   keep domains related to the target
  → output             write results to file
```

### Relevance filtering

For each certificate found, certsweep checks three criteria:

1. **Apex match** — any domain in the cert's CN/SAN matches the target domain
2. **Org match** — the cert's Organization field matches the target's cert org (catches subsidiaries using the parent's CA-verified org name)
3. **Keyword match** — any domain contains a user-supplied brand keyword

## Install

```bash
go install github.com/Hxntrarch/certsweep@latest
```

### Dependencies

These must be installed and in your PATH:

- [subfinder](https://github.com/projectdiscovery/subfinder) — `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- [caduceus](https://github.com/g0ldencybersec/Caduceus) — `go install github.com/g0ldencybersec/Caduceus/cmd/caduceus@latest`

### Subfinder API keys

certsweep uses subfinder for subdomain enumeration. Configure API keys in `~/.config/subfinder/provider-config.yaml` for better coverage:

```yaml
shodan:
  - "your-key"
github:
  - "your-token"
virustotal:
  - "your-key"
chaos:
  - "your-key"
securitytrails:
  - "your-key"
```

## Usage

```bash
# Basic scan
certsweep -d target.com

# With brand keywords for subsidiary matching
certsweep -d target.com -k subsidiary,brandname

# JSON output with match reasons
certsweep -d target.com -json

# Multiple domains
certsweep -d target.com,other.com

# Domains from file
certsweep -dL targets.txt

# Full options
certsweep -d target.com -k brand -json -c 500 -p 443,8443 -t 3 -o results.txt
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d` | — | Target domain (required unless `-dL`) |
| `-dL` | — | File with target domains, one per line |
| `-k` | — | Brand keywords, comma-separated |
| `-o` | `{domain}-certsweep.txt` | Output file |
| `-c` | `100` | Scan concurrency |
| `-p` | `443` | TLS ports, comma-separated |
| `-t` | `3` | TLS handshake timeout (seconds) |
| `-wc` | `true` | Include wildcard domains |
| `-json` | `false` | JSON output with match reasons |
| `-silent` | `false` | Suppress progress output |

## Output

**Plain text** (default) — one domain per line:

```
staging.target.com
internal-api.target.com
dev.subsidiary.com
```

**JSON** (`-json`) — includes metadata:

```json
{"domain":"staging.target.com","source_ip":"203.0.113.51:443","org":"Target Corp","match":"apex"}
{"domain":"dev.subsidiary.com","source_ip":"203.0.113.60:443","org":"Target Corp","match":"org"}
```

## When to use

This tool works best against targets with **dedicated infrastructure** — companies that own their IP space, run their own servers, and have services on adjacent IPs. It discovers assets invisible to passive recon.

Less effective against targets fully behind shared CDNs (Cloudflare, Akamai, etc.) where neighboring IPs belong to unrelated customers.

## License

[MIT](LICENSE)
