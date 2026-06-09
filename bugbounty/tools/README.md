# Bug Bounty Tools

## Scripts

### check_duplicates.sh
Check for duplicate findings before submission.

**Usage:**
```bash
./check_duplicates.sh <target> <vulnerability_type>
```

**Example:**
```bash
./check_duplicates.sh mokapos.com "swagger exposure"
./check_duplicates.sh tokopedia.com "internal api"
```

## Installed Tools

### Subdomain Enumeration
- `subfinder` — Fast passive subdomain enumeration
- `amass` — In-depth attack surface mapping
- `assetfinder` — Find domains and subdomains

### Live Host Probing
- `httpx` — Fast HTTP probing

### Technology Fingerprinting
- `whatweb` — Web technology identification

### WAF Detection
- `wafw00f` — Web Application Firewall detection

### Directory Bruteforcing
- `ffuf` — Fast web fuzzer
- `gobuster` — Directory/File bruteforcing

### Port Scanning
- `nmap` — Network exploration tool

### Vulnerability Scanning
- `nuclei` — Fast vulnerability scanner

### SSL Analysis
- `sslscan` — SSL/TLS scanner

### DNS Analysis
- `dig` — DNS lookup utility
- `nslookup` — DNS lookup utility

### HTTP Clients
- `curl` — Command line tool for transferring data
- `wget` — Internet file retriever
- `httpx` (Python) — Async HTTP client

### Browser Automation
- `playwright` — Browser automation library
- `puppeteer` — Node.js browser automation

## Usage Examples

### Full Recon
```bash
# Subdomain enumeration
subfinder -d target.com -silent | tee subdomains.txt

# Live host probing
cat subdomains.txt | httpx -silent -status-code -title | tee live_hosts.txt

# Technology fingerprinting
whatweb https://target.com

# WAF detection
wafw00f https://target.com

# Directory bruteforcing
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403

# Port scanning
nmap -sV -sC -T4 --top-ports 100 target.com

# Vulnerability scanning
echo "https://target.com" | nuclei -silent -t /path/to/templates/
```

### API Discovery
```bash
# Check common API paths
for path in /api /graphql /swagger.json /openapi.json /api-docs; do
    curl -s -o /dev/null -w "%{http_code}" "https://target.com${path}"
done
```

### Config File Discovery
```bash
# Check common config files
for file in /.env /config.json /.git/config /robots.txt; do
    curl -s -o /dev/null -w "%{http_code}" "https://target.com${file}"
done
```

---

*Tools maintained by Vilona*
