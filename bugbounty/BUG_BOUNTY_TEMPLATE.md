# Bug Bounty Hunting Template — Vilona Protocol

> **Version:** 1.0
> **Created:** 2026-05-20
> **Purpose:** Prevent informative/rejected findings, maximize bounty potential

---

## 🎯 PRE-HUNT CHECKLIST

### 1. Platform Rules & Scope
```bash
# ALWAYS check program rules FIRST
- [ ] Read full program description
- [ ] Check scope (in-scope / out-of-scope domains)
- [ ] Check bounty range
- [ ] Check submission limits
- [ ] Check disclosure policy
- [ ] Check safe harbor rules
```

### 2. Duplicate Prevention
```bash
# BEFORE hunting, check existing findings
- [ ] Search disclosed reports on platform
- [ ] Check hacktivity/disclosed vulnerabilities
- [ ] Search CVE databases
- [ ] Check if target has been patched recently
- [ ] Use: curl "https://api.yeswehack.com/programs/{slug}/reports" (if API available)
```

### 3. Reputation Protection
```bash
# Rules to prevent reputation damage
- [ ] NO duplicate submissions
- [ ] NO automated attacks (unless allowed)
- [ ] NO data exfiltration
- [ ] NO accessing other users' data
- [ ] Report immediately if found critical
- [ ] Stop testing if asked by program
```

---

## 🔍 PHASE 1: PASSIVE RECON

### 1.1 Subdomain Enumeration
```bash
# Multiple sources for comprehensive coverage
subfinder -d {domain} -silent | tee subdomains.txt
amass enum -passive -d {domain} | tee -a subdomains.txt
assetfinder --subs-only {domain} | tee -a subdomains.txt

# Remove duplicates
sort -u subdomains.txt > subdomains_unique.txt
```

### 1.2 Live Host Probing
```bash
# Probe for live hosts
cat subdomains_unique.txt | httpx -silent -status-code -title -tech-detect | tee live_hosts.txt

# Filter 200 OK
grep "\[200\]" live_hosts.txt | tee live_200.txt
```

### 1.3 Technology Fingerprinting
```bash
# Identify technology stack
whatweb {target} --color=never 2>/dev/null | tee tech_stack.txt

# Check for specific technologies
curl -s -I https://{target} | grep -iE "server|x-powered-by|x-aspnet|X-Runtime"
```

### 1.4 WAF Detection
```bash
# Detect WAF
wafw00f https://{target} 2>/dev/null | tee waf_detection.txt
```

### 1.5 DNS Records
```bash
# Get all DNS records
dig {domain} ANY +short | tee dns_records.txt
dig {domain} MX +short
dig {domain} TXT +short
dig {domain} NS +short
```

### 1.6 SSL/TLS Analysis
```bash
# Check SSL configuration
sslscan {target} 2>/dev/null | tee ssl_report.txt
```

---

## 🔍 PHASE 2: ACTIVE RECON

### 2.1 Directory Bruteforcing
```bash
# Common directories
ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 50 | tee directories.txt

# API endpoints
ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302,403 -t 50
```

### 2.2 Port Scanning
```bash
# Top 100 ports
nmap -sV -sC -T4 --top-ports 100 {target} | tee nmap_scan.txt

# Full port scan (if allowed)
nmap -sV -sC -T4 -p- {target} | tee nmap_full.txt
```

### 2.3 Vulnerability Scanning
```bash
# Nuclei scan
echo "https://{target}" | nuclei -silent -t /path/to/templates/ | tee nuclei_results.txt

# Specific vulnerability types
echo "https://{target}" | nuclei -silent -t /path/to/templates/http/vulnerabilities/
echo "https://{target}" | nuclei -silent -t /path/to/templates/http/misconfigurations/
```

### 2.4 API Discovery
```bash
# Common API paths
for path in /api /graphql /swagger.json /openapi.json /api-docs /v1 /v2 /v3; do
    result=$(curl -s -o /dev/null -w "%{http_code}" "https://{target}${path}")
    if [ "$result" = "200" ] || [ "$result" = "401" ] || [ "$result" = "403" ]; then
        echo "FOUND: https://{target}${path} → HTTP $result"
    fi
done
```

### 2.5 Configuration File Discovery
```bash
# Common config files
for file in /.env /config.json /settings.json /.git/config /.svn/entries /robots.txt /sitemap.xml /security.txt /.well-known/security.txt; do
    result=$(curl -s -o /dev/null -w "%{http_code}" "https://{target}${file}")
    if [ "$result" = "200" ]; then
        echo "FOUND: https://{target}${file}"
    fi
done
```

---

## 🔍 PHASE 3: DEEP ANALYSIS

### 3.1 Swagger/OpenAPI Analysis
```bash
# Download and analyze swagger
curl -s "https://{target}/swagger.json" > swagger.json

# Extract endpoints
cat swagger.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
paths = data.get('paths', {})
print(f'Total endpoints: {len(paths)}')
for path, methods in paths.items():
    for method in methods.keys():
        if method in ['get', 'post', 'put', 'delete', 'patch']:
            print(f'  {method.upper()} {path}')
"

# Look for sensitive endpoints
cat swagger.json | grep -iE "admin|internal|debug|user|auth|token|password|secret|key"
```

### 3.2 JavaScript Analysis
```bash
# Extract JS files
curl -s "https://{target}" | grep -oE 'src="[^"]*\.js"' | tee js_files.txt

# Analyze JS for secrets
for js in $(cat js_files.txt); do
    curl -s "$js" | grep -iE "api_key|apikey|secret|token|password|aws|firebase|google"
done
```

### 3.3 Error Message Analysis
```bash
# Trigger error messages
for path in /nonexistent /admin /debug /test; do
    curl -s "https://{target}${path}" | grep -iE "error|exception|stack|trace|version"
done
```

### 3.4 CORS Misconfiguration
```bash
# Check CORS
curl -s -I "https://{target}" -H "Origin: https://evil.com" | grep -i "access-control"
```

---

## 📝 PHASE 4: FINDING VALIDATION

### 4.1 Severity Assessment
```bash
# CVSS Calculator
# Use: https://www.first.org/cvss/calculator/3.1

# Severity Matrix:
# P1 (Critical): RCE, Auth Bypass, SQLi, SSRF → $5K-$250K
# P2 (High): XSS Stored, IDOR, CSRF → $1K-$5K
# P3 (Medium): XSS Reflected, Info Disclosure → $500-$1K
# P4 (Low): Missing Headers, Version Leak → $100-$500
# P5 (Info): Best Practices, Minor Issues → $0-$100
```

### 4.2 Duplicate Check
```bash
# Before submitting, check if already reported
# 1. Search platform's disclosed reports
# 2. Check CVE databases
# 3. Search Google: site:bugcrowd.com "{target}" "{vulnerability}"
# 4. Check if endpoint is documented/public
```

### 4.3 Impact Assessment
```bash
# Questions to determine impact:
# 1. Can attacker access other users' data?
# 2. Can attacker modify/delete data?
# 3. Can attacker escalate privileges?
# 4. Can attacker access production systems?
# 5. Can attacker cause financial loss?
```

---

## 📋 PHASE 5: REPORT WRITING

### 5.1 Report Template
```markdown
# Vulnerability: [Clear, Specific Title]

## Program
**Target:** {target}
**URL:** {vulnerable_url}
**Bounty Range:** ${min} - ${max}

## Summary
[1-2 sentence description of the vulnerability]

## Severity
**CVSS v3.1:** {score} ({severity})
**CWE:** CWE-{number} ({name})

## Affected Asset
- {url_1}
- {url_2}

## Steps to Reproduce

### Step 1: [Action]
```bash
curl "https://{target}/{vulnerable_endpoint}"
```

### Step 2: [Action]
[Browser steps or additional commands]

### Step 3: [Observe]
[What the attacker sees]

## Proof of Concept

### Request
```http
GET /vulnerable-endpoint HTTP/1.1
Host: {target}
Authorization: Bearer {token}
```

### Response
```json
{
  "sensitive_data": "..."
}
```

### Screenshot
[Attach screenshot if applicable]

## Impact

### Direct Impact
1. [Impact 1]
2. [Impact 2]

### Attack Chain
```
Step 1 → Step 2 → Step 3 → Final Impact
```

### Business Impact
- [Financial loss]
- [Reputation damage]
- [Regulatory compliance]

## Remediation
1. [Fix 1]
2. [Fix 2]

## References
- [OWASP Link]
- [CWE Link]
- [CVE if applicable]

## Evidence
- [Screenshot 1]
- [Log file 1]
- [PoC script]
```

### 5.2 PoC Best Practices
```bash
# ALWAYS include:
# 1. Clear steps to reproduce
# 2. Actual request/response
# 3. Screenshot/video proof
# 4. Impact explanation
# 5. Remediation suggestions

# NEVER:
# 1. Exfiltrate real data
# 2. Access other users' accounts
# 3. Cause damage
# 4. Publicly disclose before fix
```

---

## 🔧 TOOLS REFERENCE

### Installed Tools
```bash
# Subdomain Enumeration
subfinder, amass, assetfinder

# Live Host Probing
httpx

# Technology Fingerprinting
whatweb

# WAF Detection
wafw00f

# Directory Bruteforcing
ffuf, gobuster

# Port Scanning
nmap

# Vulnerability Scanning
nuclei

# SSL Analysis
sslscan

# DNS Analysis
dig, nslookup

# HTTP Clients
curl, wget, httpx (Python)

# Browser Automation
playwright, puppeteer
```

### Custom Scripts
```bash
# Location: /home/openclaw/.openclaw/workspace/bugbounty/tools/
# - recon.sh (automated recon)
# - poc_generator.sh (PoC template)
# - report_writer.md (report template)
```

---

## ⚠️ RULES & ETHICS

### DO's
- ✅ Always read program rules first
- ✅ Check for duplicates before submitting
- ✅ Stop if asked by program
- ✅ Report immediately if critical
- ✅ Be professional in communications
- ✅ Provide clear remediation

### DON'Ts
- ❌ Never access other users' data
- ❌ Never cause damage
- ❌ Never publicly disclose before fix
- ❌ Never submit duplicates
- ❌ Never use automated attacks (unless allowed)
- ❌ Never exfiltrate data

### Platform-Specific Rules
```bash
# Bugcrowd
- Submission limit: Check before submitting
- MBB programs: Quality matters for reputation
- VDPs: Unlimited submissions

# YesWeHack
- KYC required for bounties
- European focus
- GDPR compliance

# HackerOne
- Private programs: Invite only
- Public programs: Open to all
- Disclosure policy: Check before publishing
```

---

## 📊 WORKFLOW DIAGRAM

```
┌─────────────────┐
│  PRE-HUNT       │
│  - Read rules   │
│  - Check scope  │
│  - Check dupes  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  PASSIVE RECON  │
│  - Subdomains   │
│  - Live hosts   │
│  - Tech stack   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  ACTIVE RECON   │
│  - Directories  │
│  - Ports        │
│  - Vulns        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  DEEP ANALYSIS  │
│  - Swagger      │
│  - JS files     │
│  - Configs      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  VALIDATION     │
│  - Severity     │
│  - Impact       │
│  - Dupes        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  REPORT         │
│  - Template     │
│  - PoC          │
│  - Submit       │
└─────────────────┘
```

---

## 📈 REPUTATION TRACKING

### Metrics to Track
```bash
# Bugcrowd
- Points: 0 → 1000+
- Accuracy: 0% → 100%
- Submissions: 0 → unlimited
- Accepted: 0 → unlimited

# YesWeHack
- Reports: 0 → unlimited
- Accepted: 0 → unlimited
- Bounty: $0 → unlimited

# HackerOne
- Reputation: 0 → 1000+
- Signal: 0 → 100%
- Impact: 0 → 100%
```

### Quality Over Quantity
```bash
# Better to submit:
# 1. 5 high-quality P1-P3 findings
# Than:
# 2. 50 low-quality P5 findings

# Focus on:
# - Critical vulnerabilities
# - Business logic flaws
# - Authentication bypasses
# - Data exposure
```

---

*Template created by Vilona — BerkahKarya AI General Manager*
*Last updated: 2026-05-20 18:27 WIB*
