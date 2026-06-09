# Bug Bounty Quick Checklist

> Print this before every hunt

---

## PRE-HUNT (5 min)
- [ ] Read program rules
- [ ] Check scope (in-scope/out-scope)
- [ ] Check bounty range
- [ ] Check submission limits
- [ ] Search for duplicates (disclosed reports)
- [ ] Check if target is documented/public

## RECON (30 min)
- [ ] Subdomain enumeration (subfinder, amass)
- [ ] Live host probing (httpx)
- [ ] Technology fingerprinting (whatweb)
- [ ] WAF detection (wafw00f)
- [ ] DNS records (dig)
- [ ] SSL/TLS analysis (sslscan)

## ACTIVE RECON (30 min)
- [ ] Directory bruteforcing (ffuf, gobuster)
- [ ] Port scanning (nmap)
- [ ] Vulnerability scanning (nuclei)
- [ ] API discovery (/api, /graphql, /swagger)
- [ ] Config file discovery (/.env, /config.json)

## DEEP ANALYSIS (30 min)
- [ ] Swagger/OpenAPI analysis
- [ ] JavaScript analysis
- [ ] Error message analysis
- [ ] CORS check
- [ ] Security headers check

## VALIDATION (15 min)
- [ ] CVSS score calculated
- [ ] Impact assessment
- [ ] Duplicate check (again)
- [ ] Severity justified

## REPORT (30 min)
- [ ] Clear title
- [ ] Steps to reproduce
- [ ] PoC (request/response)
- [ ] Screenshot/video
- [ ] Impact explanation
- [ ] Remediation suggestions

## SUBMIT (5 min)
- [ ] Double-check for duplicates
- [ ] Verify scope compliance
- [ ] Submit with proper severity
- [ ] Track submission

---

## RED FLAGS — DON'T SUBMIT IF:
- ❌ Finding is documented/public
- ❌ Endpoint is in official docs
- ❌ Already disclosed by others
- ❌ Out of scope
- ❌ Automated attack (unless allowed)
- ❌ Accessing other users' data

## GREEN LIGHT — SUBMIT IF:
- ✅ Internal endpoint exposed
- ✅ Credentials/keys leaked
- ✅ Authentication bypass
- ✅ Data exposure
- ✅ Business logic flaw
- ✅ Impact is clear and demonstrable

---

*Quick reference — keep this on your desk*
