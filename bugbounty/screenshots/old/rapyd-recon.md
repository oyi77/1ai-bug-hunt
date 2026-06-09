# Rapyd Bug Bounty Recon Report
**Date:** 2026-05-20
**Program:** https://bugcrowd.com/engagements/rapyd
**Bounty:** $100 - $7,500
**Scope:** api.rapyd.net, dashboard.rapyd.net

---

## Finding #1: Configuration File Exposure (Information Disclosure)
**Severity:** Medium
**URL:** https://dashboard.rapyd.net/config.json

### Description
The Rapyd Client Portal dashboard exposes a `config.json` file that contains sensitive production configuration data.

### Exposed Data:
- Google reCAPTCHA site key: `6LcBSMsUAAAAACGDa_gWU-KnaUDQhxrRt3fGp6Sn`
- Google reCAPTCHA TEST automation key: `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI`
- Google Analytics tracking ID: `UA-159377714-1`
- Mixpanel tracking ID: `95b13a73ede4a29433eee13fce48d763`
- HubSpot form submission URL
- SFTP client whitelist IPs: `34.197.94.166`, `52.44.86.145`, `34.237.5.30`, `34.196.149.32`
- Internal resources URL (HTTP): `http://iconslib.rapyd.net/assets/client-portal`
- Physical environment names: development, sandbox, production
- Internal error codes (8 codes)
- Excluded settlement countries list
- App version: `1.6.6`
- Settlement minimums: 100 USD/EUR

### Impact
- An attacker can use the reCAPTCHA test key to bypass CAPTCHA protections
- Internal IPs and environment names aid further reconnaissance
- Tracking IDs can be used for analytics poisoning or user tracking
- Error codes reveal internal system architecture

### Remediation
- Remove config.json from public access or strip sensitive values
- Use environment variables injected at build time
- Remove test/automation API keys from production

---

## Finding #2: Missing Security Headers
**Severity:** Low
**URL:** https://dashboard.rapyd.net, https://api.rapyd.net

### Missing Headers:
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Content-Security-Policy
- Referrer-Policy
- Permissions-Policy

### Impact
- Clickjacking attacks possible
- MIME-type sniffing attacks
- Missing HSTS allows downgrade attacks

---

## Finding #3: Cloudflare Trace Exposes Location
**Severity:** Informational
**URL:** https://api.rapyd.net/cdn-cgi/trace

The Cloudflare trace endpoint reveals:
- Client IP: 192.88.101.14
- Datacenter: SIN (Singapore)
- Location: ID (Indonesia)
- TLS: v1.3

---

## Other Observations
- api.rapyd.net returns 404 for all tested paths (API likely requires auth tokens)
- dashboard.rapyd.net is a React SPA (all paths return the SPA shell)
- Cloudflare is used as CDN/WAF
- No CORS misconfigurations found
- No GraphQL endpoints found
