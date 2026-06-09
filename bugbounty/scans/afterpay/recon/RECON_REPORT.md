# Afterpay Recon Report
**Date**: 2026-05-20
**Target**: afterpay.com (Bugcrowd)
**Scope**: *.afterpay.com

---

## Summary

| Metric | Count |
|--------|-------|
| Total subdomains | 842 |
| Live hosts (HTTP responsive) | 360 |
| 200 OK | 37 |
| 403 Forbidden | 245 |
| 404 Not Found | 36 |
| 401 Unauthorized | 1 |
| 5xx Errors | 8 |
| 3xx Redirects | 30 |

---

## High-Value Targets

### 1. Exposed API Config Leak
- **portal.health.afterpay.com** - Health Merchant Portal (SPA/Angular)
  - `/env.js` leaks internal API: `MERCHANT_API_URL: "https://api.portal.health.afterpay.com"`
  - api.portal.health.afterpay.com returns **401** with `application/json` - real API backend
  - All paths return 200 (SPA catch-all)

### 2. Basic Auth Protected (Java)
- **shop-product.afterpay.com** - 401 with `Basic realm="Realm"`
  - Java backend (JSESSIONID cookie, Envoy proxy)
  - Has: `x-frame-options: DENY`, HSTS, proper security headers
  - Potential brute-force target

### 3. Sandbox/Staging Environments (200 OK)
- **web-onboarding.sandbox.afterpay.com** [200]
- **web-onboarding.us-sandbox.afterpay.com** [200]
- **web-orders.sandbox.afterpay.com** [200]
- **web-orders.us-sandbox.afterpay.com** [200]
- **hub.sandbox.afterpay.com** [200]
- **hub.us-sandbox.afterpay.com** [200]
- **ir-external.sbox.afterpay.com** [200]
- **ir-external.us-sbox.afterpay.com** [200]
- **mobile-builder-preview-page-staging.afterpay.com** [200]
- **widgets.sandbox.afterpay.com** [200]

### 4. Developer/Portal Infrastructure
- **developers.afterpay.com** [307] - Next.js/Vercel (developer docs)
- **developers-beta.afterpay.com** [307] - Next.js/Vercel (beta dev docs)
- **reports.afterpay.com** [200] - "API Portal" (Amazon CloudFront/S3)
- **docs.afterpay.com** [301] -> developers.afterpay.com
- **developers.health.afterpay.com** [302] - Render-hosted
- **status.afterpay.com** [200] - Vercel-hosted status page

### 5. Cloudflare Access Protected
- **mastercard-webhook-sandbox.au.afterpay.com** [403]
- **mastercard-webhook.au.afterpay.com** [403]
- **nexus.corp.afterpay.com** [403]

### 6. Internal/Corp Infrastructure (Accessible)
- **tea.corp.afterpay.com** [200] - "AWS TEA" (Teleport Enterprise Access)
- **tea-dev.corp.afterpay.com** [200] - "AWS TEA" dev instance
- **cribl.corp.afterpay.com** [503] - Cribl (log management)
- **dq-testing.corp.afterpay.com** [302] - Data quality testing
- **dq-testing-dev.corp.afterpay.com** [302]
- **dq-testing-qa.corp.afterpay.com** [302]

### 7. Interesting Services
- **lp.afterpay.com** [200] - Userled (Next.js/Vercel/Snowplow Analytics)
- **careers.afterpay.com** [200] - Gatsby 2.24.31 site
- **newsroom.afterpay.com** [200] - Vercel/Google Analytics
- **genderfree.afterpay.com** [200] - Shop subdomain
- **mi.afterpay.com** [200] - Movable Ink (email marketing)
- **retailers.afterpay.com** [200] - Unbounce landing page
- **bold-widget.afterpay.com** [200] - Afterpay Bold Widget (S3)
- **widgets.afterpay.com** [200] - Widget (S3)
- **risk-insight-web.afterpay.com** [530] - Risk insight tool

---

## Tech Stack

| Technology | Occurrences |
|-----------|-------------|
| Cloudflare | 331 |
| Cloudflare Bot Management | 325 |
| Envoy Proxy | 42 |
| Amazon Web Services | 42 |
| Amazon CloudFront | 39 |
| Amazon S3 | 12 |
| Vercel | 5 |
| HTTP/3 | 5 |
| React | 4 |
| Webpack | 4 |
| Nginx | 4 |
| Next.js | 3 |
| Node.js | 3 |
| OpenResty | 3 |
| Java | 2 |
| Zendesk | 2 |
| Google Tag Manager | 2 |
| Apache HTTP Server | 2 |
| Gatsby 2.24.31 | 1 |
| ASP.NET | 1 |
| IIS 10.0 | 1 |
| Okta | 1 |
| Plaid | 1 |
| Kasada (bot protection) | 1 |
| Render | 1 |

---

## Security Findings

### Positive Security Posture
- HSTS with preload on main domain (max-age=31536000)
- Cloudflare WAF + Bot Management across most infrastructure
- Cloudflare Access on sensitive internal services
- Proper `x-frame-options: DENY` on Java apps
- `x-content-type-options: nosniff` on APIs
- HttpOnly + Secure + SameSite cookies

### Potential Attack Surface
1. **API Config Leak**: portal.health.afterpay.com/env.js exposes internal API URL
2. **Basic Auth**: shop-product.afterpay.com uses Basic auth (potential brute-force)
3. **Sandbox environments**: Multiple sandbox hosts accessible from internet
4. **Corp hosts accessible**: tea.corp.afterpay.com (Teleport) reachable
5. **Missing CORS header**: No Access-Control-Allow-Origin returned on www.afterpay.com (not a vuln, but worth noting)
6. **Old Gatsby version**: careers.afterpay.com runs Gatsby 2.24.31 (check for CVEs)
7. **Expired security.txt**: Expires 2026-03-19 (already expired)
8. **5xx errors on internal hosts**: cribl.corp, insight, risk-insight-web returning errors

---

## API Endpoints (afterpay.com main domain)

| Path | Status |
|------|--------|
| /.well-known/security.txt | 200 |
| /.env | 403 |
| /api | 301 |
| /api/v1 | 301 |
| /api/v2 | 301 |
| /graphql | 301 |
| /swagger.json | 301 |
| /openapi.json | 301 |
| /robots.txt | 301 |
| /sitemap.xml | 301 |
| /security.txt | 301 |
| /actuator | 301 |
| /health | 301 |

Note: 301 redirects go to www.afterpay.com equivalent paths.

---

## Response Headers (afterpay.com)

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
server: cloudflare
cf-ray: active
x-envoy-upstream-service-time: present (Envoy backend)
set-cookie: __cf_bm (Cloudflare Bot Management), _cfuvid
```

---

## Recommendations for Bug Bounty

1. **Test portal.health.afterpay.com** deeply - SPA with leaked API config, check for IDOR, auth bypass
2. **Brute-force shop-product.afterpay.com** Basic auth (within scope/rules)
3. **Enumerate sandbox endpoints** - web-onboarding, web-orders, widgets in sandbox
4. **Check developers.afterpay.com** for API key exposure, documentation leaks
5. **Test reports.afterpay.com** API Portal for access control issues
6. **Probe tea.corp.afterpay.com** - Teleport Enterprise Access, check for auth bypass
7. **Review Gatsby 2.24.31** on careers.afterpay.com for known CVEs
8. **Test Plaid integration** - financial data aggregation vector
9. **Check web-orders endpoints** for order manipulation/IDOR
10. **Review Mastercard webhook endpoints** - payment processing attack surface

---

## Files Generated

- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/subdomains.txt` - 842 subdomains
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/live_hosts.txt` - 360 live hosts with tech
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/security_txt.txt` - PGP-signed security.txt
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/robots_txt.txt` - robots.txt
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/api_endpoints.txt` - Main domain endpoint scan
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/tech_fingerprint.txt` - WhatWeb fingerprint
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/response_headers.txt` - HTTP headers
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/interesting_hosts.txt` - Notable subdomain probes
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/afterpay/recon/RECON_REPORT.md` - This report
