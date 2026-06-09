# Bug Bounty Recon Summary — 2026-05-20 17:25 WIB

## Targets Scanned

### High-Value Programs
| Target | Platform | Status | Findings |
|--------|----------|--------|----------|
| Okta | HackerOne | Active | Properly secured, 403 on all endpoints |
| Zendesk | HackerOne | Active | 403 on all endpoints, Cloudflare protected |
| Coinbase | HackerOne | Active | Proper auth (401), CORS: NONE |
| Rapyd | Bugcrowd | Active | 404 on API endpoints, CORS: googletagmanager |
| Axis OS | Bugcrowd | Active | **CORS: * on all endpoints** (Low) |

### Crypto/Fintech Programs
| Target | Platform | Status | Findings |
|--------|----------|--------|----------|
| Luno | Bugcrowd | Active | Public tickers API (expected), auth on private endpoints |
| Bitso | Bugcrowd | Active | Proper auth (401) |
| Fireblocks | Bugcrowd | Active | Cloudflare protected, 403 |
| eToro | Bugcrowd | Active | 404 on API endpoints |

## Key Findings

### 1. Axis.com — CORS Misconfiguration (Low)
- **URL:** www.axis.com
- **Issue:** `Access-Control-Allow-Origin: *` on all endpoints
- **Endpoints:** /api, /api/v1, /api/v2, /graphql, /swagger, /docs, /health, /status
- **Severity:** Low (all endpoints return 404)
- **Report:** `axis-cors-misconfiguration.md`

### 2. Luno — Public Tickers API (Informational)
- **URL:** api.luno.com/api/1/tickers
- **Issue:** Public API returns 134 market tickers
- **Severity:** Informational (expected behavior)

## Subdomain Findings

### Okta
- login.okta.com — 200 (AWS S3)
- admin.okta.com — 200 (AWS S3)
- api.okta.com — 200 (AWS S3)
- staging.okta.com — 200 (AWS S3)
- preview.okta.com — 200 (AWS S3)
- beta.okta.com — 429 (rate limited)

### Coinbase
- exchange.coinbase.com — 200 (proper auth)
- prime.coinbase.com — 200 (proper auth)
- commerce.coinbase.com — 302
- dev.coinbase.com — 403

### Zendesk
- api.zendesk.com — 301
- support.zendesk.com — 301
- chat.zendesk.com — 301

## Recommendations
1. Submit Axis CORS finding to Bugcrowd (Axis OS program)
2. Continue recon on Okta/Coinbase subdomains
3. Check for exposed APIs on staging/dev environments
4. Monitor for new programs on Bugcrowd/HackerOne

## Next Steps
- [ ] Submit Axis CORS finding
- [ ] Deep recon on Okta staging/preview environments
- [ ] Check Coinbase dev environment
- [ ] Monitor for new bug bounty programs
