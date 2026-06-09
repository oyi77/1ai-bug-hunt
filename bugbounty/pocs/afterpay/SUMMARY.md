# Afterpay Bug Bounty - CORS & Header Analysis
**Date**: 2026-05-20
**Target**: Afterpay (Bugcrowd)

## 1. CORS Results
No `Access-Control-Allow-Origin` headers returned on any host for either `evil.com` or `null` origins.
- `api.portal.health.afterpay.com` returns `Vary: Origin` (correct behavior, reflects origin in vary but no ACAO)
- All other hosts: no CORS headers at all
- **Verdict**: No CORS misconfiguration found

## 2. Header Injection Results
- `portal.health.afterpay.com`: exposes `x-amz-server-side-encryption: AES256` and `server: cloudflare`
- `shop-product.afterpay.com`: exposes `server: cloudflare`
- **Low severity**: Server/encryption type disclosure (info leak, not exploitable)

## 3. Open Redirect Results
- `portal.health.afterpay.com`: Returns 200 for all test params (ignores them, no redirect)
- `developers.afterpay.com`: Redirects to `/afterpay-online-developer/home` for all params except `redirect?url=` (404). Redirects go to internal path, NOT to evil.com
- **Verdict**: No open redirect found

## 4. Cookie Security
- `portal.health.afterpay.com`: `__cf_bm` - HttpOnly, Secure, SameSite=None ✓
- `shop-product.afterpay.com`: `JSESSIONID` - HttpOnly, Secure (no SameSite), `__cf_bm` - HttpOnly, Secure, SameSite=None ✓
- **Minor**: JSESSIONID missing SameSite attribute (low risk, HttpOnly+Secure present)

## 5. CSP Results
- `portal.health.afterpay.com`: No CSP header
- `reports.afterpay.com`: No CSP header
- `developers.afterpay.com`: Has CSP but allows `unsafe-inline`, `unsafe-eval`, `https:` wildcard, `blob:`, `data:` in most directives
- **Low severity**: Missing CSP on 2 hosts; overly permissive CSP on developers host

## Summary of Findings
| Test | Severity | Status |
|------|----------|--------|
| CORS Misconfiguration | - | Not found |
| Header Injection | Info | Server/encryption disclosure |
| Open Redirect | - | Not found |
| Cookie Security | Low | JSESSIONID missing SameSite |
| CSP | Low | Missing/permissive CSP |

## Verdict
No high-severity CORS or header injection vulnerabilities found. The hosts are properly configured with Cloudflare and don't reflect arbitrary origins. Minor informational findings only (server disclosure, missing SameSite on JSESSIONID, weak CSP).
