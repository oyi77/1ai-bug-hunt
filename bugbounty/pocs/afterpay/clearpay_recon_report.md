# Clearpay Production Recon Report
**Date**: 2026-05-21
**Targets**: clearpay.co.uk, clearpay.com, portal.clearpay.com, mobileapi.clearpay.com, api.clearpay.com, portalapi.eu.clearpay.co.uk

---

## Test 1: Host Discovery

| Host | Status | Notes |
|------|--------|-------|
| clearpay.co.uk | 403 | Cloudflare WAF blocking all requests |
| clearpay.com | 301 | Redirects to https://www.clearpay.com/ |
| portal.clearpay.com | 302 | Redirects to /uk/ (merchant portal) |
| mobileapi.clearpay.com | 000 | Connection failed - host unreachable/DNS failure |
| api.clearpay.com | 530 | Cloudflare origin DNS error - backend down |
| portalapi.eu.clearpay.co.uk | 403 | Cloudflare WAF blocking all paths |

## Test 2: API Endpoint Discovery

### mobileapi.clearpay.com
- **Result**: No response (host unreachable, status 000)
- All tested paths returned nothing

### api.clearpay.com
- **Result**: All paths return 530 (Cloudflare origin DNS error)
- Tested: /, /api, /v1, /v2, /health, /ping, /version, /swagger.json, /openapi.json, /graphql, /v1/users, /v1/orders, /v1/merchants
- **Interpretation**: Backend origin is down or DNS not configured. Cloudflare is proxying but origin doesn't exist.

## Test 3: portalapi.eu.clearpay.co.uk

- All paths return 403 via Cloudflare WAF
- Tested: /, /api, /v1, /health, /ping, /swagger.json, /graphql
- Security headers confirmed: HSTS, X-Frame-Options: SAMEORIGIN, referrer-policy: same-origin
- Cloudflare cookies present (__cf_bm)
- **Interpretation**: Properly locked down behind Cloudflare WAF

## Test 4: GDPR/Privacy Endpoints

- **mobileapi.clearpay.com**: No response (host unreachable)
- **api.clearpay.com**: All return 530 (origin down)
- **portalapi.eu.clearpay.co.uk**: All return 403 (WAF blocked)
- Tested: /v1/gdpr, /v1/data-export, /v1/data-deletion, /v1/consent, /v1/privacy

## Test 5: IDOR Testing

- **mobileapi.clearpay.com**: No response for any user ID (host unreachable)
- Tested IDs: 1, 2, 100, 1000
- **Result**: No vulnerability found (host not accessible)

---

## Summary

### Key Observations:
1. **mobileapi.clearpay.com is completely dead** - DNS doesn't resolve, connection fails with status 000
2. **api.clearpay.com origin is down** - Cloudflare proxies but returns 530 (origin DNS error) on all paths
3. **portalapi.eu.clearpay.co.uk is well-protected** - Cloudflare WAF blocks all unauthenticated requests with 403
4. **portal.clearpay.com is the only functional service** - Returns 302 to /uk/ (merchant portal login)
5. **clearpay.co.uk** - Also behind Cloudflare WAF (403)

### Attack Surface Assessment:
- The Clearpay production APIs appear to be either decommissioned or moved behind Cloudflare with no public access
- The merchant portal (portal.clearpay.com) redirects to a UK login page - this may have authenticated attack surface
- The EU portal API (portalapi.eu.clearpay.co.uk) is properly WAF-protected

### Potential Next Steps:
1. Test portal.clearpay.com/uk/ for auth bypass, SSRF, or OAuth misconfigurations
2. Check if clearpay.com/www.clearpay.com has any exposed endpoints
3. Look for staging/sandbox equivalents (parallel to afterpay sandbox findings)
4. Check for subdomain takeover on dead hosts (mobileapi.clearpay.com, api.clearpay.com origin)

### Evidence Files:
- `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/discovery_clearpay.txt`
- `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/api_discovery_clearpay.txt`
- `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/portalapi_eu_discovery.txt`
- `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/gdpr_endpoints.txt`
- `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/idor_clearpay.txt`
