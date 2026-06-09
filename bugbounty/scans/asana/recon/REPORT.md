# Asana Bug Bounty Recon Report
**Date**: 2026-05-20
**Target**: asana.com (Bugcrowd)

---

## Executive Summary

Recon completed on Asana's attack surface. Found 2,189 subdomains, confirmed CORS misconfiguration on API endpoints, mapped tech stack, and identified several areas warranting deeper testing.

---

## 1. Subdomain Enumeration

**Total subdomains found**: 2,189

### High-Value Categories

| Category | Count | Examples |
|----------|-------|---------|
| ArgoCD (K8s deploy) | ~30+ | `prod-us1-asana-cell16-886d1201.asana.argocd.app.asana.com` |
| Internal cells | ~15 | `prod-us1-internal-cell04-eeeda9c7.app.asana.com` |
| Beta environments | ~20+ | `share-beta.asana.com`, `beta-us1-asana-cell01-*.app.asana.com` |
| Sync endpoints | ~10 | `r26963756.sync.app.asana.com` |
| API/Services | ~10 | `api.asana.com`, `cdp-api.asana.com`, `dev.cdp-api.asana.com` |
| Admin portals | 3 | `admin.connect.asana.com`, `login.connect.asana.com` |
| Regional cells | Multiple | `prod-au1-*`, `prod-jp1-*`, `prod-us2-*` |

### Live Subdomains (HTTP responsive)

| Host | Status | Notes |
|------|--------|-------|
| api.asana.com | 307 | Redirects to app.asana.com |
| apps.asana.com | 307 | Redirects to asana.com/404 |
| beta.asana.com | 307 | Redirects |
| cloud.asana.com | 307 | Redirects |
| azure.asana.com | 307 | Redirects |
| connect.asana.com | 303 | Redirects to asana.com |
| developers.asana.com | 200 | Asana API docs portal |
| status.asana.com | 200 | Asana Status page (Statuspage.io) |
| help.asana.com | 301 | Redirects to help.asana.com/s/ |
| academy.asana.com | 200 | Asana Academy |
| cdp-api.asana.com | 404 | CDP API (empty) |

---

## 2. API Endpoint Discovery

### app.asana.com/api/1.0

All endpoints return `Not Authorized` (not `Not Found`) - confirming they exist and require auth:

- `/api/1.0/users/me` -> 401 "Not Authorized"
- `/api/1.0/attachments` -> 401 "Not Authorized"
- `/api/1.0/webhooks` -> 401 "Not Authorized"
- `/api/1.0/teams` -> 401 "Not Authorized"
- `/api/1.0/workspaces` -> 401 "Not Authorized"

### GraphQL

- `/api/1.0/graphql` -> "No matching route" (not available)
- `/graphql` -> No response (not available)

---

## 3. CORS Misconfiguration (Potential P3)

**Severity**: Medium (P3 candidate)
**Endpoint**: `app.asana.com` (all API endpoints)

### Finding

The API reflects arbitrary `Origin` headers in `Access-Control-Allow-Origin`:

```
Request:  Origin: https://evil.com
Response: access-control-allow-origin: https://evil.com

Request:  Origin: null
Response: access-control-allow-origin: null
```

### Impact Assessment

- **BUT**: `Access-Control-Allow-Credentials: true` is **NOT** set
- Without credentials header, browsers won't send cookies cross-origin
- **Exploitability**: LOW for data theft, but may still leak response data for non-cookie auth flows
- If combined with Bearer token in URL or other auth mechanism, could be exploitable

### CORS Headers Exposed

```
access-control-allow-headers: X-Requested-With, X-Allow-Asana-Client, X-Asana-Client-Lib, Content-Type, Authorization, Asana-Enable, Asana-Disable, Asana-First-Party-Disable
access-control-allow-methods: POST, GET, PUT, DELETE, OPTIONS
access-control-expose-headers: Connection, Content-Length, Date, Location, Retry-After, Asana-Change
```

---

## 4. Open Redirect Potential

`/oauth/authorize` passes `redirect_uri` through to login:

```
https://app.asana.com/oauth/authorize?redirect_uri=https://evil.com
-> 302 -> https://app.asana.com/-/login?u=%2Foauth%2Fauthorize%3Fredirect_uri%3Dhttps%253A%252F%252Fevil.com
```

The `redirect_uri` is URL-encoded into the `u` parameter. Needs deeper testing to see if post-login redirects honor the external URL.

---

## 5. Tech Stack

### asana.com (Marketing)
- **Framework**: Next.js (X-Powered-By: Next.js)
- **Hosting**: Netlify
- **CDN**: Netlify Edge
- **Security**: HSTS, X-Frame-Options: DENY, CSP headers
- **IP**: 15.197.167.90

### app.asana.com (Application)
- **CDN**: Amazon CloudFront
- **Backend**: Envoy proxy (x-envoy-upstream-service-time header)
- **Security**: HSTS, X-Frame-Options: SAMEORIGIN, X-XSS-Protection, CSP
- **Custom headers**: x-asana-edge-router, x-asana-cell, x-asana-wsm-rid
- **IP**: 99.86.20.34

### Infrastructure
- **Kubernetes**: ArgoCD for deployments (cell-based architecture)
- **Regions**: US (us1, us2), Australia (au1), Japan (jp1)
- **Cell naming**: `{env}-us1-asana-cell{N}-{hash}` pattern
- **Internal cells**: Separate internal cell network

---

## 6. Recommendations for Next Steps

1. **CORS**: Test with authenticated session + `access-control-allow-credentials` behavior
2. **OAuth redirect**: Full OAuth flow testing for account takeover via redirect_uri manipulation
3. **Webhook SSRF**: Test `/api/1.0/webhooks` POST with internal URLs (requires auth token)
4. **ArgoCD**: If any ArgoCD subdomain resolves, test for default credentials / unauthenticated access
5. **Cell enumeration**: Test cell-specific subdomains for misconfigured per-cell auth
6. **Rate limiting**: Test API rate limits for brute force / enumeration

---

## Files

- Subdomains: `subdomains.txt` (2,189 entries)
- Live hosts: `live_hosts.txt`
- API endpoints: `api_endpoints.txt`
- Exposed envs: `exposed_envs.txt`
- High-value live: `high_value_live.txt`
