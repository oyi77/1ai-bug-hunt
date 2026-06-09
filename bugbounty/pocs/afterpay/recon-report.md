# Afterpay Bug Bounty Recon Report
**Date**: 2026-05-20
**Target**: mobileapi.afterpay.com, portalapi.*.afterpay.com
**Scope**: Mobile API and Portal API

---

## Summary

Conducted comprehensive reconnaissance against Afterpay's mobile and portal APIs. Both are behind Cloudflare with Envoy proxy backend. Discovered several real API endpoints on mobileapi that require authentication. No unauthenticated data exposure, IDOR, injection, or SSRF found.

---

## Infrastructure

| Property | Value |
|----------|-------|
| CDN | Cloudflare |
| Backend Proxy | Envoy (x-envoy-upstream-service-time header) |
| TLS | HSTS enabled, includeSubDomains, preload |
| Response Format | JSON (errorCode/message/httpStatusCode pattern) |
| Cookie Domain | .afterpay.com |

---

## mobileapi.afterpay.com Findings

### Active Endpoints Discovered

| Endpoint | GET | POST | PUT | OPTIONS (Allowed Methods) |
|----------|-----|------|-----|---------------------------|
| `/ping` | 200 ("pong") | - | - | - |
| `/v1/consumers` | 401 | 405 | 405 | HEAD,GET,OPTIONS |
| `/v1/consumers/profile` | 405 | 401 | 401 | POST,OPTIONS,PUT |
| `/v1/consumers/orders` | 401 | 405 | 405 | - |
| `/v1/consumers/cards` | 401 | 405 | 405 | - |
| `/v1/consumers/limit` | 401 | 405 | 405 | - |
| `/v1/consumers/bank-accounts` | 401 | 405 | 405 | - |
| `/v1/consumers/statements` | 401 | 405 | 405 | - |

### Key Observations

1. **`/v1/consumers/profile`** accepts POST and PUT (returns 401 auth required). This is the profile update endpoint for authenticated consumers.

2. **All consumer endpoints require authentication** - consistently return:
   ```json
   {"errorCode":"unauthorized","errorId":"...","message":"Credentials are required to access this resource.","httpStatusCode":401}
   ```

3. **No user enumeration** - Error messages are uniform regardless of input.

4. **No CORS misconfiguration** - `Access-Control-Allow-Origin` not returned for arbitrary origins.

5. **API structure pattern**: `/v1/consumers/{resource}` with standard REST verbs.

### Negative Results (No Vulnerability Found)

- **Auth bypass**: No bypass via headers (X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization, X-Real-IP, X-Forwarded-Host), null/empty/guest/basic tokens
- **IDOR**: All `/v1/consumers/{id}` paths return 404 (not enumerable)
- **Injection**: No SQL/SSTI/XSS reflection in error messages
- **SSRF**: No callback/webhook/redirect/proxy endpoints found
- **GraphQL**: Not available (404)
- **Method tampering**: TRACE/PROPFIND/WebDAV methods return 405
- **Info disclosure**: No swagger/openapi/version/config endpoints exposed

---

## portalapi.afterpay.com Findings

| Endpoint | Status |
|----------|--------|
| `/ping` | 200 ("pong") |
| All other paths | 404 |

**portalapi is heavily locked down** - no API endpoints discovered beyond `/ping`.

### Additional Headers (vs mobileapi)
- `x-content-type-options: nosniff`
- `x-frame-options: DENY`
- `x-xss-protection: 0`
- `vary: Origin`

---

## Security Posture Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| Auth | Strong | All sensitive endpoints require auth, uniform error responses |
| WAF | Strong | Cloudflare blocks .env, .git, WebDAV, X-Original-URL |
| CORS | Clean | No wildcard or reflected origins |
| Info Disclosure | Low Risk | `/ping` leaks "pong" but no version info |
| Enumeration | Mitigated | Uniform 401 errors, no ID-based enumeration possible |

---

## Potential Attack Surfaces for Authenticated Testing

If valid credentials are obtained, the following should be tested:

1. **IDOR on `/v1/consumers/cards/{id}`** - Test if card IDs are sequential/guessable
2. **IDOR on `/v1/consumers/orders/{id}`** - Cross-consumer order access
3. **Profile update via PUT `/v1/consumers/profile`** - Privilege escalation, field injection
4. **Rate limiting** - Login/registration brute force (endpoints not found unauthenticated)
5. **JWT manipulation** - If Bearer tokens are JWTs, test alg:none, key confusion

---

## Evidence Files

All raw curl output captured in this directory.
