# Afterpay Health Portal - Bug Bounty Recon Report
**Date**: 2026-05-20
**Target**: portal.health.afterpay.com (Bugcrowd)
**Researcher**: oyi77

---

## Summary of Findings

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1 | env.js exposes internal API hostname | Low-Medium | Information Disclosure |
| 2 | Java stack trace leakage on login endpoint | Medium | Information Disclosure |
| 3 | Full API route enumeration from JS bundle | Medium | Information Disclosure |
| 4 | S3 bucket accessible (portal.health.afterpay.com) | Low | Misconfiguration |
| 5 | Logout endpoint accessible without authentication | Low | Broken Access Control |
| 6 | Reset-password endpoint returns error with trace ID | Low | Information Disclosure |
| 7 | Medicare-related client-side data handling | Info | Sensitive Data |
| 8 | robots.txt allows all crawling | Info | Misconfiguration |

---

## Finding 1: env.js Exposes Internal API Hostname

**URL**: `https://portal.health.afterpay.com/env.js`
**Severity**: Low-Medium

**Evidence**:
```javascript
window.ENV = {
  MERCHANT_API_URL: "https://api.portal.health.afterpay.com",
};
```

**Impact**: Exposes internal API hostname. The `api.portal.health.afterpay.com` subdomain is not publicly documented. An attacker can enumerate and target this backend directly, bypassing any frontend protections.

**Notes**: The env.js file is loaded by the SPA via `<script src="/env.js"></script>` in the HTML. This is a common pattern for Angular/React apps but should not expose internal infrastructure.

---

## Finding 2: Java Stack Trace Leakage on Login Endpoint

**URL**: `POST https://api.portal.health.afterpay.com/v1/login/process`
**Severity**: Medium

**Evidence** (any POST request triggers this):
```html
HTTP ERROR 500 java.lang.NullPointerException: Cannot invoke
"String.replaceAll(String, String)" because "username" is null

URI: http://api.portal.health.afterpay.com/v1/login/process
STATUS: 500
MESSAGE: java.lang.NullPointerException
```

**Key observations**:
- Internal URI is `http://` (not https) -- backend runs plain HTTP
- Full Java exception class and method exposed
- Reveals the login process uses `String.replaceAll()` on the username field
- No input validation before the null-sensitive operation
- Java-based backend (likely Spring Boot given Jetty-style error pages)

**Impact**: Stack traces reveal internal implementation details, framework versions, and potential attack vectors. The NullPointerException itself indicates missing input validation which could be exploited for other attacks.

---

## Finding 3: Full API Route Enumeration from JS Bundle

**URL**: `https://portal.health.afterpay.com/main.6833aa882a3094b22471.esm.js`
**Severity**: Medium

**Complete API route map extracted**:

### Authentication & Accounts
- `POST /v1/login/process` -- Login (leaks stack trace)
- `GET /v1/logout` -- Logout (returns 200 without auth)
- `POST /v1/reset-password/request` -- Request password reset
- `POST /v1/reset-password/check` -- Check reset token
- `POST /v1/reset-password/confirm` -- Confirm reset
- `GET /v1/accounts` -- List accounts
- `GET /v1/accounts/user` -- Get user account
- `GET /v1/accounts/provider` -- Get provider account
- `POST /v1/accounts/change-password` -- Change password

### Business Data
- `GET /v1/organisations` -- List organisations
- `GET /v1/profiles` -- List profiles
- `GET /v1/modalities` -- List modalities
- `GET /v1/responseCode` -- Response codes
- `GET /v1/supportDetail` -- Support details
- `GET /v1/trainingMaterial` -- Training materials
- `GET /v1/faq` -- FAQ data
- `GET /v1/features/nonconsolidated/excluded/funds` -- Feature flags

### Reports
- `GET /v1/report/activity` -- Activity reports
- `GET /v1/report/consolidatedClaims` -- Consolidated claims
- `GET /v1/report/nonConsolidatedClaims` -- Non-consolidated claims
- `GET /v1/report/reconciliation` -- Reconciliation reports
- `GET /v1/report/public/reconciliation` -- Public reconciliation
- `GET /v1/report/shift` -- Shift reports

### Notifications
- `GET /v1/notifications` -- List notifications
- `GET /v1/notifications/unread_count` -- Unread count
- `POST /v1/notifications/all/read` -- Mark all read

### Terminal Management
- `GET /v1/terminal-association` -- Terminal associations
- `GET /v1/terminal-association/storeId/` -- Store terminal lookup

### Medicare Integration (client-side references)
- `medicareClientId` (localStorage)
- `medicareToken`
- `medicareAssertion`
- `medicareClaimEstimation`
- `medicareNumber`
- `medicareRefNumber`
- `medicareStatus` / `medicareStatusCode`

---

## Finding 4: S3 Bucket Accessible

**URL**: `http://portal.health.afterpay.com.s3.amazonaws.com/`
**Severity**: Low

**Evidence**:
```
HTTP/1.1 403 Forbidden
x-amz-bucket-region: ap-southeast-2
Server: AmazonS3
```

**Notes**:
- The bucket exists (403, not 404) but listing is denied
- Region: ap-southeast-2 (Sydney)
- The portal is hosted from S3 via CloudFront
- Bucket has server-side encryption (AES256)
- Versioning is enabled (x-amz-version-id present)

**Other bucket names tested** (all 404): health.afterpay.com, afterpay-health, afterpay-health-portal, health-merchant-portal

---

## Finding 5: Logout Endpoint Accessible Without Authentication

**URL**: `GET https://api.portal.health.afterpay.com/v1/logout`
**Severity**: Low

**Evidence**:
```
HTTP/2 200
content-length: 0
```

The logout endpoint returns 200 with empty body for any unauthenticated request. While not directly exploitable, it indicates the logout handler does not validate session state, and could potentially be used for CSRF-based session invalidation attacks.

---

## Finding 6: Reset-Password Error Leakage

**URL**: `POST https://api.portal.health.afterpay.com/v1/reset-password/request`
**Severity**: Low

**Evidence**:
```json
{
  "code": 500,
  "message": "There was an error processing your request. It has been logged (ID 0aa57b545398b87d)."
}
```

Returns error with trace ID even for invalid requests. Could enable log injection or correlation attacks.

---

## Finding 7: Infrastructure Details

### CDN Stack
- **Cloudflare**: CDN + WAF (cf-ray headers)
- **AWS CloudFront**: Origin CDN (x-amz-cf-pop)
- **S3**: Static hosting (ap-southeast-2)
- **Backend**: Java application server (internal HTTP, not HTTPS)

### Security Headers (API)
- `strict-transport-security: max-age=3600; preload`
- `x-frame-options: DENY`
- `x-content-type-options: nosniff`
- `x-xss-protection: 0` (modern approach -- CSP preferred)
- `cache-control: no-cache, no-store, max-age=0, must-revalidate`

### Security Headers (Portal Frontend)
- `strict-transport-security: max-age=3600; preload`
- `x-content-type-options: nosniff`
- No X-Frame-Options on frontend (potential clickjacking)
- No CSP headers

### CORS
- No `Access-Control-Allow-Origin` returned for `Origin: https://evil.com`
- CORS properly restricted on portal frontend

### Missing Headers
- No Content-Security-Policy on either portal or API
- No X-Frame-Options on portal frontend
- Short HSTS max-age (3600 = 1 hour, recommended 31536000 = 1 year)

---

## Testing Notes

### Auth Bypass Attempts (all failed)
- `X-Forwarded-For: 127.0.0.1` -- still 401
- `Authorization: Bearer test` -- still 401
- `X-API-Key: test` -- still 401

### GraphQL
- `POST /graphql` on portal returns S3 `MethodNotAllowed` XML error (not a real GraphQL endpoint)

### .env File
- Returns Cloudflare WAF block page (403 with "Sorry, you have been blocked")

---

## Recommended Next Steps

1. **Register for a merchant account** to obtain auth tokens and test authenticated endpoints
2. **Test IDOR** on `/v1/accounts/user`, `/v1/organisations`, `/v1/notifications` with valid tokens
3. **Fuzz the login endpoint** -- the NPE suggests weak input handling
4. **Test Medicare integration endpoints** for PII leakage (medicareNumber is sensitive health data)
5. **Check rate limiting** on `/v1/reset-password/request` for account enumeration
6. **Test the /v1/report/public/reconciliation** endpoint -- "public" prefix suggests it may not require auth
