# Afterpay Sandbox Reconnaissance Report
**Date**: 2026-05-20
**Targets**: Afterpay Sandbox environments (Bugcrowd scope)

---

## FINDING 1: Publicly Exposed config.json with Sensitive Credentials
**Severity**: HIGH (P2 - Information Disclosure)
**Hosts**: hub.sandbox.afterpay.com, hub.us-sandbox.afterpay.com
**URL**: https://hub.sandbox.afterpay.com/config.json
**Status**: HTTP 200, no auth required

### Leaked Credentials:
- **Google Maps API Key**: `AIzaSyBnnbGJB6MMtYMGXzC6altA_l11MuBmub8`
- **LaunchDarkly Client IDs**: `61a46efb7386bf104965194c`, `61a46eb32b64630f230ac7f8`
- **Amplitude Client ID**: `339eb92886e7a28c3355608dd804ada1`
- **Okta Client ID**: `0oas65cfxEdhhmToY4x6`
- **Okta Issuer URL**: `https://afterpayb2b-us-sbox.okta.com/oauth2/default`
- **Datadog Application ID**: `ccb882cb-3841-4893-925d-569b1ad78b18`
- **Datadog Client Token**: `pub6df119a04320609b1b0c8b0ab59ef4e5`
- **Sentry Debug ID**: `d5d800b5-a711-44ad-bc83-1a742f60ea43`

### Leaked Internal Infrastructure URLs:
- `portal.sandbox.afterpay.com` (AU/US/NZ/CA merchant portal)
- `portal.sandbox.clearpay.co.uk` (UK/FR/IT/ES/DE merchant portal)
- `merchantportalapi-sandbox.afterpay.com`
- `merchantportalapi.us-sandbox.afterpay.com`
- `merchantportalapi.eu-sandbox.clearpay.co.uk`
- `getstaging.afterpay.com` (MOP staging)
- `afterpayb2b-us-sbox.okta.com` (Okta identity provider)

### Impact:
- API keys can be abused for unauthorized tracking, analytics injection
- Okta issuer URL + client ID enables potential OAuth/OIDC attacks against sandbox
- Internal infrastructure map enables targeted attacks on backend services
- LaunchDarkly feature flag manipulation possible with client-side IDs

---

## FINDING 2: ir-external exposes Webpack Module Federation remoteEntry.js
**Severity**: MEDIUM (P3 - Information Disclosure)
**Hosts**: ir-external.sbox.afterpay.com, ir-external.us-sbox.afterpay.com
**URL**: https://ir-external.sbox.afterpay.com/remoteEntry.js
**Status**: HTTP 200, no auth required

### Exposed Module Names:
- `./Disputes` -> `DisputesContainer.tsx`
- `./DisputesFAQ` -> `DisputesFAQ.tsx`

### Cross-References:
- References `webAppShell@[window.WEB_APP_SHELL]/remoteEntry.js`
- References `webMerchant@[window.WEB_MERCHANT]/remoteEntry.js`
- Uses webpack module federation with shared dependencies (react, axios, recoil)

### Impact:
- Exposes internal micro-frontend architecture
- Module names reveal business logic (Disputes system)
- Could enable supply-chain attacks via module federation manipulation

---

## FINDING 3: Exposed Bundle Files with CSP Nonces
**Severity**: LOW-MEDIUM
**Hosts**: hub.sandbox.afterpay.com, ir-external.sbox.afterpay.com

### Details:
- Main bundles accessible: `/main.5ab1e0b59dac54568460.bundle.js`, `/main.1304040b898182448a55.bundle.js`
- CSP nonces are embedded in HTML: `meta property="csp-nonce"`
- ir-external uses `eval-source-map` devtool (debug/source maps in production)

### Impact:
- Source maps enable reverse engineering of application logic
- CSP nonces in meta tags can be extracted for XSS bypass

---

## FINDING 4: .env Path Returns 403 via Cloudflare
**Severity**: LOW (Positive - Blocked)
**Host**: hub.sandbox.afterpay.com
**URL**: https://hub.sandbox.afterpay.com/.env

### Details:
- Returns HTTP 403 (Cloudflare WAF block)
- Confirms .env file exists or is explicitly blocked
- Cloudflare is properly blocking sensitive paths

---

## FINDING 5: SPA Catch-All Returns 200 for All Paths
**Severity**: INFO
**Hosts**: hub.sandbox.afterpay.com, hub.us-sandbox.afterpay.com

### Details:
- All paths return 200 with same SPA HTML (React app)
- /api, /graphql, /swagger.json, /openapi.json, /health, /debug, /admin, /login, /config all return 200
- This is expected behavior for SPA with client-side routing
- No actual API endpoints exposed at these paths

---

## CORS Analysis
**Status**: No Access-Control headers returned for evil.com origin
- No CORS misconfiguration detected on tested hosts

---

## S3 Bucket Analysis
**Host**: mobile-builder-preview-page-staging.afterpay.com
**Status**: Serves Expo/React Native web app, not an open S3 bucket
- `?list-type=2` returns same SPA HTML (not S3 listing)
- Server: AmazonS3 (S3-backed static hosting)

---

## Security Headers Analysis
### Positive:
- HSTS enabled: `max-age=31536000; includeSubDomains; preload`
- CSP present on hub.sandbox with nonce-based script-src
- Cloudflare WAF active
- X-Frame-Options: SAMEORIGIN (on .env block page)

### Concerns:
- ir-external lacks CSP header
- ir-external uses `eval-source-map` (debug mode in production)
- mobile-builder serves via AmazonS3 without Cloudflare protection

---

## Screenshots
- `hub_sandbox_afterpay_com.png` - Login page (React SPA)
- `ir-external_sbox_afterpay_com.png` - IR External module (React SPA)

---

## Files Collected
All evidence in: `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/`
- `config_check.txt` - Full config.json from both hub sandboxes
- `evidence.txt` - Raw HTML responses from all hosts
- `api_endpoints.txt` - API endpoint discovery results
- `js_analysis.txt` - JavaScript bundle analysis
- `ir_modules.txt` - ir-external module federation analysis
- `headers_check.txt` - HTTP response headers
- `cors_check.txt` - CORS test results
- `s3_check.txt` - S3 bucket check results
