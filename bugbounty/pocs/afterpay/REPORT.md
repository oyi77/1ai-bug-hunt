# Afterpay Bug Bounty - Security Assessment Report
## Date: 2026-05-21

---

## FINDING 1: Client-Side Secret & API Key Exposure (MEDIUM)
**Target:** portal.afterpay.com/au/
**Type:** Information Disclosure / Misconfiguration

The consumer portal HTML embeds sensitive configuration in DOM divs:

```
STRIPE_PUBLISHABLE_KEY = pk_live_LrEyJmZxQ5rrmZQe6LpSTucy (LIVE production key)
GOOGLEMAPS_API_KEY = AIzaSyAal00vvQU1rw9s5kRtqi9KUBpXZuoNO0I
LAUNCH_DARKLY_CLIENT_SIDE_ID = 5b1513721ec3de318c3e2df8
AMPLITUDE_CLIENT_SIDE_ID = 365902604116212ecb4d662502db6da8
ADWORDS_ID = AW-759612104
FRIENDBUY_MERCHANT_ID = 53b97f41-e407-4e7b-9d5e-1e9a72c1ea10
APPLE_PAY_MERCHANT_ID = merchant.com.afterpay.afterpay-payments-production
TM_ORGANISATION_ID = 9eb199og (ThreatMetrix)
```

**Impact:**
- Stripe LIVE key confirmed: Stripe API returns account ID `acct_1DjGXnH35CUlpaF0` in error responses
- LaunchDarkly goals API returns internal checkout flow details (button selectors, URL patterns)
- Google Maps key has referer restrictions (properly configured)

**Evidence:** portal_config.txt, stripe_test.txt, ld_test.txt

---

## FINDING 2: Internal Infrastructure URL Disclosure (LOW-MEDIUM)
**Target:** portal.afterpay.com/au/ + reports.afterpay.com source maps
**Type:** Information Disclosure

### From portal.afterpay.com HTML:
```
PORTAL_API_BASE_URL = https://portalapi.afterpay.com
TOPAZ_BASE_URL = https://card-api.au.payments.afterpay.com
BUSINESS_HUB_BASE_URL = https://hub.afterpay.com
SHOP_API_BASE_URL = https://shop-service.consumer.us.platform.afterpay.com
THREE_DS_REDIRECT_URL = https://prod-payments-threeds.afterpay.com
PAYMENT_SOURCE_BASE_URL = https://api.au.payments.afterpay.com
```

### From reports.afterpay.com source maps (full source code accessible):
```
https://afterpaytouch.okta.com (Okta tenant)
https://tableau.corp.afterpay.com/#/projects/135 (Internal Tableau - Key Reports)
https://tableau.corp.afterpay.com/#/projects/185 (Internal Tableau - Global L1 KPI)
https://defamibxuy2ya.cloudfront.net/ (CloudFront distribution)
bi@afterpay.com (BI team email)
```

**Impact:** Reveals internal infrastructure, Okta tenant name, Tableau dashboards, CloudFront distribution IDs.

**Evidence:** portal_config.txt, reports_app.js.map, reports_vendors.js.map

---

## FINDING 3: Source Map Exposure (MEDIUM)
**Target:** reports.afterpay.com
**Type:** Information Disclosure

Full webpack source maps publicly accessible:
- `/js/app.7968de09.js.map` (20KB) - 17 source files including Vue components, router config, Okta auth config
- `/js/chunk-vendors.a766c409.js.map` (1.2MB) - 256 vendor source files including @okta/okta-auth-js

**Impact:** Attackers can reconstruct original source code, revealing:
- Okta configuration (issuer URL, auth flow)
- Internal API endpoints
- Business logic and routing
- Third-party service integrations

**Evidence:** reports_app.js.map, reports_vendors.js.map

---

## FINDING 4: Unauthenticated Endpoints (INFORMATIONAL)
**Target:** api.portal.health.afterpay.com, portalapi.afterpay.com
**Type:** Information Disclosure

Both API hosts expose unauthenticated `/ping` endpoints:
```
GET https://api.portal.health.afterpay.com/ping -> 200: pong
GET https://portalapi.afterpay.com/ping -> 200: pong
```

**Impact:** Confirms API hostnames are valid and responsive. Could be used for:
- Service discovery
- Uptime monitoring by attackers
- Reconnaissance for further attacks

---

## FINDING 5: Potential .env/.git Exposure Behind WAF (INFORMATIONAL)
**Target:** api.portal.health.afterpay.com, portalapi.afterpay.com
**Type:** Misconfiguration

Both API hosts return 403 (not 404) for sensitive files:
```
/.env -> 403 (WAF blocked)
/.git/HEAD -> 403 (WAF blocked)
/.git/config -> 403 (WAF blocked)
```

**Impact:** 403 vs 404 response suggests these files may exist behind the WAF. If WAF rules are misconfigured or bypassed, these could expose:
- Environment variables (API keys, database credentials)
- Git repository contents

---

## FINDING 6: LaunchDarkly Goals Leak (LOW)
**Target:** portal.afterpay.com via LaunchDarkly
**Type:** Information Disclosure

LaunchDarkly client-side SDK goals endpoint returns internal checkout flow details:
```json
[{
  "key": "d21fe3a5-9a7a-4e02-b0b2-4c3370551b9e",
  "kind": "click",
  "selector": "button[data-testid=\"summary-button\"]",
  "urls": [{"kind": "exact", "url": "https://portal.afterpay.com/v2/checkout/en-US/summary"}]
}]
```

**Impact:** Reveals internal URL structure and UI element selectors for A/B testing.

---

## SUBDOMAIN INVENTORY

| Host | Status | Notes |
|------|--------|-------|
| portal.afterpay.com | 302 -> /au/ | Consumer portal, massive config leak |
| portalapi.afterpay.com | 401/403 | Consumer API, /ping exposed |
| api.portal.health.afterpay.com | 401 | Health portal API, /ping exposed |
| reports.afterpay.com | 200 | "API Portal" - BI reports, source maps exposed |
| hub.sandbox.afterpay.com | 200 | Sandbox SPA |
| hub.us-sandbox.afterpay.com | 200 | US Sandbox SPA |
| status.afterpay.com | 200 | incident.io status page, API accessible |
| tableau.corp.afterpay.com | 302 | Internal Tableau (likely VPN-only) |
| api.afterpay.com | 404 | Not found |
| card-api.au.payments.afterpay.com | 403 | Payment card API, restricted |
| defamibxuy2ya.cloudfront.net | 200 | CloudFront distribution for reports |
| mastercard-webhook-sandbox.au.afterpay.com | Cloudflare Access | Protected |

---

## RAW EVIDENCE FILES

All saved to `/home/openclaw/.openclaw/workspace/bugbounty/pocs/afterpay/`:
- portal_au_full.html - Full portal HTML with config
- portal_config.txt - Extracted config values
- stripe_test.txt - Stripe API key test results
- ld_test.txt - LaunchDarkly test results
- reports_app.js.map - Source map (20KB)
- reports_vendors.js.map - Source map (1.2MB)
- reports_app.js - Decompiled app JS
- api_fuzz_extended.txt - API endpoint fuzzing
- portalapi_test.txt - portalapi endpoint testing
- seon_fingerprint.js - Seon fraud detection JS (136KB)
- gmaps_key_test.txt - Google Maps API key test
- incident_io.txt - Status page API dump
- sandbox_bundle.js - Sandbox SPA bundle
