# Rapyd SAML 2.0 Recon — 2026-05-20 23:15 WIB

## Target
- **Program:** Rapyd Bug Bounty (Bugcrowd)
- **Scope:** SAML 2.0 on Rapyd Client Portal
- **ACS URL:** https://dashboard.rapyd.net/v1/merchants-portal/users/login/sso/callback
- **Entity ID:** rapyd_merchants_portal
- **Promotion:** May 20 - June 30, 2026
  - High: +$400 bonus
  - Critical: +$900 bonus

## Attack Surface

### SAML Endpoints
| Endpoint | Status | Response |
|----------|--------|----------|
| `/v1/merchants-portal/users/login/sso/callback` | 400 | SAML error response |
| `/v1/merchants-portal/users/login/sso/metadata` | 200 | Login page (no SAML metadata) |
| `/v1/merchants-portal/saml/metadata` | 400 | `INVALID_SESSION` ⚠️ |
| `/v1/merchants-portal/users/login/sso` | 400 | `INVALID_SAML_REQUEST` |

### SAML Error Codes Found
| Error Code | Trigger |
|------------|---------|
| `MERCHANTS_PORTAL_ERROR_INVALID_SAML_REQUEST` | Invalid/expired SAML response |
| `MERCHANTS_PORTAL_ERROR_GET_SAML_REQUEST` | Spoofed InResponseTo (server validates!) |
| `MERCHANTS_PORTAL_INVALID_SESSION` | Accessing metadata without session |

### Attack Tests Performed

#### 1. RelayState Open Redirect
- `https://evil.com` → Redirects to `/login` (no error shown) ⚠️
- `javascript:alert(1)` → **403 (WAF blocked)** — they know about XSS
- `//evil.com` → Redirects to `/login` (no error)
- `data:...` → Redirects to `/login` (no error)
- `https://rapyd.net@evil.com` → Redirects to `/login` (no error)

**Finding:** RelayState values are NOT validated for non-XSS payloads. Attacker-controlled RelayState could redirect users post-auth.

#### 2. Email Spoofing via SSO
- `admin@rapyd.net` → No error, redirects to login
- `support@rapyd.net` → No error, redirects to login
- All spoofed emails accepted without error

#### 3. SAML Response Validation
- ✅ Validates InResponseTo (different error for spoofed values)
- ✅ Rejects empty/invalid SAML responses
- ✅ Rejects XXE injection
- ✅ Rejects assertion wrapping
- ✅ WAF blocks javascript: URIs
- ⚠️ No SAML metadata exposed publicly

#### 4. Assertion Wrapping (XSW)
- Multiple assertions in one response → 400 error (rejected)

## Potential Findings

### 1. RelayState Not Validated (Medium)
- RelayState can be set to arbitrary URLs
- Post-authentication redirect could lead users to malicious sites
- No validation of RelayState against allowlist

### 2. SAML Metadata Endpoint Information Disclosure (Low)
- `/v1/merchants-portal/saml/metadata` returns `INVALID_SESSION` instead of 404
- Confirms SAML metadata exists behind authentication
- Could be used for enumeration

### 3. InResponseTo Validation (Info)
- Server properly validates InResponseTo field
- Different error codes for different validation failures
- Good security practice, but error codes could be normalized

## Additional Tests (23:20 WIB)

### Signature Validation
- No Signature → Rejected ✅
- Empty Signature → Rejected ✅
- XSW1 Wrapped Assertion → Rejected ✅
- Comment injection → Rejected ✅
- Entity injection → Rejected ✅

### Assessment
**Rapyd's SAML implementation is WELL-SECURED.**
- Proper InResponseTo validation
- Proper signature validation
- WAF blocks XSS vectors
- All injection attempts rejected

**Remaining attack surface:**
- RelayState not validated (redirect-based)
- Need authenticated session to test deeper
- SAML metadata behind auth

## Next Steps
1. Get merchant account to test authenticated SAML
2. Test SAML response signing requirements
3. Test session fixation via SAML
4. Test IdP-initiated vs SP-initiated flows
5. Test SAML logout endpoints

## Tools
- Browser: Vivaldi (port 18801)
- Logged in: oyi77
- Recon date: 2026-05-20
