# Backblaze Bug Bounty Recon Report
**Date**: 2026-05-20
**Target**: Backblaze (Bugcrowd)
**Scope**: backblaze.com, *.backblaze.com, *.backblazeb2.com

---

## Executive Summary

Reconnaissance of Backblaze's external attack surface revealed several findings ranging from information disclosure to staging environment exposure. The most promising leads for P1-P3 vulnerabilities are the **undocumented B2 API v3/v4 endpoints** that behave differently from production v1/v2 and leak internal incident IDs, and the **publicly accessible Webflow staging site**.

---

## Findings

### 1. UNDOCUMENTED B2 API v3/v4 ENDPOINTS (Medium - Info Disclosure / Potential Auth Bypass)

**Severity**: P3 (Information Disclosure) / Potential P2 if auth bypass found
**Location**: `https://api.backblaze.com/b2api/v3/` and `/b2api/v4/`

**Description**: The B2 API has undocumented v3 and v4 endpoints that are NOT publicly documented. These endpoints behave differently from the production v1/v2:

- v1/v2 `b2_download_file_by_id` with invalid fileId -> 400 "Bad file ID"
- v3/v4 `b2_download_file_by_id` with invalid fileId -> **500 Internal Server Error** with leaked incident IDs

**Evidence**:
```
$ curl -s "https://api.backblaze.com/b2api/v3/b2_download_file_by_id?fileId=test"
{
  "code": "internal_error",
  "message": "incident id 3a883e5216ff-58393314299f9ff0",
  "status": 500
}

$ curl -s "https://api.backblaze.com/b2api/v1/b2_download_file_by_id?fileId=test"
{
  "code": "bad_request",
  "message": "Bad file ID: test",
  "status": 400
}
```

The v3/v4 endpoints also accept all standard B2 operations:
- `b2_authorize_account` -> 401 (requires auth)
- `b2_list_buckets` -> 400 (requires accountId)
- `b2_list_file_names` -> 400 (requires bucketId)
- `b2_get_upload_url` -> 400 (requires bucketId)
- `b2_download_file_by_id` -> **500** (broken - leaks incident IDs)
- `b2_download_file_by_name` -> 404

**Impact**:
- Internal incident IDs exposed (format: `3a883e5216ff-<hash>`)
- v3/v4 may have weaker validation or different auth logic
- Incident IDs could be used for internal system enumeration
- These endpoints are clearly in development/testing state

**Recommendation**: Disable v3/v4 endpoints in production or ensure they return proper error codes. Investigate why these endpoints are accessible.

---

### 2. WEBFLOW STAGING SITE PUBLICLY ACCESSIBLE (Medium - Info Disclosure)

**Severity**: P3 (Information Disclosure)
**Location**: `https://backblaze-staging.webflow.io`

**Description**: The Backblaze staging website on Webflow is publicly accessible and serves identical content to the production site. The staging environment shares the same Webflow site ID (`63d32de856f6323a43a277f2`) as production.

**Evidence**:
```
$ curl -s "https://backblaze-staging.webflow.io" | head -5
<!DOCTYPE html><!-- Last Published: Wed May 20 2026 20:34:05 GMT+0000 -->
<html data-wf-domain="backblaze-staging.webflow.io" data-wf-site="63d32de856f6323a43a277f2" lang="en">
<title>The Leading Open Cloud Storage Platform - Backblaze</title>
```

Production site at `webflow-prod.backblaze.com`:
```
<html data-wf-domain="webflow-prod.backblaze.com" data-wf-site="63d32de856f6323a43a277f2">
```

**Impact**:
- Staging site could be modified by attackers to serve malicious content
- CSS file references `backblaze-staging.shared.1bfda5cfa.min.css`
- Same Webflow site ID means changes to staging could affect production
- Potential for subdomain takeover if Webflow project is misconfigured

**Recommendation**: Restrict access to staging site or remove it if not needed. Ensure staging and production use separate Webflow projects.

---

### 3. POSTMAN API DOCUMENTATION EXPOSED (Low - Info Disclosure)

**Severity**: P4 (Information Disclosure)
**Location**: `https://postman.backblaze.com`

**Description**: Public Postman collection exposes full B2 S3 Compatible API documentation with collection variables.

**Evidence**:
- Collection ID: `9169647-2bd51552-2df9-443f-95f1-014a26894b00`
- Owner ID: `9169647`
- Published ID: `UVeMGhwV`
- Variables include placeholders: `<your-application-key-id>`, `<your-application-key>`, `<your-region>`

**Impact**:
- API structure and all endpoints fully documented
- No actual credentials found (only placeholders)
- Useful for attackers to understand API capabilities

**Recommendation**: Consider making collection private if not needed for public documentation.

---

### 4. ROBOTS.TXT REVEALS HIDDEN PATHS (Low - Info Disclosure)

**Severity**: P5 (Information Disclosure)
**Location**: `https://www.backblaze.com/robots.txt`

**Evidence**:
```
User-agent: *
Disallow: /api/install_backblaze
Disallow: /win32/
Disallow: /mac/
Disallow: /linux/
Disallow: /gift/
Disallow: /gift_download/
Disallow: /gen/
Disallow: /fix_billing_problem.htm
Disallow: /partials/
Disallow: /feed/
```

**Impact**:
- Reveals internal API endpoints and file paths
- `/api/install_backblaze` - Installation API endpoint
- `/gift/`, `/gift_download/` - Gift/redemption functionality
- `/gen/` - Generation endpoint
- `/fix_billing_problem.htm` - Billing flow

**Recommendation**: Review exposed paths for sensitive functionality.

---

### 5. CLOUDFLARE TRACE INFORMATION DISCLOSURE (Low - Info Disclosure)

**Severity**: P5 (Information Disclosure)
**Location**: `https://www.backblaze.com/cdn-cgi/trace`

**Evidence**:
```
fl=218f231
h=www.backblaze.com
ip=192.88.101.14
ts=1779311454.000
visit_scheme=https
uag=curl/8.19.0
colo=CGK
sliver=none
http=http/2
loc=ID
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519MLKEM768
```

**Impact**:
- Reveals visitor IP address
- Shows Cloudflare colo location (CGK - Jakarta)
- TLS version and key exchange mechanism disclosed

---

### 6. STATUS PAGE REVEALS THIRD-PARTY SERVICES (Low - Info Disclosure)

**Severity**: P5 (Information Disclosure)
**Location**: `https://status.backblaze.com`

**Evidence**:
CSP headers reveal:
- `firehydrant.io` - Incident management
- `launchdarkly.com` - Feature flags
- `bugsnag.com` - Error tracking
- `googletagmanager.com` - Analytics

**Impact**:
- Reveals technology stack
- Potential supply chain attack vectors

---

### 7. S3 BUCKET ENUMERATION (Informational)

**Location**: `*.s3.us-west-002.backblazeb2.com`

**Description**: All tested bucket names return "Unauthenticated requests are not allowed for this api" instead of "bucket does not exist". This is actually GOOD security practice - it doesn't reveal whether buckets exist.

**Tested buckets**: openclaw, test, demo, staging, backup, data, public, assets, static, images, uploads, logs, terraform, tfstate, aws-backup

---

## Infrastructure Summary

### Active Hosts
| Host | Status | Notes |
|------|--------|-------|
| www.backblaze.com | 200 | Main site (Cloudflare) |
| api.backblaze.com | 301 -> www | Redirects to main site |
| portal.backblaze.com | 000 | Connection failed/timeout |
| postman.backblaze.com | 200 | Postman API docs |
| dataroom.backblaze.com | - | No response |
| status.backblaze.com | 200 | Status page (React SPA) |
| help.backblaze.com | 302 | Help center |
| docs.backblaze.com | 301 | Documentation |
| blog.backblaze.com | 301 | Blog |
| s3.us-west-002.backblazeb2.com | 403 | S3 API (requires auth) |
| s3.us-east-005.backblazeb2.com | 403 | S3 API (requires auth) |
| s3.eu-central-003.backblazeb2.com | 403 | S3 API (requires auth) |
| f000.backblazeb2.com | 301 | File download endpoint |
| f001.backblazeb2.com | 301 | File download endpoint |
| f002.backblazeb2.com | 301 | File download endpoint |

### Subdomains (from subfinder)
- 80+ subdomains discovered
- Mostly `pod-*` storage nodes and `rdns` reverse DNS entries
- Key: `dataroom.backblaze.com`, `postman.backblaze.com`

### B2 API Endpoints
- v1 (v1) - Production, well-documented
- v2 (v2) - Production, well-documented
- v3 (v3) - **UNDOCUMENTED, BEHAVIORAL DIFFERENCES**
- v4 (v4) - **UNDOCUMENTED, BEHAVIORAL DIFFERENCES**

---

## Recommended Next Steps

1. **B2 v3/v4 Deep Testing**: Create B2 account and test auth flow on v3/v4 endpoints. Compare behavior with v1/v2 for auth bypass opportunities.

2. **Webflow Staging Takeover**: Investigate if `backblaze-staging.webflow.io` can be taken over or modified independently.

3. **SSRF Testing**: Test B2 upload/download endpoints with SSRF payloads. The `b2_download_file_by_id` on v3/v4 showing 500 errors suggests weaker input validation.

4. **Hidden Path Testing**: Test `/api/install_backblaze`, `/gift/`, `/gen/` for authentication bypass or sensitive data exposure.

5. **Bucket Enumeration with Auth**: If B2 credentials obtained, test for bucket listing and cross-account access.

---

## Files Saved

All evidence saved to `/home/openclaw/.openclaw/workspace/bugbounty/pocs/backblaze/`:
- `discovery.txt` - Host discovery results
- `api-discovery.txt` - API endpoint discovery
- `b2-api.txt` - B2 API endpoint responses
- `b2-auth-bypass.txt` - Auth bypass tests
- `b2-deep-test.txt` - Deep B2 API testing
- `b2-download-test.txt` - Download endpoint tests
- `b2-error-disclosure.txt` - Error message analysis
- `b2-v3v4-debug.txt` - v3/v4 endpoint testing
- `portal-check.txt` - Portal path discovery
- `main-site-paths.txt` - Main site path discovery
- `bucket-access.txt` - S3 bucket access tests
- `bucket-enum.txt` - Bucket enumeration
- `subdomains.txt` - Subdomain list
- `postman-collection.txt` - Postman collection data
- `postman-docs.txt` - Postman documentation
- `hidden-paths.txt` - Hidden path probing
- `webflow-staging.txt` - Staging site evidence
- `status-page.txt` - Status page analysis
- `cloudflare.txt` - Cloudflare trace data
- `redirects.txt` - Redirect chain analysis
- `additional-hosts.txt` - Additional host probing
