# Zendesk Recon Report
**Date:** 2026-05-20
**Program:** https://bugcrowd.com/engagements/zendesk
**Bounty:** $100 - $50,000
**Scope:** bb-acidburn-01.zendesk.com (test instance)

## Findings

### Test Instance Accessible
- https://bb-acidburn-01.zendesk.com/ returns 200
- Login page at /admin accessible (requires auth)
- CSP with nonce-based script loading

### Missing Security Headers
- X-Content-Type-Options: NOT SET
- X-XSS-Protection: NOT SET
- Referrer-Policy: NOT SET
- Permissions-Policy: NOT SET
- Strict-Transport-Security: NOT SET on API responses

### API Returns 403 (Properly Secured)
- /api/v2/* endpoints return 403 without auth
- Security.txt returns 403

### Cloudflare Protected
- Uses Cloudflare CDN/WAF
