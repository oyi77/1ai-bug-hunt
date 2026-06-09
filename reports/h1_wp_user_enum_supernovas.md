# H1 Report: WordPress REST API User Enumeration on coaching.supernovas.indrive.com

## Quick Submit Instructions

1. **Open incognito/private browser**, go to https://hackerone.com/indrive/reports/new
2. **Login** with: grahainsanmandiri@gmail.com / Utanglunas100% + 2FA (TOTP)
3. **Fill the form** with the details below:

---

**Title:**
```
WordPress REST API User Enumeration (CVE-2023-5561) on coaching.supernovas.indrive.com exposes admin account
```

**Vulnerability Information:**
```
## Summary

The WordPress REST API on coaching.supernovas.indrive.com exposes a user enumeration vulnerability (CVE-2023-5561). An unauthenticated attacker can retrieve registered users including the admin account.

## Steps to Reproduce

1. Send GET request:
   curl -s "https://coaching.supernovas.indrive.com/wp-json/wp/v2/users?search=@"

2. Response returns all registered users:
```json
[{"id":1,"name":"admin adminov","slug":"zhumirovgmail-com","avatar_urls":{"24":"https://secure.gravatar.com/avatar/...","48":"https://secure.gravatar.com/avatar/...","96":"https://secure.gravatar.com/avatar/..."}}]
```

3. Admin also accessible directly:
   curl -s "https://coaching.supernovas.indrive.com/wp-json/wp/v2/users/1"

4. Author archive confirms existence:
   https://coaching.supernovas.indrive.com/author/zhumirovgmail-com/

## Impact

User enumeration enabling targeted brute-force, credential-stuffing, and social engineering attacks against the admin account. The admin username, slug (derived from email zhumirov@gmail.com), and Gravatar hash are exposed.

Login page has reCAPTCHA but REST API has no rate limiting.

## Remediation

Disable the REST API user endpoint or restrict via security plugin.

## Supporting Material

- Asset in scope: coaching.supernovas.indrive.com (confirmed via H1 GraphQL API — eligible_for_bounty: true, max_severity: critical)
- CVE: CVE-2023-5561
- Also listed in scope: www.supernovas.indrive.com (same domain hierarchy)
```

**Severity:** Medium

**Impact:** User enumeration exposes admin username enabling targeted brute-force and credential-stuffing attacks.

**Remediation Advice:** Disable REST API user endpoint or restrict via security plugin.

---

## Evidence Files Saved

| File | Description |
|------|-------------|
| `/home/openclaw/projects/bugbounty/scans/indrive/evidence_coaching_supernovas.md` | Full reproduction evidence |
| `/tmp/h1_report_mutation.json` | GraphQL mutation payload |
| `/tmp/h1_playwright_submit.py` | Auto-submission script (blocked by Cloudflare) |

---

## Average Bounty for Medium on inDrive: **$309**
