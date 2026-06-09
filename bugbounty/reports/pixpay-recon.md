# Pixpay Recon — 2026-05-20 23:35 WIB

## Target
- **Program:** Acorns (Bugcrowd) — includes Pixpay
- **URL:** https://www.pixpay.fr/
- **Tech:** Webflow, CloudFront CDN

## Findings

### 1. Sensitive Files Exposed (403 Blocked)
Multiple sensitive files return 403 from CloudFront (exist but blocked):

| File | Status | Risk |
|------|--------|------|
| `.env` | 403 | Environment variables may contain credentials |
| `phpinfo.php` | 403 | PHP info page (information disclosure) |
| `.htaccess` | 403 | Apache configuration |
| `web.config` | 403 | IIS configuration |
| `wp-login.php` | 403 | WordPress login (CMS disclosure) |

**Note:** Files are blocked by CloudFront but exist on origin server.

### 2. Server Error on manifest.json
- `manifest.json` returns 500 error
- Indicates server misconfiguration
- Error message: "Something unexpected happened"

### 3. Hidden Paths from robots.txt
```
Disallow: /lp/parent/noel-2025
Disallow: /lp/parent/noel-2025-newsletter
```

### 4. Multi-domain Infrastructure
- pixpay.fr (French)
- pixpay.es (Spanish)
- pixpay.it (Italian)
- website.pixpay.app (app domain)

### 5. Security Headers
- ✅ HSTS: max-age=31536000; includeSubDomains; preload
- ✅ CSP: frame-ancestors 'self'
- ✅ X-Frame-Options: SAMEORIGIN
- ❌ No CORS headers (good)

## Assessment
- **Severity:** Low/Informational
- **Finding:** Sensitive files exist on origin but blocked by CDN
- **Impact:** Limited (files not directly accessible)
- **Recommendation:** Remove sensitive files from origin server

## Next Steps
1. Test if CloudFront can be bypassed via origin IP
2. Check for other exposed files
3. Test Pixpay app for vulnerabilities
