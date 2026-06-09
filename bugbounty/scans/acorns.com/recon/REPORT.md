# Recon Report: acorns.com
**Date:** 2026-05-20
**Tools:** katana, ffuf, curl

---

## 1. URLs Found (Katana - 200 raw, 67 unique)

### Core Pages
| URL | Notes |
|-----|-------|
| https://www.acorns.com/ | Main site |
| https://www.acorns.com/invest | Investment product |
| https://www.acorns.com/later | Retirement (IRA) |
| https://www.acorns.com/banking/ | Banking product |
| https://www.acorns.com/earn/ | Earn/rewards |
| https://www.acorns.com/early/ | Early (kids) product |
| https://www.acorns.com/early-invest/ | Early + Invest combo |
| https://www.acorns.com/money-manager/ | Money manager tool |
| https://www.acorns.com/pricing | Pricing page |
| https://www.acorns.com/learn/ | Content/blog |
| https://www.acorns.com/about/ | Company info |
| https://www.acorns.com/careers/ | Jobs |
| https://www.acorns.com/press/ | Press/media |
| https://www.acorns.com/security/ | Security page |
| https://www.acorns.com/our-pledge/ | Company pledge |
| https://www.acorns.com/invite/ | Referral program |

### Legal/Compliance Pages (numerous)
- /terms/, /privacy/, /disclosures/, /wrap-fee-brochure/
- /important-disclosures/, /accessibility/
- /documents-plain/acorns-privacy-policy-05192025/
- /documents-plain/acorns-privacy-policy-04022025/
- /early/privacy-notice/, /early/cardholder-terms/
- /early-invest-gifting-terms-of-use

### Early (Kids) Promotion Terms
- /early/a-minecraft-movie-promotion-terms-v2/
- /early/april-2026-promotion-terms/
- /early/roblox-gift-card-promo-terms/
- /early/maple-partnership-terms/
- /early/december-2025-promotion/
- /early/november-2025-promotion/
- And more promotional terms pages

### Subdomains Discovered
| Subdomain | Purpose |
|-----------|---------|
| app.acorns.com | Web application (login portal) |
| support.acorns.com | Help center (Zendesk) |
| signup.acorns.com | Registration flow |

### Third-Party Integrations
- **Google Tag Manager:** GTM-5Z5XQQ
- **Amplitude:** Experiment SDK (key: 5ccb29d8e22cd77a6a5f879142bc0c96)
- **RudderLabs:** Analytics (cdn.rudderlabs.com)
- **Microsoft Clarity:** Session recording
- **Adjust:** Attribution (app.adjust.com)
- **Impact.com:** Affiliate program
- **Nagich:** Accessibility overlay (aacdn.nagich.com)

### External References
- https://brokercheck.finra.org/firm/summary/168172 (FINRA broker check)
- https://www.sipc.org/ (SIPC member)
- https://www.fdic.gov/resources/deposit-insurance/
- https://www.cambr.com/bank-list (Banking partner list)

### Social Media
- Instagram: @acorns
- X/Twitter: @acorns
- Facebook: AcornsGrow
- YouTube: @AcornsGrow
- TikTok: @acorns

---

## 2. Directory Bruteforce (ffuf)

### Summary
- Total wordlist entries: 4,614 (dirb/common.txt)
- Status 200 (real hits): **1** (/favicon.ico)
- Status 403 (blocked): **4,477** (WAF blanket blocking)

### Finding: Aggressive WAF/CDN
Acorns uses a WAF (likely Cloudflare or similar) that returns **403 Forbidden** for virtually all unknown paths. Every path returns the same 403 response (134 bytes), indicating a blanket block rather than actual access control.

**No real directory exposure found.** The only 200 response was /favicon.ico (standard).

---

## 3. API Endpoint Scan

### Results (after following redirects)
| Path | Initial | Final | Notes |
|------|---------|-------|-------|
| /api | 301 | 404 | Not found |
| /api/v1 | 301 | 404 | Not found |
| /graphql | 301 | 404 | Not found |
| /swagger.json | 301 | 404 | Not found |
| /openapi.json | 301 | 404 | Not found |
| /.env | 403 | 403 | Blocked by WAF |
| /robots.txt | 301 | **200** | Exposed |
| /sitemap.xml | 301 | **200** | Exposed (1,200 URLs) |
| /security.txt | 301 | 404 | Not found |
| /.well-known/security.txt | 301 | 404 | Not found |

### Key Findings
- **No public API endpoints found** at common paths
- **/.env blocked** by WAF (good - not exposed)
- **robots.txt exposed** - reveals disallowed paths and sitemap locations
- **sitemap.xml exposed** - contains 1,200 URLs (massive attack surface)

---

## 4. robots.txt Analysis

```
Sitemap: https://www.acorns.com/sitemap.xml
Sitemap: https://www.acorns.com/sitemap-grow.xml

Disallow: /verizon
Disallow: /found-money-subscribe
Disallow: /submitted
Disallow: /redeem
Disallow: /foundmoney/terms
```

### Interesting Disallowed Paths
- `/verizon` - Legacy partner page?
- `/found-money-subscribe` - Old feature
- `/submitted` - Form submission page
- `/redeem` - Redemption flow
- `/foundmoney/terms` - Old terms page

---

## 5. sitemap.xml Analysis

- **Total URLs:** 1,200
- **CMS:** Zesty.io (detected from robots.txt comments)
- **Content includes:** Legal documents, product pages, promotional terms, plain-text document archives

### Notable URL Patterns
- `/documents-plain/*` - Plain text legal documents (versioned by date)
- `/early/*` - Kids product with many promotional terms
- `/program-agreement/` - Financial terms (recently updated 2026-04-30)

---

## 6. Attack Surface Summary

### High-Value Targets
1. **app.acorns.com** - Main web app (login portal)
2. **signup.acorns.com** - Registration flow
3. **support.acorns.com** - Zendesk help center
4. **Program agreement** - Financial compliance document (updated recently)

### Potential Areas for Further Investigation
1. **Zesty.io CMS** - Check for CMS-specific vulnerabilities
2. **Amplitude/RudderLabs keys** - May leak in JS bundles
3. **Adjust attribution links** - Open redirect potential
4. **GTM container** - Check for tag injection vulnerabilities
5. **Legacy disallowed paths** (/verizon, /foundmoney) - May have old code
6. **Plain document archives** - Versioned legal docs may reveal internal info
7. **Referral system** (/invite/) - Business logic testing

### Security Posture
- WAF aggressively blocks unknown paths (403 for everything)
- No public API endpoints exposed
- .env properly blocked
- No security.txt found (should be added per RFC 9116)
- Heavy third-party integration surface

---

## Files Saved
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/acorns.com/recon/urls.txt` - Raw katana URLs (200)
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/acorns.com/recon/urls-unique.txt` - Deduplicated URLs (67)
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/acorns.com/recon/dirs.txt` - ffuf filtered results
- `/home/openclaw/.openclaw/workspace/bugbounty/scans/acorns.com/recon/api-endpoints.txt` - API scan results
