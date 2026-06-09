# Vulnerability: Admin Panel Publicly Accessible with SameSite=None Session Cookies

## Program
**Target:** Acorns Grow, Inc. (@acorns)
**URL:** https://api.acorns.com/sign_in
**Platform:** Bugcrowd
**Scope:** *.acorns.com (in scope), graphql.acorns.com (in scope)
**Safe Harbor:** Full

## Summary
The admin login panel at `api.acorns.com/sign_in` is publicly accessible without authentication. Session cookies are set with `SameSite=None`, allowing cross-site request forgery and potential session hijacking. The CSP policy permits `unsafe-inline` and `unsafe-eval` in `script-src`, further weakening protections.

## Severity
**CVSS v3.1:** 5.4 (Medium)
**CWE:** CWE-1004 (Sensitive Cookie Without 'SameSite' Attribute)
**Bug Bounty Severity:** P3

## Affected Assets
- https://api.acorns.com/sign_in
- https://api-app.acorns.com/sign_in
- https://api-mobile.acorns.com/sign_in

## Steps to Reproduce

### Step 1: Access admin login panel without authentication
```bash
curl -s -m 10 "https://api.acorns.com/sign_in"
```

**Result:** Server returns HTTP 200 with full Devise login form (3214 bytes).

### Step 2: Extract session cookie
```bash
curl -sI -m 5 "https://api.acorns.com/sign_in" | grep -i set-cookie
```

**Result:**
```
set-cookie: _session_id=2860704c97a9ab53f525c87655fad1cd; path=/; secure; HttpOnly; SameSite=None
```

The `SameSite=None` attribute allows the cookie to be sent in cross-origin requests.

### Step 3: Verify CSP allows inline script execution
```bash
curl -sI -m 5 "https://api.acorns.com/" | grep -i content-security-policy
```

**Result:**
```
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' apis.google.com www.google-analytics.com; style-src 'self' 'unsafe-inline'
```

`unsafe-inline` and `unsafe-eval` in `script-src` allow arbitrary JavaScript execution if any injection point exists.

### Step 4: Confirm Sidekiq panel exposure
```bash
curl -sI -m 5 "https://api.acorns.com/sidekiq"
```

**Result:** HTTP 302 redirect to `https://admin.acorns.com:443/sign_in?locale=en` with same `SameSite=None` cookie. Confirms Sidekiq background job processor is deployed.

### Step 5: Health endpoint leaks server info
```bash
curl -s -m 5 "https://api.acorns.com/health"
```

**Result:**
```
Health Check Passed @ Wed, 20 May 2026 09:00:11 -0700
```

Leaks server timezone (PDT, -0700 offset).

## Proof of Concept

### Request
```http
GET /sign_in HTTP/1.1
Host: api.acorns.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml
Connection: keep-alive
```

### Response
```http
HTTP/2 200 OK
content-type: text/html; charset=utf-8
set-cookie: _session_id=2860704c97a9ab53f525c87655fad1cd; path=/; secure; HttpOnly; SameSite=None
x-request-id: 2db06377-3c4a-4b4a-bb35-44aa5945a025
x-runtime: 0.003643
content-security-policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' ...
```

### Response Body (3214 bytes)
```html
<form class="simple_form new_user" id="new_user" action="/sign_in?locale=en" accept-charset="UTF-8" method="post">
  <input name="utf8" type="hidden" value="&#x2713;" />
  <input type="hidden" name="authenticity_token" value="0/dLdwpPU34j5xWCdPEPcQ5/DlNc0Ws5TG14wfhUbpzom5NDBp0zK1xOLMXk5WNEn1FN54HfehNmzf0NYrCMMw==" />
  <input class="form-control string email optional" autocomplete="off" autofocus="autofocus" placeholder="Email" type="email" name="user[email]" id="user_email" />
  <input class="form-control password optional" placeholder="Password" type="password" name="user[password]" id="user_password" />
  <input type="submit" name="commit" value="Sign In" class="btn btn-success btn-block" data-disable-with="Sign In" />
</form>
```

### Screenshot
Admin panel screenshot attached showing publicly accessible login form.

## Impact

### Direct Impact
1. Admin login form exposed to unauthenticated users
2. `SameSite=None` cookies enable cross-site session attacks
3. CSP `unsafe-inline` + `unsafe-eval` weakens XSS protections
4. Server info leaked via health endpoint and response headers

### Attack Scenario
```
1. Attacker discovers admin panel at api.acorns.com/sign_in
2. Crafts malicious page that makes cross-site requests to api.acorns.com
3. Victim (Acorns employee) visits attacker's page while authenticated
4. Session cookie sent cross-site due to SameSite=None
5. Attacker captures session token or performs actions as victim
```

### Business Impact
- Unauthorized access to admin panel login page
- Potential session hijacking of admin users
- Information disclosure (server timezone, request IDs, Sidekiq presence)
- Weakened security posture for a financial services platform

## Remediation

### Immediate (1-2 days)
1. Restrict `/sign_in` and `/sidekiq` to internal IPs or VPN
2. Change session cookie to `SameSite=Strict` or `SameSite=Lax`
3. Remove `unsafe-inline` and `unsafe-eval` from CSP `script-src`

### Short-term (1-2 weeks)
1. Implement IP allowlisting for all admin endpoints
2. Add rate limiting on login attempts
3. Remove server info from health endpoint response
4. Strip `x-request-id` and `x-runtime` headers in production

### Long-term
1. Implement network-level access control (VPN/bastion)
2. Add MFA for admin authentication
3. Use CSP nonces instead of `unsafe-inline`
4. Security audit of all admin-adjacent endpoints

## References
- OWASP Session Management: https://owasp.org/www-community/attacks/Session_hijacking_attack
- CWE-1004: https://cwe.mitre.org/data/definitions/1004.html
- MDN SameSite cookies: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite

## Evidence
- `pocs/admin_page.html` — Full HTML login form (3214 bytes)
- `pocs/acorns_admin.png` — Screenshot of admin panel
- Raw HTTP headers captured in Steps 2, 3, 4, 5

---
*Report generated: 2026-05-20 | Researcher: oyi77 | Bugcrowd: Acorns Grow, Inc.*
