# PoC Template — Bugcrowd Submission

> **Rule:** NO PROOF = NO SUBMIT. Every submission MUST include at least one of:
> - curl command with actual response
> - Browser screenshot
> - HTTP request/response capture
> - Video walkthrough

---

## PoC Format Options

### Option 1: curl Command (Preferred for API/HTTP issues)

```bash
# COMMAND — Copy-paste ready
curl -s -i "https://TARGET/vulnerable-endpoint" \
  -H "Origin: https://evil.com" \
  -H "User-Agent: Mozilla/5.0" \
  --connect-timeout 10 2>&1 | head -50

# EXPECTED OUTPUT (paste actual output below)
```

**Actual Output:**
```http
HTTP/2 200 OK
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
content-type: application/json

{"users": [{"email": "victim@example.com", "ssn": "123-45-6789"}]}
```

### Option 2: Browser-Based PoC

**Steps:**
1. Open browser DevTools (F12) → Console
2. Paste this code:
```javascript
fetch('https://TARGET/api/user/123', {credentials: 'include'})
  .then(r => r.json())
  .then(data => document.body.innerText = JSON.stringify(data, null, 2))
```
3. Observe: [describe what appears]

**Screenshot:** [attach screenshot]

### Option 3: HTTP Request/Response Pair

```http
REQUEST:
GET /api/admin/users HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Cookie: session=abc123
User-Agent: Mozilla/5.0

RESPONSE:
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-Id: 12345

{"users": [{"id": 1, "email": "admin@target.com", "role": "admin"}]}
```

---

## Evidence Checklist

Before submitting, ensure you have:

- [ ] **Actual request** used (not hypothetical)
- [ ] **Actual response** received (not fabricated)
- [ ] **Redacted data** (mask real PII: use `victim***@example.com`)
- [ ] **Reproduction steps** numbered and exact
- [ ] **curl command** that anyone can copy-paste to verify
- [ ] **Screenshot** if browser-based (DevTools network tab works great)
- [ ] **Timestamp** of when you captured the evidence

---

## Common PoC Patterns

### Information Disclosure
```bash
# Show what's leaked
curl -s "https://TARGET/.env" | grep -iE "key|secret|token|password"
curl -s "https://TARGET/config.json" | python3 -m json.tool
curl -s "https://TARGET/debug/vars" | head -20
```

### CORS Misconfiguration
```bash
# Prove arbitrary origin is reflected
curl -sI "https://TARGET/api/data" -H "Origin: https://attacker.com" | grep -i "access-control"
```

### Missing Authentication
```bash
# Access admin endpoint without credentials
curl -s "https://TARGET/admin/users" | head -50
# vs authenticated (if you have an account)
curl -s "https://TARGET/admin/users" -H "Cookie: session=YOUR_SESSION" | head -50
```

### User Enumeration
```bash
# Show different responses for valid vs invalid users
curl -s "https://TARGET/api/login" -d '{"email":"real@target.com","password":"x"}' | head -20
curl -s "https://TARGET/api/login" -d '{"email":"fake@target.com","password":"x"}' | head -20
```

---

## PoC Quality Scale

| Level | What It Shows | Verdict |
|-------|--------------|---------|
| 🔴 **Weak** | "This endpoint exists" | Likely informational |
| 🟡 **Medium** | "This endpoint returns data" with curl proof | P4-P5 |
| 🟢 **Strong** | "This data is sensitive" with actual response | P3-P4 |
| 🟣 **Critical** | "This leads to account takeover / RCE" with full chain | P1-P2 |

---

*Remember: Triagers see 100+ reports. Make yours impossible to dismiss.*
