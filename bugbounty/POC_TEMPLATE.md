# PoC Template — Proof of Concept

> Use this template for every finding

---

## PoC Structure

### 1. Title
```
[CWE-XXX] Clear Description of Vulnerability
```

### 2. Summary
```
1-2 sentences explaining what the vulnerability is and why it matters.
```

### 3. Affected URL
```
https://target.com/vulnerable/endpoint
```

### 4. Steps to Reproduce

#### Step 1: [Action Description]
```bash
curl -X GET "https://target.com/vulnerable/endpoint" \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json"
```

#### Step 2: [Action Description]
```bash
curl -X POST "https://target.com/another/endpoint" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

#### Step 3: [Observe Result]
```
Expected result: [What should happen]
Actual result: [What actually happens]
```

### 5. Request/Response Evidence

#### Request
```http
GET /vulnerable/endpoint HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
User-Agent: Mozilla/5.0
```

#### Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Powered-By: Express

{
  "sensitive_data": "This should not be exposed",
  "user_id": 12345,
  "email": "user@example.com"
}
```

### 6. Screenshot
```
[Attach screenshot showing the vulnerability]
```

### 7. Impact Analysis

#### Direct Impact
1. [What can attacker do directly?]
2. [What data can be accessed?]
3. [What systems can be compromised?]

#### Attack Chain
```
Step 1: [Initial access]
    ↓
Step 2: [Escalation]
    ↓
Step 3: [Data exfiltration]
    ↓
Final: [Business impact]
```

#### Business Impact
- Financial: [Potential loss]
- Reputation: [Brand damage]
- Compliance: [Regulatory violations]

### 8. Remediation

#### Immediate Fix
```code
// What to change immediately
```

#### Long-term Fix
```
1. [Architectural change]
2. [Security control]
3. [Monitoring]
```

### 9. References
- OWASP: [Link]
- CWE: [Link]
- CVE: [If applicable]

---

## PoC Examples

### Example 1: Information Disclosure
```bash
# PoC: Access internal API without authentication
curl -s "https://internal-api.target.com/users" | jq .

# Response
{
  "users": [
    {"id": 1, "email": "admin@target.com", "role": "admin"},
    {"id": 2, "email": "user@target.com", "role": "user"}
  ]
}
```

### Example 2: CSRF Token Extraction
```bash
# Step 1: Extract CSRF token
CSRF=$(curl -s "https://target.com/login" | grep -oE 'csrf_token" value="[^"]*"' | cut -d'"' -f3)

# Step 2: Use token for authenticated request
curl -X POST "https://target.com/transfer" \
  -H "X-CSRF-Token: $CSRF" \
  -d "amount=1000&to=attacker@email.com"
```

### Example 3: API Key Exposure
```bash
# PoC: Extract API key from JavaScript
curl -s "https://target.com/app.js" | grep -oE 'apiKey:"[^"]*"'

# Response
apiKey: "sk_live_abc123def456"

# Step 2: Use API key
curl -s "https://api.target.com/v1/users" \
  -H "Authorization: Bearer sk_live_abc123def456"
```

### Example 4: Swagger File Exposure
```bash
# PoC: Access swagger file
curl -s "https://target.com/swagger.json" | jq '.paths | keys'

# Response
[
  "/api/v1/users",
  "/api/v1/admin/users",
  "/api/v1/internal/config"
]
```

---

## PoC Quality Checklist

### Good PoC Includes:
- [ ] Clear, reproducible steps
- [ ] Actual request/response
- [ ] Screenshot or video
- [ ] Impact explanation
- [ ] Remediation suggestions

### Bad PoC Includes:
- ❌ "I found a vulnerability"
- ❌ No evidence
- ❌ No impact explanation
- ❌ No remediation
- ❌ Automated scan results only

---

## Severity Matrix

### P1 (Critical) — $5K-$250K
- Remote Code Execution
- Authentication Bypass
- SQL Injection
- SSRF to Internal Network
- Full Account Takeover

### P2 (High) — $1K-$5K
- Stored XSS
- IDOR (Access Other Users)
- CSRF (Critical Actions)
- Payment Bypass

### P3 (Medium) — $500-$1K
- Reflected XSS
- Information Disclosure
- Weak Password Policy
- Missing Rate Limiting

### P4 (Low) — $100-$500
- Missing Security Headers
- Version Information Leak
- Verbose Error Messages

### P5 (Info) — $0-$100
- Best Practices
- Minor Issues
- Informational

---

*Template created by Vilona — Use for every finding*
