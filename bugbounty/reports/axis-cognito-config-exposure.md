# AWS Cognito Configuration Exposure via Public JavaScript Bundle

## Program
**Target:** axis.com (Axis OS Public Bug Bounty)
**URL:** https://admin.dev.audiomanager.axis.com/
**Bounty Range:** $500 - $40,000

## Summary
The Axis AudioManager development portal at `admin.dev.audiomanager.axis.com` exposes AWS Cognito User Pool configuration in its publicly accessible JavaScript bundle. This allows an attacker to extract the User Pool ID, Client ID, and application architecture details, enabling targeted attacks against the authentication infrastructure.

## Severity
**CVSS v3.1:** 4.3 (Medium) — AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

## Affected Asset
- `https://admin.dev.audiomanager.axis.com/` (Development Portal - "Claudio Admin Tool")
- JS Bundle: `/assets/index-DhvL3_B2.js`

## Steps to Reproduce

### Step 1: Access the development portal
Navigate to:
```
https://admin.dev.audiomanager.axis.com/
```

### Step 2: Locate the JavaScript bundle
View page source and find the main JS bundle:
```html
<script type="module" crossorigin src="/assets/index-DhvL3_B2.js"></script>
```

### Step 3: Extract Cognito configuration
Access the JS bundle directly:
```
https://admin.dev.audiomanager.axis.com/assets/index-DhvL3_B2.js
```

Search for the Cognito configuration object:
```javascript
const Yy = {
    USER_POOL_ID: "eu-west-1_fsfwD9fwE",
    USER_POOL_APP_CLIENT_ID: "4vituhli2m4ab10k69eeqc1839"
};
```

### Step 4: Verify the User Pool ID is valid
The User Pool ID format `eu-west-1_XXXXX` identifies:
- **Region:** eu-west-1 (Ireland)
- **Pool ID:** fsfwD9fwE

## Impact

### Direct Impact
1. **User Enumeration:** An attacker can use the User Pool ID to query Cognito for user existence via `AWS CognitoIdentityProvider Service.InitiateAuth` or `SignUp` calls
2. **Targeted Phishing:** Knowing the exact Cognito pool allows crafting convincing phishing pages that mimic the real login flow
3. **Architecture Disclosure:** Reveals the application uses AWS Amplify + Cognito for authentication, Apollo GraphQL for API, and is hosted on CloudFront/S3
4. **Brute Force Potential:** With the Client ID, an attacker can attempt credential stuffing against the Cognito endpoint

### Attack Chain
```
Cognito Config (JS) → User Enumeration → Credential Stuffing → Account Takeover
```

### Verified Attack Proof
```bash
# Verify Cognito User Pool exists
curl -s -X POST https://cognito-idp.eu-west-1.amazonaws.com/ \
  -H "X-Amz-Target: AWSCognitoIdentityProviderService.SignUp" \
  -H "Content-Type: application/x-amz-json-1.1" \
  -d '{
    "ClientId": "4vituhli2m4ab10k69eeqc1839",
    "Username": "test_recon",
    "Password": "***",
    "UserAttributes": [{"Name": "email", "Value": "test@example.com"}]
  }'

# Response confirms pool exists:
# {"__type":"NotAuthorizedException","message":"SignUp is not permitted for this user pool"}
```

## Additional Findings on Same Asset

### Exposed GraphQL Endpoint
The JS bundle also reveals a GraphQL API endpoint:
```
https://api.admin.dev.audiomanager.axis.com/graphql
```

This endpoint requires authentication but reveals its existence and technology (Apollo Server) via error messages:
```json
{
  "errors": [{
    "errorType": "UnauthorizedException",
    "message": "Valid authorization header not provided."
  }]
}
```

### Technology Stack Exposed
- **Frontend:** React + Vite
- **Auth:** AWS Amplify + Cognito
- **API:** Apollo GraphQL Client v3.14.0
- **Hosting:** Amazon CloudFront + S3
- **UI Framework:** Fluent UI (Microsoft)

## Remediation
1. **Remove Cognito config from public JS:** Use environment variables injected at build time, not hardcoded in client-side code
2. **Restrict dev portal access:** Implement IP allowlisting or VPN requirement for `*.dev.audiomanager.axis.com`
3. **Add CSP headers:** The admin portal is missing Content-Security-Policy
4. **Rotate Cognito Client ID:** If the dev portal should not be public, rotate the compromised credentials

## Evidence
- Screenshot of JS bundle showing Cognito config (attached)
- curl response confirming Cognito pool exists

## References
- [OWASP - Information Disclosure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [AWS Cognito Security Best Practices](https://docs.aws.amazon.com/cognito/latest/developerguide/security-best-practices.html)
