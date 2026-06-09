# Blockchain.com Recon Report
**Date:** 2026-05-20
**Program:** https://bugcrowd.com/engagements/blockchain-dot-com
**Bounty:** $100 - $10,000

## Findings

### Missing Security Headers on login.blockchain.com
- X-Frame-Options: NOT SET
- Referrer-Policy: NOT SET  
- Permissions-Policy: NOT SET
- Cross-Origin-Opener-Policy: NOT SET
- CSP frame-ancestors present (partial protection)

### Technology Stack Exposed
- Next.js (x-powered-by header)
- x-request-id headers leaked on all subdomains

### Subdomains Found (all 200)
- api.blockchain.com
- wallet.blockchain.com
- login.blockchain.com
- exchange.blockchain.com

### GraphQL Endpoint
- api.blockchain.com/graphql returns 200 (HTML page, not active GraphQL)
- No introspection enabled

### Security.txt Present
- https://blockchain.com/.well-known/security.txt exists ✅
