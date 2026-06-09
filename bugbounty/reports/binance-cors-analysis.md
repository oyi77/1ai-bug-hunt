# Binance CORS Analysis — 2026-05-20 21:30 WIB

## Summary
Binance.com and api.binance.com return `Access-Control-Allow-Origin: *` on all endpoints.

## Findings

### Public API (api.binance.com)
- `/api/v3/ping` — 200, CORS: * (expected, public endpoint)
- `/api/v3/time` — 200, CORS: * (expected, public endpoint)
- `/api/v3/exchangeInfo` — 200, CORS: * (expected, public endpoint)
- `/api/v3/ticker/price` — 200, CORS: * (expected, public endpoint)
- `/api/v3/ticker/24hr` — 200, CORS: * (expected, public endpoint)

### Authenticated API (api.binance.com)
- `/api/v3/account` — 400 (requires API key + signature)
- `/api/v3/myTrades` — 400 (requires API key + signature)
- `/api/v3/order` — 400 (requires API key + signature)
- `/api/v3/openOrders` — 400 (requires API key + signature)

### Main Domain (www.binance.com)
- All endpoints return 202 (WAF challenge)
- CORS: * on all responses
- `x-amzn-waf-action: challenge` header present

## Assessment
- **Public API CORS: *** — Expected behavior for public APIs designed for cross-origin access
- **Authenticated API CORS: *** — Not exploitable because endpoints require API key + HMAC signature
- **Main Domain CORS: *** — WAF challenge responses, not real data

## Conclusion
- **Severity:** Informational/None
- **Exploitability:** None (public API designed for cross-origin access, authenticated endpoints require cryptographic signatures)
- **Recommendation:** No action needed (expected behavior for public trading APIs)

## Status
- [x] Analyzed
- [ ] Submit — NOT SUBMITTED (expected behavior)
