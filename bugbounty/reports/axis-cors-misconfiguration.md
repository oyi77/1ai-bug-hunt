# Axis Communications — CORS Misconfiguration

## Summary
Axis.com (www.axis.com) returns `Access-Control-Allow-Origin: *` on multiple endpoints, including API paths, GraphQL, Swagger, and OAuth endpoints.

## Affected Endpoints
- `/api` — 404, CORS: *
- `/api/v1` — 404, CORS: *
- `/api/v2` — 404, CORS: *
- `/graphql` — 404, CORS: *
- `/swagger` — 404, CORS: *
- `/docs` — 404, CORS: *
- `/health` — 404, CORS: *
- `/status` — 404, CORS: *
- `/.well-known/openid-configuration` — 404, CORS: *
- `/oauth/authorize` — 404, CORS: *

## Impact
- Wildcard CORS allows any origin to make cross-origin requests to these endpoints
- If any endpoint returns sensitive data, it could be accessed by malicious websites
- Potential for CSRF attacks if authentication is cookie-based

## Severity
Low-Medium (all endpoints return 404, but the CORS policy is still misconfigured)

## Evidence
```
HTTP/1.1 404 Not Found
Access-Control-Allow-Origin: *
```

## Recommendation
- Restrict CORS to specific trusted origins
- Use `Access-Control-Allow-Origin: https://www.axis.com` instead of `*`
- Implement proper CORS preflight handling

## Status
- [ ] Submit to Bugcrowd (Axis OS program)
- [ ] Verify with authenticated endpoints
- [ ] Check for other Axis subdomains
