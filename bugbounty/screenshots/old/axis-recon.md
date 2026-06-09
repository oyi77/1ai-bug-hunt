# AXIS OS Recon Report
**Date:** 2026-05-20
**Program:** https://bugcrowd.com/engagements/axis-os-public
**Bounty:** $500 - $40,000
**Scope:** axis.com

## Findings

### Missing Security Headers
- X-Frame-Options: NOT SET
- X-Content-Type-Options: NOT SET
- Strict-Transport-Security: NOT SET
- Content-Security-Policy: NOT SET

### CORS Wildcard (*) on 404 Pages
- Some axis.com 404 pages return Access-Control-Allow-Origin: *
- Not confirmed on valid endpoints yet

### Security.txt Present
- https://www.axis.com/.well-known/security.txt exists ✅

### Further Testing Needed
- Firmware analysis (AXIS OS is for IP cameras)
- Default credential testing on management interfaces
- Check for exposed RTSP streams
