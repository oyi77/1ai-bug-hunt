#!/usr/bin/env python3
"""Browser-assisted bug-bounty scanner for high-value targets.
Uses cloakbrowser + system Firefox where possible. Falls back to curl.
"""
from __future__ import annotations
import json, re, subprocess, sys, time
from pathlib import Path
from urllib.parse import urljoin, urlparse

BASE = Path.home() / "projects" / "auto-bug-bounty"
TARGETS = {
    "bugbounty.ch": ["https://www.bugbounty.ch"],
    "bugcrowd.com": ["https://www.bugcrowd.com"],
    "intigriti.com": ["https://app.intigriti.com"],
    "yeswehack.com": ["https://yeswehack.com"],
    "hackerone.com": ["https://hackerone.com"],
    "hostpoint.ch": ["https://www.hostpoint.ch"],
    "proton.me": ["https://proton.me"],
    "swisscom.com": ["https://www.swisscom.com"],
}

CHECK_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
    "/np/security",
    "/security",
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
]


def probe(target: str, path: str, timeout: int = 15) -> dict:
    """Try a curl probe first (fast, no browser), then optional cloak fallback."""
    url = urljoin(target, path)
    try:
        proc = subprocess.run(
            ["curl", "-skL", "--max-time", str(timeout), "-D", "-", "-o", "/tmp/cloakbrowser_probe_body.txt", url],
            capture_output=True, text=True
        )
        headers = proc.stdout
        body_path = Path("/tmp/cloakbrowser_probe_body.txt")
        body = body_path.read_text(errors="ignore")[:4000] if body_path.exists() else ""
        status = None
        for line in headers.splitlines():
            if line.lower().startswith("http/"):
                status = int(line.split()[1]) if len(line.split()) > 1 else None
        return {"status": status, "headers": headers, "body": body, "error": None}
    except Exception as exc:  # noqa: BLE001
        return {"status": None, "headers": "", "body": "", "error": str(exc)}


def analyze(resp: dict) -> list[str]:
    flags: list[str] = []
    body = resp.get("body", "") or ""
    status = resp.get("status")
    ct = ""
    for line in (resp.get("headers") or "").splitlines():
        if line.lower().startswith("content-type:"):
            ct = line.split(":", 1)[1].strip().lower()
            break

    if status == 200:
        if "application/json" in ct and any(x in body for x in ["email", "emails", "contact", "security"]):
            flags.append("JSON_CONTACT_ENDPOINT")
        if "text/html" in ct:
            if re.search(r"<title>.*(404|not found|error).*</title>", body, re.I):
                flags.append("HTML_404")
            else:
                flags.append("HTML_OK")
        if "text/plain" in ct:
            if "contact:" in body or "security:" in body:
                flags.append("TXT_SECURITY_CONTACT")
        if not ct and body.strip():
            flags.append("RAW_BODY")
        if "index of /" in body.lower() or "parent directory" in body.lower():
            flags.append("DIR_LISTING")
        if "sql syntax" in body.lower() or "mysql_fetch" in body.lower():
            flags.append("SQL_ERROR")
        if "warning:" in body.lower() and "php" in body.lower():
            flags.append("PHP_WARNING")
    if status == 401:
        flags.append("AUTH_REQUIRED")
    if status == 403:
        flags.append("FORBIDDEN")
    if status == 301 and "location" in (resp.get("headers") or "").lower():
        flags.append("REDIRECT")
    if status is None:
        flags.append("NO_RESPONSE")
    return flags


def run():
    print("=== Browser-assisted recon run ===\n")
    results = []
    for domain, roots in TARGETS.items():
        root = roots[0]
        print(f"-- {domain} --")
        for path in CHECK_PATHS:
            resp = probe(root, path)
            flags = analyze(resp)
            if flags:
                print(f"  {path:40s} -> {resp.get('status')} | {', '.join(flags)}")
                if "TXT_SECURITY_CONTACT" in flags or "JSON_CONTACT_ENDPOINT" in flags:
                    results.append({"domain": domain, "path": path, "flags": flags, "status": resp.get("status"), "body_snip": (resp.get("body") or "")[:500]})
        time.sleep(0.2)
    print(f"\nFindings: {len(results)}")
    if results:
        out = BASE / "scans" / "browser_probe_results.json"
        out.write_text(json.dumps({"findings": results}, indent=2))
        print(f"Saved to {out}")


if __name__ == "__main__":
    run()
