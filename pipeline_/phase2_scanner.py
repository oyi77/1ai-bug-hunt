#!/usr/bin/env python3
"""Phase 2-3: Recon + Vulnerability Scanner with false positive prevention"""
import json, os, sys, subprocess, urllib.request, ssl, time, re
from pathlib import Path
from urllib.parse import urlparse

BASE = Path.home() / "projects" / "auto-bug-bounty"
CONFIG = json.load(open(BASE / "pipeline" / "pipeline_config.json"))

# Disable SSL cert verification for scanning
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

def check_url(target_url, path, method="GET"):
    """Check a URL with false-positive prevention. Returns dict with result status."""
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    
    full_url = f"{target_url.rstrip('/')}{path}"
    result = {"url": full_url, "status": "unknown", "http_code": 0, "body_size": 0, "content_type": "", "is_html": False, "evidence": ""}
    
    try:
        req = urllib.request.Request(full_url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
        req.add_header("Accept", "application/json, text/plain, */*")
        
        # DON'T follow redirects - critical for false positive prevention!
        resp = urllib.request.urlopen(req, timeout=8, context=ssl_ctx)
        result["http_code"] = resp.status
        result["content_type"] = resp.headers.get("Content-Type", "")
        result["is_html"] = "text/html" in result["content_type"]
        body = resp.read(2000)
        result["body_size"] = len(body)
        result["evidence"] = body[:500].decode("utf-8", errors="replace")
        result["status"] = "ok"
    except urllib.request.HTTPError as e:
        result["http_code"] = e.code
        result["status"] = "blocked" if e.code in (403, 429) else "not_found" if e.code == 404 else f"http_{e.code}"
        result["evidence"] = str(e)
    except urllib.request.URLError as e:
        result["status"] = "timeout" if "timed out" in str(e).lower() else "error"
        result["evidence"] = str(e)
    except Exception as e:
        result["status"] = "error"
        result["evidence"] = str(e)
    
    return result

def check_wordpress(target):
    """Check for WordPress user enumeration. Returns finding dict or None."""
    result = check_url(target, "/wp-json/wp/v2/users?search=@")
    
    # False positive prevention:
    if result["http_code"] == 200 and not result["is_html"]:
        # Check if response is actually JSON with user data
        try:
            data = json.loads(result["evidence"][:result["body_size"]])
            if isinstance(data, list) and len(data) > 0:
                users = [{"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")} for u in data[:10]]
                return {
                    "vuln_type": "WordPress User Enumeration",
                    "target": target,
                    "severity": "medium",
                    "endpoint": "/wp-json/wp/v2/users",
                    "evidence": json.dumps(users, indent=2)[:1000],
                    "remediation": "Disable REST API user endpoint or restrict to authenticated users",
                    "poc": f"curl -s '{target}/wp-json/wp/v2/users?search=@'"
                }
        except:
            pass  # Not JSON = not a real WP user enum
    
    # Check if WP REST API root is accessible (info disclosure)
    result2 = check_url(target, "/wp-json/")
    if result2["http_code"] == 200 and not result2["is_html"]:
        try:
            data = json.loads(result2["evidence"][:result2["body_size"]])
            if "namespaces" in data:
                return {
                    "vuln_type": "WordPress REST API Exposure",
                    "target": target,
                    "severity": "low",
                    "endpoint": "/wp-json/",
                    "evidence": json.dumps({k: data[k] for k in ["namespaces", "authentication"] if k in data}, indent=2)[:1000],
                    "remediation": "Restrict /wp-json/ access or implement authentication",
                    "poc": f"curl -s '{target}/wp-json/'"
                }
        except:
            pass
    
    return None

def check_git_exposure(target):
    """Check for .git/config exposure."""
    result = check_url(target, "/.git/config")
    if result["http_code"] == 200 and "[core]" in result["evidence"]:
        return {
            "vuln_type": "Git Repository Exposure",
            "target": target,
            "severity": "critical",
            "endpoint": "/.git/config",
            "evidence": result["evidence"][:500],
            "remediation": "Block /.git/ paths at web server or CDN level",
            "poc": f"curl -s '{target}/.git/config'"
        }
    return None

def check_env_exposure(target):
    """Check for .env file exposure."""
    result = check_url(target, "/.env")
    if result["http_code"] == 200 and ("DB_" in result["evidence"] or "APP_" in result["evidence"] or "SECRET" in result["evidence"] or "PASSWORD" in result["evidence"]):
        return {
            "vuln_type": "Environment File Exposure",
            "target": target,
            "severity": "critical",
            "endpoint": "/.env",
            "evidence": result["evidence"][:500],
            "remediation": "Block /.env at web server level",
            "poc": f"curl -s '{target}/.env'"
        }
    return None

def scan_target(target, program_name="unknown"):
    """Run all checks on a target."""
    findings = []
    
    wp = check_wordpress(target)
    if wp:
        wp["program"] = program_name
        findings.append(wp)
        print(f"  🎯 {wp['vuln_type']} on {target} [{wp['severity']}]")
    
    git = check_git_exposure(target)
    if git:
        git["program"] = program_name
        findings.append(git)
        print(f"  🎯 {git['vuln_type']} on {target} [{git['severity']}]")
    
    env = check_env_exposure(target)
    if env:
        env["program"] = program_name
        findings.append(env)
        print(f"  🎯 {env['vuln_type']} on {target} [{env['severity']}]")
    
    return findings

def scan_targets_from_file(filepath, source_label=""):
    """Load targets from a JSON file and scan each one."""
    findings = []
    print(f"\n{'='*60}")
    print(f"SCANNING: {source_label}")
    print(f"File: {filepath}")
    print(f"{'='*60}")
    
    try:
        data = json.load(open(filepath))
    except Exception as e:
        print(f"  Error loading: {e}")
        return []
    
    # Handle different JSON structures
    targets = []
    if isinstance(data, dict):
        for key in ["companies", "programs", "targets"]:
            if key in data:
                targets = data[key]
                break
        if not targets:
            # Try platform structure
            for p in data.get("platforms", []):
                name = p.get("name", "")
                url = p.get("url", "")
                prog_url = p.get("public_programs_url", "")
                if url: targets.append({"company": name, "url": url, "program_url": prog_url})
    elif isinstance(data, list):
        targets = data
    
    print(f"Loaded {len(targets)} potential targets")
    
    for idx, t in enumerate(targets):
        # Get the URL/domain from various fields
        domain = t.get("url") or t.get("domain") or t.get("identifier") or ""
        prog_name = t.get("company") or t.get("name") or t.get("handle") or source_label
        
        if not domain:
            continue
        
        # Extract domain without protocol
        domain = re.sub(r'https?://', '', domain).split('/')[0].split('?')[0]
        if not domain or domain.startswith('*.'):
            continue
        
        print(f"\n[{idx+1}/{len(targets)}] {prog_name} → {domain}")
        batch = scan_target(domain, prog_name)
        findings.extend(batch)
        
        if len(batch) == 0:
            print(f"  No findings")
    
    return findings

if __name__ == "__main__":
    print("=== PHASE 2-3: RECON + VULNERABILITY SCANNER ===")
    print("v2.0 — False Positive Prevention Active")
    
    all_findings = []
    
    # Scan from our existing target files
    scans = [
        (BASE / "targets" / "scan_picklist.json", "Priority Picklist"),
        (BASE / "targets" / "direct_disclosure.json", "Direct Disclosure Contacts"),
    ]
    
    for filepath, label in scans:
        if filepath.exists():
            batch = scan_targets_from_file(filepath, label)
            all_findings.extend(batch)
    
    # Save all findings
    if all_findings:
        output = {
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_findings": len(all_findings),
            "findings": all_findings
        }
        outfile = BASE / "scans" / f"findings_{time.strftime('%Y%m%d_%H%M')}.json"
        with open(outfile, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE! {len(all_findings)} finding(s) saved to {outfile}")
        print(f"{'='*60}")
        
        # Group by severity
        by_severity = {}
        for f in all_findings:
            s = f["severity"]
            by_severity[s] = by_severity.get(s, 0) + 1
        print(f"By severity: {json.dumps(by_severity)}")
    else:
        print(f"\nNo findings in this scan cycle.")
