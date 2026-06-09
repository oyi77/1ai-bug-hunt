#!/usr/bin/env python3
"""Build deduped master target list from ALL sources, then scan all of them."""
import json, re, time, urllib.request, ssl, sys
from pathlib import Path
from urllib.parse import urlparse

BASE = Path.home() / "projects" / "auto-bug-bounty" / "targets"
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def clean(s):
    if not s:
        return None
    s = str(s).strip().lower()
    if s.startswith(("http://", "https://")):
        s = urlparse(s).netloc
    s = s.strip(".")
    s = re.sub(r"^\*\.", "", s)
    s = "/".join(s.split("/")[:1])
    if not s or "*" in s or len(s) < 3 or " " in s:
        return None
    return s

def req(url, path=""):
    full = (url.rstrip("/") + "/" + path.lstrip("/")) if path else url
    try:
        req = urllib.request.Request(full)
        req.add_header("User-Agent", UA)
        req.add_header("Accept", "application/json,text/plain,*/*")
        # Do NOT follow redirects — prevents false positives
        resp = urllib.request.urlopen(req, timeout=8, context=SSL_CTX)
        ct = resp.headers.get("Content-Type", "")
        body = resp.read(1500)
        return {
            "code": resp.status,
            "is_html": "text/html" in ct,
            "is_json": "application/json" in ct,
            "body": body[:500].decode("utf-8", "replace"),
        }
    except urllib.request.HTTPError as e:
        return {"code": e.code, "body": str(e)[:100], "is_html": False, "is_json": False}
    except Exception as e:
        return {"code": 0, "body": str(e)[:60], "is_html": False, "is_json": False}

print("=" * 70)
print("AUTO BUG BOUNTY — FULL MULTI-PLATFORM SCAN")
print("=" * 70)

# ── Collect targets from every source ──────────────────────────────────────
targets = []  # list of (domain, source, name)

# 1. Scan picklist (H1, Bugcrowd, YesWeHack, Intigriti)
if (BASE / "scan_picklist.json").exists():
    data = json.loads((BASE / "scan_picklist.json").read_text())
    for platform, items in data.items():
        if not isinstance(items, list):
            continue
        for item in items:
            handle = item.get("handle") or item.get("name", "")
            domain = clean(handle)
            if domain:
                targets.append((domain, f"picklist:{platform}", item.get("name", handle)))

# 2. Direct disclosure (real company domains — most valuable)
if (BASE / "direct_disclosure.json").exists():
    data = json.loads((BASE / "direct_disclosure.json").read_text())
    for item in data.get("companies", []):
        domain = clean(item.get("domain"))
        email = item.get("security_contact_email", "")
        if domain and email:
            targets.append((domain, f"direct:{item.get('source','?')}", item.get("company", "")))

# 3. H1 programs: handle as domain approximation
if (BASE / "h1_programs.json").exists():
    data = json.loads((BASE / "h1_programs.json").read_text())
    for item in data.get("programs", []):
        h = item.get("handle", "")
        domain = clean(h)
        if domain:
            targets.append((domain, "hackerone", item.get("name", h)))

# 4. Other platforms (extract domains from program URLs)
if (BASE / "other_platforms.json").exists():
    data = json.loads((BASE / "other_platforms.json").read_text())
    for key in ["bugcrowd", "intigriti", "yeswehack"]:
        sec = data.get(key, {})
        progs = sec.get("programs", []) if isinstance(sec, dict) else []
        for prog in progs:
            domain = clean(prog.get("url", prog.get("domain", "")))
            if domain:
                targets.append((domain, f"other:{key}", prog.get("name", "")))

# 5. All_bb_platforms (public program directories)
if (BASE / "all_bb_platforms.json").exists():
    data = json.loads((BASE / "all_bb_platforms.json").read_text())
    for plat in data.get("platforms", []):
        domain = clean(plat.get("domain", ""))
        if domain:
            targets.append((domain, f"allbb:{plat.get('name','')}", plat.get("name", "")))

# Deduplicate
seen = set()
deduped = []
for t in targets:
    domain, src, name = t
    if domain and domain not in seen:
        seen.add(domain)
        deduped.append((domain, src, name))

print(f"\nMaster list: {len(deduped)} UNIQUE domains\n")
print(f"{'#':5s} {'Domain':35s} {'Source':25s} Name")
print("-" * 80)

for i, (domain, src, name) in enumerate(deduped[:50], 1):
    print(f"{i:5d} {domain:35s} {src:25s} {name[:30]}")
if len(deduped) > 50:
    print(f"     ... and {len(deduped)-50} more")

# ── Scan all targets ────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"SCANNING ALL {len(deduped)} TARGETS")
print(f"{'='*70}\n")

findings = []
errors = 0
start = time.time()

for idx, (domain, src, name) in enumerate(deduped, 1):
    time.sleep(0.25)  # rate-limit

    wp = req(domain, "/wp-json/wp/v2/users?search=@")
    git = req(domain, "/.git/config")
    env = req(domain, "/.env")
    dbg = req(domain, "/wp-content/debug.log")
    xml = req(domain, "/xmlrpc.php")
    wp_root = req(domain, "/wp-json/")

    # False-positive-safe checks
    # WP user enum: JSON response with array/object starting with [ or {
    is_wp_json = (wp["code"] == 200 and not wp["is_html"]
                  and wp["is_json"]
                  and ("slug" in wp["body"] or wp["body"].strip().startswith(("[", "{"))))

    # Git: contains [core] marker
    is_git = (git["code"] == 200 and "[core]" in git.get("body", ""))

    # ENV: status 200, not HTML, contains credential markers
    is_env = (env["code"] == 200
              and not env["is_html"]
              and not env["is_json"]
              and ("DB_" in env.get("body", "") or "PASSWORD" in env.get("body", "")
                   or "SECRET" in env.get("body", "") or "APP_" in env.get("body", "")))

    # Debug log: contains PHP errors
    is_dbg = (dbg["code"] == 200
              and not dbg["is_html"]
              and not dbg["is_json"]
              and ("PHP" in dbg.get("body", "") or "Warning" in dbg.get("body", "")
                   or "Error" in dbg.get("body", "") or "Notice" in dbg.get("body", "")))

    # XMLRPC: XML document starting with <?xml
    is_xml = xml["code"] == 200 and xml.get("body", "").strip().startswith("<?xml")

    has_vuln = any([is_wp_json, is_git, is_env, is_dbg, is_xml])

    if has_vuln:
        vulns = []
        if is_wp_json: vulns.append("WP_USER_ENUM")
        if is_git: vulns.append("GIT_EXPOSED")
        if is_env: vulns.append("ENV_LEAKED")
        if is_dbg: vulns.append("DEBUG_LOG")
        if is_xml: vulns.append("XMLRPC")

        snip = ""
        if is_wp_json: snip = wp["body"][:300]
        elif is_git: snip = git["body"][:300]
        elif is_env: snip = env["body"][:300]
        elif is_dbg: snip = dbg["body"][:300]

        print(f"[{idx}/{len(deduped)}] 🎯 {domain:35s} {', '.join(vulns)}")
        print(f"      Snippet: {snip[:200].replace(chr(10), ' ')}")
        findings.append({
            "domain": domain,
            "source": src,
            "name": name,
            "url": f"https://{domain}",
            "findings": {"wp_user_enum": is_wp_json, "git_exposed": is_git,
                         "env_exposed": is_env, "debug_log": is_dbg, "xmlrpc": is_xml},
            "snippet": snip[:300],
        })
    else:
        sys.stdout.write(f"\r[{idx}/{len(deduped)}] Scanning: {domain:35s}")
        sys.stdout.flush()

elapsed = time.time() - start

print(f"\n\n{'='*70}")
print(f"SCAN COMPLETE — {elapsed:.1f}s | {len(deduped)} targets | {len(findings)} findings")
print(f"{'='*70}\n")

for f in findings:
    vulns = [k.replace("_", " ").title() for k, v in f["findings"].items() if v]
    print(f"💥 {f['domain']:40s} [{f['source']}]")
    print(f"   → {', '.join(vulns)}")
    print(f"   → https://{f['domain']}")
    print()

# Save raw findings
out = {
    "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "duration_s": round(elapsed, 1),
    "targets_scanned": len(deduped),
    "findings_count": len(findings),
    "findings": findings,
}
outfile = BASE.parent / "scans" / f"full_scan_{time.strftime('%Y%m%d_%H%M')}.json"
outfile.parent.mkdir(exist_ok=True)
outfile.write_text(json.dumps(out, indent=2))
print(f"\nSaved to: {outfile}")
