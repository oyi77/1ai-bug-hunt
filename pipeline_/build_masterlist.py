#!/usr/bin/env python3
"""Build a deduped master target list from every source we have."""
import json, re
from pathlib import Path

BASE = Path.home() / "projects" / "auto-bug-bounty"
targets_dir = BASE / "targets"

domains = []
sources = []

# H1 programs
p = targets_dir / "h1_programs.json"
if p.exists():
    data = json.load(open(p))
    for prog in data.get("programs", []):
        for scope in prog.get("structured_scopes", []):
            if scope.get(" eligible_for_submission"):
                fqdn = scope.get("identifier", "").strip()
                if fqdn and fqdn not in domains:
                    domains.append(fqdn)
                    sources.append(f"h1:{prog.get('name','?')}")

# Other platforms (Bugcrowd, Intigriti, YesWeHack, etc.)
p = targets_dir / "other_platforms.json"
if p.exists():
    data = json.load(open(p))
    # Try common keys
    items = data.get("programs", data.get("items", []))
    for item in items:
        # Each item should have domain/url
        fqdn = item.get("url", item.get("domain", "")).strip()
        if fqdn and fqdn not in domains:
            domains.append(fqdn)
            sources.append(f"other:{item.get('source','?')}")

# Direct disclosure contacts
p = targets_dir / "direct_disclosure.json"
if p.exists():
    data = json.load(open(p))
    for c in data.get("companies", []):
        fqdn = c.get("domain", "").strip()
        email = c.get("security_contact_email", "")
        if fqdn and fqdn not in domains and email:
            domains.append(fqdn)
            sources.append(f"direct:{c.get('company','?')}")

# All_bb_platforms
p = targets_dir / "all_bb_platforms.json"
if p.exists():
    data = json.load(open(p))
    for plat in data.get("platforms", []):
        for prog in plat.get("programs", []):
            fqdn = prog.get("url", prog.get("domain", "")).strip()
            if fqdn and fqdn not in domains:
                domains.append(fqdn)
                sources.append(f"all:{plat.get('name','?')}")

# Dedupe
seen = set()
output = []
for i, d in enumerate(domains):
    d_clean = re.sub(r"^https?://", "", d).split("/")[0].lower()
    if not d_clean or "*" in d_clean or d_clean in seen:
        continue
    seen.add(d_clean)
    output.append({
        "domain": d_clean,
        "original": d,
        "source": sources[i] if i < len(sources) else "unknown"
    })

out = {
    "generated": __import__('datetime').datetime.utcnow().isoformat(),
    "count": len(output),
    "targets": output
}

outfile = targets_dir / "master_scanlist.json"
with open(outfile, "w") as f:
    json.dump(out, f, indent=2)

print(f"Master scanlist: {len(output)} unique domains")
print(f"Saved to {outfile}")
for item in output[:20]:
    print(f"  {item['domain']:40s} [{item['source']}]")
if len(output) > 20:
    print(f"  ... and {len(output)-20} more")
