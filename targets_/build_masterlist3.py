#!/usr/bin/env python3
"""Build master scan list from ALL platform sources with correct field mapping."""
import json, re
from pathlib import Path
from collections import Counter

BASE = Path.home() / "projects" / "auto-bug-bounty" / "targets"

print("=== BUILDING MASTER SCAN LIST ===\n")

# 1. Direct Disclosure (correct field: 'domain')
try:
    data = json.loads((BASE / "direct_disclosure.json").read_text())
    comps = data.get("companies", [])
    email_targets = []
    for c in comps:
        d = c.get("domain", "").strip().lower()
        email = c.get("security_contact_email", "")
        if d and email and d not in [t.get("domain") for t in email_targets]:
            email_targets.append({
                "domain": d,
                "name": c.get("company", ""),
                "program": c.get("bounty_program", ""),
                "bounty_max": c.get("bounty_max", "Varies"),
                "email": email,
                "source": "direct_email",
                "submission": c.get("program_url", ""),
            })
    print(f"Direct disclosure targets: {len(email_targets)}")
    print(f"  Top payouts: {sorted(email_targets, key=lambda x: x.get('bounty_max',''), reverse=True)[:5]}")
except Exception as e:
    print(f"Error reading direct_disclosure: {e}")
    email_targets = []

# 2. H1 programs (correct field: 'handle' as identifier)
try:
    data = json.loads((BASE / "h1_programs.json").read_text())
    progs = data.get("programs", [])
    h1_targets = []
    for p in progs:
        handle = p.get("handle", "")
        name = p.get("name", "")
        if handle and handle not in [t.get("domain") for t in h1_targets]:
            h1_targets.append({
                "domain": handle,
                "name": name,
                "handle": handle,
                "offers_bounties": p.get("offers_bounties", False),
                "submission_state": p.get("submission_state", ""),
                "source": "hackerone",
                "submission": f"https://hackerone.com/{handle}",
            })
    print(f"\nHackerOne programs: {len(h1_targets)}")
    bounty_count = sum(1 for t in h1_targets if t.get("offers_bounties"))
    print(f"  With bounties: {bounty_count}")
    open_count = sum(1 for t in h1_targets if t.get("submission_state") == "open")
    print(f"  Open for submission: {open_count}")
except Exception as e:
    print(f"Error reading h1_programs: {e}")
    h1_targets = []

# 3. Other platforms (correct structure: data["bugcrowd"], data["intigriti"], etc.)
try:
    data = json.loads((BASE / "other_platforms.json").read_text())
    other_targets = []
    for key in ["bugcrowd", "intigriti", "yeswehack", "top_recommendations"]:
        section = data.get(key, {})
        if isinstance(section, dict):
            programs = section.get("programs", [])
            for prog in programs:
                url = prog.get("url", prog.get("domain", "")).strip().lower()
                if url and url not in [t.get("domain") for t in other_targets]:
                    other_targets.append({
                        "domain": re.sub(r'^https?://', '', url).split('/')[0],
                        "name": prog.get("name", ""),
                        "program": prog.get("program", ""),
                        "bounty_max": prog.get("bounty_max", "Varies"),
                        "source": key,
                        "submission": url,
                    })
        elif isinstance(section, list):
            for prog in section:
                url = prog.get("url", prog.get("domain", "")).strip().lower()
                if url:
                    other_targets.append({
                        "domain": re.sub(r'^https?://', '', url).split('/')[0],
                        "name": prog.get("name", ""),
                        "program": prog.get("program", ""),
                        "bounty_max": prog.get("bounty_max", "Vares"),
                        "source": key,
                        "submission": url,
                    })
    print(f"\nOther platforms (BC/Intigriti/YesWeHack): {len(other_targets)}")
except Exception as e:
    print(f"Error reading other_platforms: {e}")
    other_targets = []

# 4. All BB platforms (correct field: 'all_bb_platforms')
try:
    data = json.loads((BASE / "all_bb_platforms.json").read_text())
    platforms = data.get("platforms", [])
    bb_targets = []
    for plat in platforms:
        domain = plat.get("domain", "").strip().lower()
        if domain and len(domain) > 3 and '*' not in domain:
            bb_targets.append({
                "domain": domain,
                "name": plat.get("name", ""),
                "region": plat.get("region", ""),
                "public_programs_url": plat.get("public_programs_url", ""),
                "source": "all_bb_platforms",
                "submission": plat.get("public_programs_url", ""),
            })
    print(f"\nAll BB platforms: {len(bb_targets)}")
except Exception as e:
    print(f"Error reading all_bb_platforms: {e}")
    bb_targets = []

# 5. Scan picklist (correct field: list under various keys)
try:
    data = json.loads((BASE / "scan_picklist.json").read_text())
    pick_targets = []
    for key, items in data.items():
        if isinstance(items, list):
            for item in items:
                url = item.get("url", item.get("domain", item.get("handle", ""))).strip().lower()
                if url:
                    pick_targets.append({
                        "domain": re.sub(r'^https?://', '', url).split('/')[0],
                        "name": item.get("name", item.get("handle", "")),
                        "platform": key,
                        "source": "picklist",
                        "submission": item.get("url", ""),
                    })
    print(f"\nScan picklist: {len(pick_targets)}")
except Exception as e:
    print(f"Error reading scan_picklist: {e}")
    pick_targets = []

# Combine and deduplicate
all_targets = email_targets + h1_targets + other_targets + bb_targets + pick_targets
seen = set()
deduped = []
for t in all_targets:
    d = t.get("domain", "").strip().lower()
    if not d or d in seen:
        continue
    seen.add(d)
    deduped.append(t)

print(f"\n{'='*60}")
print(f"MASTER SCAN LIST: {len(deduped)} UNIQUE DOMAINS")
print(f"{'='*60}")

# Count by source (Top 10)
src_counts = Counter(t.get("source", "") for t in deduped)
print(f"\nBreakdown by source:")
for src, cnt in sorted(src_counts.items(), key=lambda x: -x[1])[:10]:
    print(f"  {src:25s}: {cnt}")

# Save master scanlist
outfile = BASE / "master_scanlist_full.json"
outfile.write_text(json.dumps({
    "count": len(deduped),
    "generated": __import__("datetime").datetime.utcnow().isoformat(),
    "targets": deduped
}, indent=2))
print(f"\n✅ Saved to: {outfile}")
