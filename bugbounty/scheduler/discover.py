#!/usr/bin/env python3
"""
Program Discovery - Fetch in-scope programs from HackerOne and Bugcrowd
"""

import json
import os
import sys
import time
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
ENV_PATH = SCRIPT_DIR.parent / ".env"


def load_env() -> dict:
    """Load .env file"""
    env = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def load_config() -> dict:
    """Load scheduler config"""
    return json.loads(CONFIG_PATH.read_text())


def load_memory() -> dict:
    """Load hunt memory (already-hunted targets, results)"""
    config = load_config()
    mem_path = Path(config["paths"]["memory"])
    if mem_path.exists():
        return json.loads(mem_path.read_text())
    return {"hunted": {}, "blacklisted": [], "stats": {"total_runs": 0, "total_findings": 0}}


def save_memory(memory: dict):
    """Save hunt memory"""
    config = load_config()
    mem_path = Path(config["paths"]["memory"])
    mem_path.parent.mkdir(parents=True, exist_ok=True)
    mem_path.write_text(json.dumps(memory, indent=2))


# ─── HackerOne ───────────────────────────────────────────────────────

def fetch_h1_programs(config: dict, env: dict) -> List[Dict]:
    """Fetch HackerOne programs via API or public data"""
    programs = []
    h1_cfg = config["platforms"]["hackerone"]
    if not h1_cfg["enabled"]:
        return programs

    token = env.get("H1_TOKEN", "")
    h1_user = env.get("H1_HANDLE", env.get("H1_EMAIL", ""))

    # Method 1: H1 API with credentials
    if token and h1_user:
        try:
            resp = requests.get(
                f"{h1_cfg['api_base']}/hackers/programs",
                headers={"Accept": "application/json"},
                auth=(h1_user, token),
                params={"page[size]": 50, "sort": "-launched_at"},
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                for prog in data.get("data", []):
                    attrs = prog.get("attributes", {})
                    programs.append({
                        "platform": "hackerone",
                        "handle": attrs.get("handle", ""),
                        "name": attrs.get("name", ""),
                        "offers_bounties": attrs.get("offers_bounties", False),
                        "state": attrs.get("state", ""),
                        "launched_at": attrs.get("launched_at", ""),
                        "meta": {"url": f"https://hackerone.com/{attrs.get('handle', '')}"}
                    })
                if programs:
                    print(f"[+] H1 API: {len(programs)} programs")
            else:
                print(f"[!] H1 API {resp.status_code}, falling back to public data")
        except Exception as e:
            print(f"[!] H1 API error: {e}")

    # Method 2: Public bounty-targets-data (no auth needed)
    if not programs:
        try:
            resp = requests.get(
                "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                for prog in data:
                    handle = prog.get("handle", "")
                    offers_bounty = prog.get("offers_bounties", False)
                    submission_state = prog.get("submission_state", "")
                    targets = prog.get("targets", {})
                    # targets is a dict with 'in_scope' and 'out_of_scope' lists
                    in_scope = targets.get("in_scope", []) if isinstance(targets, dict) else []
                    scope_urls = [s.get("asset_identifier", "") for s in in_scope if s.get("asset_type") == "URL"]
                    programs.append({
                        "platform": "hackerone",
                        "handle": handle,
                        "name": prog.get("name", handle),
                        "offers_bounties": offers_bounty,
                        "state": "open",
                        "meta": {
                            "url": f"https://hackerone.com/{handle}",
                            "scope_count": len(scope_urls),
                            "sample_scopes": scope_urls[:5],
                        }
                    })
                print(f"[+] Public data: {len(programs)} H1 programs")
        except Exception as e:
            print(f"[!] Public data error: {e}")

    # Filter: active, not blacklisted
    memory = load_memory()
    blacklisted = set(memory.get("blacklisted", []))
    filtered = [p for p in programs if p["handle"] not in blacklisted and p.get("state") == "open"]
    return filtered[:h1_cfg["max_programs_per_run"]]


def fetch_h1_scopes(handle: str, env: dict) -> List[str]:
    """Fetch in-scope assets for a H1 program from public data"""
    scopes = []
    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            for prog in data:
                if prog.get("handle", "").lower() == handle.lower():
                    targets = prog.get("targets", {})
                    in_scope = targets.get("in_scope", []) if isinstance(targets, dict) else []
                    for target in in_scope:
                        asset_type = target.get("asset_type", "")
                        identifier = target.get("asset_identifier", "")
                        if asset_type in ("URL", "WILDCARD"):
                            scopes.append(identifier.replace("*.", ""))
                    break
    except Exception as e:
        print(f"[!] Scope fetch error for {handle}: {e}")
    return scopes


# ─── Bugcrowd ────────────────────────────────────────────────────────

def fetch_bc_programs(config: dict, env: dict) -> List[Dict]:
    """Fetch Bugcrowd programs from public data"""
    programs = []
    bc_cfg = config["platforms"]["bugcrowd"]
    if not bc_cfg["enabled"]:
        return programs

    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
            timeout=30
        )
        if resp.status_code == 200:
            data = resp.json()
            for prog in data:
                handle = prog.get("name", "").lower().replace(" ", "-")
                programs.append({
                    "platform": "bugcrowd",
                    "handle": handle,
                    "name": prog.get("name", ""),
                    "offers_bounties": True,
                    "state": "open",
                    "meta": {
                        "url": f"https://bugcrowd.com/{handle}",
                        "scope_count": len(prog.get("targets", {}).get("in_scope", [])),
                    }
                })
            print(f"[+] Public data: {len(programs)} Bugcrowd programs")
    except Exception as e:
        print(f"[!] Bugcrowd fetch error: {e}")

    memory = load_memory()
    blacklisted = set(memory.get("blacklisted", []))
    filtered = [p for p in programs if p["handle"] not in blacklisted and p["state"] == "open"]
    return filtered[:bc_cfg["max_programs_per_run"]]


# ─── Program Selection ───────────────────────────────────────────────

def select_targets(config: dict, env: dict, max_targets: int = 3) -> List[Dict]:
    """Select best targets to hunt next"""
    memory = load_memory()
    hunted = memory.get("hunted", {})
    now = datetime.now()

    # Fetch from both platforms
    h1_programs = fetch_h1_programs(config, env)
    bc_programs = fetch_bc_programs(config, env)
    all_programs = h1_programs + bc_programs

    if not all_programs:
        print("[!] No programs found")
        return []

    # Score and rank
    scored = []
    for prog in all_programs:
        handle = prog["handle"]
        score = 50  # base

        # Prefer bounties over VDP
        if prog.get("offers_bounties"):
            score += 30

        # Prefer not recently hunted
        if handle in hunted:
            last_hunt = hunted[handle].get("last_hunt", "")
            if last_hunt:
                try:
                    last_dt = datetime.fromisoformat(last_hunt)
                    hours_ago = (now - last_dt).total_seconds() / 3600
                    if hours_ago < 24:
                        score -= 40  # hunted recently
                    elif hours_ago < 72:
                        score -= 20
                except:
                    pass

            # Prefer targets with past findings
            if hunted[handle].get("findings", 0) > 0:
                score += 20

        # Prefer H1 (better API)
        if prog["platform"] == "hackerone":
            score += 10

        scored.append((score, prog))

    scored.sort(key=lambda x: x[0], reverse=True)
    selected = [prog for score, prog in scored[:max_targets]]

    print(f"[*] Selected {len(selected)} targets:")
    for prog in selected:
        print(f"    - [{prog['platform']}] {prog['handle']} ({prog['name']})")

    return selected


# ─── CLI ─────────────────────────────────────────────────────────────

def main():
    """CLI entry point"""
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Program Discovery")
    parser.add_argument("--platform", choices=["h1", "bc", "all"], default="all")
    parser.add_argument("--max", type=int, default=3, help="Max targets")
    parser.add_argument("--list", action="store_true", help="List programs only")
    parser.add_argument("--scopes", type=str, help="Get scopes for H1 program handle")
    args = parser.parse_args()

    config = load_config()
    env = load_env()

    if args.scopes:
        scopes = fetch_h1_scopes(args.scopes, env)
        print(f"\n[*] Scopes for {args.scopes}:")
        for s in scopes:
            print(f"    {s}")
        return

    if args.list:
        if args.platform in ("h1", "all"):
            progs = fetch_h1_programs(config, env)
            print(f"\n[*] HackerOne Programs ({len(progs)}):")
            for p in progs:
                bounty = "$" if p.get("offers_bounties") else "VDP"
                print(f"    [{bounty}] {p['handle']} - {p['name']}")
        if args.platform in ("bc", "all"):
            progs = fetch_bc_programs(config, env)
            print(f"\n[*] Bugcrowd Programs ({len(progs)}):")
            for p in progs:
                bounty = "$" if p.get("offers_bounties") else "VDP"
                print(f"    [{bounty}] {p['handle']} - {p['name']}")
        return

    targets = select_targets(config, env, args.max)
    print(json.dumps(targets, indent=2))


if __name__ == "__main__":
    main()
