#!/usr/bin/env python3
"""Pipeline state manager — tracks phase progress + findings across all phases."""
import json, os, sys
from pathlib import Path
from datetime import datetime

BASE = Path.home() / "projects" / "auto-bug-bounty"
STATE_FILE = BASE / "pipeline" / "state.json"
CONFIG_FILE = BASE / "pipeline" / "pipeline_config.json"

def init():
    if not STATE_FILE.exists():
        state = {
            "pipeline": "auto-bug-bounty",
            "version": "2.0",
            "created": datetime.utcnow().isoformat(),
            "phases": {
                "discover": {"status": "idle", "last_run": None, "findings": 0, "programs": 0},
                "recon": {"status": "idle", "last_run": None, "subdomains": 0, "targets": 0},
                "scan": {"status": "idle", "last_run": None, "findings": 0, "vulns": []},
                "poc": {"status": "idle", "last_run": None, "confirmed": 0},
                "verify": {"status": "idle", "last_run": None, "verified": 0},
                "review": {"status": "idle", "last_run": None, "approved": 0},
                "submit": {"status": "idle", "last_run": None, "submitted": 0}
            },
            "metrics": {
                "total_findings": 0,
                "total_submissions": 0,
                "total_bounties": 0,
                "last_updated": datetime.utcnow().isoformat()
            }
        }
        save(state)
        print("State initialized.")
    return load()

def load():
    with open(STATE_FILE) as f:
        return json.load(f)

def save(state):
    state["metrics"]["last_updated"] = datetime.utcnow().isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)

def update_phase(phase_id, **kwargs):
    state = load()
    if phase_id in state["phases"]:
        state["phases"][phase_id].update(kwargs)
        state["phases"][phase_id]["last_run"] = datetime.utcnow().isoformat()
        save(state)
        print(f"Phase '{phase_id}' updated.")
    else:
        print(f"Unknown phase: {phase_id}")

def add_finding(vuln_type, target, severity, evidence, program):
    state = load()
    finding = {
        "id": f"BB-{datetime.utcnow().strftime('%y%m%d')}-{len(state['phases']['scan']['vulns'])+1:03d}",
        "type": vuln_type,
        "target": target,
        "severity": severity,
        "evidence": evidence,
        "program": program,
        "status": "unverified",
        "found_at": datetime.utcnow().isoformat()
    }
    state["phases"]["scan"]["vulns"].append(finding)
    state["phases"]["scan"]["findings"] = len(state["phases"]["scan"]["vulns"])
    state["metrics"]["total_findings"] += 1
    save(state)
    print(f"Finding added: {finding['id']} - {vuln_type} on {target}")
    return finding["id"]

def next_phase():
    """Auto-advance pipeline if current phase done."""
    state = load()
    order = ["discover", "recon", "scan", "poc", "verify", "review", "submit"]
    for i, phase in enumerate(order):
        if state["phases"][phase]["status"] in ("running", "done"):
            continue
        # Check if previous phase is done
        if i > 0 and state["phases"][order[i-1]]["status"] != "done":
            print(f"Waiting for '{order[i-1]}' to complete before starting '{phase}'")
            return None
        # Start this phase
        state["phases"][phase]["status"] = "ready"
        save(state)
        print(f"Phase '{phase}' is ready to run.")
        return phase
    print("All phases complete!")
    return None

def status():
    state = load()
    print("\n=== PIPELINE STATUS ===")
    for pid, pdata in state["phases"].items():
        icon = {"idle": "⬜", "ready": "🟡", "running": "🟢", "done": "✅"}.get(pdata["status"], "⬜")
        print(f"  {icon} {pid:12s} {pdata['status']:8s} last: {str(pdata.get('last_run','-')[:16])}")
    print(f"  ─────────────────────────────")
    print(f"  📊 Findings: {state['metrics']['total_findings']}")
    print(f"  📨 Submissions: {state['metrics']['total_submissions']}")
    print(f"  💰 Bounties: {state['metrics']['total_bounties']}")

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "init": init()
    elif cmd == "status": status()
    elif cmd == "next": next_phase()
    elif cmd == "add_finding" and len(sys.argv) >= 5:
        add_finding(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "", sys.argv[6] if len(sys.argv) > 6 else "")
    elif cmd == "advance":
        pid = sys.argv[2] if len(sys.argv) > 2 else None
        if pid:
            update_phase(pid, status="done")
        next_phase()
    else:
        print(f"Usage: {sys.argv[0]} [init|status|next|advance <phase>|add_finding ...]")
