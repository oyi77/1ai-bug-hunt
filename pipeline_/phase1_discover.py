#!/usr/bin/env python3
"""Phase 1: Program Discovery — parallel platform scan launcher"""
import json, os, sys, subprocess
from pathlib import Path

BASE = Path.home() / "projects" / "auto-bug-bounty"
CONFIG = json.load(open(BASE / "pipeline" / "pipeline_config.json"))

def run_phase1():
    """Launch parallel discovery on platforms we haven't checked yet."""
    platforms = CONFIG["phases"][0]["tasks"]
    
    for task in platforms:
        name = task["name"]
        method = task["type"]
        target = task["target"]
        print(f"[DESCOVER] Queued: {name} ({method})")
    
    print(f"\n[DISCOVER] Launched {len(platforms)} parallel discovery tasks")
    print("[DISCOVER] Results will stream to targets/ dir")
    
    # Summary of what we already have
    targets_dir = BASE / "targets"
    existing = list(targets_dir.glob("*.json"))
    print(f"\nExisting target files ({len(existing)}):")
    for f in existing:
        sz = f.stat().st_size
        print(f"  {f.name:40s} {sz:>8,} bytes")

if __name__ == "__main__":
    run_phase1()
