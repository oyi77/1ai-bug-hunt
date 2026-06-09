#!/usr/bin/env python3
"""
Bug Bounty Scheduler - Main Orchestrator
Runs the full pipeline: discover -> recon -> hunt -> report
"""

import json
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

from discover import load_config, load_env, load_memory, save_memory, select_targets, fetch_h1_scopes
from recon import run_recon
from hunt import run_hunt
from report import save_report, generate_report

# AI Brain (optional, uses Ollama)
try:
    from brain import BugBountyBrain
    AI_AVAILABLE = True
except:
    AI_AVAILABLE = False

# Logging
LOG_DIR = SCRIPT_DIR.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / f"scheduler_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bugbounty_scheduler")


def load_state() -> dict:
    """Load scheduler state"""
    config = load_config()
    state_path = Path(config["paths"]["state"])
    if state_path.exists():
        return json.loads(state_path.read_text())
    return {"last_run": None, "runs": [], "current_target": None}


def save_state(state: dict):
    """Save scheduler state"""
    config = load_config()
    state_path = Path(config["paths"]["state"])
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2))


def should_run(config: dict, state: dict) -> bool:
    """Check if scheduler should run based on interval"""
    scheduler_cfg = config.get("scheduler", {})
    interval_hours = scheduler_cfg.get("run_interval_hours", 6)

    last_run = state.get("last_run")
    if not last_run:
        return True

    try:
        last_dt = datetime.fromisoformat(last_run)
        hours_since = (datetime.now() - last_dt).total_seconds() / 3600
        if hours_since >= interval_hours:
            return True
        else:
            logger.info(f"Next run in {interval_hours - hours_since:.1f} hours")
            return False
    except:
        return True


def run_pipeline(max_targets: int = None, dry_run: bool = None, target_override: str = None):
    """Run the full bug bounty pipeline"""
    config = load_config()
    env = load_env()
    memory = load_memory()
    state = load_state()

    scheduler_cfg = config.get("scheduler", {})

    if max_targets is None:
        max_targets = scheduler_cfg.get("max_targets_per_run", 3)
    if dry_run is None:
        dry_run = scheduler_cfg.get("dry_run", True)

    auto_submit = scheduler_cfg.get("auto_submit", False)

    # Initialize AI brain
    brain = None
    if AI_AVAILABLE:
        try:
            brain = BugBountyBrain()
            logger.info(f"AI Brain: {brain.model} ({'enabled' if brain.enabled else 'disabled'})")
        except:
            logger.info("AI Brain: not available")

    run_record = {
        "started_at": datetime.now().isoformat(),
        "targets": [],
        "findings": [],
        "reports": [],
        "dry_run": dry_run,
    }

    logger.info("=" * 60)
    logger.info(f"BUG BOUNTY SCHEDULER - Run at {datetime.now().isoformat()}")
    logger.info(f"Max targets: {max_targets}, Dry run: {dry_run}")
    logger.info("=" * 60)

    # Step 1: Discover targets
    if target_override:
        targets = [{
            "platform": "manual",
            "handle": target_override,
            "name": target_override,
            "offers_bounties": True,
            "state": "open",
        }]
        logger.info(f"Target override: {target_override}")
    else:
        logger.info("[Phase 1] Discovering targets...")
        targets = select_targets(config, env, max_targets)

    if not targets:
        logger.warning("No targets found, exiting")
        state["last_run"] = datetime.now().isoformat()
        save_state(state)
        return run_record

    # Step 2-4: Process each target
    for i, target in enumerate(targets):
        handle = target["handle"]
        logger.info(f"\n[{i+1}/{len(targets)}] Processing: {handle}")

        target_record = {
            "handle": handle,
            "platform": target["platform"],
            "started_at": datetime.now().isoformat(),
            "recon": None,
            "findings": [],
            "reports": [],
        }

        try:
            # Resolve scopes - get actual domains from program handle
            domains = []
            if target["platform"] in ("hackerone", "bugcrowd"):
                logger.info(f"  Resolving scopes for {handle}...")
                domains = fetch_h1_scopes(handle, env) if target["platform"] == "hackerone" else []
                if not domains:
                    # Try from meta data
                    domains = target.get("meta", {}).get("sample_scopes", [])
                if not domains:
                    # Last resort: use handle as domain
                    domains = [handle]
                logger.info(f"  Resolved {len(domains)} domains in scope")
            elif target["platform"] == "manual":
                # Manual target is already a domain
                domains = [handle]
            else:
                domains = [handle]

            # Process each domain in scope (limit to 3)
            for domain in domains[:3]:
                domain = domain.replace("*.", "").replace("https://", "").replace("http://", "").strip("/")
                if not domain or len(domain) < 3:
                    continue
                domain = domain.replace("*.", "").strip()
                if not domain:
                    continue

                logger.info(f"\n  [Recon] {domain}")
                recon_results = run_recon(domain, config=config)
                target_record["recon"] = {
                    "domain": domain,
                    "subdomains": len(recon_results.get("subdomains", [])),
                    "live_hosts": len(recon_results.get("live_hosts", [])),
                    "nuclei_findings": len(recon_results.get("nuclei_findings", [])),
                }

                # AI: Analyze recon results
                if brain and brain.enabled:
                    logger.info("\n  [AI] Analyzing recon results...")
                    ai_analysis = brain.analyze_recon(recon_results)
                    if ai_analysis.get("priority_targets"):
                        logger.info(f"  [AI] {len(ai_analysis['priority_targets'])} priority targets identified")
                        for pt in ai_analysis["priority_targets"][:3]:
                            logger.info(f"    → {pt.get('url', '?')}: {pt.get('reason', '?')}")
                    target_record["ai_analysis"] = ai_analysis

                # Hunt
                logger.info(f"\n  [Hunt] {domain}")
                recon_dir = Path(config["paths"]["output_base"]) / domain / "recon"
                findings = run_hunt(domain, str(recon_dir), config=config)

                # AI: Validate findings
                if brain and brain.enabled and findings:
                    logger.info(f"\n  [AI] Validating {len(findings)} findings...")
                    validated = []
                    for finding in findings:
                        validation = brain.validate_finding(finding)
                        finding["ai_validation"] = validation
                        if validation.get("valid", True):
                            validated.append(finding)
                            logger.info(f"  [AI] ✓ {finding.get('title', '?')} (confidence: {validation.get('confidence', '?')})")
                        else:
                            logger.info(f"  [AI] ✗ {finding.get('title', '?')}: {validation.get('reason', 'false positive')}")
                    findings = validated

                if findings:
                    logger.info(f"\n  [!] Found {len(findings)} vulnerabilities!")
                    target_record["findings"].extend(findings)

                    # Generate reports
                    for finding in findings:
                        if not dry_run or True:  # Always generate reports even in dry run
                            report_path = save_report(
                                finding,
                                config["paths"]["reports"],
                                target
                            )
                            target_record["reports"].append(str(report_path))
                            run_record["reports"].append(str(report_path))

                            logger.info(f"  [Report] {report_path.name}")

                # Cooldown between domains
                time.sleep(scheduler_cfg.get("cooldown_between_targets_minutes", 2) * 10)

            target_record["finished_at"] = datetime.now().isoformat()
            run_record["targets"].append(target_record)
            run_record["findings"].extend(target_record["findings"])

            # Update memory
            if handle not in memory.get("hunted", {}):
                memory.setdefault("hunted", {})[handle] = {
                    "first_hunt": datetime.now().isoformat(),
                    "findings": 0,
                    "platform": target["platform"],
                }
            memory["hunted"][handle]["last_hunt"] = datetime.now().isoformat()
            memory["hunted"][handle]["findings"] = memory["hunted"][handle].get("findings", 0) + len(target_record["findings"])

        except Exception as e:
            logger.error(f"  [!] Error processing {handle}: {e}")
            target_record["error"] = str(e)
            target_record["finished_at"] = datetime.now().isoformat()
            run_record["targets"].append(target_record)

        # Cooldown between targets
        if i < len(targets) - 1:
            cooldown = scheduler_cfg.get("cooldown_between_targets_minutes", 10)
            logger.info(f"\n  Cooldown: {cooldown} minutes before next target...")
            time.sleep(cooldown * 60)

    # Finalize
    run_record["finished_at"] = datetime.now().isoformat()
    memory["stats"]["total_runs"] = memory.get("stats", {}).get("total_runs", 0) + 1
    memory["stats"]["total_findings"] = memory.get("stats", {}).get("total_findings", 0) + len(run_record["findings"])

    save_memory(memory)

    state["last_run"] = datetime.now().isoformat()
    state["runs"].append({
        "started_at": run_record["started_at"],
        "finished_at": run_record["finished_at"],
        "targets": len(targets),
        "findings": len(run_record["findings"]),
        "reports": len(run_record["reports"]),
    })
    save_state(state)

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("RUN SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Targets processed: {len(run_record['targets'])}")
    logger.info(f"Total findings: {len(run_record['findings'])}")
    logger.info(f"Reports generated: {len(run_record['reports'])}")

    if run_record["findings"]:
        logger.info("\nFindings:")
        for f in run_record["findings"]:
            logger.info(f"  [{f.get('severity', '?')}] {f.get('title', '?')} - {f.get('url', '?')}")

    # Save run record
    run_file = LOG_DIR / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    run_file.write_text(json.dumps(run_record, indent=2, default=str))
    logger.info(f"\nRun record saved: {run_file}")

    return run_record


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Scheduler")
    parser.add_argument("--target", "-t", help="Override target (skip discovery)")
    parser.add_argument("--max-targets", "-m", type=int, help="Max targets to process")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (no submissions)")
    parser.add_argument("--no-dry-run", action="store_true", help="Disable dry run")
    parser.add_argument("--force", "-f", action="store_true", help="Force run ignoring interval")
    parser.add_argument("--status", action="store_true", help="Show scheduler status")
    args = parser.parse_args()

    config = load_config()
    state = load_state()

    if args.status:
        memory = load_memory()
        print("\n=== Bug Bounty Scheduler Status ===")
        print(f"Last run: {state.get('last_run', 'Never')}")
        print(f"Total runs: {memory.get('stats', {}).get('total_runs', 0)}")
        print(f"Total findings: {memory.get('stats', {}).get('total_findings', 0)}")
        print(f"Hunted targets: {len(memory.get('hunted', {}))}")
        if state.get("runs"):
            last = state["runs"][-1]
            print(f"\nLast run details:")
            print(f"  Started: {last.get('started_at', '?')}")
            print(f"  Targets: {last.get('targets', 0)}")
            print(f"  Findings: {last.get('findings', 0)}")
            print(f"  Reports: {last.get('reports', 0)}")
        return

    if not args.force and not should_run(config, state):
        logger.info("Not time for next run yet. Use --force to override.")
        return

    dry_run = True
    if args.no_dry_run:
        dry_run = False
    elif args.dry_run:
        dry_run = True
    else:
        dry_run = config.get("scheduler", {}).get("dry_run", True)

    run_pipeline(
        max_targets=args.max_targets,
        dry_run=dry_run,
        target_override=args.target,
    )


if __name__ == "__main__":
    main()
