#!/usr/bin/env python3
# BugRap Web3 Preflight Check for ~/projects/bugbounty
import os
from pathlib import Path


BASE = Path('/home/openclaw/projects/bugbounty')
FILES = {
    'report': BASE / 'reports/web3/bugrap-bitget-report-skeleton.md',
    'checklist': BASE / 'reports/web3/bugrap-bitget-submission-checklist.md',
    'skill': BASE / 'reports/web3/smart_contract_skill.md',
    'recon': BASE / 'scripts/recon_cloak_flow.py',
}
TARGET = {
    'program': 'Bitget',
    'bounty': '1,000,000 USDC',
    'report_present': False,
    'checklist_present': False,
    'skill_present': False,
    'recon_present': False,
    'estimated_sprint': '7 days',
}


def main() -> int:
    missing = []
    for key in ('report', 'checklist', 'skill', 'recon'):
        path = FILES[key]
        exists = path.is_file()
        TARGET[f'{key}_present'] = exists
        if not exists:
            missing.append(key)

    print('BugRap Web3 preflight')
    for key in ('report', 'checklist', 'skill', 'recon'):
        path = FILES[key]
        print(f' - {key}: {path} -> {"OK" if TARGET[f"{key}_present"] else "MISSING"}')

    if missing:
        print(f'MISSING: {missing}')
        return 2

    print(f"Program: {TARGET['program']}")
    print(f"Bounty: {TARGET['bounty']}")
    print(f"Estimated sprint: {TARGET['estimated_sprint']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
