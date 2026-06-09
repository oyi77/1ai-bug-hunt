# Bug Bounty Scheduler

Automated bug bounty hunting pipeline.

## Architecture

```
scheduler/
├── config.json      # Configuration (platforms, recon, hunting settings)
├── discover.py      # Program discovery (HackerOne, Bugcrowd, YesWeHack)
├── recon.py         # Reconnaissance pipeline (subfinder, httpx, nuclei, nmap, ffuf)
├── hunt.py          # Vulnerability hunting (12 vuln classes)
├── report.py        # Report generation (P1-P5 severity, CWE mapping)
├── run.py           # Main orchestrator (full pipeline)
├── setup_cron.sh    # Cron scheduler setup
├── state.json       # Scheduler state (last run, history)
├── memory.json      # Hunt memory (hunted targets, findings)
└── README.md        # This file
```

## Pipeline Flow

```
1. DISCOVER  → Fetch programs from H1/BC/YWH, select best targets
2. RECON     → Subdomain enum, live probing, nuclei, nmap, ffuf, API discovery
3. HUNT      → 12 vuln classes: XSS, SQLi, SSRF, IDOR, CSRF, auth bypass, etc.
4. REPORT    → Generate submission-ready reports with PoC
```

## Usage

### Manual Run
```bash
# Full pipeline (auto-select targets)
python3 run.py

# Single target
python3 run.py --target example.com

# With limits
python3 run.py --max-targets 2 --dry-run

# Force run (ignore cooldown)
python3 run.py --force

# Check status
python3 run.py --status
```

### Individual Components
```bash
# Discovery only
python3 discover.py --list
python3 discover.py --platform h1 --max 5

# Get scopes for H1 program
python3 discover.py --scopes example

# Recon only
python3 recon.py example.com

# Hunt only
python3 hunt.py example.com

# Generate reports
python3 report.py /path/to/findings.json
```

### Cron Setup
```bash
bash setup_cron.sh
```

## Configuration

Edit `config.json`:

- **platforms**: Enable/disable H1, BC, YWH; set bounty filters
- **scheduler**: Run interval, max targets, dry run mode
- **recon**: Enable/disable tools, set timeouts
- **hunting**: Vuln classes to test, time limits
- **reporting**: CVSS threshold, templates

## Vuln Classes Tested

| Class | Severity | Check |
|-------|----------|-------|
| XSS | P3 | Reflected XSS in URL parameters |
| SQLi | P1 | SQL error indicators in responses |
| SSRF | P1 | URL parameters accepting internal URLs |
| IDOR | P2 | Sequential numeric ID access |
| CSRF | P3 | Missing CSRF tokens in POST forms |
| Auth Bypass | P2 | Admin panels accessible without auth |
| Info Disclosure | P4-P5 | Missing headers, server version, stack traces |
| CORS | P2-P3 | Origin reflection, wildcard + credentials |
| Open Redirect | P3 | Redirect parameters accepting arbitrary URLs |
| File Upload | P3 | Unrestricted upload endpoints |
| Race Condition | P3 | Concurrent request handling |
| Business Logic | P3 | Negative values, parameter manipulation |

## Credentials

Stored in `../.env` (gitignored):
- HackerOne: email, password, 2FA, API token
- Bugcrowd: email, password, TOTP
- YesWeHack: email, password
- Chaos API key (subdomain enumeration)

## Logs

- `logs/scheduler_YYYYMMDD.log` - Daily scheduler logs
- `logs/run_YYYYMMDD_HHMMSS.json` - Run records
- `logs/cron.log` - Cron job output

## Safety

- **Dry run by default** - No auto-submission
- **Cooldown between targets** - Prevents rate limiting
- **Hunt memory** - Tracks already-hunted targets
- **Blacklist support** - Skip specific programs
- **5-minute rule** - Skip unresponsive targets
