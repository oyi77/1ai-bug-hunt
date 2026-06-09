#!/usr/bin/env python3
"""
Report Generator - Creates bug bounty reports from findings
Follows POC_TEMPLATE.md and BUG_BOUNTY_TEMPLATE.md format
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

SCRIPT_DIR = Path(__file__).parent


def generate_report(finding: Dict, program: Dict = None) -> str:
    """Generate markdown report from finding"""

    vuln_class = finding.get("vuln_class", "unknown")
    title = finding.get("title", "Vulnerability Finding")
    severity = finding.get("severity", "P3")
    url = finding.get("url", "")
    evidence = finding.get("evidence", "")
    description = finding.get("description", "")
    remediation = finding.get("remediation", "")
    target = finding.get("target", "")

    # CWE mapping
    cwe_map = {
        "xss": ("CWE-79", "Cross-site Scripting"),
        "sqli": ("CWE-89", "SQL Injection"),
        "ssrf": ("CWE-918", "Server-Side Request Forgery"),
        "idor": ("CWE-639", "Insecure Direct Object Reference"),
        "csrf": ("CWE-352", "Cross-Site Request Forgery"),
        "cors": ("CWE-942", "Permissive Cross-domain Policy"),
        "open_redirect": ("CWE-601", "URL Redirection to Untrusted Site"),
        "auth_bypass": ("CWE-287", "Improper Authentication"),
        "info_disclosure": ("CWE-200", "Information Exposure"),
        "file_upload": ("CWE-434", "Unrestricted Upload of File"),
        "race_condition": ("CWE-362", "Race Condition"),
        "business_logic": ("CWE-840", "Business Logic Error"),
    }

    cwe_id, cwe_name = cwe_map.get(vuln_class, ("CWE-0", "Unknown"))

    # CVSS mapping by severity
    cvss_map = {
        "P1": ("9.0", "Critical"),
        "P2": ("7.5", "High"),
        "P3": ("5.5", "Medium"),
        "P4": ("3.5", "Low"),
        "P5": ("1.0", "Info"),
    }
    cvss_score, cvss_label = cvss_map.get(severity, ("5.0", "Medium"))

    program_name = program.get("name", target) if program else target
    program_handle = program.get("handle", target) if program else target
    bounty_range = ""
    if program:
        if program.get("offers_bounties"):
            bounty_range = "Paid bounty program"
        else:
            bounty_range = "VDP (Vulnerability Disclosure Program)"

    report = f"""# Vulnerability: {title}

## Program
**Target:** {program_name} (@{program_handle})
**URL:** {url}
**Bounty:** {bounty_range}

## Summary
{description if description else f"A {vuln_class.upper()} vulnerability was found at {url}."}

## Severity
**CVSS v3.1:** {cvss_score} ({cvss_label})
**CWE:** {cwe_id} ({cwe_name})
**Bug Bounty Severity:** {severity}

## Affected Asset
- {url}

## Steps to Reproduce

### Step 1: Navigate to the target
```
{url}
```

### Step 2: Observe the vulnerability
```
{evidence}
```

## Proof of Concept

### Request
```http
GET {url} HTTP/1.1
Host: {target}
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36
Accept: */*
```

### Response / Evidence
```
{evidence}
```

## Impact

### Direct Impact
"""

    # Impact by vuln class
    impact_map = {
        "xss": """1. Attacker can execute arbitrary JavaScript in victim's browser
2. Session hijacking via cookie theft
3. Phishing via fake login forms injected into page
4. Defacement of the application""",
        "sqli": """1. Full database access including all user data
2. Authentication bypass (admin access)
3. Data exfiltration (PII, credentials, financial data)
4. Potential remote code execution via xp_cmdshell""",
        "ssrf": """1. Access to internal cloud metadata (AWS/GCP/Azure credentials)
2. Internal network scanning and service discovery
3. Access to internal APIs and databases
4. Potential RCE via internal services""",
        "idor": """1. Access to other users' private data (PII, financial records)
2. Ability to modify or delete other users' data
3. Full account takeover by accessing account settings
4. Mass data exfiltration""",
        "cors": """1. Cross-origin data theft with user credentials
2. Reading authenticated API responses from malicious site
3. Bypassing same-origin policy protections""",
        "auth_bypass": """1. Unauthorized access to admin functionality
2. Full application takeover
3. Access to all user data and system configuration
4. Ability to modify application settings""",
        "info_disclosure": """1. Exposure of sensitive system information
2. Enables further targeted attacks
3. May reveal credentials or internal URLs""",
        "open_redirect": """1. Phishing attacks using trusted domain
2. OAuth token theft via redirect manipulation
3. Malware distribution through trusted URL""",
        "race_condition": """1. Double-spending in financial transactions
2. Redeeming coupons/vouchers multiple times
3. Bypassing quantity limits""",
        "business_logic": """1. Financial manipulation (negative amounts)
2. Bypassing business rules and restrictions
3. Unauthorized discounts or credits""",
        "file_upload": """1. Remote code execution via webshell upload
2. XSS via uploaded HTML/SVG files
3. Denial of service via large file uploads""",
        "csrf": """1. Unauthorized actions performed on behalf of authenticated users
2. Account settings modification
3. Unauthorized fund transfers or purchases""",
    }

    report += impact_map.get(vuln_class, "1. Impact depends on context and application sensitivity") + "\n"

    report += f"""
### Attack Chain
```
1. Attacker identifies vulnerable endpoint: {url}
2. Crafts exploit payload for {vuln_class.upper()}
3. Delivers payload to target
4. Achieves unauthorized access/data extraction
```

### Business Impact
- Financial: Potential data breach costs, regulatory fines
- Reputation: User trust damage if vulnerability is exploited
- Compliance: May violate GDPR, PCI-DSS, or other regulations

## Remediation
{remediation if remediation else "Implement proper input validation and output encoding."}

## References
- OWASP: https://owasp.org/www-community/attacks/
- {cwe_id}: https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html

## Evidence
- Finding ID: {finding.get('id', 'N/A')}
- Found at: {finding.get('found_at', datetime.now().isoformat())}
- Target: {target}

---
*Generated by Automated Bug Bounty Scheduler*
"""

    return report


def save_report(finding: Dict, output_dir: str, program: Dict = None) -> Path:
    """Save report to file"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = generate_report(finding, program)

    # Filename: YYYY-MM-DD_vulnclass_target.md
    date_str = datetime.now().strftime("%Y-%m-%d")
    safe_class = finding.get("vuln_class", "unknown").replace(" ", "_")
    safe_target = finding.get("target", "unknown").replace(".", "_")
    filename = f"{date_str}_{safe_class}_{safe_target}.md"

    report_path = output_path / filename
    report_path.write_text(report)
    print(f"[*] Report saved: {report_path}")

    return report_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Bug Bounty Report")
    parser.add_argument("findings_file", help="Path to findings.json")
    parser.add_argument("--output", "-o", help="Output directory")
    args = parser.parse_args()

    findings = json.loads(Path(args.findings_file).read_text())
    output_dir = args.output or str(SCRIPT_DIR.parent.parent / "reports")

    for finding in findings:
        save_report(finding, output_dir)
