#!/usr/bin/env python3
"""
Bug Bounty AI Brain - Uses local Ollama models for intelligent hunting
Provides: recon analysis, payload generation, finding validation, report enhancement
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).parent

# Ollama config
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODELS = [
    "deepseek-coder-v2:16b",
    "qwen3:4b",
    "qwen2.5:7b",
    "qwen2.5:1.5b",
]


def ollama_chat(model: str, system: str, user: str, temperature: float = 0.3) -> str:
    """Call Ollama API"""
    import requests
    try:
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": {"temperature": temperature}
            },
            timeout=120
        )
        if resp.status_code == 200:
            return resp.json().get("message", {}).get("content", "")
        else:
            print(f"  [!] Ollama error: {resp.status_code}")
            return ""
    except Exception as e:
        print(f"  [!] Ollama error: {e}")
        return ""


def get_available_model() -> Optional[str]:
    """Find first available Ollama model"""
    import requests
    try:
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
        if resp.status_code == 200:
            available = [m["name"] for m in resp.json().get("models", [])]
            for model in MODELS:
                if model in available:
                    return model
            # Fallback to any available model
            if available:
                return available[0]
    except:
        pass
    return None


class BugBountyBrain:
    """AI-powered bug bounty reasoning engine"""

    def __init__(self, model: str = None):
        self.model = model or get_available_model()
        if not self.model:
            print("[!] No Ollama models available. AI features disabled.")
            self.enabled = False
        else:
            print(f"[*] AI Brain: {self.model}")
            self.enabled = True

    def _chat(self, system: str, user: str, temperature: float = 0.3) -> str:
        if not self.enabled:
            return ""
        return ollama_chat(self.model, system, user, temperature)

    # ─── Recon Analysis ──────────────────────────────────────────────

    def analyze_recon(self, recon_data: Dict) -> Dict:
        """AI analysis of recon results to identify attack vectors"""
        if not self.enabled:
            return {"priority_targets": [], "attack_vectors": [], "notes": "AI disabled"}

        system = """You are an expert bug bounty hunter. Analyze recon data and identify the most promising attack vectors.
Focus on: high-impact vulns (RCE, SQLi, SSRF, auth bypass), exposed admin panels, API endpoints, misconfigurations.
Output JSON: {"priority_targets": [{"url": "...", "reason": "...", "vuln_class": "..."}], "attack_vectors": ["..."], "tech_risks": ["..."]}"""

        user = f"""Target: {recon_data.get('target', 'unknown')}

Subdomains: {len(recon_data.get('subdomains', []))} found
Live hosts: {recon_data.get('live_hosts', [])[:10]}
Tech stack: {recon_data.get('tech_stack', [])[:5]}
Ports: {recon_data.get('ports', [])[:10]}
Nuclei findings: {recon_data.get('nuclei_findings', [])[:5]}
Interesting URLs: {recon_data.get('interesting_urls', [])[:15]}
Directories: {recon_data.get('directories', [])[:10]}
DNS records: {recon_data.get('dns_records', [])[:5]}

Analyze and output JSON with priority_targets, attack_vectors, tech_risks."""

        response = self._chat(system, user)
        try:
            # Extract JSON from response
            if "{" in response:
                json_str = response[response.index("{"):response.rindex("}")+1]
                return json.loads(json_str)
        except:
            pass
        return {"priority_targets": [], "attack_vectors": [], "raw": response}

    # ─── Payload Generation ──────────────────────────────────────────

    def generate_payloads(self, vuln_class: str, target_url: str, tech_stack: List[str]) -> List[Dict]:
        """Generate context-aware payloads based on tech stack"""
        if not self.enabled:
            return []

        system = f"""You are an expert in {vuln_class} exploitation. Generate targeted payloads for the given tech stack.
Output JSON array: [{{"payload": "...", "description": "...", "expected_response": "...", "severity": "P1-P5"}}]
Generate 3-5 payloads, ordered by likelihood of success. Be specific to the tech stack."""

        user = f"""Vulnerability class: {vuln_class}
Target URL: {target_url}
Tech stack: {', '.join(tech_stack)}

Generate payloads specific to this tech stack. Include both common and advanced techniques."""

        response = self._chat(system, user, temperature=0.5)
        try:
            if "[" in response:
                json_str = response[response.index("["):response.rindex("]")+1]
                return json.loads(json_str)
        except:
            pass
        return []

    # ─── Finding Validation ──────────────────────────────────────────

    def validate_finding(self, finding: Dict) -> Dict:
        """AI validates if finding is exploitable and not a false positive"""
        if not self.enabled:
            return {"valid": True, "confidence": 0.5, "reason": "AI disabled"}

        system = """You are a bug bounty triage expert. Validate if this finding is:
1. Actually exploitable (not just theoretical)
2. Not a false positive
3. Has real impact
4. Not a duplicate of common findings

Output JSON: {"valid": true/false, "confidence": 0.0-1.0, "reason": "...", "improvement": "...", "severity_adjustment": "P1-P5"}"""

        user = f"""Finding:
- Class: {finding.get('vuln_class', 'unknown')}
- Title: {finding.get('title', '')}
- URL: {finding.get('url', '')}
- Severity: {finding.get('severity', '')}
- Evidence: {finding.get('evidence', '')[:500]}
- Description: {finding.get('description', '')}

Is this a valid, exploitable finding with real impact?"""

        response = self._chat(system, user)
        try:
            if "{" in response:
                json_str = response[response.index("{"):response.rindex("}")+1]
                return json.loads(json_str)
        except:
            pass
        return {"valid": True, "confidence": 0.5, "reason": "Could not parse AI response"}

    # ─── Report Enhancement ──────────────────────────────────────────

    def enhance_report(self, finding: Dict, raw_report: str) -> str:
        """AI enhances report to be more submission-ready"""
        if not self.enabled:
            return raw_report

        system = """You are a professional bug bounty report writer. Enhance this report to:
1. Be clear and concise
2. Have strong impact explanation
3. Include actionable remediation
4. Sound professional, not robotic
5. Follow HackerOne/Bugcrowd best practices

Output the enhanced report in markdown."""

        user = f"""Enhance this bug bounty report:

{raw_report}

Make it more compelling and professional while keeping all technical details accurate."""

        return self._chat(system, user, temperature=0.4) or raw_report

    # ─── Next Steps ──────────────────────────────────────────────────

    def suggest_next_steps(self, recon_data: Dict, findings: List[Dict], time_remaining: int) -> List[str]:
        """AI suggests what to test next based on current state"""
        if not self.enabled:
            return []

        system = """You are a bug bounty strategist. Given the current state, suggest the top 5 next actions to take.
Consider: time remaining, what's been tested, what looks promising, ROI of each action.
Output JSON array of strings: ["action 1", "action 2", ...]"""

        user = f"""Target: {recon_data.get('target', 'unknown')}
Time remaining: {time_remaining} minutes

Recon summary:
- Subdomains: {len(recon_data.get('subdomains', []))}
- Live hosts: {len(recon_data.get('live_hosts', []))}
- Interesting URLs: {len(recon_data.get('interesting_urls', []))}
- Tech: {recon_data.get('tech_stack', [])[:3]}

Current findings: {len(findings)}
Finding classes: {[f.get('vuln_class') for f in findings[:5]]}

What should I test next?"""

        response = self._chat(system, user)
        try:
            if "[" in response:
                json_str = response[response.index("["):response.rindex("]")+1]
                return json.loads(json_str)
        except:
            pass
        return []

    # ─── Exploit Chain ───────────────────────────────────────────────

    def build_exploit_chain(self, findings: List[Dict]) -> Dict:
        """AI builds exploit chains from multiple findings"""
        if not self.enabled or len(findings) < 2:
            return {"chains": [], "note": "Need 2+ findings for chaining"}

        system = """You are an expert at chaining vulnerabilities for maximum impact.
Given multiple findings, identify if they can be combined for greater impact (e.g., XSS+CSRF, SSRF+internal access, IDOR+auth bypass).

Output JSON: {"chains": [{"name": "...", "steps": ["step1", "step2"], "impact": "...", "severity": "P1-P5"}]}"""

        user = f"""Findings to chain:
{json.dumps([{"class": f.get("vuln_class"), "url": f.get("url"), "severity": f.get("severity")} for f in findings[:10]], indent=2)}

Can any of these be chained for greater impact?"""

        response = self._chat(system, user)
        try:
            if "{" in response:
                json_str = response[response.index("{"):response.rindex("}")+1]
                return json.loads(json_str)
        except:
            pass
        return {"chains": [], "raw": response}


# ─── CLI ─────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty AI Brain")
    parser.add_argument("--analyze-recon", type=str, help="Path to recon_results.json")
    parser.add_argument("--validate", type=str, help="Path to finding JSON")
    parser.add_argument("--suggest", type=str, help="Path to recon_results.json for next steps")
    parser.add_argument("--model", type=str, help="Override model")
    args = parser.parse_args()

    brain = BugBountyBrain(args.model)

    if args.analyze_recon:
        data = json.loads(Path(args.analyze_recon).read_text())
        result = brain.analyze_recon(data)
        print(json.dumps(result, indent=2))

    elif args.validate:
        finding = json.loads(Path(args.validate).read_text())
        result = brain.validate_finding(finding)
        print(json.dumps(result, indent=2))

    elif args.suggest:
        data = json.loads(Path(args.suggest).read_text())
        steps = brain.suggest_next_steps(data, [], 60)
        for i, step in enumerate(steps, 1):
            print(f"{i}. {step}")

    else:
        print(f"Model: {brain.model}")
        print(f"Enabled: {brain.enabled}")


if __name__ == "__main__":
    main()
