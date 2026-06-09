#!/usr/bin/env python3
"""
Recon Pipeline - Full Kali Linux tool integration
Uses: subfinder, amass, assetfinder, fierce, dnsrecon, dnsenum, theHarvester,
      httpx, whatweb, wafw00f, nmap, masscan, nuclei, nikto, sslscan, sslyze,
      ffuf, gobuster, dirb, wfuzz, katana, gau, searchsploit, wpscan
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def run_cmd(cmd: str, timeout: int = 300, label: str = "") -> tuple:
    """Run shell command, return (stdout, stderr, returncode)"""
    print(f"  [>] {label or cmd[:80]}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        print(f"  [!] Timeout: {label}")
        return "", "timeout", 1
    except Exception as e:
        print(f"  [!] Error: {e}")
        return "", str(e), 1


class ReconPipeline:
    def __init__(self, target: str, output_dir: str, config: dict):
        self.target = target.replace("*.", "").replace("https://", "").replace("http://", "").strip("/")
        self.output_dir = Path(output_dir) / self.target / "recon"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config.get("recon", {})
        self.results = {
            "target": self.target,
            "started_at": datetime.now().isoformat(),
            "subdomains": [],
            "live_hosts": [],
            "tech_stack": [],
            "ports": [],
            "directories": [],
            "nuclei_findings": [],
            "nikto_findings": [],
            "interesting_urls": [],
            "dns_records": [],
            "ssl_info": [],
            "waf_info": [],
            "cms_info": [],
            "url_history": [],
        }

    def run_all(self) -> Dict:
        """Run full recon pipeline"""
        print(f"\n{'='*60}")
        print(f"[*] RECON: {self.target}")
        print(f"{'='*60}\n")

        # Phase 1: Subdomain enumeration (parallel)
        self.step_subdomain_enum()

        # Phase 2: DNS analysis
        self.step_dns_analysis()

        # Phase 3: Live host probing
        self.step_live_probing()

        # Phase 4: WAF detection
        self.step_waf_detection()

        # Phase 5: Technology fingerprinting
        self.step_tech_fingerprint()

        # Phase 6: Port scanning
        self.step_port_scan()

        # Phase 7: SSL/TLS analysis
        self.step_ssl_analysis()

        # Phase 8: URL history discovery
        self.step_url_history()

        # Phase 9: Directory bruteforcing
        self.step_directory_bruteforce()

        # Phase 10: API discovery
        self.step_api_discovery()

        # Phase 11: Config file discovery
        self.step_config_discovery()

        # Phase 12: Vulnerability scanning
        self.step_vuln_scan()

        # Phase 13: CMS detection & scanning
        self.step_cms_scan()

        self.results["finished_at"] = datetime.now().isoformat()

        # Save results
        output_file = self.output_dir / "recon_results.json"
        output_file.write_text(json.dumps(self.results, indent=2))
        print(f"\n[*] Recon saved: {output_file}")

        return self.results

    def step_subdomain_enum(self):
        """Phase 1: Subdomain enumeration with multiple tools"""
        print("\n[Phase 1] Subdomain Enumeration")
        subdomains_file = self.output_dir / "subdomains.txt"
        all_subs = set()

        # subfinder
        if self.config.get("subfinder", True):
            out, err, rc = run_cmd(
                f"subfinder -d {self.target} -silent -timeout 30",
                timeout=120, label="subfinder"
            )
            if out.strip():
                subs = set(line.strip() for line in out.strip().splitlines() if line.strip())
                all_subs.update(subs)
                print(f"  [+] subfinder: {len(subs)} subdomains")

        # amass passive
        if self.config.get("amass", False):
            out, err, rc = run_cmd(
                f"amass enum -passive -d {self.target} -timeout 10",
                timeout=600, label="amass passive"
            )
            if out.strip():
                new = set(line.strip() for line in out.strip().splitlines() if line.strip())
                all_subs.update(new)
                print(f"  [+] amass: {len(new)} subdomains")

        # assetfinder
        if self.config.get("assetfinder", True):
            out, err, rc = run_cmd(
                f"assetfinder --subs-only {self.target}",
                timeout=60, label="assetfinder"
            )
            if out.strip():
                new = set(line.strip() for line in out.strip().splitlines() if line.strip())
                all_subs.update(new)
                print(f"  [+] assetfinder: {len(new)} subdomains")

        # fierce
        if self.config.get("fierce", True):
            out, err, rc = run_cmd(
                f"fierce --domain {self.target} --timeout 30",
                timeout=120, label="fierce"
            )
            if out.strip():
                import re
                found = re.findall(r'[\w.-]+\.' + re.escape(self.target), out)
                all_subs.update(found)
                print(f"  [+] fierce: {len(found)} subdomains")

        # dnsrecon
        if self.config.get("dnsrecon", True):
            out, err, rc = run_cmd(
                f"dnsrecon -d {self.target} -t std -j {self.output_dir}/dnsrecon.json",
                timeout=120, label="dnsrecon"
            )
            if out.strip():
                import re
                found = re.findall(r'[\w.-]+\.' + re.escape(self.target), out)
                all_subs.update(found)
                print(f"  [+] dnsrecon: {len(found)} subdomains")

        # theHarvester
        if self.config.get("theHarvester", True):
            out, err, rc = run_cmd(
                f"theHarvester -d {self.target} -b all -l 200",
                timeout=120, label="theHarvester"
            )
            if out.strip():
                import re
                found = re.findall(r'[\w.-]+\.' + re.escape(self.target), out)
                all_subs.update(found)
                print(f"  [+] theHarvester: {len(found)} subdomains")

        # Always add base domain
        all_subs.add(self.target)

        # Save
        subdomains_file.write_text("\n".join(sorted(all_subs)) + "\n")
        self.results["subdomains"] = list(all_subs)
        print(f"  [*] Total unique subdomains: {len(all_subs)}")

    def step_dns_analysis(self):
        """Phase 2: DNS record analysis"""
        print("\n[Phase 2] DNS Analysis")

        # dig all records
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
            out, err, rc = run_cmd(
                f"dig {self.target} {rtype} +short",
                timeout=15, label=f"dig {rtype}"
            )
            if out.strip():
                self.results["dns_records"].append({"type": rtype, "records": out.strip().splitlines()})

        # dnsenum
        if self.config.get("dnsenum", True):
            out, err, rc = run_cmd(
                f"dnsenum {self.target} --enum -f /usr/share/dnsenum/dns.txt",
                timeout=120, label="dnsenum"
            )
            if out.strip():
                print(f"  [+] dnsenum results saved")

    def step_live_probing(self):
        """Phase 3: Live host probing with httpx"""
        print("\n[Phase 3] Live Host Probing")
        subdomains_file = self.output_dir / "subdomains.txt"
        live_file = self.output_dir / "live_hosts.txt"

        if not subdomains_file.exists():
            print("  [!] No subdomains file, skipping")
            return

        out, err, rc = run_cmd(
            f"cat {subdomains_file} | httpx -silent -status-code -title -tech-detect "
            f"-follow-redirects -cdn -ip -method",
            timeout=180, label="httpx probe"
        )

        if out.strip():
            live = []
            for line in out.strip().splitlines():
                live.append(line.strip())
                parts = line.split()
                if parts:
                    self.results["live_hosts"].append(parts[0])

            live_file.write_text("\n".join(live) + "\n")
            print(f"  [+] {len(live)} live hosts found")

            # Extract tech from httpx output
            for line in live:
                if "[" in line and "]" in line:
                    tech_part = line[line.index("["):line.rindex("]")+1]
                    self.results["tech_stack"].append(tech_part)

    def step_waf_detection(self):
        """Phase 4: WAF detection with wafw00f"""
        print("\n[Phase 4] WAF Detection")

        if not self.config.get("wafw00f", True):
            return

        out, err, rc = run_cmd(
            f"wafw00f https://{self.target} -a -o {self.output_dir}/waf_results.txt",
            timeout=60, label="wafw00f"
        )

        if out.strip():
            if "No WAF" in out:
                print("  [-] No WAF detected")
                self.results["waf_info"] = ["No WAF detected"]
            else:
                self.results["waf_info"] = out.strip().splitlines()
                print(f"  [+] WAF detected: {out.strip()[:100]}")

    def step_tech_fingerprint(self):
        """Phase 5: Technology fingerprinting with whatweb"""
        print("\n[Phase 5] Technology Fingerprinting")

        if not self.config.get("whatweb", True):
            return

        out, err, rc = run_cmd(
            f"whatweb https://{self.target} --color=never -a 3",
            timeout=60, label="whatweb"
        )

        if out.strip():
            self.results["tech_stack"] = list(set(self.results["tech_stack"] + [out.strip()]))
            print(f"  [+] Technologies identified")

        # Check response headers for tech
        out, err, rc = run_cmd(
            f"curl -sI -m 10 https://{self.target}",
            timeout=15, label="headers check"
        )
        if out.strip():
            for header in ["server", "x-powered-by", "x-aspnet-version", "x-runtime", "x-generator"]:
                for line in out.splitlines():
                    if line.lower().startswith(header):
                        self.results["tech_stack"].append(line.strip())

    def step_port_scan(self):
        """Phase 6: Port scanning with nmap + masscan"""
        print("\n[Phase 6] Port Scanning")
        nmap_output = self.output_dir / "nmap_results.txt"

        # masscan quick sweep first
        if self.config.get("masscan", True):
            out, err, rc = run_cmd(
                f"masscan {self.target} -p1-1000 --rate=1000 -oL {self.output_dir}/masscan.txt",
                timeout=120, label="masscan quick"
            )
            if out.strip():
                print(f"  [+] masscan results saved")

        # nmap detailed scan
        if self.config.get("nmap", True):
            out, err, rc = run_cmd(
                f"nmap -sV -sC -T4 --top-ports 1000 -oN {nmap_output} -oX {self.output_dir}/nmap.xml {self.target}",
                timeout=600, label="nmap detailed"
            )

            if out.strip():
                ports = []
                for line in out.strip().splitlines():
                    if "/tcp" in line or "/udp" in line:
                        ports.append(line.strip())
                self.results["ports"] = ports
                print(f"  [+] {len(ports)} open ports found")

    def step_ssl_analysis(self):
        """Phase 7: SSL/TLS analysis"""
        print("\n[Phase 7] SSL/TLS Analysis")

        # sslscan
        if self.config.get("sslscan", True):
            out, err, rc = run_cmd(
                f"sslscan {self.target} --no-colour",
                timeout=60, label="sslscan"
            )
            if out.strip():
                self.results["ssl_info"].append({"tool": "sslscan", "output": out[:2000]})
                # Check for weaknesses
                if "SSLv2" in out or "SSLv3" in out:
                    print("  [!] Weak SSL versions detected!")
                if "0 cipher" not in out:
                    print(f"  [+] SSL configuration analyzed")

        # sslyze
        if self.config.get("sslyze", True):
            out, err, rc = run_cmd(
                f"sslyze --certinfo=basic --http_headers {self.target}",
                timeout=60, label="sslyze"
            )
            if out.strip():
                self.results["ssl_info"].append({"tool": "sslyze", "output": out[:2000]})

    def step_url_history(self):
        """Phase 8: URL history with katana and gau"""
        print("\n[Phase 8] URL History Discovery")
        urls_file = self.output_dir / "urls.txt"
        all_urls = set()

        # katana crawl
        if self.config.get("katana", True):
            out, err, rc = run_cmd(
                f"katana -u https://{self.target} -d {self.config.get('katana_depth', 3)} -silent -jc",
                timeout=300, label="katana crawl"
            )
            if out.strip():
                urls = set(line.strip() for line in out.strip().splitlines() if line.strip())
                all_urls.update(urls)
                print(f"  [+] katana: {len(urls)} URLs")

        # gau (wayback + commoncrawl)
        if self.config.get("gau", True):
            out, err, rc = run_cmd(
                f"echo {self.target} | gau --blacklist png,jpg,gif,css,js,woff,svg",
                timeout=120, label="gau"
            )
            if out.strip():
                urls = set(line.strip() for line in out.strip().splitlines() if line.strip())
                all_urls.update(urls)
                print(f"  [+] gau: {len(urls)} URLs")

        if all_urls:
            urls_file.write_text("\n".join(sorted(all_urls)) + "\n")
            self.results["url_history"] = list(all_urls)[:1000]
            print(f"  [*] Total unique URLs: {len(all_urls)}")

    def step_directory_bruteforce(self):
        """Phase 9: Directory bruteforcing with ffuf + gobuster"""
        print("\n[Phase 9] Directory Bruteforcing")
        ffuf_output = self.output_dir / "ffuf_results.json"

        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ]
        wordlist = None
        for wl in wordlists:
            if Path(wl).exists():
                wordlist = wl
                break

        if not wordlist:
            print("  [!] No wordlist found, skipping")
            return

        # ffuf
        if self.config.get("ffuf", True):
            out, err, rc = run_cmd(
                f"ffuf -u https://{self.target}/FUZZ -w {wordlist} "
                f"-mc 200,301,302,403,401 -t {self.config.get('ffuf_threads', 40)} "
                f"-o {ffuf_output} -of json -s -timeout 10",
                timeout=300, label="ffuf directory scan"
            )

            if ffuf_output.exists():
                try:
                    data = json.loads(ffuf_output.read_text())
                    results = data.get("results", [])
                    self.results["directories"] = [r.get("input", {}).get("FUZZ", "") for r in results]
                    print(f"  [+] ffuf: {len(results)} directories found")
                except:
                    pass

        # gobuster
        if self.config.get("gobuster", True):
            out, err, rc = run_cmd(
                f"gobuster dir -u https://{self.target} -w {wordlist} "
                f"-t {self.config.get('ffuf_threads', 40)} -s '200,301,302,403' -q",
                timeout=300, label="gobuster"
            )
            if out.strip():
                new_dirs = [line.split()[0] for line in out.strip().splitlines() if line.strip()]
                self.results["directories"] = list(set(self.results["directories"] + new_dirs))
                print(f"  [+] gobuster: {len(new_dirs)} directories found")

    def step_api_discovery(self):
        """Phase 10: API endpoint discovery"""
        print("\n[Phase 10] API Discovery")
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/swagger.json", "/openapi.json",
            "/api-docs", "/v1", "/v2", "/v3",
            "/.well-known/openid-configuration",
            "/wp-json/wp/v2",
            "/api/swagger", "/api/docs", "/api/redoc",
            "/api/health", "/api/status", "/api/ping",
            "/graphql/playground", "/graphiql",
            "/api/v1/users", "/api/v1/auth", "/api/v1/admin",
        ]

        found = []
        for path in api_paths:
            out, err, rc = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 'https://{self.target}{path}'",
                timeout=10, label=f"check {path}"
            )
            code = out.strip().strip("'")
            if code in ("200", "401", "403", "301", "302"):
                found.append(f"{path} -> {code}")
                self.results["interesting_urls"].append(f"https://{self.target}{path}")

        if found:
            print(f"  [+] {len(found)} API endpoints found")
            for f in found:
                print(f"      {f}")

    def step_config_discovery(self):
        """Phase 11: Configuration file discovery"""
        print("\n[Phase 11] Config File Discovery")
        config_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/config.json", "/config.js", "/config.yml", "/config.yaml",
            "/settings.json", "/settings.py",
            "/.git/config", "/.git/HEAD", "/.svn/entries", "/.hg/dirstate",
            "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
            "/.well-known/security.txt", "/security.txt",
            "/debug", "/trace", "/actuator", "/actuator/env", "/actuator/health",
            "/elmah.axd", "/server-status", "/server-info",
            "/.htaccess", "/.htpasswd", "/web.config",
            "/phpinfo.php", "/info.php", "/test.php",
            "/backup", "/backup.sql", "/database.sql", "/dump.sql",
            "/admin", "/administrator", "/wp-admin",
            "/.DS_Store", "/Thumbs.db", "/.idea/",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/WEB-INF/web.xml",
        ]

        found = []
        for path in config_paths:
            out, err, rc = run_cmd(
                f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 'https://{self.target}{path}'",
                timeout=10, label=f"check {path}"
            )
            code = out.strip().strip("'")
            if code == "200":
                found.append(path)
                self.results["interesting_urls"].append(f"https://{self.target}{path}")

        if found:
            print(f"  [+] {len(found)} config files exposed")
            for f in found:
                print(f"      {f}")

    def step_vuln_scan(self):
        """Phase 12: Vulnerability scanning with nuclei + nikto"""
        print("\n[Phase 12] Vulnerability Scanning")
        live_file = self.output_dir / "live_hosts.txt"

        # nuclei
        if self.config.get("nuclei", True):
            severity = ",".join(self.config.get("nuclei_severity", ["critical", "high", "medium"]))
            nuclei_output = self.output_dir / "nuclei_results.txt"

            target_file = live_file if live_file.exists() else None
            target_input = f"cat {target_file} |" if target_file else f"echo https://{self.target} |"

            out, err, rc = run_cmd(
                f"{target_input} nuclei -silent -severity {severity} -timeout 10 -retries 2",
                timeout=self.config.get("timeout_minutes", 30) * 60,
                label="nuclei scan"
            )

            if out.strip():
                findings = out.strip().splitlines()
                nuclei_output.write_text("\n".join(findings) + "\n")
                self.results["nuclei_findings"] = findings
                print(f"  [+] nuclei: {len(findings)} findings")
            else:
                print("  [-] nuclei: no findings")

        # nikto
        if self.config.get("nikto", True):
            nikto_output = self.output_dir / "nikto_results.txt"
            out, err, rc = run_cmd(
                f"nikto -h https://{self.target} -Format txt -output {nikto_output} -Tuning 123",
                timeout=600, label="nikto scan"
            )
            if out.strip():
                self.results["nikto_findings"] = out.strip().splitlines()
                print(f"  [+] nikto: findings saved")

        # searchsploit for known exploits based on tech
        if self.config.get("searchsploit", True) and self.results.get("tech_stack"):
            for tech in self.results["tech_stack"][:5]:
                # Extract clean tech name
                tech_name = tech.split("[")[0].strip() if "[" in tech else tech.strip()
                if tech_name and len(tech_name) > 2:
                    out, err, rc = run_cmd(
                        f"searchsploit '{tech_name}' --json 2>/dev/null | head -50",
                        timeout=30, label=f"searchsploit {tech_name}"
                    )
                    if out.strip() and "No results" not in out:
                        print(f"  [+] searchsploit: exploits found for {tech_name}")

    def step_cms_scan(self):
        """Phase 13: CMS detection and scanning"""
        print("\n[Phase 13] CMS Scanning")

        # wpscan
        if self.config.get("wpscan", True):
            out, err, rc = run_cmd(
                f"wpscan --url https://{self.target} --enumerate vp,vt,u --no-banner --random-user-agent",
                timeout=300, label="wpscan"
            )
            if out.strip():
                if "WordPress" in out or "wp-" in out.lower():
                    self.results["cms_info"].append({"cms": "WordPress", "output": out[:2000]})
                    print(f"  [+] WordPress detected")
                    # Check for vulnerabilities
                    if "[+]" in out:
                        vulns = [l for l in out.splitlines() if "[+]" in l]
                        print(f"      {len(vulns)} potential vulnerabilities")
                else:
                    print("  [-] Not WordPress")


def run_recon(target: str, output_dir: str = None, config: dict = None) -> Dict:
    """Main entry point"""
    if config is None:
        config = load_config()
    if output_dir is None:
        output_dir = config["paths"]["output_base"]

    pipeline = ReconPipeline(target, output_dir, config)
    return pipeline.run_all()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Recon Pipeline (Full Kali)")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--output", "-o", help="Output directory")
    args = parser.parse_args()

    config = load_config()
    results = run_recon(args.target, args.output, config)
    print(f"\n[*] Summary:")
    for k, v in results.items():
        if isinstance(v, list):
            print(f"    {k}: {len(v)} items")
        elif isinstance(v, str):
            print(f"    {k}: {v}")
