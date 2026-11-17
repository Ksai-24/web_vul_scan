"""
Project Name: Web Application Vulnerability Scanner (Minor Project)
Description: Academic tool to detect missing headers, SQLi error signatures,
Reflected XSS, Open Redirects, CORS misconfiguration, insecure cookies,
exposed directories/sensitive files, and TLS downgrade issues.
This module is the single shared engine used by both the web UI (app.py)
and the command line interface.
"""

import sys
import os
import re
import time
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    # Provide a minimal fallback using urllib when 'requests' isn't installed
    import urllib.request
    import urllib.error
    _HAS_REQUESTS = False

USER_AGENT = "VulScan-SecurityEngine/2.5"

# ==========================================
# 0. HTTP TRANSPORT LAYER
# ==========================================

class SimpleResponse:
    """Minimal response object used when 'requests' is not installed."""
    def __init__(self, resp):
        self.headers = {k.lower(): v for k, v in resp.getheaders()}
        self.status_code = resp.status
        try:
            self.text = resp.read().decode('utf-8', errors='replace')
        except Exception:
            self.text = ''
        self.cookies = None


def http_get(url, timeout=5):
    """Compatibility wrapper that returns an object with `.headers`, `.text`,
    `.status_code` and `.cookies`. Uses `requests` when available, otherwise
    falls back to `urllib`."""
    if _HAS_REQUESTS:
        return requests.get(url, timeout=timeout)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return SimpleResponse(resp)


# ==========================================
# 1. RISK SCORING
# ==========================================

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 7, "Low": 2}
_SEVERITY_ORDER = {"High": 0, "Critical": 0, "Medium": 1, "Low": 2}


def score_grade(findings):
    """Converts findings into a 0-100 risk score and a letter grade (A-F)."""
    score = 100 - sum(SEVERITY_WEIGHTS.get(f["severity"], 2) for f in findings)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


# ==========================================
# 2. SCANNER ENGINE (SHARED)
# ==========================================

class RealTimeScanner:
    """Live multi-threaded vulnerability scanner engine."""

    def __init__(self, target_url):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.session = requests.Session() if _HAS_REQUESTS else None
        if self.session:
            self.session.headers.update({"User-Agent": USER_AGENT})

    # ---------- helpers ----------

    def _with_param(self, key, value):
        """Append a query parameter, respecting existing query strings."""
        sep = "&" if "?" in self.target_url else "?"
        return f"{self.target_url}{sep}{key}={quote(value)}"

    def _fetch(self, url, timeout=5, headers=None, allow_redirects=True):
        """GET that never raises - returns None on any failure."""
        if _HAS_REQUESTS and self.session:
            try:
                return self.session.get(url, timeout=timeout, headers=headers,
                                        allow_redirects=allow_redirects)
            except requests.exceptions.RequestException:
                return None
        try:
            hdrs = headers or {"User-Agent": USER_AGENT}
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return SimpleResponse(resp)
        except Exception:
            return None

    @staticmethod
    def _finding(vulnerability, severity, description, impact, remediation):
        return {
            "vulnerability": vulnerability,
            "severity": severity,
            "description": description,
            "impact": impact,
            "remediation": remediation,
        }

    # ---------- orchestrator ----------

    def run_live_scan(self):
        findings = []
        details = {
            "ip_address": "Unknown",
            "response_time": "Unknown",
            "server": "Not disclosed",
            "technology": "Not disclosed",
        }

        # 1. BASELINE REQUEST (also collects headers, cookies and timing)
        start_t = time.time()
        base_res = self._fetch(self.target_url, timeout=6)
        elapsed = time.time() - start_t

        if base_res is None:
            findings.append(self._finding(
                "Target Connection Failure", "High",
                f"Could not establish connection to remote target ({self.target_url}).",
                "Scanner is unable to connect to the specified host or port.",
                "Verify target URL format, ensure host server is active, and verify firewall accessibility."
            ))
            return {"findings": findings, "site_details": details}

        details["response_time"] = f"{round(elapsed * 1000)} ms"
        details["server"] = base_res.headers.get("Server", "Not disclosed")
        details["technology"] = base_res.headers.get("X-Powered-By", "Not disclosed")

        try:
            details["ip_address"] = socket.gethostbyname(self.parsed.hostname or "")
        except Exception:
            details["ip_address"] = "Unresolvable"

        # 2. SECURITY HEADERS (fast, local analysis of the baseline response)
        findings.extend(self._check_security_headers(base_res))

        # 3. ACTIVE CHECKS (network-bound, run concurrently for speed)
        active_checks = [
            self._check_sqli,
            self._check_xss,
            self._check_open_redirect,
            self._check_cors,
            self._check_exposed_dirs,
            self._check_sensitive_files,
            self._check_https_redirect,
        ]
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(check): check.__name__ for check in active_checks}
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    pass  # a failing check must never break the scan

        # 4. LOCAL POST-ANALYSIS (uses baseline response only)
        findings.extend(self._check_cookies(base_res))
        findings.extend(self._check_version_disclosure(base_res))

        # 5. Sort findings by severity so the most important appear first
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 3))

        return {"findings": findings, "site_details": details}

    # ---------- passive checks ----------

    def _check_security_headers(self, base_res):
        headers = base_res.headers
        findings = []
        security_headers = {
            "x-frame-options": (
                "Low",
                "Missing X-Frame-Options header.",
                "Attackers can embed this site in an iframe to trick users into performing unauthorized actions (Clickjacking).",
                "Configure web server with 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
            ),
            "content-security-policy": (
                "Medium",
                "Missing Content-Security-Policy (CSP) header.",
                "Without CSP, the browser cannot restrict script sources, increasing vulnerability to XSS.",
                "Implement a strict Content-Security-Policy header whitelisting allowed domain resources."
            ),
            "x-content-type-options": (
                "Low",
                "Missing X-Content-Type-Options header.",
                "Browsers may try to MIME-sniff response types, executing non-executable content as scripts.",
                "Set 'X-Content-Type-Options: nosniff' header on all HTTP responses."
            ),
            "strict-transport-security": (
                "Medium",
                "Missing Strict-Transport-Security (HSTS) header.",
                "Increased risk of Man-in-the-Middle (MitM) downgrade attacks over unencrypted HTTP.",
                "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
            ),
            "referrer-policy": (
                "Low",
                "Missing Referrer-Policy header.",
                "Full referral URLs (possibly containing tokens or personal data) leak to third-party sites.",
                "Set 'Referrer-Policy: strict-origin-when-cross-origin' header."
            ),
            "permissions-policy": (
                "Low",
                "Missing Permissions-Policy header.",
                "Powerful browser features (camera, microphone, geolocation) can be used by embedded third-party frames.",
                "Set a 'Permissions-Policy' header restricting features to trusted origins."
            ),
        }
        is_https = self.parsed.scheme == "https"
        for header, (sev, desc, imp, rem) in security_headers.items():
            if header == "strict-transport-security" and not is_https:
                continue  # HSTS is only meaningful over HTTPS
            # Case-insensitive check (works with requests and the urllib fallback)
            if header not in {h.lower() for h in headers}:
                findings.append(self._finding(
                    f"Missing {header.title()} Header", sev, desc, imp, rem
                ))
        return findings

    def _check_cookies(self, base_res):
        findings = []
        if not _HAS_REQUESTS or not base_res.cookies:
            return findings
        missing_secure = missing_httponly = missing_samesite = False
        try:
            for cookie in base_res.cookies:
                if not cookie.secure:
                    missing_secure = True
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    missing_httponly = True
                if not cookie.has_nonstandard_attr("SameSite"):
                    missing_samesite = True
        except Exception:
            return findings
        missing = []
        if self.parsed.scheme == "https" and missing_secure:
            missing.append("Secure (cookie sent over plain HTTP)")
        if missing_httponly:
            missing.append("HttpOnly (readable by JavaScript, stealable via XSS)")
        if missing_samesite:
            missing.append("SameSite (exposed to Cross-Site Request Forgery)")
        if missing:
            findings.append(self._finding(
                "Insecure Cookie Configuration", "Low",
                "Session cookies are set without recommended protection flags: " + "; ".join(missing) + ".",
                "Attackers can steal or reuse session cookies through XSS, network interception, or CSRF attacks.",
                "Set 'Secure', 'HttpOnly' and 'SameSite=Lax/Strict' attributes on all cookies."
            ))
        return findings

    def _check_version_disclosure(self, base_res):
        disclosed = []
        for header in ("Server", "X-Powered-By"):
            value = base_res.headers.get(header, "")
            if value and re.search(r"\d+\.\d+", value):
                disclosed.append(f"{header}: {value}")
        if disclosed:
            findings = [self._finding(
                "Server Version Disclosure", "Low",
                "The server advertises its exact software versions: " + ", ".join(disclosed) + ".",
                "Attackers can match these versions against public CVE databases to find known exploits.",
                "Suppress version banners in server configuration (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx)."
            )]
            return findings
        return []

    # ---------- active checks ----------

    def _check_sqli(self):
        """Error-based SQLi with baseline comparison to avoid false positives."""
        db_error_signatures = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "mysql_fetch_array",
            "warning: mysql",
            "warning: mysqli",
            "warning: sqlite",
            "sqlite3.operationalerror",
            "pg_query()",
            "postgresql error",
            "ora-00933",
            "ora-01756",
            "microsoft ole db provider",
            "odbc driver",
        ]
        baseline_res = self._fetch(self._with_param("id", "1"), timeout=5)
        payload_res = self._fetch(self._with_param("id", "'"), timeout=5)
        if baseline_res is None or payload_res is None:
            return []
        if payload_res.text != baseline_res.text and any(
            err in payload_res.text.lower() for err in db_error_signatures
        ):
            return [self._finding(
                "Potential Error-Based SQL Injection", "High",
                "The application returned raw database driver exception logs upon receiving malformed input.",
                "High risk of data breach. Attackers can view, extract, modify, or delete database records.",
                "Use Prepared Statements (Parameterized Queries) or an ORM for all database operations."
            )]
        return []

    def _check_xss(self):
        """Reflected XSS - only flagged when the payload is reflected because
        of our request, not when it is already part of normal page content."""
        xss_payload = "<script>alert(1)</script>"
        baseline_res = self._fetch(self._with_param("q", "vulscan-probe"), timeout=5)
        payload_res = self._fetch(self._with_param("q", xss_payload), timeout=5)
        if baseline_res is None or payload_res is None:
            return []
        if xss_payload in payload_res.text and xss_payload not in baseline_res.text:
            return [self._finding(
                "Reflected Cross-Site Scripting (XSS)", "High",
                "Injected script payload reflected identically back into the page HTML response.",
                "Attackers can execute malicious JavaScript in victims' browser sessions, hijacking sessions or stealing tokens.",
                "Sanitize and context-encode all user input before rendering inside HTML templates."
            )]
        return []

    def _check_open_redirect(self):
        probe = "https://vulscan-probe.example.com"
        if not _HAS_REQUESTS:
            return []  # redirect interception requires requests
        findings = []
        for param in ("next", "url"):
            res = self._fetch(self._with_param(param, probe), timeout=5,
                              allow_redirects=False)
            if res is not None and 300 <= res.status_code < 400:
                location = res.headers.get("Location", "")
                if location.startswith(probe):
                    findings.append(self._finding(
                        "Open Redirect", "Medium",
                        f"The '{param}' parameter redirects users to an arbitrary external domain without validation.",
                        "Attackers can craft links that redirect victims to malicious phishing sites while appearing to come from your domain.",
                        "Validate redirect targets server-side: only allow whitelisted relative paths or trusted domains."
                    ))
                    break
        return findings

    def _check_cors(self):
        probe_origin = "https://vulscan-probe.example.com"
        res = self._fetch(self.target_url, timeout=5,
                          headers={"Origin": probe_origin})
        if res is None:
            return []
        acao = res.headers.get("Access-Control-Allow-Origin", "")
        if acao == probe_origin:
            return [self._finding(
                "CORS Allows Arbitrary Origins", "Medium",
                "The server reflects any Origin header in 'Access-Control-Allow-Origin', allowing cross-origin reads.",
                "Any website can read authenticated responses from this application on behalf of a visiting user.",
                "Return a strict allow-list of trusted origins instead of reflecting the request Origin."
            )]
        if acao == "*":
            return [self._finding(
                "Permissive CORS Policy (Wildcard)", "Low",
                "The server returns 'Access-Control-Allow-Origin: *', allowing any site to read public responses.",
                "With wildcard CORS, browser-based attackers can read non-authenticated API responses cross-origin.",
                "Restrict CORS to the exact origins that need access; avoid '*' on endpoints handling user data."
            )]
        return []

    def _check_exposed_dirs(self):
        common_dirs = ["/admin", "/backup", "/config", "/.git/"]
        findings = []
        # Soft-404 probe: only report directories whose body differs from a
        # nonexistent path (sites that answer 200 for everything).
        probe_res = self._fetch(self.target_url + "/vulscan-nonexistent-probe-9x7/", timeout=4)
        for d in common_dirs:
            res = self._fetch(self.target_url + d, timeout=4)
            if res is None:
                continue
            soft_404 = probe_res is not None and res.text == probe_res.text
            if res.status_code == 200 and not soft_404:
                findings.append(self._finding(
                    f"Exposed Sensitive Directory: {d}", "Medium",
                    f"Sensitive directory '{d}' is directly accessible over the web without authentication.",
                    "Exposure of administrative dashboards, system configuration files, or database backups.",
                    "Restrict directory access via authentication rules or move files outside web root."
                ))
                if "index of" in res.text.lower():
                    findings.append(self._finding(
                        f"Directory Listing Enabled: {d}", "Medium",
                        f"The '{d}' directory exposes a browsable file index of its contents.",
                        "Attackers can enumerate and download every file inside the directory, including source code and backups.",
                        "Disable directory listing (e.g., 'Options -Indexes' in Apache) and serve only intended files."
                    ))
        return findings

    def _check_sensitive_files(self):
        """Checks common sensitive files, validating content to avoid false positives."""
        def looks_like_env(text):
            return re.search(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=", text) is not None

        targets = [
            ("/.env", "High", "Environment File", looks_like_env),
            ("/.DS_Store", "Medium", "macOS Metadata File", None),
            ("/server-status", "Medium", "Apache Server Status", None),
        ]
        findings = []
        probe_res = self._fetch(self.target_url + "/vulscan-nonexistent-probe-9x7/", timeout=4)
        for path, sev, label, validator in targets:
            res = self._fetch(self.target_url + path, timeout=4)
            if res is None or res.status_code != 200:
                continue
            if probe_res is not None and res.text == probe_res.text:
                continue  # soft-404
            if validator and not validator(res.text):
                continue  # content does not look like the real file
            findings.append(self._finding(
                f"Exposed Sensitive File: {path}", sev,
                f"A sensitive {label} ({path}) is publicly accessible and its content is readable.",
                "Exposure of application secrets, database credentials, or internal server information that aids further attacks.",
                "Block access to hidden/technical files at the web server level and keep secrets out of the web root."
            ))
        return findings

    def _check_https_redirect(self):
        """Flags plain-HTTP targets that have HTTPS available but do not redirect."""
        hostname = self.parsed.hostname or ""
        if self.parsed.scheme == "https":
            return []
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return []
        try:
            # Skip when the host is a raw IP (no TLS name to validate anyway)
            socket.inet_aton(hostname)
            return []
        except Exception:
            pass
        https_res = self._fetch("https://" + self.target_url.split("//", 1)[1], timeout=5)
        if https_res is not None:
            return [self._finding(
                "No Forced HTTPS Redirect", "Low",
                "The site is reachable over plain HTTP and does not redirect visitors to its HTTPS version.",
                "Credentials, session cookies and personal data can be intercepted in transit (Man-in-the-Middle).",
                "Enable a permanent 301 HTTPS redirect and deploy HSTS once the HTTPS version is stable."
            )]
        return []


# ==========================================
# 3. TEXT REPORT GENERATOR (CLI)
# ==========================================

def generate_report(target, findings, simulated=False):
    """Generates a structured, presentation-ready scan report."""
    report_filename = "Vulnerability_Scan_Report.txt"
    score, grade = score_grade(findings)

    with open(report_filename, "w", encoding="utf-8") as report:
        report.write("=" * 60 + "\n")
        report.write("          WEB APPLICATION VULNERABILITY REPORT          \n")
        report.write("=" * 60 + "\n")
        report.write(f"Target URL : {target}\n")
        report.write(f"Scan Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Mode       : {'SIMULATED (educational demo)' if simulated else 'LIVE SCAN'}\n")
        report.write(f"Risk Score : {score}/100  |  Grade: {grade}\n")
        report.write("=" * 60 + "\n\n")

        if not findings:
            report.write("[+] No common vulnerabilities identified during this scan.\n")
        else:
            report.write(f"[!] Total Issues Identified: {len(findings)}\n\n")
            for idx, item in enumerate(findings, 1):
                report.write(f"{idx}. [{item['severity']}] {item['vulnerability']}\n")
                report.write(f"   Description : {item['description']}\n")
                report.write(f"   Remediation : {item['remediation']}\n")
                report.write("-" * 50 + "\n")

    print(f"\n[+] Success! Comprehensive report generated: '{report_filename}'")
    print(f"[+] Risk Score: {score}/100 | Grade: {grade}")


# ==========================================
# 4. LOCAL LABORATORY SIMULATION MODE
# ==========================================

def run_simulation():
    """Simulates a scan against a dummy test app for live grading display.
    Header findings come from a real request if the lab is running; the
    injection findings are clearly labeled as simulated in the report."""
    print("=" * 60)
    print("   LAUNCHING VULNERABILITY SCANNER (LOCAL ACADEMIC LAB)   ")
    print("=" * 60)

    simulated_target = "http://localhost:8080/demo_lab"

    findings = []
    try:
        res = http_get(simulated_target, timeout=3)
        findings.extend(RealTimeScanner(simulated_target)._check_security_headers(res))
    except Exception:
        pass

    print("[*] Phase 2: Testing Input Parameters for SQL Injection... (simulated)")
    findings.append(RealTimeScanner._finding(
        "Potential Error-Based SQL Injection", "High",
        "The application appears to output raw database diagnostic errors when parsing malformed inputs.",
        "Attackers can leverage this flaw to view, modify, or maliciously delete database records.",
        "Immediately transition to using Prepared Statements (Parameterized Queries) or an ORM for all database interactions."
    ))
    print("[*] Phase 3: Testing for Reflected Cross-Site Scripting... (simulated)")
    findings.append(RealTimeScanner._finding(
        "Reflected Cross-Site Scripting (XSS)", "High",
        "Injected script tags were reflected identically back into the page source.",
        "Attackers can execute arbitrary malicious JavaScript in victims' browsers.",
        "Implement strict context-aware output encoding and deploy a strong Content Security Policy (CSP)."
    ))
    print("[*] Phase 4: Checking for Exposed Directories... (simulated)")
    findings.append(RealTimeScanner._finding(
        "Exposed Sensitive Directory: /backup", "Medium",
        "The directory '/backup' is directly accessible over the web without requiring any authentication.",
        "Exposure of sensitive source code, database credentials, or administrative panels.",
        "Restrict access to sensitive directories using server-level authentication or move them outside the web root."
    ))

    generate_report(simulated_target, findings, simulated=True)


# ==========================================
# 5. MAIN INTERFACE EXECUTOR (CLI)
# ==========================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scanner = RealTimeScanner(target)
        print(f"[*] Scanning {target} ...")
        result = scanner.run_live_scan()
        generate_report(target, result["findings"])
    else:
        run_simulation()
