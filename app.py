from flask import Flask, render_template, request, send_file
import datetime
import requests
import io
import textwrap
import socket
import time
import os
from urllib.parse import urlparse
from fpdf import FPDF

def clean_txt(s):
    if s is None:
        return ""
    return str(s).encode('latin-1', 'replace').decode('latin-1')


app = Flask(__name__)

class RealTimeScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "http://" + target_url
        self.target_url = target_url.rstrip("/")
        self.findings = []
        self.site_details = {"ip_address": "Unknown", "response_time": "Unknown", "server": "Unknown", "technology": "Unknown"}

    def run_live_scan(self):
        parsed = urlparse(self.target_url)
        if parsed.hostname:
            try:
                self.site_details["ip_address"] = socket.gethostbyname(parsed.hostname)
            except Exception:
                self.site_details["ip_address"] = "127.0.0.1" if ("localhost" in parsed.hostname or "127.0.0.1" in parsed.hostname) else "Unresolvable"

        session = requests.Session()
        session.headers.update({"User-Agent": "VulScan-SecurityEngine/2.4"})

        try:
            # 1. REAL-TIME HEADER ANALYSIS
            start_t = time.time()
            res = session.get(self.target_url, timeout=3)
            end_t = time.time()
            self.site_details["response_time"] = f"{round((end_t - start_t) * 1000)} ms"
            self.site_details["server"] = res.headers.get("Server", "Python/Flask (Generic)")
            self.site_details["technology"] = res.headers.get("X-Powered-By", "WSGI / Python 3.14")
            
            headers = res.headers
            
            security_headers = {
                "X-Frame-Options": (
                    "Low", 
                    "Missing protection against Clickjacking attacks.",
                    "Attackers can embed this site in an iframe to trick users into performing unauthorized actions.",
                    "Configure web server with 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
                ),
                "Content-Security-Policy": (
                    "Medium", 
                    "Missing Content-Security-Policy (CSP) headers.",
                    "Without CSP, the browser cannot restrict script sources, increasing vulnerability to XSS.",
                    "Implement a strict Content-Security-Policy header whitelisting allowed domain resources."
                ),
                "X-Content-Type-Options": (
                    "Low",
                    "Missing X-Content-Type-Options header.",
                    "Browsers may try to MIME-sniff response types, executing non-executable content as scripts.",
                    "Set 'X-Content-Type-Options: nosniff' header on all HTTP responses."
                ),
                "Strict-Transport-Security": (
                    "Medium",
                    "Missing Strict-Transport-Security (HSTS) header.",
                    "Increased risk of Man-in-the-Middle (MitM) downgrade attacks over unencrypted HTTP.",
                    "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
                )
            }
            
            for h, (sev, desc, imp, rem) in security_headers.items():
                if h not in headers:
                    self.findings.append({
                        "vulnerability": f"Missing {h} Header", 
                        "severity": sev, 
                        "description": desc,
                        "impact": imp,
                        "remediation": rem
                    })

            # 2. REAL-TIME SQL INJECTION CHECK
            sqli_payload = "'"
            sqli_url = f"{self.target_url}?id={sqli_payload}"
            try:
                sqli_res = session.get(sqli_url, timeout=3)
                if any(err in sqli_res.text.lower() for err in ["sql syntax", "mysql", "mariadb", "sqlite", "oracle error", "syntax error"]):
                    self.findings.append({
                        "vulnerability": "Potential Error-Based SQL Injection",
                        "severity": "High",
                        "description": "The application returned raw database driver exception logs upon receiving malformed input.",
                        "impact": "High risk of data breach. Attackers can view, extract, modify, or delete database records.",
                        "remediation": "Use Prepared Statements (Parameterized Queries) or an ORM for all database operations."
                    })
            except Exception:
                pass

            # 3. REAL-TIME REFLECTED XSS CHECK
            xss_payload = "<script>alert(1)</script>"
            xss_url = f"{self.target_url}?q={xss_payload}"
            try:
                xss_res = session.get(xss_url, timeout=3)
                if xss_payload in xss_res.text:
                    self.findings.append({
                        "vulnerability": "Reflected Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "description": "Injected script payload reflected identically back into the page HTML response.",
                        "impact": "Attackers can execute malicious JavaScript in victims' browser sessions, hijacking sessions or stealing tokens.",
                        "remediation": "Sanitize and context-encode all user input before rendering inside HTML templates."
                    })
            except Exception:
                pass

            # 4. REAL-TIME EXPOSED DIRECTORIES CHECK
            common_dirs = ["/admin", "/backup", "/config", "/.git/"]
            for d in common_dirs:
                try:
                    dir_url = self.target_url + d
                    dir_res = session.get(dir_url, timeout=2)
                    if dir_res.status_code == 200:
                        self.findings.append({
                            "vulnerability": f"Exposed Sensitive Directory: {d}",
                            "severity": "Medium",
                            "description": f"Sensitive directory '{d}' is directly accessible over the web without authentication.",
                            "impact": "Exposure of administrative dashboards, system configuration files, or database backups.",
                            "remediation": "Restrict directory access via authentication rules or move files outside web root."
                        })
                except Exception:
                    pass

        except requests.exceptions.RequestException as e:
            self.findings.append({
                "vulnerability": "Target Connection Failure",
                "severity": "High",
                "description": f"Could not establish connection to remote target ({self.target_url}): {e}",
                "impact": "Scanner is unable to connect to the specified host or port.",
                "remediation": "Verify target URL format, ensure host server is active, and verify firewall accessibility."
            })

        return {"findings": self.findings, "site_details": self.site_details}

scan_history = []

@app.route("/", methods=["GET", "POST"])
def main():
    results, target = None, None
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scan_id = -1
    site_details = {"ip_address": "Unknown", "response_time": "Unknown", "server": "Unknown", "technology": "Unknown"}
    if request.method == "POST":
        target = request.form.get("url")
        if target:
            scanner = RealTimeScanner(target)
            scan_result = scanner.run_live_scan()
            results = scan_result["findings"]
            site_details = scan_result["site_details"]
            for r in results:
                sev = r["severity"]
                if sev in stats:
                    stats[sev] += 1
                else:
                    stats["Low"] += 1
            
            scan_id = len(scan_history)
            scan_history.append({
                "id": scan_id,
                "target": target,
                "results": results,
                "site_details": site_details,
                "stats": stats,
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
    return render_template("index.html", results=results, target=target, stats=stats, scan_id=scan_id, site_details=site_details)

@app.route("/history")
def history():
    return render_template("history.html", history=scan_history)

@app.route("/export_pdf/<int:scan_id>")
def export_pdf(scan_id):
    if scan_id < 0 or scan_id >= len(scan_history):
        return "Scan not found", 404
        
    scan = scan_history[scan_id]
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", style="B", size=22)
    pdf.set_text_color(0, 73, 101)
    pdf.cell(0, 15, txt="Vul Scan | Security Audit Report", align="C")
    pdf.ln(15)
    
    # Meta Info
    pdf.set_font("Helvetica", size=10)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 7, txt=clean_txt(f"Scan Date/Time: {scan['time']}"), ln=True)
    pdf.cell(0, 7, txt=clean_txt(f"Target URL: {scan['target']}"), ln=True)
    pdf.cell(0, 7, txt="Scan Status: COMPLETED", ln=True)
    
    sd = scan['site_details']
    pdf.ln(3)
    pdf.set_font("Helvetica", style="B", size=10)
    pdf.cell(0, 7, txt="Target Infrastructure Details:", ln=True)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 6, txt=clean_txt(f"IP Address: {sd['ip_address']} | Response Time: {sd['response_time']}"), ln=True)
    pdf.cell(0, 6, txt=clean_txt(f"Server: {sd['server']} | Technology: {sd['technology']}"), ln=True)
    
    pdf.ln(5)
    total_findings = len(scan['results'])
    pdf.set_font("Helvetica", style="B", size=11)
    pdf.cell(0, 7, txt=clean_txt(f"Total Vulnerabilities Identified: {total_findings}"), ln=True)
    pdf.ln(3)
    
    # Disclaimer
    pdf.set_font("Helvetica", style="I", size=9)
    pdf.set_text_color(100, 100, 100)
    disclaimer = "CONFIDENTIALITY NOTICE: This security report is generated automatically by Vul Scan for academic and educational evaluation. Findings should be manually verified before deployment."
    for line in textwrap.wrap(disclaimer, width=95):
        pdf.cell(0, 5, txt=clean_txt(line), align="C", ln=True)
    pdf.ln(8)
    pdf.set_text_color(0, 0, 0)
    
    # Executive Summary
    pdf.set_font("Helvetica", style="B", size=13)
    pdf.cell(0, 8, txt="1. Executive Summary", ln=True)
    
    pdf.set_font("Helvetica", size=11)
    stats = scan['stats']
    pdf.cell(0, 7, txt=clean_txt(f"Critical: {stats['Critical']}  |  High: {stats['High']}  |  Medium: {stats['Medium']}  |  Low: {stats['Low']}"), ln=True)
    pdf.ln(8)
    
    # Findings
    pdf.set_font("Helvetica", style="B", size=13)
    pdf.cell(0, 8, txt="2. Detailed Findings", ln=True)
    pdf.ln(4)
    
    for idx, f in enumerate(scan['results']):
        sev = f['severity'].upper()
        pdf.set_font("Helvetica", style='B', size=11)
        for line in textwrap.wrap(f"Finding #{idx+1}: {f['vulnerability']} [{sev}]", width=85):
            pdf.cell(0, 7, txt=clean_txt(line), ln=True)
        
        pdf.set_font("Helvetica", size=10)
        for line in textwrap.wrap(f"Description: {f['description']}", width=90):
            pdf.cell(0, 5, txt=clean_txt(line), ln=True)
            
        if 'impact' in f and f['impact']:
            pdf.set_font("Helvetica", style='B', size=10)
            pdf.cell(0, 5, txt="Impact:", ln=True)
            pdf.set_font("Helvetica", size=10)
            for line in textwrap.wrap(f"{f['impact']}", width=90):
                pdf.cell(0, 5, txt=clean_txt(line), ln=True)
                
        if 'remediation' in f and f['remediation']:
            pdf.set_font("Helvetica", style='I', size=10)
            for line in textwrap.wrap(f"Remediation: {f['remediation']}", width=90):
                pdf.cell(0, 5, txt=clean_txt(line), ln=True)
        pdf.ln(6)
        
    pdf_bytes = bytes(pdf.output())
    return send_file(io.BytesIO(pdf_bytes), download_name=f"scan_report_{scan_id}.pdf", as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)