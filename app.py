from flask import Flask, render_template, request, send_file
import datetime
import io
import json
import os
import sqlite3
import textwrap
import socket
import ipaddress
from urllib.parse import urlparse
from fpdf import FPDF

from scanner import RealTimeScanner, score_grade


def clean_txt(s):
    if s is None:
        return ""
    return str(s).encode('latin-1', 'replace').decode('latin-1')


app = Flask(__name__)

# ==========================================
# PERSISTENCE (SQLite - survives restarts)
# ==========================================

DB_PATH = os.environ.get(
    "DATABASE_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")
)
MAX_HISTORY = 100  # rows kept in the database


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                target   TEXT    NOT NULL,
                time     TEXT    NOT NULL,
                score    INTEGER,
                grade    TEXT,
                stats    TEXT    NOT NULL,
                findings TEXT    NOT NULL,
                details  TEXT    NOT NULL
            )
        """)


def save_scan(target, findings, details, stats, score, grade):
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO scans (target, time, score, grade, stats, findings, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                target,
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                score, grade,
                json.dumps(stats),
                json.dumps(findings),
                json.dumps(details),
            ),
        )
        return cur.lastrowid


def get_scan(scan_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    return {
        "id": row["id"],
        "target": row["target"],
        "time": row["time"],
        "score": row["score"],
        "grade": row["grade"],
        "stats": json.loads(row["stats"]),
        "results": json.loads(row["findings"]),
        "site_details": json.loads(row["details"]),
    }


def get_history():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, target, time, score, grade, stats FROM scans "
            "ORDER BY id DESC LIMIT ?", (MAX_HISTORY,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "target": r["target"],
            "time": r["time"],
            "score": r["score"],
            "grade": r["grade"],
            "stats": json.loads(r["stats"]),
        }
        for r in rows
    ]


init_db()

# ==========================================
# SSRF GUARD (essential once deployed publicly)
# ==========================================


def _target_allowed(target_url):
    """Blocks scanning of private/internal addresses on public deployments.
    Set ALLOW_PRIVATE_TARGETS=1 (local development) to scan the local lab."""
    if os.environ.get("ALLOW_PRIVATE_TARGETS") == "1":
        return True
    try:
        hostname = urlparse(target_url).hostname
        if not hostname:
            return False
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                return False
        return True
    except Exception:
        return False


# ==========================================
# ROUTES
# ==========================================

@app.route("/", methods=["GET", "POST"])
def main():
    results, target, error = None, None, None
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scan_id = -1
    score, grade = None, None
    site_details = {"ip_address": "Unknown", "response_time": "Unknown", "server": "Not disclosed", "technology": "Not disclosed"}

    if request.method == "POST":
        target = request.form.get("url", "").strip()
        if target:
            if not _target_allowed(target):
                error = (
                    "Scanning private or internal addresses is blocked on public deployments "
                    "for security reasons (SSRF protection). To scan the local lab while developing, "
                    "start the app with the environment variable ALLOW_PRIVATE_TARGETS=1."
                )
            else:
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
                score, grade = score_grade(results)
                scan_id = save_scan(target, results, site_details, stats, score, grade)

    return render_template(
        "index.html",
        results=results, target=target, stats=stats, scan_id=scan_id,
        site_details=site_details, score=score, grade=grade, error=error
    )


@app.route("/health")
def health():
    return {"status": "ok", "service": "vul-scan", "engine": "2.5-extended"}


@app.route("/history")
def history():
    return render_template("history.html", history=get_history())


@app.route("/export_pdf/<int:scan_id>")
def export_pdf(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        return "Scan not found", 404

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
    pdf.cell(0, 7, txt=clean_txt(f"Risk Score: {scan.get('score')}/100   |   Grade: {scan.get('grade')}"), ln=True)
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
