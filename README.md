# Web Application Vulnerability Scanner (Vul Scan v2.5)

## Overview
The Web Application Vulnerability Scanner is a security tool developed to identify common web vulnerabilities. It serves as an academic project to enhance understanding of web security and provide practical experience in vulnerability detection.

## Features
- **SQL Injection Detection**: Injects error-based vectors and compares responses against a baseline to avoid false positives (pages that merely mention database terms are not flagged).
- **Cross-Site Scripting (XSS) Detection**: Tests for Reflected XSS by verifying the payload is reflected because of the scanner's request, not pre-existing page content.
- **Open Redirect Detection**: Probes common redirect parameters (`next`, `url`) for unvalidated external redirects.
- **CORS Misconfiguration**: Detects wildcard policies and servers that reflect any `Origin` header.
- **Insecure Cookie Flags**: Audits `Set-Cookie` headers for missing `Secure`, `HttpOnly` and `SameSite` attributes.
- **Security Headers Audit**: Checks CSP, HSTS (HTTPS targets only), X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy.
- **Exposed Directories & Sensitive Files**: Scans `/admin`, `/backup`, `/config`, `/.git/`, `/.env` (content-validated), `/.DS_Store` and `/server-status`, with soft-404 detection so SPA sites don't trigger false positives. Detects enabled directory listing.
- **Server Version Disclosure & HTTPS Downgrade**: Flags banners leaking exact versions and HTTP sites without a forced HTTPS redirect.
- **Risk Score & Grade**: Every scan produces a 0-100 risk score and letter grade (A-F).
- **Concurrent Scanning**: Active checks run in a thread pool, making scans several times faster.
- **Persistent Scan History**: Scan results are stored in SQLite and survive application restarts.
- **Report Generation**: Automatic TXT (CLI) and PDF (web) reports with severity levels, remediation advice, and risk score.
- **SSRF Protection**: On public deployments, scanning private/internal addresses is blocked (`ALLOW_PRIVATE_TARGETS=1` enables the local lab for development).
- **Health Endpoint**: `/health` returns a JSON heartbeat for Render health checks.

## Setup & Installation

### Requirements
- Python 3.9+ (deployed on Render with Python 3.13)

### Installation
1. Clone or download this project.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: If `requests` is unavailable, the CLI scanner includes a fallback that utilizes the built-in `urllib`.*

## Usage

### 1. Live Interactive Web UI
A modern web interface is provided for easy usage. To start the scanner UI (with the local lab allowed):
```bash
# Windows PowerShell
$env:ALLOW_PRIVATE_TARGETS="1"; python app.py
# Linux / macOS
ALLOW_PRIVATE_TARGETS=1 python app.py
```
Then navigate to `http://localhost:5000` in your web browser. Enter the target URL and launch the live audit.

### 2. Command Line Interface (CLI)
You can use the vulnerability scanner directly from the terminal against any target URL:
```bash
python scanner.py "http://example.com"
```
This will run the full suite of checks and output a `Vulnerability_Scan_Report.txt` file with the risk score in the same directory.

### 3. Simulation & Grading Mode
The project comes with a built-in "dummy" lab target to demonstrate functionality safely without attacking real systems.
To start the vulnerable target lab, run:
```bash
python target_app.py
```
This starts the dummy target on `http://localhost:8080`. You can then scan it from the web UI or run `python scanner.py "http://127.0.0.1:8080"`.
Running `python scanner.py` with no arguments executes a clearly-labeled mock simulation for grading demos.

## Free Cloud Deployment

### Recommended Platform: **Render** (100% Free Web Service)
1. Push this code to GitHub.
2. Go to [Render.com](https://render.com) and create a **Free Web Service**.
3. Connect your GitHub repository.
4. Render reads `render.yaml` automatically (Blueprint). Otherwise set:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app --workers 1 --threads 8 --timeout 120`
   - **Health Check Path:** `/health`
5. Click **Create Web Service**. Render will automatically build and deploy your app.
6. Your live scanner will be available at `https://<your-service>.onrender.com`.

**Note on deployment:** `ALLOW_PRIVATE_TARGETS` defaults to `0` on Render, which blocks scanning of private IPs (SSRF protection). Scanning public websites works normally.

## Disclaimer
This project is built for educational and ethical hacking purposes. Only scan applications and networks for which you have explicit permission.
