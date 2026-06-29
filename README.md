# OWASP ZAP Security Dashboard

A professional **Web Application Vulnerability Assessment & Penetration Testing (VAPT)** platform built with Python and Flask, powered by OWASP ZAP 2.17.0.

---

## Overview

This platform automates web application security testing through an intuitive dashboard. It not only finds vulnerabilities — it also explains **how to fix them**, provides **business impact analysis**, and tracks **security improvement** over time through before/after comparisons.

---

## Features

### Scanning Engine
- **Spider Scan** — Crawls all URLs and maps the full attack surface
- **Passive Scan** — Monitors HTTP traffic without sending attack payloads
- **Active Scan** — Actively probes the target with attack payloads
- **Fuzzer** — Sends crafted payloads to test for SQLi, XSS, Path Traversal
- **Authentication Testing** — Tests valid, invalid, empty, and injection credentials
- **API Endpoint Scanner** — Discovers and tests all API endpoints for exposure

### Risk Assessment
- Overall risk score (0–100) per target
- CVSS score per vulnerability
- Real-world attack scenario explanation per finding
- Business impact analysis (Confidentiality, Integrity, Availability)
- Affected assets identification
- Fix urgency classification (24hrs / 7 days / 30 days)

### Remediation Workflow
- Step-by-step fix instructions per vulnerability
- Root cause explanation
- Ready-to-use fix code snippets
- Fix verification commands
- OWASP and MDN references
- Mark-as-fixed tracking with notes

### Before vs After Comparison
- Scan history stored in SQLite database
- Side-by-side comparison of initial scan vs re-scan
- Security improvement metrics
- Re-scan after fix verification

### Reports
- HTML report export
- JSON report export
- Scan history persistence across sessions

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, Flask |
| Scanning Engine | OWASP ZAP 2.17.0 |
| Database | SQLite |
| Frontend | HTML5, CSS3, Jinja2 |
| ZAP Integration | python-owasp-zap-v2.4 |

---

## Project Structure

```
OWASP-ZAP-PROJECT/
├── app.py                  # Flask application + all routes
├── zap_helper.py           # ZAP API integration layer
├── target_app.py           # Intentionally vulnerable test app
├── remediation_db.py       # Vulnerability fix guide database
├── risk_assessment.py      # Risk scoring and business impact data
├── scan_history.db         # SQLite scan history (auto-created)
├── requirements.txt
├── templates/
│   ├── index.html          # Main dashboard (2-column layout)
│   ├── remediation.html    # Remediation guide page
│   ├── risk_assessment.html # Risk assessment page
│   └── compare.html        # Before vs after comparison
├── static/
│   └── style.css
└── reports/                # Generated scan reports
```

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- OWASP ZAP 2.17.0 installed
- Git

### Step 1 — Clone the repository
```bash
git clone https://github.com/sateeshkonjeti2001-lgtm/owasp-zap.git
cd owasp-zap
```

### Step 2 — Create virtual environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Start OWASP ZAP
Open OWASP ZAP application. Ensure it is running with API enabled on `localhost:8080`.

### Step 5 — Start the vulnerable target app
```bash
python target_app.py
# Runs on http://127.0.0.1:5001
```

### Step 6 — Start the dashboard
```bash
python app.py
# Runs on http://127.0.0.1:5000
```

---

## Usage Workflow

```
1. Open http://127.0.0.1:5000
2. Click "Run Spider"          → Maps all URLs
3. Click "Run Passive Scan"    → Monitors traffic
4. Click "Run Active Scan"     → Finds vulnerabilities (2-3 min)
5. Click "View Risk Assessment" → See business impact per vuln
6. Click "View Remediation Guide" → Get step-by-step fixes
7. Apply fixes to target_app.py
8. Click "Re-scan After Fix"   → Verify fixes worked
9. Click "View Comparison"     → Before vs After results
10. Download Report            → Export HTML/JSON
```

---

## Dashboard Pages

| Page | URL | Description |
|---|---|---|
| Main Dashboard | `/` | 2-column control center |
| Risk Assessment | `/risk-assessment` | CVSS scores + business impact |
| Remediation Guide | `/remediation` | Step-by-step fix instructions |
| Before vs After | `/compare` | Security improvement comparison |
| Re-scan | `/rescan` | Run fresh scan after fixes |
| Report | `/report` | Download HTML report |

---

## Target App Vulnerabilities

The included `target_app.py` is an intentionally vulnerable Flask application containing:

- Reflected XSS in `/search` endpoint
- SQL Injection in `/login`
- Missing security headers (X-Frame-Options, CSP, X-Content-Type-Options)
- No CSRF protection
- HTTP only (no HTTPS)
- Server version disclosure

---

## Security Disclaimer

> This tool is built for **authorized security testing and educational purposes only**.
> Only test applications you own or have explicit written permission to test.
> Unauthorized scanning is illegal.

---

## Author

**Naga Venkata Sateesh Konjeti**
- GitHub: [@sateeshkonjeti2001-lgtm](https://github.com/sateeshkonjeti2001-lgtm)

---

## License

MIT License — see [LICENSE](LICENSE) for details.