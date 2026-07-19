# WebSec Scanner 🔍

**Web Vulnerability Scanner & Security Analyzer** — A comprehensive web security scanning tool with multiple scan modes, specific CVE/CWE detection, and professional report generation.

```
+--------------------------------------------------------------+
|                    WebSec Scanner v1.0                        |
|         Web Vulnerability Scanner & Security Analyzer         |
+--------------------------------------------------------------+
```

---

## Features

### 🚀 4 Scan Modes

| Mode | Description | Speed |
|------|-------------|-------|
| **Quick** | Basic info gathering: HTTP headers, SSL/TLS, tech detection | ~2-5s |
| **Standard** | OWASP Top 10, tech-specific CVEs, security config checks | ~5-15s |
| **Deep** | Full crawl, endpoint fuzzing, API discovery, NVD CVE lookup | ~30-120s |
| **Enterprise** | All modules, multi-threaded (20 threads), detailed reporting | ~60-180s |

### 📦 Detection Modules (22+ plugins)

**Recon (8 modules)**
- WHOIS lookup, DNS Enumeration (A, MX, NS, TXT, SOA, PTR, CNAME)
- Subdomain Discovery (50+ common subdomains)
- Port Scan (25 common ports)
- HTTP Security Headers analysis
- SSL/TLS certificate check (expiry, version, cipher)
- WAF Detection (Cloudflare, CloudFront, Akamai, F5, ModSecurity, Sucuri, ...)
- Technology Detection (WordPress, Laravel, Django, React, Vue, Nginx, Apache, ...)

**Vulnerability (14 modules)**
- SQL Injection (error-based, boolean-based, time-based)
- Cross-Site Scripting (reflected, DOM-based)
- CSRF Token Analysis & SameSite check
- Server-Side Request Forgery (SSRF)
- Local/Remote File Inclusion (LFI/RFI)
- Command Injection
- Server-Side Template Injection (SSTI)
- Open Redirect
- Insecure Direct Object Reference (IDOR)
- CORS Misconfiguration
- Security Headers audit (HSTS, CSP, XFO, XCTO, RP, PP)
- Cookie Security audit (Secure, HttpOnly, SameSite)
- **Tech-Specific CVE Scanner**
- **Config Flaw Checker with CWE mapping**

**CVE Scanner**
- Known Vulnerabilities Database (200+ CVE entries for 18+ technologies)
- NVD API Integration
- Exploit-DB Search
- Version-aware CVE matching

**Crawl Engine**
- Website Crawler (robots.txt, sitemap.xml, link extraction)
- API Discovery (/api, /graphql, /swagger, /admin, ...)
- Hidden Endpoint Detection
- HTTP Method Discovery (GET, POST, PUT, DELETE, OPTIONS)

### 🏷️ Specific CVE/CWE Detection

When a technology is detected, the tool automatically cross-references known CVEs:

```
[Python] CVE-2024-9287 - Heap Overflow in SSL/TLS (Critical, 9.8)
[Python] CVE-2023-27043 - RCE via email module (Critical, 9.8)
[Laravel] CVE-2021-3129 - RCE via Ignition (Critical, 9.8)
[WordPress] CVE-2025-2731 - RCE via XML-RPC (Critical, 9.8)
```

Each vulnerability type is mapped to its CWE identifier:
```
SQLi       → CWE-89
XSS        → CWE-79
CSRF       → CWE-352
SSRF       → CWE-918
LFI        → CWE-98
CMDi       → CWE-78
SSTI       → CWE-1336
Open Redirect → CWE-601
IDOR       → CWE-639
CORS       → CWE-942
```

### 📊 Scoring System

| Score | Level | Meaning |
|-------|-------|---------|
| 90–100 | 🟢 Very Safe | Excellent security posture |
| 75–89 | 🟡 Safe | Good, minor improvements needed |
| 50–74 | 🟠 Needs Improvement | Several issues found |
| 25–49 | 🔴 Risky | High risk, action required |
| 0–24 | ⚫ Critical Danger | Immediate action needed |

### 📄 Multi-Format Reports

- **HTML** — Dark mode UI with score visualization and severity-grouped findings
- **JSON** — Machine-readable with full metadata
- **CSV** — Excel-friendly for filtering and analysis

### 🔌 Plugin Architecture

Add new modules without modifying the core:

```python
@plugin("module_name", "Description", "vuln")
class MyPlugin(VulnPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        # your logic here
        pass
```

### ✅ Safe Verification

The tool uses **non-intrusive** detection techniques:
- Error-based detection (analyzing response patterns)
- Boolean-based detection (comparing response lengths)
- Time-based detection (measuring response delays)
- No automated data extraction
- No destructive payloads

---

## Installation

### Requirements

- Python 3.10+
- pip

### Setup

```bash
# Clone or copy the source
cd webscanner

# Install dependencies
pip install httpx

# (Optional) Install whois for WHOIS lookups
# Linux: sudo apt install whois
# macOS: brew install whois
# Windows: skip (or use WSL)
```

### Project Structure

```
webscanner/
├── main.py                 # CLI entry point (argparse)
├── config.py               # Scan mode configuration
├── core/
│   ├── scanner.py          # Scanner engine
│   └── plugin_system.py    # Plugin registry + auto-discovery
├── models/
│   ├── target.py           # ScanTarget dataclass
│   └── result.py           # Finding + ScanResult (auto-scoring)
├── modules/
│   ├── recon/              # 8 recon modules
│   │   ├── whois.py, dns_enum.py, subdomain.py, port_scan.py
│   │   ├── http_header.py, ssl_tls.py, waf_detect.py, tech_detect.py
│   ├── vulnerability/      # 14 vuln modules
│   │   ├── sqli.py, xss.py, csrf.py, ssrf.py, lfi_rfi.py
│   │   ├── command_injection.py, ssti.py, open_redirect.py
│   │   ├── idor.py, cors.py, security_headers.py, cookie_security.py
│   │   ├── tech_vuln_scanner.py, config_checks.py
│   │   └── known_vulns.py         # 200+ CVE database
│   ├── cve/                # CVE scanner
│   │   ├── nvd.py, exploit_db.py
│   └── crawl/              # Crawl engine
│       ├── crawler.py, api_discovery.py
├── dashboard/cli.py        # CLI real-time dashboard
├── report/                 # Report generators
│   ├── html_report.py, json_report.py, csv_report.py
├── utils/                  # Utilities
│   ├── http_client.py, scoring.py, helpers.py
├── samples/
│   └── vulnerable_app.py   # Test Flask app
├── requirements.txt
├── setup.py
└── pyproject.toml
```

---

## Usage

### Quick Start

```bash
cd C:\Users\HANH
$env:PYTHONPATH = "C:\Users\HANH"

# Quick scan
python -m webscanner example.com -m quick

# Standard scan with all reports
python -m webscanner https://example.com -m standard -r all

# Deep scan
python -m webscanner https://example.com -m deep --crawl-depth 3

# Enterprise scan with proxy
python -m webscanner https://example.com -m enterprise --threads 30 --proxy http://127.0.0.1:8080
```

### CLI Options

```
positional arguments:
  target                Target URL or domain to scan

options:
  -h, --help            Show help message
  -m, --mode {quick,standard,deep,enterprise}
                        Scan mode (default: quick)
  -t, --threads THREADS
                        Number of threads (0 = mode default)
  -p, --proxy PROXY     Proxy server (e.g., http://127.0.0.1:8080)
  -r, --report {html,json,csv,all}
                        Report format (default: html)
  --crawl-depth CRAWL_DEPTH
                        Crawl depth (default: 2)
  --max-pages MAX_PAGES
                        Max pages to crawl (default: 50)
  --no-banner           Skip banner display
  --list-plugins        List all available plugins
```

### Examples

```bash
# Quick info scan
python -m webscanner example.com -m quick

# Full scan with all report formats
python -m webscanner https://example.com -m standard -r all

# Deep scan with crawl
python -m webscanner https://example.com -m deep --crawl-depth 3 --max-pages 100

# Enterprise scan, JSON only
python -m webscanner https://example.com -m enterprise --threads 50 -r json

# List all available modules
python -m webscanner --list-plugins
```

### Testing with Vulnerable App

```bash
# Terminal 1: Start the vulnerable test app
cd C:\Users\HANH
$env:PYTHONPATH = "C:\Users\HANH"
python -m webscanner.samples.vulnerable_app

# Terminal 2: Scan it
python -m webscanner http://127.0.0.1:5000 -m standard -r all
```

---

## Architecture

```
                     ┌─────────────┐
                     │    CLI      │
                     │  (main.py)  │
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │   Scanner   │
                     │   Engine    │
                     └──────┬──────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                  │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌──────▼──────┐
    │   Recon   │    │  Vuln     │    │CVE/Crawl    │
    │  Modules  │    │  Modules  │    │  Modules    │
    └─────┬─────┘    └─────┬─────┘    └──────┬──────┘
          │                 │                  │
          └─────────────────┼──────────────────┘
                            │
                     ┌──────▼──────┐
                     │   Results   │
                     │ (Findings)  │
                     └──────┬──────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                  │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌──────▼──────┐
    │ Dashboard │    │  Report   │    │   Scoring   │
    │  (CLI)    │    │HTML/JSON/ │    │   System    │
    └───────────┘    │    CSV    │    └─────────────┘
                     └───────────┘
```

---

## Sample Output

### CLI Dashboard

```
============================================================
  Scan Complete!
  Duration: 4.23s
============================================================

  Security Score: [--] 0/100 - Critical Danger

  [CRITICAL] 3 finding(s)
  [HIGH    ] 8 finding(s)
  [MEDIUM  ] 5 finding(s)
  [LOW     ] 4 finding(s)
  [INFO    ] 7 finding(s)

  Technology: Python, Flask
  Open Ports: 5000
  Pages Crawled: 5
  Endpoints Found: 12

============================================================

  [CRITICAL - 3]
  --------------------------------------------------------
  1. CVE-2024-9287 - Heap Overflow in SSL/TLS
     Desc: [Python] CVE-2024-9287: Heap Overflow in SSL/TLS...
     Evidence: Detected: Python | CVE: CVE-2024-9287 | CVSS: 9.8
     Fix: Update Python to a version newer than 3.13.0
     CVE: CVE-2024-9287 | CWE: CWE-1104 | CVSS: 9.8
```

### HTML Report

Dark-themed report with:
- Color-coded security score
- Summary cards (Critical / High / Medium / Low / Info counts)
- Technology Stack badges
- Findings grouped by severity with CVE/CWE references
- Detailed recommendations

### JSON Report

```json
{
  "target": "https://example.com",
  "security_score": 42,
  "risk_level": "dangerous",
  "critical": 2,
  "findings": [
    {
      "type": "specific_cve_python",
      "name": "CVE-2024-9287 - Heap Overflow...",
      "severity": "critical",
      "cve_id": "CVE-2024-9287",
      "cwe_id": "CWE-1104",
      "cvss": 9.8
    }
  ]
}
```

---

## Supported Technologies (CVE Database)

| Technology | Entries | Technology | Entries |
|------------|---------|------------|---------|
| WordPress | 10 | Drupal | 4 |
| Laravel | 10 | Magento | 3 |
| Python | 10 | ASP.NET | 3 |
| PHP | 9 | Django | 5 |
| Nginx | 8 | Flask | 4 |
| Apache | 7 | Express | 4 |
| MySQL | 4 | Spring | 4 |
| PostgreSQL | 4 | Symfony | 3 |
| Redis | 4 | jQuery | 6 |

---

## Requirements

- `httpx` — Async HTTP client
- Python 3.10+ standard library (`asyncio`, `ssl`, `socket`, `re`, `json`, `csv`)

No heavy dependencies. No browser engine needed.

---

## License

MIT License

---

<p align="center">
  <i>WebSec Scanner — Find vulnerabilities before hackers do</i>
</p>
