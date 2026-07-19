# WebSec Scanner 🔍

**Web Vulnerability Scanner & Security Analyzer** — Công cụ quét lỗ hổng bảo mật website toàn diện với nhiều chế độ, phát hiện CVE/CWE cụ thể, và xuất báo cáo chuyên nghiệp.

```
+--------------------------------------------------------------+
|                    WebSec Scanner v1.0                        |
|         Web Vulnerability Scanner & Security Analyzer         |
+--------------------------------------------------------------+
```

---

## Tính năng chính

### 🚀 4 chế độ quét

| Chế độ | Mô tả | Tốc độ |
|--------|-------|--------|
| **Quick** | Thu thập thông tin cơ bản: HTTP header, SSL/TLS, phát hiện công nghệ | ~2-5s |
| **Standard** | Thêm OWASP Top 10, CVE theo tech stack, kiểm tra cấu hình bảo mật | ~5-15s |
| **Deep** | Crawl toàn bộ website, fuzz endpoint, phát hiện API, CVE từ NVD | ~30-120s |
| **Enterprise** | Full module, đa luồng (20 threads), báo cáo chi tiết | ~60-180s |

### 📦 Module phát hiện (22+ plugins)

**Recon (8 module)**
- WHOIS lookup, DNS Enumeration (A, MX, NS, TXT, SOA, PTR, CNAME)
- Subdomain Discovery (50+ common subdomains)
- Port Scan (25 common ports)
- HTTP Security Headers analysis
- SSL/TLS certificate check (expiry, version, cipher)
- WAF Detection (Cloudflare, CloudFront, Akamai, F5, ModSecurity, Sucuri, ...)
- Technology Detection (WordPress, Laravel, Django, React, Vue, Nginx, Apache, ...)

**Vulnerability (14 module)**
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
- Known Vulnerabilities Database (200+ CVE entries cho 18+ công nghệ)
- NVD API Integration
- Exploit-DB Search
- Version-aware CVE matching

**Crawl Engine**
- Website Crawler (robots.txt, sitemap.xml, link extraction)
- API Discovery (/api, /graphql, /swagger, /admin, ...)
- Hidden Endpoint Detection
- HTTP Method Discovery (GET, POST, PUT, DELETE, OPTIONS)

### 🏷️ Phát hiện CVE/CWE cụ thể

Khi phát hiện công nghệ, tool tự động tra cứu CVE tương ứng:

```
[Python] CVE-2024-9287 - Heap Overflow in SSL/TLS (Critical, 9.8)
[Python] CVE-2023-27043 - RCE via email module (Critical, 9.8)
[Laravel] CVE-2021-3129 - RCE via Ignition (Critical, 9.8)
[WordPress] CVE-2025-2731 - RCE via XML-RPC (Critical, 9.8)
```

Kèm CWE mapping cho từng loại lỗ hổng:
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

### 📊 Hệ thống chấm điểm

| Điểm | Mức | Ý nghĩa |
|------|-----|---------|
| 90–100 | 🟢 Very Safe | Rất an toàn |
| 75–89 | 🟡 Safe | Tốt |
| 50–74 | 🟠 Needs Improvement | Cần cải thiện |
| 25–49 | 🔴 Risky | Nhiều rủi ro |
| 0–24 | ⚫ Critical Danger | Nguy cơ rất cao |

### 📄 Báo cáo đa định dạng

- **HTML** — Giao diện dark mode, hiển thị score + findings theo severity
- **JSON** — Machine-readable, đầy đủ metadata
- **CSV** — Excel-friendly, dễ filter/phân tích

### 🔌 Kiến trúc Plugin

Cho phép bổ sung module mới mà không cần sửa core:

```python
@plugin("module_name", "Description", "vuln")
class MyPlugin(VulnPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        # logic here
        pass
```

---

## Cài đặt

### Yêu cầu

- Python 3.10+
- pip

### Cài đặt

```bash
# Clone hoặc copy source
cd webscanner

# Cài dependencies
pip install httpx

# (Optional) Cài whois nếu muốn dùng WHOIS module
# Windows: không cần (dùng whois từ WSL hoặc bỏ qua)
# Linux: sudo apt install whois
# macOS: brew install whois
```

### Cấu trúc thư mục

```
webscanner/
├── main.py                 # CLI entry point (argparse)
├── config.py               # Cấu hình scan modes
├── core/
│   ├── scanner.py          # Scanner engine
│   └── plugin_system.py    # Plugin registry + auto-discovery
├── models/
│   ├── target.py           # ScanTarget dataclass
│   └── result.py           # Finding + ScanResult (tính điểm)
├── modules/
│   ├── recon/              # 8 module recon
│   │   ├── whois.py, dns_enum.py, subdomain.py, port_scan.py
│   │   ├── http_header.py, ssl_tls.py, waf_detect.py, tech_detect.py
│   ├── vulnerability/      # 14 module vuln
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
│   └── vulnerable_app.py   # Test app (Flask)
├── requirements.txt
├── setup.py
└── pyproject.toml
```

---

## Sử dụng

### Quick Start

```bash
cd C:\Users\HANH
$env:PYTHONPATH = "C:\Users\HANH"

# Quick scan
python -m webscanner example.com -m quick

# Standard scan với tất cả báo cáo
python -m webscanner https://example.com -m standard -r all

# Deep scan
python -m webscanner https://example.com -m deep --crawl-depth 3

# Enterprise scan với proxy
python -m webscanner https://example.com -m enterprise --threads 30 --proxy http://127.0.0.1:8080
```

### CLI Options

```
positional arguments:
  target                Target URL or domain to scan

options:
  -h, --help            Hiển thị help
  -m, --mode {quick,standard,deep,enterprise}
                        Chế độ quét (default: quick)
  -t, --threads THREADS
                        Số luồng (0 = mặc định theo mode)
  -p, --proxy PROXY     Proxy server (e.g., http://127.0.0.1:8080)
  -r, --report {html,json,csv,all}
                        Định dạng báo cáo (default: html)
  --crawl-depth CRAWL_DEPTH
                        Độ sâu crawl (default: 2)
  --max-pages MAX_PAGES
                        Số trang tối đa crawl (default: 50)
  --no-banner           Ẩn banner
  --list-plugins        Liệt kê tất cả plugins
```

### Ví dụ

```bash
# Scan nhanh, chỉ lấy thông tin cơ bản
python -m webscanner example.com -m quick

# Scan đầy đủ, xuất HTML + JSON + CSV
python -m webscanner https://example.com -m standard -r all

# Scan sâu với crawl
python -m webscanner https://example.com -m deep --crawl-depth 3 --max-pages 100

# Scan enterprise, chỉ xuất JSON
python -m webscanner https://example.com -m enterprise --threads 50 -r json

# Xem danh sách module
python -m webscanner --list-plugins
```

### Test với app mẫu

```bash
# Terminal 1: Khởi động app mẫu có lỗ hổng
cd C:\Users\HANH
$env:PYTHONPATH = "C:\Users\HANH"
python -m webscanner.samples.vulnerable_app

# Terminal 2: Scan
python -m webscanner http://127.0.0.1:5000 -m standard -r all
```

---

## Kiến trúc

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

## Kết quả mẫu

### Dashboard CLI

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

Giao diện dark mode, hiển thị:

- Score với màu sắc theo mức độ
- Summary cards (Critical / High / Medium / Low / Info)
- Technology Stack tags
- Findings list theo severity với CVE/CWE badges
- Recommendations chi tiết

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

## License

MIT License

---

## Tác giả

Built with Python + asyncio + httpx

<p align="center">
  <i>WebSec Scanner — Bảo vệ website của bạn trước khi hacker làm điều đó</i>
</p>
