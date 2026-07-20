SCAN_MODES = {
    "quick": {
        "recon": ["http_header", "ssl_tls", "tech_detect"],
        "vuln": [],
        "crawl": False,
        "cve": False,
        "concurrency": 1,
    },
    "standard": {
        "recon": ["whois", "dns_enum", "http_header", "ssl_tls", "waf_detect", "tech_detect"],
        "vuln": ["sqli", "xss", "csrf", "xxe", "host_header_injection", "nosqli", "lfi_rfi", "security_headers", "cookie_security", "tech_vuln_scanner", "config_checks"],
        "crawl": False,
        "cve": False,
        "concurrency": 5,
    },
    "deep": {
        "recon": ["whois", "dns_enum", "subdomain", "port_scan", "http_header", "ssl_tls", "waf_detect", "tech_detect", "cert_transparency"],
        "vuln": ["sqli", "xss", "csrf", "ssrf", "xxe", "host_header_injection", "graphql_check", "nosqli", "lfi_rfi", "command_injection", "ssti", "open_redirect", "idor", "cors", "security_headers", "cookie_security", "tech_vuln_scanner", "config_checks"],
        "crawl": True,
        "cve": True,
        "concurrency": 10,
    },
    "enterprise": {
        "recon": ["whois", "dns_enum", "subdomain", "port_scan", "http_header", "ssl_tls", "waf_detect", "tech_detect", "cert_transparency"],
        "vuln": ["sqli", "xss", "csrf", "ssrf", "xxe", "host_header_injection", "graphql_check", "nosqli", "lfi_rfi", "command_injection", "ssti", "open_redirect", "idor", "cors", "security_headers", "cookie_security", "tech_vuln_scanner", "config_checks"],
        "crawl": True,
        "cve": True,
        "concurrency": 20,
    },
}

RECON_MODULES = {}
VULN_MODULES = {}
CVE_MODULES = {}
CRAWL_MODULES = {}

TIMEOUT = 30
MAX_RETRIES = 3
REQUEST_DELAY = 0.1

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
    "curl/8.7.1",
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9090, 27017]
COMMON_SUBDOMAINS = ["www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "blog", "cdn", "m", "mobile", "shop", "secure", "vpn", "webmail", "portal", "support", "help", "docs", "status", "app", "demo", "beta", "store", "news", "media", "download", "wiki", "forum", "community"]

DB_PATH = "webscanner.db"
