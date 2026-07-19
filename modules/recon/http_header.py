import httpx
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


@plugin("http_header", "Analyze HTTP security headers", "recon")
class HTTPHeaderPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        try:
            resp = await http_client.get(target.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            info = Finding(
                type="info",
                name="HTTP Headers",
                severity="info",
                description=f"Server: {headers.get('server', 'N/A')}",
                evidence=str(dict(resp.headers))[:500],
                module="http_header",
                url=target.url,
            )
            findings.append(info)

            security_checks = {
                "strict-transport-security": {
                    "name": "Missing HSTS Header",
                    "severity": "medium",
                    "desc": "HTTP Strict Transport Security header is missing",
                    "rec": "Add Strict-Transport-Security header with a minimum age of 31536000s",
                },
                "content-security-policy": {
                    "name": "Missing CSP Header",
                    "severity": "high",
                    "desc": "Content Security Policy header is missing - vulnerable to XSS",
                    "rec": "Implement CSP header to control resource loading",
                },
                "x-content-type-options": {
                    "name": "Missing X-Content-Type-Options Header",
                    "severity": "medium",
                    "desc": "X-Content-Type-Options: nosniff header is missing",
                    "rec": "Add X-Content-Type-Options: nosniff header",
                },
                "x-frame-options": {
                    "name": "Missing X-Frame-Options Header",
                    "severity": "medium",
                    "desc": "X-Frame-Options header is missing - vulnerable to clickjacking",
                    "rec": "Add X-Frame-Options: DENY or SAMEORIGIN header",
                },
                "referrer-policy": {
                    "name": "Missing Referrer-Policy Header",
                    "severity": "low",
                    "desc": "Referrer-Policy header is missing",
                    "rec": "Add Referrer-Policy: strict-origin-when-cross-origin",
                },
                "permissions-policy": {
                    "name": "Missing Permissions-Policy Header",
                    "severity": "low",
                    "desc": "Permissions-Policy header is missing",
                    "rec": "Add Permissions-Policy header to restrict feature access",
                },
            }

            for hdr, check in security_checks.items():
                if hdr not in headers:
                    findings.append(Finding(
                        type="missing_header",
                        name=check["name"],
                        severity=check["severity"],
                        description=check["desc"],
                        recommendation=check["rec"],
                        module="http_header",
                        url=target.url,
                    ))

            if "x-powered-by" in headers:
                findings.append(Finding(
                    type="info_disclosure",
                    name="X-Powered-By Header Disclosure",
                    severity="low",
                    description=f"Server technology disclosed: {headers['x-powered-by']}",
                    evidence=headers["x-powered-by"],
                    recommendation="Remove X-Powered-By header to obscure technology stack",
                    module="http_header",
                    url=target.url,
                ))

            server = headers.get("server", "")
            if server and server not in ("cloudflare", "nginx", "Apache"):
                findings.append(Finding(
                    type="info_disclosure",
                    name="Server Header Disclosure",
                    severity="low",
                    description=f"Server header reveals: {server}",
                    evidence=server,
                    recommendation="Obfuscate or remove Server header",
                    module="http_header",
                    url=target.url,
                ))

            if headers.get("x-xss-protection", "") != "0":
                pass

        except httpx.HTTPError:
            findings.append(Finding(
                type="error",
                name="HTTP Header Scan Failed",
                severity="info",
                description=f"Could not retrieve headers from {target.url}",
                module="http_header",
                url=target.url,
            ))

        return findings
