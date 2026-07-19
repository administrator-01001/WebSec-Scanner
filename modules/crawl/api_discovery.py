import httpx
from urllib.parse import urlparse
from webscanner.modules.crawl.base import CrawlPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding
from webscanner.utils.helpers import extract_api_endpoints


COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/swagger", "/swagger/v1", "/swagger/v2", "/swagger/v3",
    "/swagger-ui", "/swagger-resources", "/api-docs", "/docs",
    "/openapi.json", "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/admin/api", "/backend/api",
    "/.well-known", "/health", "/healthcheck", "/status",
    "/login", "/logout", "/register", "/signup", "/forgot-password",
    "/reset-password", "/oauth", "/oauth2",
    "/token", "/refresh", "/auth",
    "/user", "/users", "/profile", "/account",
    "/admin", "/administrator", "/management",
    "/config", "/configuration", "/settings",
    "/upload", "/uploads", "/download", "/downloads",
    "/search", "/query", "/filter",
    "/export", "/import", "/report",
    "/webhook", "/webhooks", "/callback",
    "/internal", "/internal/api",
    "/debug", "/trace", "/monitor", "/metrics",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.env", "/.git/config", "/.gitignore",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


@plugin("api_discovery", "Discover API endpoints and hidden paths", "crawl")
class APIDiscoveryPlugin(CrawlPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        discovered = []
        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        try:
            resp = await http_client.get(target.url)
            body = resp.text
            api_urls = extract_api_endpoints(body, target.url)
            for url in api_urls:
                if url not in discovered:
                    discovered.append(url)
        except httpx.HTTPError:
            pass

        paths_to_check = COMMON_API_PATHS
        if target.mode in ("deep", "enterprise"):
            pass

        for path in paths_to_check:
            test_url = f"{base}{path}"
            try:
                resp = await http_client.get(test_url, timeout=8)
                if resp.status_code != 404:
                    discovered.append(test_url)
                    sev = "high" if any(kw in path for kw in [".env", ".git", "admin", "internal", "config", "debug", "phpinfo"]) else "info"
                    findings.append(Finding(
                        type="api_endpoint",
                        name=f"Discovered Endpoint: {path}",
                        severity=sev,
                        description=f"Accessible endpoint found: {test_url} (HTTP {resp.status_code})",
                        evidence=f"Status: {resp.status_code}, Content-Length: {len(resp.text)}",
                        recommendation="Restrict access to this endpoint if not intended to be public" if sev == "high" else "",
                        module="api_discovery",
                        url=test_url,
                    ))

                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    if "json" in ct or "application/json" in ct:
                        findings.append(Finding(
                            type="api_json",
                            name=f"JSON API: {path}",
                            severity="info",
                            description=f"Endpoint returns JSON: {test_url}",
                            module="api_discovery",
                            url=test_url,
                        ))
            except httpx.HTTPError:
                continue

        if target.mode in ("deep", "enterprise"):
            for endpoint in discovered[:20]:
                for method in HTTP_METHODS:
                    try:
                        resp = await http_client.request(method, endpoint, timeout=8)
                        if resp.status_code not in (404, 405):
                            findings.append(Finding(
                                type="api_method",
                                name=f"API Method: {method} {urlparse(endpoint).path}",
                                severity="info",
                                description=f"Endpoint supports {method} method (HTTP {resp.status_code})",
                                evidence=f"Method: {method} -> {resp.status_code}",
                                module="api_discovery",
                                url=endpoint,
                            ))
                    except httpx.HTTPError:
                        continue

        target.endpoints_found = discovered

        return findings
