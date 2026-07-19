import re
import httpx
from urllib.parse import urlparse, urljoin
from webscanner.modules.crawl.base import CrawlPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding
from webscanner.utils.helpers import extract_links, extract_forms, extract_js_urls


@plugin("crawler", "Crawl website to discover pages and endpoints", "crawl")
class CrawlerPlugin(CrawlPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        visited = set()
        to_visit = {target.url}
        max_pages = getattr(target, "max_pages", 50)
        max_depth = getattr(target, "crawl_depth", 2)
        depth = {target.url: 0}
        domain = urlparse(target.url).netloc
        pages_crawled = 0
        all_urls = {}

        robots_urls = await self._fetch_robots_txt(target, http_client)
        for u in robots_urls:
            all_urls[u] = {"source": "robots.txt"}

        sitemap_urls = await self._fetch_sitemap(target, http_client)
        for u in sitemap_urls:
            all_urls[u] = {"source": "sitemap.xml"}

        while to_visit and pages_crawled < max_pages:
            current_url = to_visit.pop()
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = await http_client.get(current_url, timeout=15)
                pages_crawled += 1
                body = resp.text

                new_links = extract_links(body, current_url)
                forms = extract_forms(body)
                js_urls = extract_js_urls(body, current_url)

                all_urls[current_url] = {"source": "crawled", "forms": len(forms)}

                for js_url in js_urls:
                    all_urls[js_url] = {"source": "js_reference"}

                for link in new_links:
                    if link not in visited and link not in to_visit:
                        link_domain = urlparse(link).netloc
                        if link_domain == domain or not link_domain:
                            link_depth = depth.get(current_url, 0) + 1
                            if link_depth <= max_depth:
                                depth[link] = link_depth
                                to_visit.add(link)

            except (httpx.HTTPError, Exception):
                continue

        target.pages_crawled = pages_crawled

        findings.append(Finding(
            type="crawl_stats",
            name="Crawl Statistics",
            severity="info",
            description=f"Crawled {pages_crawled} pages, discovered {len(all_urls)} unique URLs",
            evidence=f"Pages: {pages_crawled}, URLs found: {len(all_urls)}, Depth: {max_depth}",
            module="crawler",
            url=target.url,
        ))

        hidden_endpoints = []
        for url_str in all_urls:
            parsed = urlparse(url_str)
            path = parsed.path.lower()
            if any(kw in path for kw in ["admin", "config", "backup", "debug", "internal", "private", "secret", "test", "dev", "api", "hidden", "upload", "db", "sql", "log"]):
                hidden_endpoints.append(url_str)

        for ep in hidden_endpoints[:10]:
            findings.append(Finding(
                type="hidden_endpoint",
                name=f"Potential Hidden Endpoint: {urlparse(ep).path}",
                severity="medium",
                description=f"Discovered potentially sensitive endpoint",
                evidence=ep,
                recommendation="Review if these endpoints should be publicly accessible",
                module="crawler",
                url=ep,
            ))

        return findings

    async def _fetch_robots_txt(self, target, http_client) -> list[str]:
        urls = []
        try:
            parsed = urlparse(target.url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = await http_client.get(robots_url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip() if ":" in line else ""
                        if path and path != "/":
                            full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                            urls.append(full_url)
        except httpx.HTTPError:
            pass
        return urls

    async def _fetch_sitemap(self, target, http_client) -> list[str]:
        urls = []
        try:
            parsed = urlparse(target.url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            resp = await http_client.get(sitemap_url)
            if resp.status_code == 200:
                urls_found = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                urls.extend(urls_found[:50])
        except httpx.HTTPError:
            pass
        return urls
