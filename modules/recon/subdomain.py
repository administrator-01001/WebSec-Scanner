import asyncio
import socket
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding
from webscanner.config import COMMON_SUBDOMAINS


@plugin("subdomain", "Discover subdomains of target domain", "recon")
class SubdomainPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        domain = target.domain
        found_subdomains = []

        async def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
                return Finding(
                    type="subdomain_found",
                    name=f"Subdomain: {subdomain}",
                    severity="info",
                    description=f"Discovered subdomain: {subdomain} ({ip})",
                    evidence=ip,
                    module="subdomain",
                    url=target.url,
                )
            except (socket.gaierror, OSError):
                return None

        tasks = [check_subdomain(s) for s in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                findings.append(r)

        target.subsdomains_found = found_subdomains

        return findings
