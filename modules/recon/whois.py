import asyncio
import socket
import subprocess
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


@plugin("whois", "Perform WHOIS lookup on target domain", "recon")
class WhoisPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        domain = target.domain

        def _run_whois(domain: str) -> str:
            result = subprocess.run(
                ["whois", domain],
                capture_output=True, timeout=15, text=True
            )
            return result.stdout

        try:
            output = await asyncio.to_thread(_run_whois, domain)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            findings.append(Finding(
                type="whois_unavailable",
                name="WHOIS Not Available",
                severity="info",
                description="WHOIS command not found or timed out",
                module="whois",
                url=target.url,
            ))
            return findings

        if output:
            important = []
            for line in output.splitlines():
                line_lower = line.lower()
                for kw in ["registrar", "creation date", "expiry date", "expiration date", "name server", "registrant", "admin email", "tech email"]:
                    if kw in line_lower:
                        important.append(line.strip())

            if important:
                findings.append(Finding(
                    type="whois_info",
                    name="WHOIS Information",
                    severity="info",
                    description="WHOIS lookup completed",
                    evidence="\n".join(important[:10])[:500],
                    recommendation="Ensure WHOIS privacy protection is enabled",
                    module="whois",
                    url=target.url,
                ))

            if "expiry date" in output.lower() or "expiration date" in output.lower():
                import re
                expiry_match = re.search(r"(?:expiry|expiration)\s*date:\s*(.+)", output, re.IGNORECASE)
                if expiry_match:
                    findings.append(Finding(
                        type="domain_expiry",
                        name="Domain Expiry Date",
                        severity="info",
                        description=f"Domain expires: {expiry_match.group(1).strip()}",
                        module="whois",
                        url=target.url,
                    ))
        else:
            findings.append(Finding(
                type="whois_unavailable",
                name="WHOIS Lookup Unavailable",
                severity="info",
                description=f"WHOIS data not available for {domain}",
                module="whois",
                url=target.url,
            ))

        return findings
