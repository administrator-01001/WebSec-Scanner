import json
import httpx
from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


@plugin("cert_transparency", "Lookup SSL certificates from Certificate Transparency logs (crt.sh)", "recon")
class CertTransparencyPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        domain = target.domain

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q={domain}&output=json",
                    headers={"User-Agent": "Mozilla/5.0"},
                )

                if resp.status_code == 200 and resp.text.strip():
                    certs = resp.json()
                    subdomains = set()
                    issuers = set()
                    valid_from = set()

                    for cert in certs[:50]:
                        name_value = cert.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
                        if cert.get("issuer_name"):
                            issuers.add(cert["issuer_name"])
                        if cert.get("not_before"):
                            valid_from.add(cert["not_before"])

                    if subdomains:
                        findings.append(Finding(
                            type="ct_subdomains",
                            name=f"Certificate Transparency - Subdomains ({len(subdomains)})",
                            severity="info",
                            description=f"Found {len(subdomains)} subdomains via crt.sh for {domain}",
                            evidence="\n".join(sorted(subdomains)[:15])[:500],
                            recommendation="Monitor certificate issuance for early detection of subdomain takeover risks.",
                            module="cert_transparency",
                            url=target.url,
                        ))

                    if issuers:
                        findings.append(Finding(
                            type="ct_issuers",
                            name="Certificate Transparency - Issuers",
                            severity="info",
                            description=f"Certificate issuers: {', '.join(list(issuers)[:5])}",
                            evidence="\n".join(list(issuers)[:5])[:500],
                            module="cert_transparency",
                            url=target.url,
                        ))

                    if not subdomains and not issuers:
                        findings.append(Finding(
                            type="ct_no_results",
                            name="Certificate Transparency - No Results",
                            severity="info",
                            description=f"No crt.sh results for {domain}",
                            module="cert_transparency",
                            url=target.url,
                        ))

        except (httpx.HTTPError, json.JSONDecodeError, Exception):
            findings.append(Finding(
                type="ct_unavailable",
                name="Certificate Transparency - Lookup Failed",
                severity="info",
                description="crt.sh lookup failed or timed out",
                module="cert_transparency",
                url=target.url,
            ))

        return findings
