from webscanner.modules.recon.base import ReconPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding
import httpx


WAF_SIGNATURES = {
    "Cloudflare": ["__cfduid", "cf-ray", "cf-cache-status", "cloudflare"],
    "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "Akamai": ["akamai", "x-akamai", "akamaized"],
    "F5 BIG-IP": ["BigIP", "BIG-IP", "x-application-context", "TS"],
    "ModSecurity": ["ModSecurity", "NOYB"],
    "Sucuri": ["sucuri", "x-sucuri"],
    "Barracuda": ["barracuda"],
    "Imperva": ["incapsula", "X-Iinfo"],
    "AWS WAF": ["x-amzn-", "awselb"],
    "Wordfence": ["wordfence"],
    "Fortinet": ["Fortigate", "x-blocked-by-fortigate"],
    "Radware": ["radware", "X-ASF"],
    "Comodo": ["comodo", "cwatch"],
    "StackPath": ["stackpath"],
    "Varnish": ["x-varnish", "varnish"],
}


@plugin("waf_detect", "Detect Web Application Firewall", "recon")
class WAFDetectPlugin(ReconPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []
        detected_wafs = set()

        try:
            resp = await http_client.get(target.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text.lower()

            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in headers or sig.lower() in body:
                        if waf_name not in detected_wafs:
                            detected_wafs.add(waf_name)
                            findings.append(Finding(
                                type="waf_detected",
                                name=f"WAF Detected: {waf_name}",
                                severity="info",
                                description=f"Web Application Firewall detected: {waf_name}",
                                evidence=f"Signature: {sig}",
                                recommendation="Consider this when crafting payloads - certain payloads may be blocked",
                                module="waf_detect",
                                url=target.url,
                            ))
                        break

            if not detected_wafs:
                malicious_payload = "?id=1' OR '1'='1"
                try:
                    test_url = target.url + ("" if "?" in target.url else "?") + malicious_payload
                    resp2 = await http_client.get(target.url, params={"id": "1' OR '1'='1"})
                    if resp2.status_code in (403, 406, 429, 503):
                        findings.append(Finding(
                            type="waf_suspected",
                            name="WAF Possibly Present",
                            severity="info",
                            description="WAF may be present (got status code when testing malicious payload)",
                            evidence=f"Status code: {resp2.status_code}",
                            module="waf_detect",
                            url=target.url,
                        ))
                except httpx.HTTPError:
                    pass

        except Exception as e:
            findings.append(Finding(
                type="error",
                name="WAF Detection Failed",
                severity="info",
                description=f"WAF detection error: {str(e)[:200]}",
                module="waf_detect",
                url=target.url,
            ))

        return findings
