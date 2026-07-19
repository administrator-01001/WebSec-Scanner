import httpx
import json
from webscanner.modules.cve.base import CVEPlugin
from webscanner.core.plugin_system import plugin
from webscanner.models.result import Finding


CVE_CACHE = {}


@plugin("nvd", "Check for known CVEs based on detected technologies", "cve")
class NVDPlugin(CVEPlugin):
    async def run(self, target, http_client) -> list[Finding]:
        findings = []

        tech_data = getattr(target, "tech_stack", {})
        if not tech_data:
            return findings

        for tech_name, tech_type in tech_data.items():
            cves = await self._search_cve_for_tech(tech_name, tech_type)
            for cve in cves:
                findings.append(Finding(
                    type="cve_found",
                    name=f"CVE: {cve['id']}",
                    severity=self._cvss_to_severity(cve.get("cvss", 0)),
                    description=f"{cve['id']}: {cve.get('description', '')[:200]}",
                    evidence=f"Affected: {tech_name}\nCVSS: {cve.get('cvss', 'N/A')}",
                    recommendation=cve.get("mitigation", "Update to latest version"),
                    cvss=cve.get("cvss"),
                    cve_id=cve["id"],
                    exploit_available=cve.get("exploit_available", False),
                    module="cve_nvd",
                    url=target.url,
                    confidence="high",
                ))

        return findings

    async def _search_cve_for_tech(self, tech_name: str, tech_type: str) -> list[dict]:
        cache_key = tech_name.lower()
        if cache_key in CVE_CACHE:
            return CVE_CACHE[cache_key]

        results = []
        search_queries = [tech_name]

        if tech_name == "WordPress":
            search_queries = ["WordPress", "wp"]

        for query in search_queries[:2]:
            cves = await self._fetch_nvd(query)
            results.extend(cves)
            if len(results) >= 5:
                break

        results = results[:8]
        CVE_CACHE[cache_key] = results
        return results

    async def _fetch_nvd(self, query: str) -> list[dict]:
        try:
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": query,
                "resultsPerPage": 5,
            }
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(nvd_url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_nvd_response(data, query)
        except (httpx.HTTPError, json.JSONDecodeError, KeyError):
            pass
        return []

    def _parse_nvd_response(self, data: dict, query: str) -> list[dict]:
        results = []
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities[:5]:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "UNKNOWN")
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            metrics = cve_data.get("metrics", {})
            cvss = 0
            for metric_ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if metrics.get(metric_ver):
                    cvss = metrics[metric_ver][0].get("cvssData", {}).get("baseScore", 0)
                    break
            references = cve_data.get("references", [])
            exploit_available = False
            for ref in references:
                tags = ref.get("tags", [])
                if "Exploit" in tags or "Vendor Advisory" in tags:
                    exploit_available = True
                    break
            results.append({
                "id": cve_id,
                "description": description,
                "cvss": cvss,
                "exploit_available": exploit_available,
                "mitigation": f"Update {query} to the latest version. See: https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return results

    def _cvss_to_severity(self, cvss: float) -> str:
        if cvss >= 9.0:
            return "critical"
        elif cvss >= 7.0:
            return "high"
        elif cvss >= 4.0:
            return "medium"
        elif cvss > 0:
            return "low"
        return "info"
