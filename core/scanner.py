import asyncio
import time
from datetime import datetime
from webscanner.config import SCAN_MODES
from webscanner.core.plugin_system import PluginRegistry
from webscanner.models.target import ScanTarget
from webscanner.models.result import ScanResult, Finding
from webscanner.utils.http_client import HttpClient
from webscanner.dashboard.cli import Dashboard
from webscanner.report.html_report import HTMLReport
from webscanner.report.json_report import JSONReport
from webscanner.report.csv_report import CSVReport


class Scanner:
    def __init__(self, target: str, mode: str = "quick", threads: int = 0, proxy: str = "", cookies: dict = None):
        self.target = ScanTarget(
            url=target,
            mode=mode,
            cookies=cookies or {},
            proxy=proxy or None,
        )
        self.mode = mode
        self.result = ScanResult(target=self.target.url, mode=mode)
        self.dashboard = Dashboard()
        self.http_client = HttpClient(proxy=self.target.proxy, cookies=self.target.cookies)

        mode_config = SCAN_MODES.get(mode, SCAN_MODES["quick"])
        if threads > 0:
            self.target.threads = threads
        else:
            self.target.threads = mode_config["threads"]

        self.recon_modules = mode_config["recon"]
        self.vuln_modules = mode_config["vuln"]
        self.crawl_enabled = mode_config["crawl"]
        self.cve_enabled = mode_config["cve"]

    async def run(self) -> ScanResult:
        self.dashboard.show_banner()
        self.dashboard.show_scan_start(self.target.url, self.mode)
        self.result.started_at = datetime.now().isoformat()

        try:
            await self._run_recon()
            await self._run_vuln()
            await self._run_crawl()
            await self._run_cve()
        finally:
            self.result.finished_at = datetime.now().isoformat()
            await self.http_client.close()

        self.dashboard.show_scan_summary(self.result)

        return self.result

    async def _run_recon(self):
        self.dashboard.show_progress("RECON", "Starting reconnaissance...")
        tasks = []
        for module_name in self.recon_modules:
            plugin_cls = PluginRegistry.get_plugin(module_name, "recon")
            if plugin_cls:
                self.dashboard.show_progress("RECON", f"Running {module_name}...")
                tasks.append(self._safe_run_plugin(module_name, "recon"))

        if tasks:
            results = await asyncio.gather(*tasks)
            for module_findings in results:
                if module_findings:
                    self.result.findings.extend(module_findings)

    async def _run_vuln(self):
        self.dashboard.show_progress("VULN", "Starting vulnerability scanning...")
        tasks = []
        for module_name in self.vuln_modules:
            plugin_cls = PluginRegistry.get_plugin(module_name, "vuln")
            if plugin_cls:
                self.dashboard.show_progress("VULN", f"Testing {module_name}...")
                tasks.append(self._safe_run_plugin(module_name, "vuln"))

        if tasks:
            results = await asyncio.gather(*tasks)
            for module_findings in results:
                if module_findings:
                    for finding in module_findings:
                        if finding not in self.result.findings:
                            self.result.findings.append(finding)

    async def _run_crawl(self):
        if not self.crawl_enabled:
            return
        self.dashboard.show_progress("CRAWL", "Starting crawler...")
        self.dashboard.show_progress("CRAWL", "Crawling website...")
        findings = await self._safe_run_plugin("crawler", "crawl")
        if findings:
            self.result.findings.extend(findings)

        self.dashboard.show_progress("CRAWL", "Discovering API endpoints...")
        api_findings = await self._safe_run_plugin("api_discovery", "crawl")
        if api_findings:
            self.result.findings.extend(api_findings)

    async def _run_cve(self):
        if not self.cve_enabled:
            return
        self.dashboard.show_progress("CVE", "Checking CVEs...")
        nvd_findings = await self._safe_run_plugin("nvd", "cve")
        if nvd_findings:
            self.result.findings.extend(nvd_findings)

        self.dashboard.show_progress("CVE", "Checking Exploit-DB...")
        exploit_findings = await self._safe_run_plugin("exploit_db", "cve")
        if exploit_findings:
            self.result.findings.extend(exploit_findings)

    async def _safe_run_plugin(self, name: str, category: str) -> list[Finding]:
        try:
            return await PluginRegistry.run_plugin(name, category, self.target, self.http_client)
        except Exception as e:
            return [Finding(
                type="plugin_error",
                name=f"Plugin Error: {name}",
                severity="info",
                description=f"Error running {category}/{name}: {str(e)[:200]}",
                module=name,
                url=self.target.url,
            )]

    async def generate_reports(self, formats: list[str]) -> dict[str, str]:
        paths = {}
        for fmt in formats:
            if fmt == "html":
                reporter = HTMLReport()
                path = reporter.generate(self.result)
                paths["html"] = path
                print(f"  HTML Report: {path}")
            elif fmt == "json":
                reporter = JSONReport()
                path = reporter.generate(self.result)
                paths["json"] = path
                print(f"  JSON Report: {path}")
            elif fmt == "csv":
                reporter = CSVReport()
                path = reporter.generate(self.result)
                paths["csv"] = path
                print(f"  CSV Report: {path}")
        return paths

    def show_detailed_findings(self):
        self.dashboard.show_detailed_findings(self.result)
