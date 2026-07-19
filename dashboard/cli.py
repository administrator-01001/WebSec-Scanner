import time
import shutil
from webscanner.utils.scoring import risk_level, risk_emoji


class Dashboard:
    def __init__(self):
        self.start_time = 0
        self.current_phase = ""

    def show_banner(self):
        banner = """
+--------------------------------------------------------------+
|                    WebSec Scanner v1.0                        |
|         Web Vulnerability Scanner & Security Analyzer         |
+--------------------------------------------------------------+
"""
        print(banner)

    def show_scan_start(self, target: str, mode: str):
        self.start_time = time.time()
        print(f"\n{'='*60}")
        print(f"  Target: {target}")
        print(f"  Mode:   {mode.upper()}")
        print(f"{'='*60}\n")

    def show_progress(self, phase: str, module: str = ""):
        self.current_phase = phase
        msg = f"  [{phase}]"
        if module:
            msg += f" {module}"
        print(msg)

    def show_finding(self, finding):
        sev_colors = {
            "critical": "CRITICAL",
            "high": "HIGH    ",
            "medium": "MEDIUM  ",
            "low": "LOW     ",
            "info": "INFO    ",
        }
        color = sev_colors.get(finding.severity, "INFO")
        print(f"  [{color}] {finding.name}")
        if finding.url:
            print(f"         URL: {finding.url}")
        if finding.evidence:
            evidence = finding.evidence[:100] if len(finding.evidence) > 100 else finding.evidence
            print(f"         Evidence: {evidence}")
        print()

    def show_scan_summary(self, result):
        duration = time.time() - self.start_time
        result.scan_duration = duration

        print(f"\n{'='*60}")
        print(f"  Scan Complete!")
        print(f"  Duration: {duration:.2f}s")
        print(f"{'='*60}\n")

        score = result.security_score
        emoji = risk_emoji(score)
        level = risk_level(score)

        print(f"  Security Score: {emoji} {score}/100 - {level}")
        print()

        sev_data = result.group_by_severity()
        for severity, findings in sev_data.items():
            if findings:
                count = len(findings)
                label = f"[{severity.upper():8}]"
                print(f"  {label} {count} finding(s)")

        tech = result.tech_stack
        if tech:
            tech_str = ", ".join(f"{k}" for k in list(tech.keys())[:8])
            print(f"\n  Technology: {tech_str}")

        if result.open_ports:
            ports_str = ", ".join(str(p) for p in result.open_ports[:10])
            print(f"  Open Ports: {ports_str}")

        if result.pages_crawled:
            print(f"  Pages Crawled: {result.pages_crawled}")

        if result.endpoints_found:
            print(f"  Endpoints Found: {len(result.endpoints_found)}")

        print(f"\n{'='*60}")

    def show_detailed_findings(self, result):
        print(f"\n{'='*60}")
        print(f"  DETAILED FINDINGS")
        print(f"{'='*60}\n")

        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = [f for f in result.findings if f.severity == severity]
            if not findings:
                continue
            print(f"  [{severity.upper()} - {len(findings)}]")
            print(f"  {'-'*56}")
            for i, f in enumerate(findings, 1):
                print(f"  {i}. {f.name}")
                print(f"     Desc: {f.description[:150]}")
                if f.evidence:
                    print(f"     Evidence: {f.evidence[:150]}")
                if f.recommendation:
                    print(f"     Fix: {f.recommendation[:150]}")
                if f.cve_id:
                    print(f"     CVE: {f.cve_id}")
                if f.cwe_id:
                    print(f"     CWE: {f.cwe_id}")
                if f.cvss:
                    print(f"     CVSS: {f.cvss}")
                if f.confidence:
                    print(f"     Confidence: {f.confidence}")
                print()

    def ask_reports(self) -> list[str]:
        print("\n  Generate Reports:")
        print("  1. HTML Report")
        print("  2. JSON Report")
        print("  3. CSV Report")
        print("  4. All Reports")
        print("  5. Skip")
        choice = input("\n  Select (1-5): ").strip()
        mapping = {
            "1": ["html"],
            "2": ["json"],
            "3": ["csv"],
            "4": ["html", "json", "csv"],
            "5": [],
        }
        return mapping.get(choice, ["html"])
