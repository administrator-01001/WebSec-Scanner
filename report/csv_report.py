import csv
from webscanner.report.base import ReportGenerator


class CSVReport(ReportGenerator):
    def generate(self, result, output_path: str = ""):
        if not output_path:
            safe_name = result.target.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
            output_path = f"scan_report_{safe_name}.csv"

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Name", "Type", "Description", "URL", "CVE ID", "CWE ID", "CVSS", "Confidence", "Exploit Available", "Recommendation", "Evidence"])
            for finding in result.findings:
                writer.writerow([
                    finding.severity,
                    finding.name,
                    finding.type,
                    finding.description,
                    finding.url,
                    finding.cve_id or "",
                    finding.cwe_id or "",
                    finding.cvss or "",
                    finding.confidence,
                    "Yes" if finding.exploit_available else "No",
                    finding.recommendation,
                    finding.evidence[:200] if finding.evidence else "",
                ])

        return output_path
