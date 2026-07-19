import json
from webscanner.report.base import ReportGenerator


class JSONReport(ReportGenerator):
    def generate(self, result, output_path: str = ""):
        data = result.to_dict()
        data["report_generated"] = __import__("datetime").datetime.now().isoformat()

        if not output_path:
            safe_name = result.target.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
            output_path = f"scan_report_{safe_name}.json"

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return output_path
