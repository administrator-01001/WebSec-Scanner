from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Finding:
    type: str
    name: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    recommendation: str = ""
    cvss: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    exploit_available: bool = False
    poc: str = ""
    module: str = ""
    url: str = ""
    payload: str = ""
    confidence: str = "medium"  # low, medium, high, confirmed




@dataclass
class ScanResult:
    target: str
    mode: str
    started_at: str = ""
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    tech_stack: dict = field(default_factory=dict)
    pages_crawled: int = 0
    endpoints_found: list[str] = field(default_factory=list)
    subsdomains_found: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    scan_duration: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "info")

    def group_by_severity(self) -> dict:
        groups = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in self.findings:
            sev = f.severity if f.severity in groups else "info"
            groups[sev].append(f)
        return groups

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scan_duration": self.scan_duration,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "tech_stack": self.tech_stack,
            "pages_crawled": self.pages_crawled,
            "endpoints_found": self.endpoints_found,
            "subdomains_found": self.subsdomains_found,
            "open_ports": self.open_ports,
            "findings": [
                {
                    "type": f.type,
                    "name": f.name,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                    "cvss": f.cvss,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "exploit_available": f.exploit_available,
                    "module": f.module,
                    "url": f.url,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }
