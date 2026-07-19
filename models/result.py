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

    @property
    def severity_score(self) -> float:
        scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        return max(scores.get(self.severity, 1.0), self.cvss or 0)


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

    @property
    def security_score(self) -> int:
        if not self.findings:
            return 100
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity if f.severity in counts else "info"
            counts[sev] += 1
        total_penalty = 0
        for sev, count in counts.items():
            w = weights[sev]
            for i in range(count):
                total_penalty += w / (1 + i * 0.5)
        score = max(10, 100 - total_penalty)
        return int(score)

    @property
    def risk_level(self) -> str:
        score = self.security_score
        if score >= 90:
            return "very_safe"
        elif score >= 75:
            return "safe"
        elif score >= 50:
            return "moderate"
        elif score >= 25:
            return "dangerous"
        else:
            return "critical"

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
            "security_score": self.security_score,
            "risk_level": self.risk_level,
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
