CVSS_SEVERITY = [
    (0.0, "none"),
    (0.1, "low"),
    (4.0, "medium"),
    (7.0, "high"),
    (9.0, "critical"),
]


def cvss_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    elif cvss >= 7.0:
        return "high"
    elif cvss >= 4.0:
        return "medium"
    elif cvss > 0.0:
        return "low"
    return "none"


def cvss_score(severity: str) -> float:
    return {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "none": 0.0}.get(severity, 0.0)
