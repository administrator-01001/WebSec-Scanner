SECURITY_HEADERS = {
    "strict-transport-security": {"weight": 8, "name": "HTTP Strict Transport Security (HSTS)"},
    "content-security-policy": {"weight": 10, "name": "Content Security Policy (CSP)"},
    "x-content-type-options": {"weight": 5, "name": "X-Content-Type-Options"},
    "x-frame-options": {"weight": 5, "name": "X-Frame-Options"},
    "x-xss-protection": {"weight": 3, "name": "X-XSS-Protection"},
    "referrer-policy": {"weight": 3, "name": "Referrer-Policy"},
    "permissions-policy": {"weight": 4, "name": "Permissions-Policy"},
    "set-cookie": {"weight": 3, "name": "Secure/HttpOnly/SameSite Cookie Attributes"},
    "access-control-allow-origin": {"weight": 3, "name": "CORS Headers"},
}


def calculate_score(findings: list, headers: dict) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "low") if isinstance(f, dict) else f.severity
        if sev in counts:
            counts[sev] += 1
    total_penalty = 0
    for sev, count in counts.items():
        w = weights[sev]
        for i in range(count):
            total_penalty += w / (1 + i * 0.5)
    score = max(10, 100 - total_penalty)
    return int(score)


def risk_level(score: int) -> str:
    if score >= 90:
        return "Very Safe"
    elif score >= 75:
        return "Safe"
    elif score >= 55:
        return "Needs Improvement"
    elif score >= 35:
        return "Risky"
    else:
        return "Critical Danger"


def risk_emoji(score: int) -> str:
    if score >= 90:
        return "[++]"
    elif score >= 75:
        return "[+]"
    elif score >= 55:
        return "[o]"
    elif score >= 35:
        return "[-]"
    else:
        return "[--]"
