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
    base = 100
    deduct_critical = 0
    deduct_high = 0
    deduct_medium = 0
    deduct_low = 0

    for finding in findings:
        sev = finding.get("severity", "low")
        if sev == "critical":
            deduct_critical += 1
        elif sev == "high":
            deduct_high += 1
        elif sev == "medium":
            deduct_medium += 1
        elif sev == "low":
            deduct_low += 1

    penalty = (
        deduct_critical * 25
        + deduct_high * 15
        + deduct_medium * 8
        + deduct_low * 3
    )

    header_score = 0
    hkeys = {k.lower(): v for k, v in headers.items()}
    for hdr, info in SECURITY_HEADERS.items():
        if hdr in hkeys:
            header_score += info["weight"]
    bonus = min(header_score, 15)

    score = min(100, max(0, base - penalty + bonus))
    return score


def risk_level(score: int) -> str:
    if score >= 90:
        return "Very Safe"
    elif score >= 75:
        return "Safe"
    elif score >= 50:
        return "Needs Improvement"
    elif score >= 25:
        return "Risky"
    else:
        return "Critical Danger"


def risk_emoji(score: int) -> str:
    if score >= 90:
        return "[++]"
    elif score >= 75:
        return "[+]"
    elif score >= 50:
        return "[o]"
    elif score >= 25:
        return "[-]"
    else:
        return "[--]"
