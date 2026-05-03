"""Security header presence and value checks (A05:2021 – Security Misconfiguration)."""

from core.http import fetch

# (header_name, check_description, failure_is_vuln)
REQUIRED_HEADERS = [
    ("Strict-Transport-Security", "HSTS missing", True),
    ("Content-Security-Policy", "CSP missing", True),
    ("X-Content-Type-Options", "X-Content-Type-Options missing", True),
    ("X-Frame-Options", "Clickjacking protection missing", True),
    ("Referrer-Policy", "Referrer-Policy missing", True),
    ("Permissions-Policy", "Permissions-Policy missing", False),
]

DANGEROUS_CORS = ("*",)


def generate_tasks(url: str, config: dict) -> list:
    return [
        {
            "url": url,
            "method": "GET",
            "type": "Security Headers",
            "executor": test_security_headers,
        }
    ]


async def test_security_headers(session, task):
    try:
        _, resp = await fetch(session, task["url"])
        if not resp:
            return {"type": "Security Headers", "url": task["url"], "vulnerable": False}

        issues = []
        headers = resp.headers

        for header_name, desc, critical in REQUIRED_HEADERS:
            val = headers.get(header_name)
            if val is None:
                issues.append({"header": header_name, "issue": desc, "critical": critical})

        # CORS wildcard check
        acao = headers.get("Access-Control-Allow-Origin", "")
        if acao.strip() == "*":
            issues.append({"header": "Access-Control-Allow-Origin", "issue": "Wildcard CORS — any origin allowed", "critical": True})

        # Weak CSP
        csp = headers.get("Content-Security-Policy", "")
        if csp and "unsafe-inline" in csp.lower():
            issues.append({"header": "Content-Security-Policy", "issue": "CSP contains 'unsafe-inline'", "critical": True})
        if csp and "unsafe-eval" in csp.lower():
            issues.append({"header": "Content-Security-Policy", "issue": "CSP contains 'unsafe-eval'", "critical": True})

        # HSTS max-age too low
        hsts = headers.get("Strict-Transport-Security", "")
        if hsts:
            import re
            m = re.search(r"max-age=(\d+)", hsts)
            if m and int(m.group(1)) < 31536000:
                issues.append({"header": "Strict-Transport-Security", "issue": f"HSTS max-age too low: {m.group(1)}s (min 31536000)", "critical": False})

        critical_issues = [i for i in issues if i.get("critical")]
        return {
            "type": "Security Headers",
            "url": task["url"],
            "vulnerable": len(critical_issues) > 0,
            "issues": issues,
            "critical_count": len(critical_issues),
            "response_headers": dict(headers),
        }
    except Exception as exc:
        return {"type": "Security Headers", "url": task["url"], "error": str(exc), "vulnerable": False}
