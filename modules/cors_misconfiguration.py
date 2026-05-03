"""
modules/cors_misconfiguration.py — CORS misconfiguration detection
Checks arbitrary origin reflection and null origin acceptance.
"""
from core.http import fetch

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.io",
    "null",
    "http://localhost",
]


def generate_tasks(url, config):
    tasks = []
    for origin in EVIL_ORIGINS:
        tasks.append({
            "url": url,
            "method": "GET",
            "params": {},
            "headers": {"Origin": origin},
            "type": "CORS Misconfiguration",
            "test_origin": origin,
            "executor": test_cors,
        })
    # Also test preflight
    for origin in EVIL_ORIGINS:
        tasks.append({
            "url": url,
            "method": "OPTIONS",
            "params": {},
            "headers": {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
            "type": "CORS Misconfiguration",
            "test_origin": origin,
            "executor": test_cors,
        })
    return tasks


async def test_cors(session, task):
    try:
        method = task.get("method", "GET")
        text, resp = await fetch(
            session, task["url"],
            method=method,
            headers=task.get("headers", {}),
        )
        if not resp:
            return {"type": "CORS Misconfiguration", "url": task["url"], "vulnerable": False}

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        test_origin = task["test_origin"]

        # Critical: reflects arbitrary origin AND allows credentials
        reflects_evil = test_origin in acao or acao == "*"
        allows_creds = acac.lower() == "true"

        if reflects_evil and allows_creds and acao != "*":
            severity = "Critical"
            detail = f"Reflects origin '{test_origin}' with credentials"
            vulnerable = True
        elif reflects_evil and acao == "*" and allows_creds:
            # wildcard + credentials is invalid but worth noting
            severity = "High"
            detail = "Wildcard CORS with credentials flag"
            vulnerable = True
        elif reflects_evil and acao != "*":
            severity = "Medium"
            detail = f"Reflects arbitrary origin '{test_origin}' (no credentials)"
            vulnerable = True
        elif acao == "*":
            severity = "Low"
            detail = "Wildcard CORS origin"
            vulnerable = True
        else:
            vulnerable = False
            detail = ""
            severity = "Info"

        return {
            "type": "CORS Misconfiguration",
            "url": task["url"],
            "test_origin": test_origin,
            "acao_header": acao,
            "acac_header": acac,
            "vulnerable": vulnerable,
            "severity": severity,
            "detail": detail,
            "owasp_category": "A01:2021 – Broken Access Control",
        }
    except Exception as exc:
        return {"type": "CORS Misconfiguration", "url": task["url"], "error": str(exc), "vulnerable": False}
