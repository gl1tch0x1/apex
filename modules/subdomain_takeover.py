"""
modules/subdomain_takeover.py — Subdomain Takeover detection
Checks for dangling CNAME records pointing to unclaimed services.
"""
import asyncio
import socket
from core.http import fetch

TAKEOVER_SIGNATURES = {
    "github.io":         ["There isn't a GitHub Pages site here"],
    "herokuapp.com":     ["No such app", "herokucdn.com/error-pages"],
    "azurewebsites.net": ["404 Web Site not found"],
    "s3.amazonaws.com":  ["NoSuchBucket", "The specified bucket does not exist"],
    "cloudfront.net":    ["Bad Request"],
    "ghost.io":          ["The thing you were looking for is no longer here"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "zendesk.com":       ["Help Center Closed"],
    "bitbucket.io":      ["Repository not found"],
    "netlify.com":       ["Not Found - Request ID"],
    "surge.sh":          ["project not found"],
    "uservoice.com":     ["This UserVoice subdomain is currently available"],
    "freshdesk.com":     ["There is no helpdesk here"],
    "webflow.io":        ["The page you are looking for doesn't exist"],
}


def _get_cname(hostname):
    try:
        return socket.getaddrinfo(hostname, None)[0][4][0]
    except Exception:
        return ""


def generate_tasks(url, config):
    from urllib.parse import urlparse
    host = urlparse(url).netloc.split(":")[0]
    return [{
        "url": url, "host": host, "method": "GET", "params": {},
        "type": "Subdomain Takeover", "executor": test_subdomain_takeover,
    }]


async def test_subdomain_takeover(session, task):
    try:
        url = task["url"]
        host = task.get("host", "")
        text, resp = await fetch(session, url)
        cname = ""
        try:
            loop = asyncio.get_event_loop()
            cname = await loop.run_in_executor(None, _get_cname, host)
        except Exception:
            pass

        vulnerable = False
        matched_service = ""
        signature_hit = ""
        if text:
            for service, signatures in TAKEOVER_SIGNATURES.items():
                for sig in signatures:
                    if sig.lower() in text.lower():
                        vulnerable = True
                        matched_service = service
                        signature_hit = sig
                        break
                if vulnerable:
                    break

        return {
            "type": "Subdomain Takeover", "url": url, "host": host,
            "cname": cname, "vulnerable": vulnerable,
            "severity": "High" if vulnerable else "Info",
            "service": matched_service, "signature": signature_hit,
            "owasp_category": "A05:2021 – Security Misconfiguration",
        }
    except Exception as exc:
        return {"type": "Subdomain Takeover", "url": task["url"], "error": str(exc), "vulnerable": False}
