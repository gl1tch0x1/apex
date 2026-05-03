"""
modules/http_request_smuggling.py — HTTP Request Smuggling detection
Tests CL.TE and TE.CL desync via timing and response anomalies.
"""
import time
from core.http import fetch

# CL.TE probe: Content-Length disagrees with Transfer-Encoding
CLTE_BODY = b"0\r\n\r\nG"  # poison byte

# TE.CL probe: Transfer-Encoding disagrees with Content-Length
TECL_BODY = b"5\r\nSMUGG\r\n0\r\n\r\n"


def generate_tasks(url, config):
    tasks = []
    tasks.append({
        "url": url, "method": "POST", "params": {},
        "type": "HTTP Request Smuggling", "vector": "CL.TE",
        "executor": test_clte,
    })
    tasks.append({
        "url": url, "method": "POST", "params": {},
        "type": "HTTP Request Smuggling", "vector": "TE.CL",
        "executor": test_tecl,
    })
    return tasks


async def test_clte(session, task):
    """CL.TE desync probe: send ambiguous CL+TE and detect timing difference."""
    try:
        url = task["url"]
        headers_normal = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "6"}
        headers_smug = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        }
        # Baseline timing
        t0 = time.perf_counter()
        await fetch(session, url, method="POST", data="x=1", headers=headers_normal)
        baseline = time.perf_counter() - t0

        # Smuggled request timing (if server hangs waiting for chunked body)
        t1 = time.perf_counter()
        try:
            await fetch(session, url, method="POST", data=CLTE_BODY, headers=headers_smug)
        except Exception:
            pass
        delayed = time.perf_counter() - t1

        vulnerable = delayed > baseline + 5.0  # significant hang = likely CL.TE
        return {
            "type": "HTTP Request Smuggling",
            "url": url, "vector": "CL.TE",
            "vulnerable": vulnerable,
            "severity": "Critical" if vulnerable else "Info",
            "timings": {"baseline_s": round(baseline, 3), "probe_s": round(delayed, 3)},
            "owasp_category": "A07:2021 – Identification and Authentication Failures",
        }
    except Exception as exc:
        return {"type": "HTTP Request Smuggling", "url": task["url"], "error": str(exc), "vulnerable": False}


async def test_tecl(session, task):
    """TE.CL desync probe."""
    try:
        url = task["url"]
        headers_smug = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
        }
        t0 = time.perf_counter()
        await fetch(session, url, method="POST", data="x=1")
        baseline = time.perf_counter() - t0

        t1 = time.perf_counter()
        try:
            await fetch(session, url, method="POST", data=TECL_BODY, headers=headers_smug)
        except Exception:
            pass
        delayed = time.perf_counter() - t1

        vulnerable = delayed > baseline + 5.0
        return {
            "type": "HTTP Request Smuggling",
            "url": url, "vector": "TE.CL",
            "vulnerable": vulnerable,
            "severity": "Critical" if vulnerable else "Info",
            "timings": {"baseline_s": round(baseline, 3), "probe_s": round(delayed, 3)},
            "owasp_category": "A07:2021 – Identification and Authentication Failures",
        }
    except Exception as exc:
        return {"type": "HTTP Request Smuggling", "url": task["url"], "error": str(exc), "vulnerable": False}
