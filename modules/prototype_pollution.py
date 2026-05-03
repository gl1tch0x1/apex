"""
modules/prototype_pollution.py — Prototype Pollution detection
Tests __proto__ and constructor.prototype injection via query params and JSON body.
"""
from core.http import fetch

PROTO_PARAMS = [
    "__proto__[x]",
    "__proto__.x",
    "constructor[prototype][x]",
    "constructor.prototype.x",
    "__proto__[toString]",
    "__proto__[valueOf]",
    "Object.prototype.x",
]

PROTO_VALUE = "apex_pp_test_7f3a"

# JSON body pollution payloads
PROTO_JSON_PAYLOADS = [
    {"__proto__": {"apex_pp": PROTO_VALUE}},
    {"constructor": {"prototype": {"apex_pp": PROTO_VALUE}}},
]


def generate_tasks(url, config):
    tasks = []
    # Query parameter injection
    for param in PROTO_PARAMS:
        tasks.append({
            "url": url,
            "method": "GET",
            "params": {param: PROTO_VALUE},
            "type": "Prototype Pollution",
            "vector": "query",
            "executor": test_proto_pollution,
        })
    # JSON body injection
    for payload in PROTO_JSON_PAYLOADS:
        tasks.append({
            "url": url,
            "method": "POST",
            "json": payload,
            "type": "Prototype Pollution",
            "vector": "json-body",
            "executor": test_proto_json,
        })
    return tasks


async def test_proto_pollution(session, task):
    try:
        text, resp = await fetch(session, task["url"], params=task["params"])
        if not resp:
            return {"type": "Prototype Pollution", "url": task["url"], "vulnerable": False}
        # Heuristic: if our value is reflected or no 400 error
        reflected = text and PROTO_VALUE in text
        return {
            "type": "Prototype Pollution",
            "url": task["url"],
            "params": task["params"],
            "vulnerable": bool(reflected),
            "severity": "Medium" if reflected else "Info",
            "vector": task.get("vector", "query"),
            "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        }
    except Exception as exc:
        return {"type": "Prototype Pollution", "url": task["url"], "error": str(exc), "vulnerable": False}


async def test_proto_json(session, task):
    try:
        import json
        headers = {"Content-Type": "application/json"}
        text, resp = await fetch(
            session, task["url"], method="POST",
            data=json.dumps(task["json"]), headers=headers,
        )
        if not resp:
            return {"type": "Prototype Pollution", "url": task["url"], "vulnerable": False}
        reflected = text and PROTO_VALUE in text
        return {
            "type": "Prototype Pollution",
            "url": task["url"],
            "body": task["json"],
            "vulnerable": bool(reflected),
            "severity": "Medium" if reflected else "Info",
            "vector": "json-body",
            "owasp_category": "A08:2021 – Software and Data Integrity Failures",
        }
    except Exception as exc:
        return {"type": "Prototype Pollution", "url": task["url"], "error": str(exc), "vulnerable": False}
