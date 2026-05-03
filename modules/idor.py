from core.http import fetch


def generate_tasks(url, config):
    tasks = []
    base = url.rstrip("/")
    max_id = int(config.get("idor_max_id", 20) or 20)
    
    # Test path-based IDOR
    for user_id in range(1, max(2, max_id) + 1):
        tasks.append({
            "url": f"{base}/user/{user_id}",
            "method": "GET",
            "type": "IDOR",
            "user_id": user_id,
            "vector": "path",
            "executor": test_idor,
        })
        
    # Test UUIDs in path
    uuids = [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
    ]
    for uid in uuids:
        tasks.append({
            "url": f"{base}/user/{uid}",
            "method": "GET",
            "type": "IDOR",
            "user_id": uid,
            "vector": "path-uuid",
            "executor": test_idor,
        })
        
    # Test parameter-based IDOR
    discovered = config.get("discovered_params", [])
    id_params = [p for p in discovered if "id" in p.lower() or "user" in p.lower() or "account" in p.lower()]
    
    for param in id_params:
        for user_id in range(1, 5):
            tasks.append({
                "url": url,
                "method": "GET",
                "params": {param: str(user_id)},
                "type": "IDOR",
                "user_id": user_id,
                "vector": "param",
                "executor": test_idor,
            })
            
    return tasks


async def test_idor(session, task):
    try:
        text, resp = await fetch(session, task["url"])
        if not resp or resp.status != 200 or not text:
            return {"type": "IDOR", "url": task["url"], "vulnerable": False}
        body = text.lower()
        # Require stronger signals than generic "user" word matches
        pii_hits = sum(
            1
            for needle in (
                "@",
                "email",
                "phone",
                "ssn",
                "address",
                "credit",
                "account",
            )
            if needle in body
        )
        role_hits = any(k in body for k in ("administrator", "role", "permission", "billing"))
        vulnerable = pii_hits >= 2 or (pii_hits >= 1 and role_hits)
        return {
            "type": "IDOR",
            "url": task["url"],
            "vulnerable": vulnerable,
            "user_id": task["user_id"],
            "confidence": "medium" if vulnerable else "none",
            "response": text[:1200],
        }
    except Exception as exc:
        return {"type": "IDOR", "url": task["url"], "error": str(exc), "vulnerable": False}
