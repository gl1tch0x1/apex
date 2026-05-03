"""Heuristic CSRF signal: HTML forms with POST and no obvious anti-CSRF token."""

from core.http import fetch


def generate_tasks(url: str, config: dict) -> list:
    return [
        {
            "url": url,
            "method": "GET",
            "type": "CSRF",
            "executor": test_csrf_forms,
        }
    ]


async def test_csrf_forms(session, task):
    try:
        text, resp = await fetch(session, task["url"])
        if not resp or not text:
            return {"type": "CSRF", "url": task["url"], "vulnerable": False}
        low = text.lower()
        if "<form" not in low:
            return {"type": "CSRF", "url": task["url"], "vulnerable": False, "note": "no forms"}
        post_form = 'method="post"' in low or "method='post'" in low
        if not post_form:
            return {"type": "CSRF", "url": task["url"], "vulnerable": False, "note": "no post forms"}
        token_markers = ("csrf", "_token", "authenticity_token", "__requestverificationtoken", "csrfmiddlewaretoken")
        has_token = any(m in low for m in token_markers)
        return {
            "type": "CSRF",
            "url": task["url"],
            "vulnerable": not has_token,
            "confidence": "low" if not has_token else "none",
            "note": "POST form without obvious CSRF token pattern (manual confirmation required)",
        }
    except Exception as exc:
        return {"type": "CSRF", "url": task["url"], "error": str(exc), "vulnerable": False}
