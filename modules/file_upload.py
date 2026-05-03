"""Probe common upload endpoints for reachable upload UI without auth hints."""

from core.http import fetch

UPLOAD_PATHS = (
    "/upload",
    "/api/upload",
    "/file/upload",
    "/files",
    "/attachments/upload",
)


def generate_tasks(url: str, config: dict) -> list:
    base = url.rstrip("/")
    tasks = []
    for path in UPLOAD_PATHS:
        tasks.append(
            {
                "url": base + path,
                "method": "GET",
                "type": "File Upload",
                "executor": test_upload_surface,
            }
        )
    return tasks


async def test_upload_surface(session, task):
    try:
        text, resp = await fetch(session, task["url"])
        if not resp or resp.status != 200 or not text:
            return {"type": "File Upload", "url": task["url"], "vulnerable": False}
        low = text.lower()
        has_input_file = 'type="file"' in low or "type='file'" in low
        has_multipart = "multipart" in low or "enctype" in low
        return {
            "type": "File Upload",
            "url": task["url"],
            "vulnerable": has_input_file or has_multipart,
            "confidence": "medium" if has_input_file else "low",
            "note": "Upload interface surfaced; requires manual abuse/misconfiguration testing",
            "response": text[:600],
        }
    except Exception as exc:
        return {"type": "File Upload", "url": task["url"], "error": str(exc), "vulnerable": False}
