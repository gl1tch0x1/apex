"""API rate-limit probe — fires rapid requests and checks for 429 / throttle signals.

API4:2023 – Unrestricted Resource Consumption
"""

import asyncio

from core.http import fetch

# Number of rapid requests to fire
BURST_COUNT = 25
# Minimum 429 / 503 ratio to consider rate-limiting ABSENT (vulnerable)
THRESHOLD_RATIO = 0.10  # if < 10% throttled → no rate limiting


def generate_tasks(url: str, config: dict) -> list:
    burst = int(config.get("rate_limit", {}).get("burst", BURST_COUNT))
    return [
        {
            "url": url,
            "method": "GET",
            "type": "No Rate Limiting",
            "burst_count": burst,
            "executor": test_rate_limit,
        }
    ]


async def test_rate_limit(session, task):
    url = task["url"]
    burst = task.get("burst_count", BURST_COUNT)
    try:
        coros = [fetch(session, url) for _ in range(burst)]
        responses = await asyncio.gather(*coros, return_exceptions=True)

        statuses = []
        for r in responses:
            if isinstance(r, Exception) or r is None:
                continue
            _, resp = r if isinstance(r, tuple) else (None, None)
            if resp is not None:
                statuses.append(resp.status)

        throttled = sum(1 for s in statuses if s in (429, 503))
        total = len(statuses)
        ratio = throttled / total if total else 0

        # Vulnerable = no rate limiting detected
        vulnerable = ratio < THRESHOLD_RATIO and total >= burst // 2

        return {
            "type": "No Rate Limiting",
            "url": url,
            "vulnerable": vulnerable,
            "burst_sent": burst,
            "responses_received": total,
            "throttled_count": throttled,
            "throttle_ratio": round(ratio, 3),
            "note": "No 429/503 observed — endpoint may lack rate limiting" if vulnerable else "Rate limiting detected",
        }
    except Exception as exc:
        return {"type": "No Rate Limiting", "url": url, "error": str(exc), "vulnerable": False}
