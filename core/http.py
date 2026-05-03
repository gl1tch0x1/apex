import asyncio
import json as jsonlib
import logging
from typing import Any, Optional, Tuple

import aiohttp

DEFAULT_TIMEOUT = 30


async def fetch(
    session: aiohttp.ClientSession,
    url: str,
    method: str = "GET",
    *,
    timeout_s: float = DEFAULT_TIMEOUT,
    **kwargs: Any,
) -> Tuple[Optional[str], Optional[aiohttp.ClientResponse]]:
    """HTTP request; TLS follows ClientSession/connector. Body read once (JSON → serialized text)."""
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_s)
        async with session.request(method, url, timeout=timeout, **kwargs) as resp:
            ct = (resp.headers.get("Content-Type") or "").lower()
            if "json" in ct:
                try:
                    payload = await resp.json()
                    text = jsonlib.dumps(payload) if not isinstance(payload, str) else payload
                except Exception:
                    text = await resp.text()
            else:
                text = await resp.text()
            return text, resp
    except Exception as e:
        logging.debug("HTTP error for %s: %s", url, e)
        return None, None


async def fetch_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    *,
    retries: int = 3,
) -> Tuple[Optional[str], Optional[aiohttp.ClientResponse]]:
    for i in range(retries):
        res = await fetch(session, url)
        if res[0] is not None:
            return res
        await asyncio.sleep(2**i)
    return None, None
