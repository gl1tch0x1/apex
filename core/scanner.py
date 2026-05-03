import asyncio
import hashlib
import inspect
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set

import aiohttp

from core.browser_cluster import BrowserCluster

# Per-host throttling: min interval between requests (seconds)
_MIN_INTERVAL_DEFAULT = 0.05


class Scanner:
    def __init__(self, concurrency: int = 10, timeout: int = 30, config: Optional[Dict[str, Any]] = None):
        self.concurrency = concurrency
        self.timeout = timeout
        self.config = config or {}
        self.browser_cluster = BrowserCluster(size=min(concurrency, 4))
        http_cfg = self.config.get("http", {})
        self.verify_ssl = http_cfg.get("verify_ssl", True)
        self.per_host_min_interval = float(http_cfg.get("per_host_min_interval", _MIN_INTERVAL_DEFAULT))
        self._last_request_at: Dict[str, float] = {}

    def _connector(self) -> aiohttp.TCPConnector:
        # ssl=True uses default CA bundle; False disables verification (lab only)
        ssl_arg = self.verify_ssl
        return aiohttp.TCPConnector(limit=self.concurrency, ssl=ssl_arg if isinstance(ssl_arg, bool) else ssl_arg)

    def _request_key(self, task: Dict[str, Any]) -> str:
        """Fingerprint task for deduplication."""
        stable = json.dumps(
            {
                "u": task.get("url"),
                "m": task.get("method", "GET"),
                "p": task.get("params"),
                "d": task.get("data"),
                "t": task.get("type"),
                "browser": task.get("browser"),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(stable.encode()).hexdigest()

    async def collect_tasks(
        self,
        modules: List[Any],
        target: str,
        selected_modules: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        tasks: List[Dict[str, Any]] = []
        for mod in modules:
            module_name = mod.__name__.split(".")[-1]
            if selected_modules and module_name not in selected_modules:
                continue

            generate = getattr(mod, "generate_tasks", None)
            if not generate:
                logging.warning("Module %s has no generate_tasks()", module_name)
                continue

            module_tasks = generate(target, self.config)
            if asyncio.iscoroutine(module_tasks):
                module_tasks = await module_tasks

            for task in module_tasks:
                task["module"] = module_name
                task["executor"] = self._resolve_executor(mod, task)
                tasks.append(task)

        return self._dedupe_tasks(tasks)

    def _dedupe_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []
        for t in tasks:
            k = self._request_key(t)
            if k in seen:
                continue
            seen.add(k)
            out.append(t)
        return out

    def _resolve_executor(self, module: Any, task: Dict[str, Any]):
        if "executor" in task and task["executor"] is not None:
            return task["executor"]

        task_type = task.get("type", "").lower().replace(" ", "_")
        candidate = getattr(module, f"execute_{task_type}", None)
        if candidate:
            return candidate

        normalized = task_type.replace("-", "_") if task_type else ""
        candidate = getattr(module, f"test_{normalized}", None)
        if callable(candidate):
            return candidate

        return getattr(module, f"test_{task_type}", None)

    async def run_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        browser_tasks = [t for t in tasks if t.get("browser")]
        http_tasks = [t for t in tasks if not t.get("browser")]

        results: List[Dict[str, Any]] = []
        if browser_tasks:
            results.extend(await self.browser_cluster.run(browser_tasks))

        if http_tasks:
            results.extend(await self._run_http_tasks(http_tasks))

        return results

    async def _throttle_host(self, url: str) -> None:
        try:
            from urllib.parse import urlparse

            host = urlparse(url).netloc or "default"
        except Exception:
            host = "default"
        now = time.monotonic()
        last = self._last_request_at.get(host, 0.0)
        wait = self.per_host_min_interval - (now - last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request_at[host] = time.monotonic()

    async def _run_http_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        connector = self._connector()
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            semaphore = asyncio.Semaphore(self.concurrency)

            async def worker(task: Dict[str, Any]):
                async with semaphore:
                    url = task.get("url") or task.get("target")
                    if url:
                        await self._throttle_host(url)
                    executor = task.get("executor")
                    if not executor:
                        logging.warning("No executor for task %s", task.get("type"))
                        return {"type": task.get("type"), "url": url, "error": "no executor"}

                    try:
                        if inspect.iscoroutinefunction(executor):
                            return await self._call_coroutine_executor(executor, session, task)
                        res = executor(session, task)
                        if inspect.isawaitable(res):
                            return await res
                        return res
                    except Exception as exc:
                        logging.error("Task execution failed: %s", exc)
                        return {"type": task.get("type"), "url": url, "error": str(exc)}

            raw = await asyncio.gather(*[worker(t) for t in tasks], return_exceptions=True)
            out: List[Dict[str, Any]] = []
            for r in raw:
                if isinstance(r, Exception):
                    out.append({"error": str(r), "vulnerable": False})
                else:
                    out.append(r)
            return out

    async def _call_coroutine_executor(self, executor, session: aiohttp.ClientSession, task: Dict[str, Any]):
        try:
            return await executor(session, task)
        except TypeError:
            return await executor(task)
