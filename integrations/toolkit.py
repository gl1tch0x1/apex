"""
integrations/toolkit.py  (rewritten)
Async tool catalog with real subprocess invocation.
"""
import shutil
from typing import Any, Dict, List, Optional

from integrations.external_tools import (
    run_naabu, run_httpx, run_arjun, run_waybackurls,
    run_uro, run_nuclei, run_katana, run_subfinder,
    get_tool_status, get_available_tools, TOOL_REGISTRY,
)


class ToolCatalog:
    """Live tool catalog backed by integrations.external_tools."""

    def __init__(self):
        self.status = get_tool_status()
        self.available_names = get_available_tools()

    # ── Status / report ──────────────────────────────────────────────────────

    def build_tool_report(self) -> Dict[str, Any]:
        available = {k: v for k, v in self.status.items() if v["available"]}
        missing   = {k: v for k, v in self.status.items() if not v["available"]}
        return {
            "available": available,
            "missing":   missing,
            "count": {"available": len(available), "missing": len(missing)},
        }

    def is_available(self, tool: str) -> bool:
        return bool(shutil.which(tool))

    # ── Async invocation pass-throughs ───────────────────────────────────────

    async def run_naabu(self, target: str, top_ports: int = 1000) -> List[Dict[str, Any]]:
        return await run_naabu(target, top_ports=top_ports)

    async def run_httpx(self, targets: List[str]) -> List[Dict[str, Any]]:
        return await run_httpx(targets)

    async def run_arjun(self, url: str) -> List[str]:
        return await run_arjun(url)

    async def run_waybackurls(self, domain: str) -> List[str]:
        return await run_waybackurls(domain)

    async def run_uro(self, urls: List[str]) -> List[str]:
        return await run_uro(urls)

    async def run_nuclei(self, target: str, templates: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        return await run_nuclei(target, templates=templates)

    async def run_katana(self, url: str, depth: int = 2) -> List[str]:
        return await run_katana(url, depth=depth)

    async def run_subfinder(self, domain: str) -> List[str]:
        return await run_subfinder(domain)
