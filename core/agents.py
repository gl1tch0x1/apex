import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import aiohttp


class BaseAgent(ABC):
    """Base class for all Apex agents."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.start_time = time.time()
        self.tasks_completed = 0

    @abstractmethod
    async def execute(self, payload: Dict[str, Any]) -> Any:
        pass

    async def health_check(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "uptime": time.time() - self.start_time,
            "tasks_completed": self.tasks_completed,
            "memory_usage": "unknown",
        }

    def _validate_payload(self, payload: Dict[str, Any], required_keys: list) -> bool:
        return all(key in payload for key in required_keys)


class ReconAgent(BaseAgent):
    """Reconnaissance: OpenAPI discovery, path enumeration, stack fingerprinting."""

    async def execute(self, payload: Dict[str, Any]) -> Any:
        task_type = payload.get("task_type", "unknown")
        if task_type == "full_reconnaissance":
            return await self._full_reconnaissance(payload)
        if task_type == "swagger_discovery":
            return await self._discover_swagger_apis(payload)
        if task_type == "endpoint_enumeration":
            return await self._enumerate_endpoints(payload)
        if task_type == "technology_detection":
            return await self._detect_technology(payload)
        raise ValueError(f"Unknown reconnaissance task: {task_type}")

    async def _full_reconnaissance(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = payload.get("target")
        if not target:
            raise ValueError("target required")
        api_hunt = payload.get("api_hunt")
        if api_hunt is None:
            api_hunt = self.config.get("api_hunt", True)
        verify = self.config.get("http", {}).get("verify_ssl", True)

        from integrations.toolkit import ToolCatalog
        from integrations.swagger_parser import SwaggerParser
        catalog = ToolCatalog()

        # Gather base endpoints using existing logic
        apis: List[Dict[str, Any]] = []
        parser = SwaggerParser(verify_ssl=verify)
        try:
            extra = self.config.get("swagger", {}).get("endpoints", [])
            apis = await parser.discover_apis(target, extra_paths=list(extra)) if api_hunt else []
        finally:
            await parser.close()

        enum_paths = self.config.get("recon", {}).get(
            "paths",
            [
                "",
                "/api",
                "/api/v1",
                "/v1",
                "/v2",
                "/graphql",
                "/swagger-ui.html",
                "/admin",
                "/login",
                "/register",
                "/health",
                "/status",
                "/docs",
            ],
        )
        base = target.rstrip("/")
        endpoints = []
        for p in enum_paths:
            endpoints.append(base + (p if p.startswith("/") or p == "" else "/" + p))

        for a in apis:
            u = a.get("url")
            if u and u not in endpoints:
                endpoints.append(u)

        if base not in endpoints:
            endpoints.insert(0, base)

        # Run external tools
        self.logger.info("Running external reconnaissance tools...")
        # Port scan
        ports = await catalog.run_naabu(target)
        if ports:
            endpoints.extend([p["url"] for p in ports])
            
        # Discover historical URLs
        from urllib.parse import urlparse
        domain = urlparse(target).netloc.split(":")[0]
        wayback_urls = await catalog.run_waybackurls(domain)
        if wayback_urls:
            # Deduplicate URLs
            deduped = await catalog.run_uro(wayback_urls)
            endpoints.extend(deduped)

        # Subdomain enumeration
        subdomains = await catalog.run_subfinder(domain)
        for sub in subdomains:
            endpoints.append(f"http://{sub}")
            endpoints.append(f"https://{sub}")
            
        # Web crawling
        crawled = await catalog.run_katana(target)
        if crawled:
             endpoints.extend(crawled)

        # Ensure live endpoints and get technologies
        live_targets = await catalog.run_httpx(endpoints)
        live_endpoints = [t["url"] for t in live_targets]
        tech_set = set()
        for t in live_targets:
            tech_set.update(t.get("tech", []))

        # Update endpoints with live ones, keeping original ones as fallback if httpx failed
        if live_endpoints:
            endpoints = live_endpoints

        max_ep = int(self.config.get("recon", {}).get("max_endpoints", 400))
        endpoints = list(dict.fromkeys(endpoints))[:max_ep]

        # Parameter discovery
        self.logger.info("Discovering parameters with Arjun...")
        discovered_params = []
        for ep in endpoints[:10]: # Limit arjun to top 10 endpoints to save time
            params = await catalog.run_arjun(ep)
            discovered_params.extend(params)
            
        discovered_params = list(set(discovered_params))

        # Basic tech detection fallback
        technologies = await self._detect_technology({"target": target, "task_type": "technology_detection"})
        all_techs = list(set(technologies.get("technologies", []) + list(tech_set)))

        self.tasks_completed += 1
        return {
            "endpoints": endpoints,
            "apis": apis,
            "technologies": all_techs,
            "technology_detail": technologies,
            "discovered_params": discovered_params,
            "api_count": len(apis),
            "method": "full_reconnaissance",
        }

    async def _discover_swagger_apis(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from integrations.swagger_parser import SwaggerParser

        target = payload.get("target")
        if not target:
            raise ValueError("Target required for swagger discovery")
        verify = self.config.get("http", {}).get("verify_ssl", True)
        parser = SwaggerParser(verify_ssl=verify)
        try:
            extra = self.config.get("swagger", {}).get("endpoints", [])
            apis = await parser.discover_apis(target, extra_paths=list(extra))
        finally:
            await parser.close()

        self.tasks_completed += 1
        return {"apis": apis, "count": len(apis), "method": "swagger_discovery"}

    async def _enumerate_endpoints(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = payload.get("target")
        paths = self.config.get("recon", {}).get("paths", ["/api", "/v1", "/admin", "/login", "/register"])
        endpoints = [f"{target.rstrip('/')}{p if p.startswith('/') else '/' + p}" for p in paths]
        self.tasks_completed += 1
        return {"endpoints": endpoints, "count": len(endpoints), "method": "common_enumeration"}

    async def _detect_technology(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = payload.get("target")
        verify = self.config.get("http", {}).get("verify_ssl", True)
        technologies: List[str] = []
        confidence = 0.2
        connector = aiohttp.TCPConnector(ssl=verify)
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=20)) as session:
                async with session.get(target, allow_redirects=True) as resp:
                    srv = resp.headers.get("Server", "")
                    xp = resp.headers.get("X-Powered-By", "")
                    if srv:
                        technologies.append(srv.strip())
                    if xp:
                        technologies.append(xp.strip())
                    ct = resp.headers.get("Content-Type", "")
                    if "php" in ct.lower():
                        technologies.append("PHP (Content-Type hint)")
                    for key in ("Set-Cookie", "set-cookie"):
                        sc = resp.headers.get(key)
                        if sc and "httponly" not in sc.lower():
                            technologies.append("Cookie: missing HttpOnly (review SameSite/Secure)")
                            break
                    confidence = 0.75 if technologies else 0.2
        except Exception as e:
            self.logger.debug("Technology probe failed: %s", e)

        self.tasks_completed += 1
        return {
            "technologies": technologies or ["unknown"],
            "confidence": confidence,
            "method": "header_fingerprint",
        }


class ScanAgent(BaseAgent):
    """Runs module pipeline (SQLi, XSS, API, …) across discovered endpoints."""

    async def execute(self, payload: Dict[str, Any]) -> Any:
        task_type = payload.get("task_type", "unknown")
        if task_type == "module_scan":
            return await self._module_scan(payload)
        raise ValueError(f"Unknown scan task: {task_type}")

    async def _module_scan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from core.owasp import enrich_finding
        from core.scanner import Scanner
        from modules import ALL_MODULES, MODULE_BY_NAME

        target = payload.get("target")
        endpoints = payload.get("endpoints") or [target]
        if isinstance(endpoints, str):
            endpoints = [endpoints]
        endpoints = [e for e in endpoints if e]

        selected = payload.get("modules")
        if selected is None:
            selected = self.config.get("modules")
        if not selected:
            selected_modules = None
        else:
            selected_modules = list(selected)

        modules = ALL_MODULES
        if selected_modules:
            modules = []
            for name in selected_modules:
                mod = MODULE_BY_NAME.get(name)
                if mod:
                    modules.append(mod)
                else:
                    self.logger.warning("Unknown module name: %s", name)

        if not modules:
            modules = ALL_MODULES

        scanner = Scanner(
            concurrency=int(self.config.get("concurrency", 10)),
            timeout=int(self.config.get("timeout", 30)),
            config=self.config,
        )

        findings: List[Dict[str, Any]] = []
        raw_results: List[Dict[str, Any]] = []
        vulnerable_count = 0

        for url in endpoints:
            # Module list already filtered above; avoid double-filter in collect_tasks.
            tasks = await scanner.collect_tasks(modules, url, selected_modules=None)
            if not tasks:
                continue
            part = await scanner.run_tasks(tasks)
            for r in part:
                if not isinstance(r, dict):
                    continue
                raw_results.append(r)
                if r.get("vulnerable"):
                    findings.append(enrich_finding(r))
        # Run external scanners
        self.logger.info("Running external scanners (Nuclei, Ghauri)...")
        from integrations.toolkit import ToolCatalog
        catalog = ToolCatalog()

        # Run Nuclei on all endpoints concurrently
        nuclei_tasks = [catalog.run_nuclei(ep) for ep in endpoints[:10]] # limit to top 10 to avoid too many processes
        nuclei_results = await asyncio.gather(*nuclei_tasks, return_exceptions=True)
        for res in nuclei_results:
            if isinstance(res, list):
                for f in res:
                    findings.append(f)
                    vulnerable_count += 1
                    raw_results.append(f)
                    
        # Extract discovered params from previous step (simulate via orchestrator memory if needed, or pass explicitly)
        # For simplicity, we just pass the endpoints to Ghauri
        ghauri_tasks = []
        for ep in endpoints[:5]: # limit
             ghauri_tasks.append(run_ghauri_safe(catalog, ep))
             
        ghauri_results = await asyncio.gather(*ghauri_tasks, return_exceptions=True)
        for res in ghauri_results:
             if isinstance(res, list):
                 for f in res:
                     findings.append(f)
                     vulnerable_count += 1
                     raw_results.append(f)

        self.tasks_completed += 1
        return {
            "findings": findings,
            "raw_count": len(raw_results),
            "vulnerable_count": vulnerable_count,
            "endpoints_scanned": len(endpoints),
            "modules_used": [m.__name__.split(".")[-1] for m in modules],
        }

async def run_ghauri_safe(catalog, ep):
    try:
        from integrations.external_tools import run_ghauri
        return await run_ghauri(ep)
    except Exception:
         return []


class AnalysisAgent(BaseAgent):
    """AI-powered analysis."""

    async def execute(self, payload: Dict[str, Any]) -> Any:
        task_type = payload.get("task_type", "unknown")
        if task_type == "llm_analysis":
            return await self._analyze_findings(payload)
        if task_type == "exploit_chain_detection":
            return await self._detect_exploit_chains(payload)
        raise ValueError(f"Unknown analysis task: {task_type}")

    async def _analyze_findings(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from core.llm_agent import LLMAgent

        findings_in = payload.get("findings", [])
        if findings_in is None:
            findings_in = []
        if not isinstance(findings_in, list):
            findings_in = [findings_in]

        context = payload.get("context", {})
        llm = LLMAgent(model=context.get("llm", {}).get("model", "gpt-4o-mini"))
        analyzed_findings: List[Dict[str, Any]] = []

        for finding in findings_in:
            payload_txt = json.dumps(finding, default=str) if isinstance(finding, dict) else str(finding)
            analysis = await llm.analyze(payload_txt)
            analyzed_findings.append(
                {
                    "finding": finding,
                    "analysis": analysis,
                    "severity": self._calculate_severity(analysis),
                    "confidence": analysis.get("confidence", 0.8) if isinstance(analysis, dict) else 0.8,
                    "type": (finding or {}).get("type", "Unknown") if isinstance(finding, dict) else "Unknown",
                }
            )

        self.tasks_completed += 1
        return {
            "analyzed_findings": analyzed_findings,
            "total_findings": len(findings_in),
            "high_severity": len([f for f in analyzed_findings if f["severity"] == "High"]),
        }

    async def _detect_exploit_chains(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from core.exploit_chain import ExploitChainEngine

        findings_in = payload.get("findings", [])
        if not isinstance(findings_in, list):
            findings_in = []

        engine = ExploitChainEngine()
        for finding in findings_in:
            engine.add(finding)

        chains = engine.correlate()
        self.tasks_completed += 1
        return {
            "exploit_chains": chains,
            "chain_count": len(chains),
            "highest_impact": max([c.get("impact", "Low") for c in chains], default="None"),
        }

    def _calculate_severity(self, analysis: Dict[str, Any]) -> str:
        severity_text = (analysis.get("severity") or "").lower()
        if "critical" in severity_text or "high" in severity_text:
            return "High"
        if "medium" in severity_text:
            return "Medium"
        if "low" in severity_text:
            return "Low"
        return "Info"


class OastAgent(BaseAgent):
    """Out-of-band (Interactsh) polling."""

    async def execute(self, payload: Dict[str, Any]) -> Any:
        task_type = payload.get("task_type", "unknown")
        if task_type == "oast_poll":
            return await self._poll_oast(payload)
        raise ValueError(f"Unknown OAST task: {task_type}")

    async def _poll_oast(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from integrations.interactsh import InteractshClient

        timeout = payload.get("timeout", 30)
        client = InteractshClient(self.config.get("interactsh", {}))
        try:
            interactions = await client.poll()
        finally:
            await client.close()
        self.tasks_completed += 1
        return {"interactions": interactions, "count": len(interactions), "timeout": timeout}


class ReportAgent(BaseAgent):
    """JSON report generation."""

    async def execute(self, payload: Dict[str, Any]) -> Any:
        task_type = payload.get("task_type", "unknown")
        if task_type == "generate_report":
            return await self._generate_report(payload)
        raise ValueError(f"Unknown report task: {task_type}")

    async def _generate_report(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        from integrations.toolkit import ToolCatalog

        from core.report import ReportGenerator

        target = payload.get("target")
        findings = payload.get("findings", [])
        exploit_chains = payload.get("exploit_chains", [])
        config = payload.get("config", {})

        catalog = ToolCatalog()
        tools = catalog.build_tool_report()

        reporter = ReportGenerator(output_dir=config.get("report_dir", "reports"))
        report = reporter.build(
            target=target,
            findings=findings,
            exploit_chains=exploit_chains,
            tools=tools,
            config=config,
        )
        report_path = reporter.save_json(report)

        severity_breakdown: Dict[str, int] = {}
        for item in findings:
            sev = item.get("severity", "Unknown")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        self.tasks_completed += 1
        return {
            "report_path": report_path,
            "summary": {
                "target": target,
                "total_findings": len(findings),
                "exploit_chains": len(exploit_chains),
                "oast_interactions": payload.get("oast_data", {}).get("count", 0),
            },
            "severity_breakdown": severity_breakdown,
            "generated_at": time.time(),
        }


class NoOpAgent(BaseAgent):
    async def execute(self, payload: Dict[str, Any]) -> Any:
        self.tasks_completed += 1
        return {"status": "skipped", "reason": "conditional_not_met"}
