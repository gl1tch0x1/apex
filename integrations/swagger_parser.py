"""OpenAPI 2 / 3 discovery and expansion into concrete HTTP tasks metadata."""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

DEFAULT_SPEC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/api-docs",
    "/api/swagger.json",
    "/.well-known/openapi.json",
]


class SwaggerParser:
    def __init__(self, verify_ssl: bool = True):
        self.session: Optional[aiohttp.ClientSession] = None
        self.verify_ssl = verify_ssl

    async def init(self) -> None:
        if self.session is None:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=25))

    async def close(self) -> None:
        if self.session:
            await self.session.close()
            self.session = None

    async def discover_apis(self, base_url: str, extra_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        await self.init()
        if self.session is None:
            raise RuntimeError("SwaggerParser session failed to initialize")
        base = base_url.rstrip("/") + "/"
        paths = list(dict.fromkeys((extra_paths or []) + DEFAULT_SPEC_PATHS))
        apis: List[Dict[str, Any]] = []

        for ep in paths:
            url = urljoin(base, ep.lstrip("/"))
            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    if resp.status != 200:
                        continue
                    ctype = (resp.headers.get("Content-Type") or "").lower()
                    is_yaml_path = ep.endswith((".yaml", ".yml"))
                    is_yaml_ct = "yaml" in ctype

                    if is_yaml_path or is_yaml_ct:
                        if not _YAML_AVAILABLE:
                            logger.debug("PyYAML not installed — skipping YAML spec at %s", url)
                            continue
                        try:
                            raw = await resp.text()
                            spec = _yaml.safe_load(raw)
                            if not isinstance(spec, dict):
                                continue
                        except Exception as exc:
                            logger.debug("YAML parse failed %s: %s", url, exc)
                            continue
                    else:
                        try:
                            spec = await resp.json(content_type=None)
                        except Exception:
                            continue

                    parsed = self._parse_spec(spec, base_url)
                    apis.extend(parsed)
            except Exception as e:
                logger.debug("Spec fetch failed %s: %s", url, e)

        # Dedupe by method+path
        seen = set()
        out: List[Dict[str, Any]] = []
        for item in apis:
            key = (item.get("method"), item.get("path"))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    def _parse_spec(self, spec: Dict[str, Any], base_url: str) -> List[Dict[str, Any]]:
        endpoints: List[Dict[str, Any]] = []
        paths = spec.get("paths") or {}
        servers = spec.get("servers") or []
        base_path = ""
        if spec.get("openapi", "").startswith("3"):
            if servers and isinstance(servers[0], dict):
                base_path = servers[0].get("url") or ""
        host = (spec.get("host") or "").strip()
        schemes = spec.get("schemes") or ["https"]
        if host and not base_path:
            base_path = f"{schemes[0]}://{host}{spec.get('basePath', '')}"

        origin = urlparse(base_url)
        root = f"{origin.scheme}://{origin.netloc}".rstrip("/")

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                m = method.upper()
                if m not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                    continue
                params = details.get("parameters") or []
                query_params: List[str] = []
                header_params: List[str] = []
                body_props: List[str] = []

                for p in params:
                    if not isinstance(p, dict):
                        continue
                    name = p.get("name")
                    pin = p.get("in")
                    if pin == "query" and name:
                        query_params.append(name)
                    elif pin == "header" and name:
                        header_params.append(name)

                req_body = details.get("requestBody")
                if isinstance(req_body, dict):
                    content = req_body.get("content") or {}
                    for _, mt in content.items():
                        if not isinstance(mt, dict):
                            continue
                        schema = mt.get("schema") or {}
                        props = (schema.get("properties") or {}) if isinstance(schema.get("properties"), dict) else {}
                        body_props.extend(props.keys())

                full_path = (base_path.rstrip("/") + "/" + path.lstrip("/")) if base_path.startswith("http") else path
                if not full_path.startswith("http"):
                    url = root + "/" + full_path.lstrip("/")
                else:
                    url = full_path

                endpoints.append(
                    {
                        "url": url,
                        "path": path,
                        "method": m,
                        "params": query_params,
                        "headers": header_params,
                        "body_fields": body_props,
                        "type": "API Endpoint",
                        "operation_id": details.get("operationId"),
                    }
                )

        return endpoints
