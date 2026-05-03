"""
integrations/external_tools.py
Async wrappers for all external security tools used by Apex.
Each wrapper:
  - Checks if the tool is available via shutil.which()
  - Runs the tool as an async subprocess
  - Parses stdout into structured Python objects
  - Returns empty list/dict gracefully if tool not found
"""

import asyncio
import json
import logging
import shutil
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# ── Internal helper ─────────────────────────────────────────────────────────

async def _run(cmd: List[str], timeout: int = 120) -> str:
    """Run a subprocess asynchronously and return stdout as a string."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            log.warning("Tool timed out: %s", cmd[0])
            return ""
        if stderr:
            log.debug("[%s] stderr: %s", cmd[0], stderr.decode(errors="replace")[:300])
        return stdout.decode(errors="replace")
    except FileNotFoundError:
        log.debug("Tool not found: %s", cmd[0])
        return ""
    except Exception as exc:
        log.error("Tool execution error (%s): %s", cmd[0], exc)
        return ""


def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return url


# ── Naabu — port scanner ────────────────────────────────────────────────────

async def run_naabu(target: str, top_ports: int = 1000, timeout: int = 120) -> List[Dict[str, Any]]:
    """
    Run Naabu port scan.
    Returns: [{"host": str, "port": int, "url": str}]
    """
    if not _available("naabu"):
        log.debug("naabu not installed — skipping port scan")
        return []

    host = _domain(target)
    out = await _run(["naabu", "-host", host, "-top-ports", str(top_ports), "-silent", "-json"], timeout=timeout)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            port = data.get("port", 0)
            host_val = data.get("host", host)
            scheme = "https" if port in (443, 8443) else "http"
            results.append({"host": host_val, "port": port, "url": f"{scheme}://{host_val}:{port}"})
        except json.JSONDecodeError:
            # plain host:port output
            m = re.match(r"^(.+):(\d+)$", line)
            if m:
                h, p = m.group(1), int(m.group(2))
                scheme = "https" if p in (443, 8443) else "http"
                results.append({"host": h, "port": p, "url": f"{scheme}://{h}:{p}"})
    log.info("naabu found %d open ports for %s", len(results), host)
    return results


# ── Httpx — HTTP probing ─────────────────────────────────────────────────────

async def run_httpx(targets: List[str], timeout: int = 90) -> List[Dict[str, Any]]:
    """
    Run Httpx to probe a list of URLs/hosts.
    Returns: [{"url": str, "status": int, "title": str, "tech": list, "ip": str}]
    """
    if not _available("httpx") or not targets:
        return []

    input_data = "\n".join(targets)
    cmd = [
        "httpx", "-silent", "-json",
        "-status-code", "-title", "-tech-detect", "-ip",
        "-no-color",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data.encode()), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return []
        out = stdout.decode(errors="replace")
    except Exception as exc:
        log.error("httpx error: %s", exc)
        return []

    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append({
                "url": data.get("url", ""),
                "status": data.get("status-code", 0),
                "title": data.get("title", ""),
                "tech": data.get("tech", []),
                "ip": data.get("host", ""),
                "content_length": data.get("content-length", 0),
            })
        except json.JSONDecodeError:
            if line.startswith("http"):
                results.append({"url": line, "status": 0, "title": "", "tech": [], "ip": ""})
    log.info("httpx probed %d targets, %d live", len(targets), len(results))
    return results


# ── Subfinder — subdomain discovery ─────────────────────────────────────────

async def run_subfinder(domain: str, timeout: int = 120) -> List[str]:
    """
    Run Subfinder to enumerate subdomains.
    Returns: list of subdomain strings
    """
    if not _available("subfinder"):
        return []

    out = await _run(["subfinder", "-d", _domain(domain), "-silent"], timeout=timeout)
    subs = [line.strip() for line in out.splitlines() if line.strip()]
    log.info("subfinder found %d subdomains for %s", len(subs), domain)
    return subs


# ── Waybackurls — historical URL discovery ──────────────────────────────────

async def run_waybackurls(domain: str, timeout: int = 120) -> List[str]:
    """
    Run waybackurls to get historical URLs from the Wayback Machine.
    Returns: list of URL strings
    """
    if not _available("waybackurls"):
        return []

    out = await _run(["waybackurls", _domain(domain)], timeout=timeout)
    urls = [line.strip() for line in out.splitlines() if line.strip().startswith("http")]
    log.info("waybackurls found %d historical URLs for %s", len(urls), domain)
    return urls


# ── URO — URL deduplication ─────────────────────────────────────────────────

async def run_uro(urls: List[str], timeout: int = 60) -> List[str]:
    """
    Run URO to deduplicate and filter URL list.
    Returns: deduplicated list of URL strings
    """
    if not _available("uro") or not urls:
        return urls  # passthrough if not available

    input_data = "\n".join(urls)
    try:
        proc = await asyncio.create_subprocess_exec(
            "uro",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data.encode()), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return urls
        out = stdout.decode(errors="replace")
        deduped = [line.strip() for line in out.splitlines() if line.strip().startswith("http")]
        log.info("uro deduplicated %d → %d URLs", len(urls), len(deduped))
        return deduped if deduped else urls
    except Exception as exc:
        log.error("uro error: %s", exc)
        return urls


# ── Arjun — parameter discovery ─────────────────────────────────────────────

async def run_arjun(url: str, timeout: int = 120) -> List[str]:
    """
    Run Arjun to discover hidden parameters for a URL.
    Returns: list of discovered parameter names
    """
    if not _available("arjun"):
        return []

    out = await _run([
        "arjun", "-u", url, "--stable", "-oJ", "-",
        "-t", "5",  # threads
        "-d", "0",  # delay
    ], timeout=timeout)

    # Arjun JSON output: {"url": ..., "params": [...]}
    params = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if isinstance(data, dict):
                found = data.get("params", [])
                params.extend(found)
            elif isinstance(data, list):
                params.extend(data)
        except json.JSONDecodeError:
            # try regex fallback for plain text output
            m = re.findall(r"\[Found\] (\w+)", line)
            params.extend(m)

    log.info("arjun found %d params for %s", len(params), url)
    return list(set(params))


# ── Katana — web crawler ─────────────────────────────────────────────────────

async def run_katana(url: str, depth: int = 2, timeout: int = 120) -> List[str]:
    """
    Run Katana to crawl a web application.
    Returns: list of discovered URLs
    """
    if not _available("katana"):
        return []

    out = await _run([
        "katana", "-u", url, "-d", str(depth), "-silent",
        "-jc",          # JavaScript crawling
        "-kf", "all",   # Known files
        "-fx",          # Form extraction
        "-rl", "25",    # Rate limit
        "-ef", "woff,css,png,svg,jpg,gif,jpeg,ico,svg",  # Skip assets
    ], timeout=timeout)

    urls = [line.strip() for line in out.splitlines() if line.strip().startswith("http")]
    log.info("katana crawled %d URLs from %s", len(urls), url)
    return urls


# ── Ffuf — directory + parameter fuzzing ─────────────────────────────────────

async def run_ffuf_dirs(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 120) -> List[str]:
    """
    Run Ffuf for directory discovery.
    Returns: list of discovered directory URLs
    """
    if not _available("ffuf"):
        return []
    if not __import__("os").path.exists(wordlist):
        # Try alternate wordlists
        for alt in ["/usr/share/dirb/wordlists/common.txt", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"]:
            if __import__("os").path.exists(alt):
                wordlist = alt
                break
        else:
            return []

    out = await _run([
        "ffuf", "-u", url.rstrip("/") + "/FUZZ",
        "-w", wordlist, "-mc", "200,201,204,301,302,307,401,403",
        "-o", "-", "-of", "json", "-s",
    ], timeout=timeout)

    urls = []
    try:
        data = json.loads(out)
        for result in data.get("results", []):
            urls.append(result.get("url", ""))
    except json.JSONDecodeError:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.append(line)
    log.info("ffuf found %d directories under %s", len(urls), url)
    return [u for u in urls if u]


# ── Nuclei — CVE/template scanning ──────────────────────────────────────────

async def run_nuclei(
    target: str,
    templates: Optional[List[str]] = None,
    severity: str = "low,medium,high,critical",
    timeout: int = 300,
) -> List[Dict[str, Any]]:
    """
    Run Nuclei with specified templates.
    Returns: list of finding dicts with type, url, severity, name, description
    """
    if not _available("nuclei"):
        return []

    cmd = [
        "nuclei", "-u", target, "-silent", "-json",
        "-severity", severity,
        "-rl", "25",       # rate limit
        "-timeout", "10",  # per-request timeout
        "-no-color",
    ]

    if templates:
        for tmpl in templates:
            cmd += ["-t", tmpl]
    else:
        # Use default community templates
        cmd += ["-t", "cves", "-t", "vulnerabilities", "-t", "misconfiguration",
                "-t", "exposures", "-t", "technologies"]

    out = await _run(cmd, timeout=timeout)
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append({
                "type": data.get("info", {}).get("name", "Nuclei Finding"),
                "url": data.get("matched-at", target),
                "severity": data.get("info", {}).get("severity", "info").title(),
                "template_id": data.get("template-id", ""),
                "description": data.get("info", {}).get("description", ""),
                "vulnerable": True,
                "source": "nuclei",
                "owasp_category": _nuclei_owasp(data.get("info", {}).get("classification", {})),
            })
        except json.JSONDecodeError:
            continue
    log.info("nuclei found %d issues for %s", len(findings), target)
    return findings


def _nuclei_owasp(classification: Dict) -> str:
    owasps = classification.get("owasp-id", [])
    if owasps:
        return ", ".join(owasps)
    cwe = classification.get("cwe-id", [])
    if cwe:
        return ", ".join(cwe)
    return "—"


# ── Ghauri — advanced SQL injection ─────────────────────────────────────────

async def run_ghauri(url: str, params: Optional[List[str]] = None, timeout: int = 180) -> List[Dict[str, Any]]:
    """
    Run Ghauri advanced SQL injection tester.
    Returns: list of SQLi finding dicts
    """
    if not _available("ghauri"):
        log.debug("ghauri not installed — skipping advanced SQLi")
        return []

    cmd = ["ghauri", "-u", url, "--batch", "--level", "2", "--dbs"]
    if params:
        cmd += ["-p", ",".join(params)]

    out = await _run(cmd, timeout=timeout)
    findings = []
    if "is vulnerable" in out.lower() or "sql injection" in out.lower():
        param_match = re.search(r"Parameter '(\w+)'", out)
        param_name = param_match.group(1) if param_match else "unknown"
        dbtype_match = re.search(r"back-end DBMS: (.+)", out)
        dbtype = dbtype_match.group(1).strip() if dbtype_match else "unknown"
        findings.append({
            "type": "SQL Injection",
            "url": url,
            "vulnerable": True,
            "severity": "Critical",
            "source": "ghauri",
            "vector": "ghauri-detected",
            "parameter": param_name,
            "dbms": dbtype,
            "evidence": out[:500],
            "owasp_category": "A03:2021 – Injection",
        })
    log.info("ghauri found %d SQLi for %s", len(findings), url)
    return findings


# ── Sqlmap — classic SQL injection ──────────────────────────────────────────

async def run_sqlmap(url: str, params: Optional[List[str]] = None, timeout: int = 180) -> List[Dict[str, Any]]:
    """
    Run sqlmap SQL injection tester.
    Returns: list of SQLi finding dicts
    """
    if not _available("sqlmap"):
        return []

    cmd = [
        "sqlmap", "-u", url, "--batch", "--level=2", "--risk=2",
        "--output-dir=/tmp/sqlmap_apex", "--format=JSON",
        "--no-logging", "-q",
    ]
    if params:
        cmd += ["-p", ",".join(params)]

    out = await _run(cmd, timeout=timeout)
    findings = []
    if "is vulnerable" in out.lower() or "sqlmap identified" in out.lower():
        param_match = re.search(r"Parameter: (\S+) \(", out)
        param_name = param_match.group(1) if param_match else "unknown"
        technique_match = re.search(r"Type: (.+)", out)
        technique = technique_match.group(1).strip() if technique_match else "unknown"
        findings.append({
            "type": "SQL Injection",
            "url": url,
            "vulnerable": True,
            "severity": "Critical",
            "source": "sqlmap",
            "vector": technique,
            "parameter": param_name,
            "evidence": out[:500],
            "owasp_category": "A03:2021 – Injection",
        })
    log.info("sqlmap found %d SQLi for %s", len(findings), url)
    return findings


# ── Anew — URL deduplication (alternative to uro) ───────────────────────────

async def run_anew(urls: List[str], timeout: int = 30) -> List[str]:
    """Run anew to deduplicate a URL list (alternative to uro)."""
    if not _available("anew") or not urls:
        return list(set(urls))
    input_data = "\n".join(urls)
    try:
        proc = await asyncio.create_subprocess_exec(
            "anew",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(input=input_data.encode()), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return list(set(urls))
        return [l.strip() for l in stdout.decode().splitlines() if l.strip()]
    except Exception:
        return list(set(urls))


# ── Tool availability report ─────────────────────────────────────────────────

TOOL_REGISTRY = {
    # (binary_name, install_hint, category)
    "naabu":        ("Port scanner",              "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "httpx":        ("HTTP prober",               "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "subfinder":    ("Subdomain enum",            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "nuclei":       ("CVE/template scanner",      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "katana":       ("Web crawler",               "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    "waybackurls":  ("Historical URLs",           "go install -v github.com/tomnomnom/waybackurls@latest"),
    "uro":          ("URL deduplicator",          "pip install uro"),
    "arjun":        ("Parameter discovery",       "pip install arjun"),
    "anew":         ("URL dedup (alt)",           "go install -v github.com/tomnomnom/anew@latest"),
    "ffuf":         ("Directory fuzzer",          "go install -v github.com/ffuf/ffuf/v2@latest"),
    "ghauri":       ("Advanced SQLi",             "pip install ghauri"),
    "sqlmap":       ("Classic SQLi",              "pip install sqlmap"),
}


def get_tool_status() -> Dict[str, Dict[str, Any]]:
    """Return availability status of all registered tools."""
    status = {}
    for name, (description, install) in TOOL_REGISTRY.items():
        status[name] = {
            "available": _available(name),
            "description": description,
            "install": install,
        }
    return status


def get_available_tools() -> List[str]:
    """Return list of names of tools that are installed."""
    return [name for name in TOOL_REGISTRY if _available(name)]
