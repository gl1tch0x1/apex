import asyncio
import argparse
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import sys

# Force UTF-8 output on Windows to avoid cp1252 crashes
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    import os
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from core.orchestrator import Orchestrator, AgentContract, CommunicationMode
from core.agents import (
    ReconAgent,
    ScanAgent,
    AnalysisAgent,
    OastAgent,
    ReportAgent,
    NoOpAgent,
)
from core.utils import setup_logger, load_config

# ── Hacker theme ────────────────────────────────────────────────────────────
THEME = Theme({
    "apex":      "bold bright_green",
    "dim_green": "dim green",
    "warn":      "bold yellow",
    "crit":      "bold bright_red",
    "info":      "bold cyan",
    "muted":     "dim white",
    "hi":        "bold white",
    "vuln":      "bold red",
    "safe":      "bold green",
    "med":       "bold yellow",
})

console = Console(theme=THEME, highlight=False)

SEV_COLOR = {
    "High":     "[bold bright_red]",
    "Critical": "[bold bright_red]",
    "Medium":   "[bold yellow]",
    "Low":      "[bold cyan]",
    "Info":     "[dim white]",
    "Unknown":  "[dim white]",
}


# ── Helpers ──────────────────────────────────────────────────────────────────
def _extract_nested(results: dict, key: str):
    if not isinstance(results, dict):
        return None
    if key in results:
        return results[key]
    for v in results.values():
        if isinstance(v, dict):
            hit = _extract_nested(v, key)
            if hit is not None:
                return hit
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    hit = _extract_nested(item, key)
                    if hit is not None:
                        return hit
    return None


def _validate_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        console.print(
            f"[crit]✗ Invalid target:[/crit] [hi]{target}[/hi]\n"
            f"  [muted]Target must start with [bold]http://[/bold] or [bold]https://[/bold][/muted]"
        )
        raise SystemExit(1)
    if not parsed.netloc:
        console.print("[crit]✗ Invalid target URL — no host detected.[/crit]")
        raise SystemExit(1)
    return target


def _status_dot(ok: bool) -> str:
    return "[safe]●[/safe]" if ok else "[crit]●[/crit]"


def _print_boot(target: str, workflow: str, modules_filter: list):
    console.print()
    console.print(Rule("[dim_green]// APEX MULTI-AGENT SCANNER // ONLINE[/dim_green]", style="dim green"))

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim green", no_wrap=True)
    meta.add_column(style="bold white")
    meta.add_row("  TARGET", target)
    meta.add_row("  WORKFLOW", Path(workflow).name)
    meta.add_row("  MODULES", ", ".join(modules_filter) if modules_filter else "ALL")
    meta.add_row("  TIME", time.strftime("%Y-%m-%dT%H:%M:%S"))
    console.print(meta)
    console.print(Rule(style="dim green"))
    console.print()


def _print_findings_table(findings: list):
    if not findings:
        console.print("  [safe]✓ No confirmed vulnerabilities detected.[/safe]\n")
        return

    tbl = Table(
        box=box.SIMPLE_HEAD,
        border_style="dim green",
        header_style="bold green",
        show_edge=False,
        pad_edge=True,
        expand=False,
    )
    tbl.add_column("#",   style="dim white",  width=4,  no_wrap=True)
    tbl.add_column("SEVERITY", width=10, no_wrap=True)
    tbl.add_column("TYPE",     width=26, no_wrap=True)
    tbl.add_column("URL",      style="dim white", no_wrap=False)
    tbl.add_column("OWASP",    width=32, no_wrap=True)

    for i, f in enumerate(findings, 1):
        finding_data = f.get("finding", f) if "finding" in f else f
        sev   = finding_data.get("severity", f.get("severity", "Unknown"))
        ftype = finding_data.get("type", f.get("type", "Unknown"))
        url   = finding_data.get("url",  f.get("url", "—"))
        owasp = finding_data.get("owasp_category", f.get("owasp_category", "—"))

        color = SEV_COLOR.get(sev, "[dim white]")
        tbl.add_row(
            str(i),
            f"{color}{sev}[/]",
            f"[bold white]{ftype}[/bold white]",
            url,
            f"[dim]{owasp}[/dim]",
        )

    console.print(tbl)


def _print_exploit_chains(chains: list):
    if not chains:
        return
    console.print(Rule("[warn]  EXPLOIT CHAINS DETECTED  [/warn]", style="yellow"))
    for c in chains:
        impact = c.get("impact", "Unknown")
        chain  = c.get("chain", "Unknown")
        color  = "[bold bright_red]" if impact in ("Critical", "High") else "[bold yellow]"
        console.print(f"  {color}⛓  {chain}[/]  [muted]→ impact: {impact}[/muted]")
    console.print()


def _print_agent_perf(status: dict):
    tbl = Table(box=box.SIMPLE_HEAD, border_style="dim green",
                header_style="bold green", show_edge=False, expand=False)
    tbl.add_column("AGENT",          style="bold white", no_wrap=True)
    tbl.add_column("TASKS",          justify="right",    width=7)
    tbl.add_column("AVG TIME",       justify="right",    width=10)
    tbl.add_column("ERR RATE",       justify="right",    width=10)
    tbl.add_column("STATE",          width=10)

    for name, data in status.get("agents", {}).items():
        perf  = data["performance"]
        state = data["state"]
        state_txt = f"[safe]{state}[/safe]" if state == "idle" else f"[warn]{state}[/warn]"
        tbl.add_row(
            name,
            str(perf["tasks_completed"]),
            f"{perf['avg_time']:.2f}s",
            f"{perf['error_rate']:.1%}",
            state_txt,
        )
    console.print(tbl)


# ── Main ─────────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(
        description="Apex — Multi-Agent Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target",          help="Target URL or API base (http:// or https://)")
    parser.add_argument("--config",        default="config.yaml",                      help="Configuration file")
    parser.add_argument("--workflow",      default="workflows/security_scan_v2.yaml",  help="Workflow YAML")
    parser.add_argument("--modules",       nargs="+",                                  help="Restrict to specific module names")
    parser.add_argument("--api-hunt",      action="store_true",                        help="Force-enable OpenAPI/Swagger discovery")
    parser.add_argument("--no-api-hunt",   action="store_true",                        help="Disable API discovery")
    parser.add_argument("--insecure-tls",  action="store_true",                        help="Disable TLS verification (lab only)")
    parser.add_argument("--caveman",       action="store_true",                        help="Caveman communication mode")
    parser.add_argument("--verbose",       action="store_true",                        help="Verbose logging")
    parser.add_argument("--all-modules",   action="store_true",                        help="Run all available modules")
    parser.add_argument("--autopilot",     action="store_true",                        help="Enable full autonomous AI+tools mode")
    parser.add_argument("--tools",         help="Comma-separated list of external tools to run")
    parser.add_argument("--all-tools",     action="store_true",                        help="Enable all external tools")
    parser.add_argument("--list-modules",  action="store_true",                        help="Print module list and exit")
    parser.add_argument("--depth",         type=int, default=2,                        help="Crawl depth for Katana (default: 2)")
    parser.add_argument("--rate-limit",    type=int, default=20,                       help="Rate limit (default: 20)")
    args = parser.parse_args()

    # Validate target URL before anything else
    _validate_target(args.target)

    config = load_config(args.config)
    if args.verbose:
        config["log_level"] = "DEBUG"
        config.setdefault("logging", {})["level"] = "DEBUG"
    if args.insecure_tls:
        config.setdefault("http", {})["verify_ssl"] = False
    if args.api_hunt:
        config["api_hunt"] = True
    if args.no_api_hunt:
        config["api_hunt"] = False

    setup_logger(config)
    logging.info("Starting Apex Multi-Agent Security Scanner")

    _print_boot(args.target, args.workflow, args.modules or [])

    # ── Wire OAST (Interactsh) URL into config for OOB-capable modules ────
    oast_url = None
    if config.get("interactsh", {}).get("enabled", False):
        try:
            from integrations.interactsh import InteractshClient
            _client = InteractshClient(config.get("interactsh", {}))
            oast_url = await _client.get_oast_url()
            await _client.close()
            if oast_url:
                config["_oast_url"] = oast_url
                console.print(f"  [info]◈ OAST[/info]  [dim_green]{oast_url}[/dim_green]")
                console.print()
        except Exception as exc:
            logging.debug("Interactsh unavailable: %s", exc)

    # ── Build orchestrator ────────────────────────────────────────────────
    orchestrator = Orchestrator(config)
    if args.caveman:
        orchestrator.set_communication_mode(CommunicationMode.CAVEMAN)

    _agents = [
        ("recon_agent",    ReconAgent,    AgentContract("recon_agent",    ["full_reconnaissance","swagger_discovery","endpoint_enumeration","technology_detection"], {"target":"string"}, {"endpoints":"array","technologies":"array"}, 100)),
        ("scan_agent",     ScanAgent,     AgentContract("scan_agent",     ["module_scan"],                  {"target":"string","endpoints":"array"}, {"findings":"array"},              500)),
        ("analysis_agent", AnalysisAgent, AgentContract("analysis_agent", ["llm_analysis","exploit_chain_detection"], {"findings":"array"}, {"analyzed_findings":"array","exploit_chains":"array"}, 300)),
        ("oast_agent",     OastAgent,     AgentContract("oast_agent",     ["oast_poll"],                   {"timeout":"number"},                   {"interactions":"array"},            50)),
        ("report_agent",   ReportAgent,   AgentContract("report_agent",   ["generate_report"],             {"target":"string","findings":"array","exploit_chains":"array"}, {"report_path":"string","summary":"object"}, 100)),
        ("noop_agent",     NoOpAgent,     AgentContract("noop_agent",     ["no_op"],                       {},                                      {"status":"string"},                  1)),
    ]
    for name, cls, contract in _agents:
        orchestrator.register_agent(name, cls, contract)

    await orchestrator.initialize_agents()

    # ── Execute workflow or Autopilot ────────────────────────────────────
    start_ts = time.time()
    results = None

    if args.list_modules:
        from modules import ALL_MODULES
        console.print("[hi]Available Modules:[/hi]")
        for m in ALL_MODULES:
            console.print(f"  - [safe]{m.__name__.split('.')[-1]}[/safe]")
        return
        
    if args.autopilot:
        console.print("\n[warn]🚀 AUTOPILOT MODE ACTIVATED[/warn]")
        console.print("[dim white]AI and external tools will autonomously hunt for vulnerabilities.[/dim white]\n")
        
        from core.autopilot import Autopilot
        autopilot = Autopilot(orchestrator, config)
        
        with Progress(
            SpinnerColumn(spinner_name="dots2", style="bold green"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=32, style="dim green", complete_style="bold green"),
            TaskProgressColumn(style="dim white"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Autopilot hunting...", total=None)
            try:
                results = await autopilot.run(args.target, selected_modules=args.modules)
                progress.update(task_id, description="[bold green]Autopilot complete", total=1, completed=1)
            except Exception as exc:
                logging.exception("Autopilot execution failed")
                console.print(f"\n[crit]✗ Autopilot failed:[/crit] {exc}\n")
                return

    else:
        workflow_path = Path(args.workflow)
        if not workflow_path.exists():
            console.print(f"[crit]✗ Workflow not found:[/crit] {args.workflow}")
            return

        with open(workflow_path, encoding="utf-8") as f:
            workflow_spec = yaml.safe_load(f)

        # Handle --all-modules logic
        modules_to_run = args.modules or []
        if getattr(args, 'all_modules', False):
            from modules import ALL_MODULES
            modules_to_run = [m.__name__.split('.')[-1] for m in ALL_MODULES]

        workflow_spec["inputs"] = {
            "target":  args.target,
            "modules": modules_to_run,
            "config":  config,
        }

        # ── Execute with live status display ─────────────────────────────────
        with Progress(
            SpinnerColumn(spinner_name="dots2", style="bold green"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=32, style="dim green", complete_style="bold green"),
            TaskProgressColumn(style="dim white"),
            console=console,
            transient=True,
        ) as progress:
            task_id = progress.add_task("Running agents...", total=None)
            try:
                results = await orchestrator.execute_workflow(workflow_spec)
                progress.update(task_id, description="[bold green]Scan complete", total=1, completed=1)
            except Exception as exc:
                logging.exception("Workflow execution failed")
                console.print(f"\n[crit]✗ Scan failed:[/crit] {exc}\n")
                return

    elapsed = time.time() - start_ts

    # ── Results ───────────────────────────────────────────────────────────
    console.print(Rule("[dim_green]// RESULTS[/dim_green]", style="dim green"))
    console.print()

    report_path      = _extract_nested(results, "report_path")
    summary          = _extract_nested(results, "summary")
    severity_breakdown = _extract_nested(results, "severity_breakdown")
    findings         = _extract_nested(results, "analyzed_findings") or _extract_nested(results, "findings") or []
    chains           = _extract_nested(results, "exploit_chains") or []
    scan_block       = results.get("vulnerability_scanning") if isinstance(results, dict) else {}

    # Summary row
    total_f  = summary.get("total_findings", 0) if summary else len(findings)
    vuln_cnt = scan_block.get("vulnerable_count", 0) if isinstance(scan_block, dict) else 0
    raw_cnt  = scan_block.get("raw_count", 0) if isinstance(scan_block, dict) else 0

    summary_grid = Table.grid(padding=(0, 4))
    summary_grid.add_column(style="dim green")
    summary_grid.add_column(style="bold white")
    summary_grid.add_row("  TOTAL FINDINGS",    str(total_f))
    summary_grid.add_row("  CHECKS EXECUTED",   f"{vuln_cnt} vuln / {raw_cnt} total")
    summary_grid.add_row("  EXPLOIT CHAINS",    str(len(chains)))
    if oast_url:
        oast_hits = summary.get("oast_interactions", 0) if summary else 0
        summary_grid.add_row("  OAST INTERACTIONS", str(oast_hits))
    summary_grid.add_row("  ELAPSED",           f"{elapsed:.1f}s")
    if report_path:
        summary_grid.add_row("  REPORT",         report_path)
    console.print(summary_grid)
    console.print()

    # Severity breakdown
    if severity_breakdown:
        sev_grid = Table.grid(padding=(0, 3))
        sev_grid.add_column(style="dim green", width=14)
        sev_grid.add_column(style="bold white")
        for sev, cnt in severity_breakdown.items():
            color = SEV_COLOR.get(sev, "[dim white]")
            sev_grid.add_row(f"  {color}{sev}[/]", str(cnt))
        console.print(sev_grid)
        console.print()

    # Findings table
    console.print(Rule("[dim_green]// VULNERABILITY FINDINGS[/dim_green]", style="dim green"))
    console.print()
    _print_findings_table(findings)

    # Exploit chains
    if chains:
        console.print()
        _print_exploit_chains(chains)

    # Agent performance
    console.print(Rule("[dim_green]// AGENT TELEMETRY[/dim_green]", style="dim green"))
    console.print()
    _print_agent_perf(orchestrator.get_status())
    console.print()
    console.print(Rule(style="dim green"))
    console.print()

    logging.info("Scan completed in %.1fs", elapsed)


if __name__ == "__main__":
    asyncio.run(main())
