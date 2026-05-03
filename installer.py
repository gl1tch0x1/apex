#!/usr/bin/env python3
"""
Apex Auto-Installer
Checks and installs all dependencies, then launches Apex.
Run this once before using main.py.
"""

import sys
import os
import subprocess
import time
import threading
import shutil
import importlib

# Force UTF-8 output on Windows to avoid cp1252 crashes
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── ANSI colour helpers (pure stdlib, no deps required) ─────────────────────
def _vt():
    """Enable VT100 on Windows 10+."""
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.SetConsoleMode(k32.GetStdHandle(-11), 7)
        except Exception:
            pass

_vt()

R  = "\033[0m"
G  = "\033[92m"
DG = "\033[32m"
Y  = "\033[93m"
C  = "\033[96m"
W  = "\033[97m"
D  = "\033[90m"
RD = "\033[91m"
B  = "\033[1m"

def g(s): return f"{G}{s}{R}"
def dg(s): return f"{DG}{s}{R}"
def y(s): return f"{Y}{s}{R}"
def c(s): return f"{C}{s}{R}"
def w(s): return f"{W}{B}{s}{R}"
def d(s): return f"{D}{s}{R}"
def rd(s): return f"{RD}{B}{s}{R}"
def b(s): return f"{B}{s}{R}"


# ── Spinner ──────────────────────────────────────────────────────────────────
class Spinner:
    FRAMES = ["-", "\\", "|", "/"]

    def __init__(self, label: str):
        self.label   = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            print(f"\r  {G}{frame}{R}  {D}{self.label}{R}", end="", flush=True)
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        print("\r" + " " * (len(self.label) + 12) + "\r", end="", flush=True)


# ── Print helpers ────────────────────────────────────────────────────────────
def _rule(label: str = ""):
    w_  = shutil.get_terminal_size((80, 24)).columns
    if label:
        pad = max(0, (w_ - len(label) - 4) // 2)
        line = dg("-" * pad) + f"  {DG}{label}{R}  " + dg("-" * pad)
    else:
        line = dg("-" * w_)
    print(line)

def ok(msg: str):
    print(f"  {G}[+]{R}  {msg}")

def fail(msg: str):
    print(f"  {RD}[!]{R}  {msg}")

def info(msg: str):
    print(f"  {C}[*]{R}  {msg}")

def warn(msg: str):
    print(f"  {Y}[~]{R}  {msg}")

def step(msg: str):
    print(f"\n  {DG}>>{R}  {w(msg)}")


# ── Boot display ─────────────────────────────────────────────────────────────
def _boot():
    os.system("cls" if sys.platform == "win32" else "clear")
    print()
    lines = [
        f"  {DG}+{'='*54}+{R}",
        f"  {DG}|{R}  {G}{B}  APEX  --  Multi-Agent Security Scanner{R}            {DG}|{R}",
        f"  {DG}|{R}  {D}  Installer & Dependency Bootstrap v2.0{R}             {DG}|{R}",
        f"  {DG}+{'='*54}+{R}",
    ]
    for l in lines:
        print(l)
    print()


# ── Python version check ─────────────────────────────────────────────────────
def _check_python():
    step("Python runtime")
    ver = sys.version_info
    if ver < (3, 9):
        fail(f"Python 3.9+ required. Found: {ver.major}.{ver.minor}.{ver.micro}")
        sys.exit(1)
    ok(f"Python {ver.major}.{ver.minor}.{ver.micro}  {d('(meets 3.9+ requirement)')}")


# ── Pip packages ─────────────────────────────────────────────────────────────
PACKAGES = [
    # (pip name,      import name,         display label)
    ("aiohttp",       "aiohttp",           "aiohttp        -- async HTTP client"),
    ("playwright",    "playwright",        "playwright      -- browser automation"),
    ("PyJWT",         "jwt",               "PyJWT           -- JWT decode/verify"),
    ("pyyaml",        "yaml",              "PyYAML          -- YAML config parsing"),
    ("simpleeval",    "simpleeval",        "simpleeval      -- safe expression eval"),
    ("rich",          "rich",              "rich            -- terminal UI"),
]


def _pip_install(pip_name: str, label: str) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", pip_name],
            capture_output=True, text=True, timeout=120
        )
        return result.returncode == 0
    except Exception:
        return False


def _check_packages():
    step("Python packages")
    missing = []
    for pip_name, import_name, label in PACKAGES:
        try:
            importlib.import_module(import_name)
            ok(label)
        except ImportError:
            warn(f"{label}  {d('→ not found')}")
            missing.append((pip_name, label))

    if missing:
        print()
        info(f"Installing {len(missing)} missing package(s)...")
        for pip_name, label in missing:
            with Spinner(f"Installing {pip_name}..."):
                success = _pip_install(pip_name, label)
            if success:
                ok(f"{pip_name}  {d('installed')}")
            else:
                fail(f"{pip_name}  — installation failed. Run:  pip install {pip_name}")

        # Verify
        still_missing = []
        for pip_name, import_name, label in PACKAGES:
            try:
                importlib.import_module(import_name)
            except ImportError:
                still_missing.append(pip_name)

        if still_missing:
            print()
            fail(f"These packages could not be installed: {', '.join(still_missing)}")
            fail("Run manually:  pip install " + " ".join(still_missing))
            sys.exit(1)


# ── Playwright browser ───────────────────────────────────────────────────────
def _check_playwright():
    step("Playwright browser (Chromium)")

    # Check if chromium executable already present
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
                browser.close()
                ok(f"Chromium  {d('already installed')}")
                return
            except Exception:
                pass
    except Exception:
        pass

    warn(f"Chromium not installed  {d('-- installing now...')}")
    with Spinner("Installing Chromium (this may take a minute)..."):
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True, text=True, timeout=300
        )

    if result.returncode == 0:
        ok(f"Chromium  {d('installed successfully')}")
    else:
        fail("Chromium install failed.")
        fail("Run manually:  python -m playwright install chromium")
        warn("DOM XSS scanning will be unavailable without Chromium.")


# ── External Tools (Go / Python) ─────────────────────────────────────────────
def _check_external_tools():
    step("External Bug Bounty Tools")
    
    # We load the tool registry from our external_tools module
    try:
        from integrations.external_tools import TOOL_REGISTRY, _available
    except ImportError:
        fail("Could not load integrations/external_tools.py")
        return

    missing_tools = []
    available_tools = []

    for name, (desc, install_cmd) in TOOL_REGISTRY.items():
        if _available(name):
            available_tools.append((name, desc))
        else:
            missing_tools.append((name, install_cmd))

    for name, desc in available_tools:
        ok(f"{name:15} -- {desc}")

    if not missing_tools:
        return

    print()
    warn(f"Missing {len(missing_tools)} external tools.")
    do_install = input(f"  {DG}>>{R}  Would you like to try auto-installing them now? (y/N): ").strip().lower()
    
    if do_install in ('y', 'yes'):
        # Check if go is installed
        if shutil.which("go") is None:
            fail("Go compiler is not installed. Cannot install Go tools.")
            info("Please install Go (https://go.dev/doc/install) and run the installer again.")
        else:
            for name, cmd in missing_tools:
                with Spinner(f"Installing {name} ({cmd})..."):
                    try:
                        subprocess.run(cmd, shell=True, capture_output=True, timeout=300)
                    except Exception:
                        pass
                
                if _available(name):
                    ok(f"{name} installed successfully")
                else:
                    fail(f"{name} install failed. Run manually: {cmd}")
    else:
        info("Skipping external tools installation. You can install them later.")


# ── Config / workspace checks ────────────────────────────────────────────────
def _check_workspace():
    step("Workspace files")

    required_files = [
        ("config.yaml",                        "Main config"),
        ("workflows/security_scan_v2.yaml",    "Scan workflow"),
        ("core/orchestrator.py",               "Orchestrator"),
        ("modules/__init__.py",                "Module registry"),
    ]

    all_ok = True
    for path, label in required_files:
        if os.path.exists(path):
            ok(f"{label:30s}  {d(path)}")
        else:
            fail(f"{label:30s}  {d(path)}  {rd('MISSING')}")
            all_ok = False

    if not all_ok:
        print()
        fail("Some required files are missing. Re-clone the repository.")
        sys.exit(1)

    # Ensure reports dir exists
    os.makedirs("reports", exist_ok=True)
    ok(f"{'reports/ directory':30s}  {d('ready')}")


# ── .env check ───────────────────────────────────────────────────────────────
def _check_env():
    step("Environment variables")

    env_path = ".env"
    openai_key = os.getenv("OPENAI_API_KEY", "")

    if not openai_key:
        # Try loading from .env manually (no python-dotenv needed)
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("OPENAI_API_KEY="):
                        openai_key = line.split("=", 1)[1].strip()
                        break

    if openai_key:
        masked = openai_key[:8] + "..." + openai_key[-4:] if len(openai_key) > 12 else "***"
        ok(f"OPENAI_API_KEY  {d(masked)}  {d('(LLM analysis enabled)')}")
    else:
        warn(f"OPENAI_API_KEY not set  {d('-- LLM analysis disabled (scanner still works)')}")
        info(f"Set it in {d('.env')}  or export before running:  export OPENAI_API_KEY=sk-..")    


# ── Final summary ────────────────────────────────────────────────────────────
def _summary():
    print()
    _rule("READY")
    print()
    print(f"  {G}All systems operational.{R}  Apex is ready to scan.\n")
    print(f"  {D}Usage:{R}")
    print(f"    {DG}python main.py{R} {C}<target_url>{R}  {D}[options]{R}")
    print()
    print(f"  {D}Examples:{R}")
    print(f"    {DG}python main.py{R} {C}https://target.com{R}")
    print(f"    {DG}python main.py{R} {C}https://target.com{R} {D}--modules sql_injection xss_reflected ssrf{R}")
    print(f"    {DG}python main.py{R} {C}https://target.com{R} {D}--api-hunt --verbose{R}")
    print(f"    {DG}python main.py{R} {C}https://target.com{R} {D}--insecure-tls{R}  {D}# lab/self-signed certs{R}")
    print()
    print(f"  {D}Available modules:{R}")

    modules = [
        "domxss",          "sql_injection",     "xss_reflected",
        "broken_auth",     "sensitive_data",    "xxe",
        "broken_access",   "misconfig",         "insecure_deserialization",
        "known_vulns",     "graphql",           "jwt",
        "idor",            "ssrf",              "open_redirect",
        "path_traversal",  "csrf",              "file_upload",
        "security_headers","api_rate_limit",    "api_mass_assignment",
        "ssti",
    ]
    cols = 3
    for i in range(0, len(modules), cols):
        row = modules[i:i+cols]
        print("    " + "  ".join(f"{DG}{m:<24}{R}" for m in row))

    print()
    _rule()
    print()


# ── Entry point ──────────────────────────────────────────────────────────────
def main():
    _boot()

    _rule("SYSTEM CHECK")
    print()

    _check_python()
    _check_packages()
    _check_playwright()
    _check_workspace()
    _check_env()
    _check_external_tools()

    _summary()


if __name__ == "__main__":
    main()
