def _get_stage_description(stage_name: str) -> str:
    s_lower = stage_name.lower()
    if "surface" in s_lower:
        return "Analyzing target surface..."
    elif "subfinder" in s_lower:
        return "Enumerating subdomains..."
    elif "httpx" in s_lower:
        return "Probing targets & services..."
    elif "recon light" in s_lower:
        return "Performing light recon scan..."
    elif "recon intel" in s_lower:
        return "Gathering deep intelligence..."
    elif "js" in s_lower or "secret" in s_lower:
        return "Scanning JS files for secrets..."
    elif "dork" in s_lower:
        return "Search engine reconnaissance..."
    elif "baseline" in s_lower:
        return "Auditing security baseline..."
    elif "waf" in s_lower or "origin" in s_lower:
        return "Hunting origin IP & WAF..."
    elif "katana" in s_lower or "crawl" in s_lower:
        return "Crawling web endpoints..."
    elif "parameter" in s_lower or "param" in s_lower:
        return "Discovering hidden parameters..."
    elif "app" in s_lower:
        return "Analyzing application structure..."
    elif "nuclei" in s_lower or "dalfox" in s_lower:
        return "Running template & XSS scans..."
    elif "injection" in s_lower:
        return "Testing injection vectors..."
    elif "smuggling" in s_lower or "oob" in s_lower:
        return "Testing smuggling & callbacks..."
    elif "cache" in s_lower or "poison" in s_lower:
        return "Testing cache poison vectors..."
    elif "directory" in s_lower:
        return "Bruteforcing directories..."
    elif "auth" in s_lower:
        return "Testing authentication..."
    elif "vulnerability" in s_lower or "assault" in s_lower:
        return "Testing vulnerabilities..."
    elif "target" in s_lower or "resolution" in s_lower:
        return "Resolving target endpoints..."
    elif "verify" in s_lower or "verification" in s_lower:
        return "Verifying security findings..."
    elif "sqli" in s_lower or "extract" in s_lower:
        return "Extracting database data..."
    elif "report" in s_lower:
        return "Generating final scan report..."
    return "Processing..."


def _get_stage_icon(name: str) -> str:
    """Return a tactical icon for the pipeline stage."""
    n = name.lower()
    if "surface" in n: return "⊙"
    if "subfinder" in n or "subdomain" in n: return "◈"
    if "httpx" in n or "probing" in n: return "⚡"
    if "waf" in n or "origin" in n: return "◎"
    if "katana" in n or "crawl" in n: return "⊕"
    if "param" in n: return "⚙"
    if "recon" in n and "light" in n: return "⊙"
    if "recon" in n: return "⊛"
    if "app" in n and "deep" in n: return "⬡"
    if "app" in n: return "⬡"
    if "nuclei" in n or "dalfox" in n: return "☢"
    if "injection" in n: return "⚔"
    if "vulnerability" in n or "assault" in n: return "☠"
    if "cache" in n or "poison" in n: return "☣"
    if "smuggling" in n: return "⇌"
    if "directory" in n: return "⊞"
    if "auth" in n: return "⊟"
    if "verification" in n or "finding" in n: return "⊘"
    if "sqli" in n or "extract" in n: return "⊞"
    if "report" in n: return "⊕"
    if "baseline" in n: return "⊙"
    if "js" in n or "secret" in n: return "⊛"
    if "dork" in n or "google" in n: return "◈"
    if "oob" in n or "flood" in n: return "⊘"
    if "target" in n or "resolution" in n: return "◎"
    return "·"


def _get_stage_subtitle(name: str) -> str:
    """Return a tactical subtitle for pipeline stage display."""
    n = name.lower()
    if "surface" in n: return "DNS + WEB DISCOVERY"
    if "subfinder" in n: return "SUBDOMAIN ENUM"
    if "httpx" in n or "probing" in n: return "LIVE HOSTS"
    if "waf" in n and "risk" in n: return "WAF RISK ASSESSMENT"
    if "waf" in n or "origin" in n: return "WAF DETECTION + ORIGIN"
    if "katana" in n or "crawl" in n: return "ENDPOINT CRAWLING"
    if "param" in n and "app" in n: return "APP + PARAM DISCOVERY"
    if "param" in n: return "HIDDEN PARAMETERS"
    if "recon light" in n: return "FAST RECON"
    if "recon intel" in n: return "DEEP INTELLIGENCE"
    if "recon" in n: return "RECONNAISSANCE"
    if "app" in n and "deep" in n: return "APP DEEP ANALYSIS"
    if "app" in n: return "APPLICATION ANALYSIS"
    if "nuclei" in n and "dalfox" in n: return "TEMPLATE + XSS SCAN"
    if "nuclei" in n: return "TEMPLATE ENGINE"
    if "injection" in n: return "INJECTION VECTORS"
    if "vulnerability" in n or "assault" in n: return "SCAN + ANALYZE"
    if "cache" in n or "poison" in n: return "CACHE POISON VECTORS"
    if "smuggling" in n: return "HTTP SMUGGLING"
    if "directory" in n: return "DIR BRUTEFORCE"
    if "auth" in n: return "AUTH BRUTEFORCE"
    if "verification" in n or "finding" in n: return "CONFIRM + VALIDATE"
    if "sqli" in n or "extract" in n: return "EXPLOIT + DUMP"
    if "report" in n: return "GENERATE REPORT"
    if "baseline" in n: return "SECURITY BASELINE"
    if "js" in n or "secret" in n: return "JS FILE SECRETS"
    if "dork" in n or "google" in n: return "SEARCH ENGINE RECON"
    if "oob" in n or "flood" in n: return "OOB + PAYLOAD FLOOD"
    if "target" in n or "resolution" in n: return "TARGET RESOLUTION"
    return "PROCESSING"

import os
import sys
import time
import re
import random
import threading
import collections
from typing import Dict, List, Optional

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskID
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich import box

console = Console(highlight=False)

# Legacy ANSI Colors (Kept for compatibility with existing string formats)
G = '\033[92m'
R = '\033[91m'
Y = '\033[93m'
C = '\033[96m'
M = '\033[95m'
W = '\033[97m'
GY = '\033[90m'
B = '\033[1m'
U = '\033[4m'
N = '\033[0m'
D = '\033[2m'
I = '\033[3m'
O = '\033[38;5;208m'

# Symbols
_CHECK = "✔"
_CROSS = "✖"
_WARN = "⚠"
_INFO = "ℹ"
_RARROW = "❯"
_DIAMOND = "◈"
_HBAR = "━"
_SKULL = "☠"
_BOLT = "⚡"
_SHIELD = "🛡"
_TARGET = "◎"
_DOT = "●"
_CIRCLE = "○"
_ARROW_R = "▸"
_BLOCK = "█"

# Rich Color Palette (Military-Tactical)
_CLR_PRIMARY = "#c8a832"
_CLR_ACCENT = "#c8a832"
_CLR_SHIMMER = "#e8d060"
_CLR_SUCCESS = "#4a8a5e"
_CLR_DANGER = "bold red"
_CLR_WARN = "#c0a020"
_CLR_MUTED = "#3a3a3a"
_CLR_TEXT = "#d0c8a0"
_CLR_DIM = "#666050"
_CLR_BORDER = "#3a3a2a"
_CLR_BG_ACCENT = "#1a1e26"

_BANNER_LINES = [
    "  " + chr(9556) + chr(9552)*29 + chr(9559),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + O + chr(9608)*4 + W + chr(183)*6 + N + O + chr(9608)*4 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183) + N + O + chr(9608)*4 + W + chr(183)*4 + N + O + chr(9608)*4 + W + chr(183) + N + W + chr(183) + N + O + chr(9608)*2 + W + chr(183)*12 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*2 + N + O + chr(9608)*4 + W + chr(183)*2 + N + O + chr(9608)*4 + W + chr(183)*2 + N + W + chr(183) + N + O + chr(9608)*2 + W + chr(183)*12 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*3 + N + O + chr(9608)*8 + W + chr(183)*3 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*4 + N + O + chr(9608)*6 + W + chr(183)*4 + N + W + chr(183) + N + W + chr(183)*9 + N + O + chr(9608)*2 + W + chr(183)*3 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*5 + N + O + chr(9608)*4 + W + chr(183)*5 + N + W + chr(183) + N + W + chr(183)*9 + N + O + chr(9608)*2 + W + chr(183)*3 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*6 + N + O + chr(9608)*2 + W + chr(183)*6 + N + W + chr(183) + N + O + chr(9608)*12 + W + chr(183)*2 + N + chr(9553),
    "  " + chr(9553) + W + chr(183)*29 + N + chr(9553),
    "  " + chr(9553) + B + W + "  " + chr(9608)*2 + "    VERDAMMT-SNIPE    " + chr(9608)*2 + " " + N + chr(9553),
    "  " + chr(9553) + C + "     recon" + chr(183) + "scan" + chr(183) + "assault      " + N + chr(9553),
    "  " + chr(9562) + chr(9552)*29 + chr(9565),
]

_MODES = {
    "1": ("recon", "RECON", "Passive intel + archive URLs"),
    "2": ("app", "APP", "WAF bypass + param discovery"),
    "3": ("assault", "ASSAULT", "Origin IP + vuln scan"),
    "4": ("poisoning", "POISONING", "Cache poison + smuggle + bruteforce"),
    "5": ("full", "FULL", "Recon + app + assault"),
    "6": ("recon_light", "RECON LIGHT", "Fast crawl + baseline"),
    "7": ("nuclei", "NUCLEI", "Template scan only"),
}

_MODE_ICONS = {
    "1": "🔍",
    "2": "🧪",
    "3": "💀",
    "4": "☣️",
    "5": "💥",
    "6": "⚡",
    "7": "🎯",
}

_IMPERSONATE_OPTS = [None, "chrome", "safari", "firefox"]

_PIPELINE_STAGES_BY_MODE: Dict[str, List[Dict[str, str]]] = {
    "RECON_LIGHT": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Light", "status": "pending", "detail": ""},
        {"name": "Baseline Checks", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "RECON": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Intel", "status": "pending", "detail": ""},
        {"name": "JS & Secret Analysis", "status": "pending", "detail": ""},
        {"name": "Google Dorking", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "APP": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "Katana Crawler", "status": "pending", "detail": ""},
        {"name": "Parameter Discovery", "status": "pending", "detail": ""},
        {"name": "App Deep Analysis", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "ASSAULT": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "WAF Risk Assessment", "status": "pending", "detail": ""},
        {"name": "Parameter Discovery", "status": "pending", "detail": ""},
        {"name": "Nuclei & Dalfox", "status": "pending", "detail": ""},
        {"name": "Injection Engine", "status": "pending", "detail": ""},
        {"name": "Smuggling & OOB", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "POISONING": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Cache Poisoning", "status": "pending", "detail": ""},
        {"name": "HTTP Smuggling", "status": "pending", "detail": ""},
        {"name": "Directory Bruteforce", "status": "pending", "detail": ""},
        {"name": "Auth Bruteforce", "status": "pending", "detail": ""},
        {"name": "OOB & Payload Flood", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "FULL": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Recon Intel", "status": "pending", "detail": ""},
        {"name": "WAF / Origin Hunt", "status": "pending", "detail": ""},
        {"name": "App & Param Discovery", "status": "pending", "detail": ""},
        {"name": "Vulnerability Assault", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
    "NUCLEI": [
        {"name": "Surface Scan", "status": "pending", "detail": ""},
        {"name": "Subfinder", "status": "pending", "detail": ""},
        {"name": "HTTPX Probing", "status": "pending", "detail": ""},
        {"name": "Target Resolution", "status": "pending", "detail": ""},
        {"name": "Nuclei Engine", "status": "pending", "detail": ""},
        {"name": "Finding Verification", "status": "pending", "detail": ""},
        {"name": "SQLi Data Extraction", "status": "pending", "detail": ""},
        {"name": "Reporter", "status": "pending", "detail": ""},
    ],
}

def strip_ansi(text: str) -> str:
    return re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)

def _side_by_side(left, right, lw=30, sep="  ", fallback=80):
    tw = 80
    try: tw = os.get_terminal_size().columns
    except Exception: pass
    if tw < fallback:
        for l in left: print(l)
        print()
        for r in right: print(r)
        return
    mh = max(len(left), len(right))
    lp = left + [""] * (mh - len(left))
    rp = right + [""] * (mh - len(right))
    for l, r in zip(lp, rp):
        lc = strip_ansi(l)
        pad = lw - len(lc)
        if pad < 0: pad = 0
        print(f"{l}{' '*pad}{sep}{r}")


def _get_term_width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


# LIVE SCANNING DASHBOARD

_DOT = "●"

class ScanDashboard:
    """Thread-safe live scanning dashboard using Rich Live.

    Provides a single, continuously-updated terminal panel that replaces
    the default line-by-line scrolling output during active scans.
    All state mutations are guarded by a threading lock and rendering is
    throttled to ~8 FPS so the UI never becomes a performance bottleneck.
    """

    _instance: Optional["ScanDashboard"] = None

    @classmethod
    def get_instance(cls) -> "ScanDashboard":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def get(cls) -> "ScanDashboard":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def active(cls) -> bool:
        return cls._instance is not None and cls._instance._active

    def __init__(self):
        self._lock = threading.Lock()
        self.target: str = ""
        self.mode: str = ""
        self.version: str = "v1.3.0 - NEXUS"
        self.phase: str = ""
        self.status: str = "STARTING"
        self.current_activity: str = ""
        self.event_count: int = 0
        self.finding_count: int = 0
        self.severity_counts: Dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
        }
        self.metrics: Dict[str, int] = {
            "Requests": 0,
            "Subdomains": 0,
            "Live Hosts": 0,
            "Endpoints": 0,
            "Parameters": 0,
        }
        self.pipeline: List[Dict[str, str]] = [dict(s) for s in _PIPELINE_STAGES_BY_MODE["FULL"]]
        self.recent_events: collections.deque = collections.deque(maxlen=7)
        self.recent_findings: collections.deque = collections.deque(maxlen=5)
        self._rps_history: collections.deque = collections.deque(maxlen=10)
        self._display_pct: float = 0.0
        self._last_completed_count: int = 0
        self._flash_until: float = 0.0
        self.warning_count: int = 0
        self.error_count: int = 0
        self.start_time: float = 0.0
        self._live: Optional[Live] = None
        self._active: bool = False
        self._last_render_time: float = 0.0
        self._min_render_interval: float = 0.125  # ~8 FPS

    # Lifecycle

    def start(self, target: str, mode: str, version: str = ""):
        """Start the live dashboard display."""
        with self._lock:
            self.target = target
            self.mode = mode or "FULL"
            if version:
                self.version = version
            self.start_time = time.time()
            self.status = "STARTING"
            self.event_count = 0
            self.finding_count = 0
            self.severity_counts = {
                "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
            }
            self.metrics = {
                "Requests": 0,
                "Subdomains": 0,
                "Live Hosts": 0,
                "Endpoints": 0,
                "Parameters": 0,
            }

            mode_key = self.mode.upper()
            if mode_key in _PIPELINE_STAGES_BY_MODE:
                raw_stages = _PIPELINE_STAGES_BY_MODE[mode_key]
            else:
                raw_stages = _PIPELINE_STAGES_BY_MODE["FULL"]

            self.pipeline = [dict(s) for s in raw_stages]
            if self.pipeline:
                self.pipeline[0]["status"] = "active"
                self.pipeline[0]["detail"] = "initializing..."

            self.recent_events.clear()
            self.recent_findings.clear()
            self._rps_history.clear()
            self._display_pct = 0.0
            self._last_completed_count = 0
            self._flash_until = 0.0
            self.recent_events.append(("▶️ Initializing scanner...", "yellow", time.time()))
            self.warning_count = 0
            self.error_count = 0
            self.phase = "STARTING"

        if not self._active:
            self._live = Live(
                get_renderable=self._build_layout,
                console=console,
                refresh_per_second=15,
                transient=True,
            )
            self._live.start()
            self._active = True

    def stop(self, status: str = "COMPLETED"):
        """Stop the live dashboard."""
        if not self._active:
            return
        with self._lock:
            self.status = status
            self._active = False
            # Mark all pipeline stages completed
            for stage in self.pipeline:
                if stage["status"] == "active":
                    stage["status"] = "completed"
            if status == "COMPLETED" and self.pipeline:
                self.pipeline[-1]["status"] = "completed"
                self.pipeline[-1]["detail"] = "report generated"

        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None

    # State mutations

    def _find_stage_index(self, keywords: tuple) -> int:
        for idx, stage in enumerate(self.pipeline):
            s_name = stage["name"].lower()
            if any(k in s_name for k in keywords):
                return idx
        return -1

    def _update_pipeline_from_phase(self, phase_name: str):
        p_lower = phase_name.lower()
        target_idx = -1

        for idx, stage in enumerate(self.pipeline):
            s_name = stage["name"].lower()
            if s_name in p_lower or p_lower in s_name:
                target_idx = idx
                break

        if target_idx == -1:
            if any(k in p_lower for k in ("surface", "phase 0")):
                target_idx = self._find_stage_index(("surface",))
            elif any(k in p_lower for k in ("subfinder", "subdomain")):
                target_idx = self._find_stage_index(("subfinder",))
            elif any(k in p_lower for k in ("httpx", "probing")):
                target_idx = self._find_stage_index(("httpx", "probing"))
            elif any(k in p_lower for k in ("origin", "waf risk", "waf detected")):
                target_idx = self._find_stage_index(("waf", "origin"))
            elif any(k in p_lower for k in ("katana", "crawl", "link")):
                target_idx = self._find_stage_index(("katana", "crawler", "link"))
            elif any(k in p_lower for k in ("browser", "spa")):
                target_idx = self._find_stage_index(("browser", "spa", "app deep"))
            elif any(k in p_lower for k in ("param", "arjun", "discovery")):
                target_idx = self._find_stage_index(("param", "parameter", "discovery"))
            elif any(k in p_lower for k in ("gau", "wayback", "osint", "dork", "takeover", "js", "secret", "recon intel", "phase 1")):
                target_idx = self._find_stage_index(("recon", "intel", "gau", "takeover", "dork", "js", "secret", "baseline"))
            elif any(k in p_lower for k in ("app", "phase 2")):
                target_idx = self._find_stage_index(("app", "dom", "api"))
            elif any(k in p_lower for k in ("nuclei", "dalfox", "assault", "vuln", "injection", "phase 3")):
                target_idx = self._find_stage_index(("nuclei", "dalfox", "injection", "vulnerability", "assault"))
            elif any(k in p_lower for k in ("poison", "smuggled", "smuggling", "cache", "directory", "auth", "exhaust", "flood")):
                target_idx = self._find_stage_index(("cache", "smuggling", "directory", "auth", "exhaust", "oob", "flood"))
            elif any(k in p_lower for k in ("verify", "confirm", "phase 4")):
                target_idx = self._find_stage_index(("verify", "verification"))
            elif any(k in p_lower for k in ("sqli", "extract", "phase 4.5")):
                target_idx = self._find_stage_index(("sqli", "extraction"))
            elif any(k in p_lower for k in ("report", "summary", "phase 5", "complete")):
                target_idx = self._find_stage_index(("report", "reporter"))

        if target_idx != -1 and target_idx < len(self.pipeline):
            for i in range(target_idx):
                if self.pipeline[i]["status"] in ("pending", "active"):
                    self.pipeline[i]["status"] = "completed"
            self.pipeline[target_idx]["status"] = "active"
            if not self.pipeline[target_idx]["detail"]:
                self.pipeline[target_idx]["detail"] = "running..."
            self.status = "SCANNING"

    def log_event(self, text: str, style: str = "white"):
        with self._lock:
            self.event_count += 1
            clean_text = strip_ansi(text)

            # Auto metric parsing from logs
            sub_m = re.search(r"(\d+)\s+subdomains?", clean_text, re.I)
            if sub_m:
                count = int(sub_m.group(1))
                self.metrics["Subdomains"] = count
                idx = self._find_stage_index(("subfinder", "subdomain"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} subdomains"

            host_m = re.search(r"(\d+)\s+(?:live\s+)?(?:hosts|services)", clean_text, re.I)
            if host_m:
                count = int(host_m.group(1))
                self.metrics["Live Hosts"] = count
                idx = self._find_stage_index(("httpx", "probing"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} live hosts"

            ep_m = re.search(r"(\d+)\s+(?:urls?|endpoints?)", clean_text, re.I)
            if ep_m and ep_m.group(1):
                count = int(ep_m.group(1))
                self.metrics["Endpoints"] = count
                idx = self._find_stage_index(("katana", "crawler", "link", "recon", "extraction"))
                if idx != -1:
                    self.pipeline[idx]["detail"] = f"{count} endpoints"

            self.recent_events.append((clean_text, style, time.time()))
        self._throttled_refresh()

    def log_finding(self, severity: str, title: str, url: str = ""):
        with self._lock:
            self.finding_count += 1
            if severity in self.severity_counts:
                self.severity_counts[severity] += 1
            
            for stage in self.pipeline:
                if stage["status"] == "active":
                    stage["detail"] = f"{self.finding_count} findings"
                    break

            msg = f"! {severity} — {title}"
            style = "bold red" if severity in ("Critical", "High") else ("bold yellow" if severity == "Medium" else "bold green")
            self.recent_events.append((msg, style, time.time()))
            self.recent_findings.append({
                "severity": severity,
                "title": title,
                "url": url,
                "time": time.time(),
            })
        self._throttled_refresh()

    def set_phase(self, phase: str):
        with self._lock:
            self.phase = phase
            self._update_pipeline_from_phase(phase)
        self._throttled_refresh()

    def set_activity(self, activity: str):
        with self._lock:
            self.current_activity = activity
        self._throttled_refresh()

    def log_warning(self, text: str):
        with self._lock:
            self.warning_count += 1
            clean_text = strip_ansi(text)
            self.recent_events.append((f"{_WARN} {clean_text}", "yellow", time.time()))
        self._throttled_refresh()

    def log_error(self, text: str):
        with self._lock:
            self.error_count += 1
            clean_text = strip_ansi(text)
            self.recent_events.append((f"{_CROSS} {clean_text}", "bold red", time.time()))
        self._throttled_refresh()

    # Rendering

    def _throttled_refresh(self):
        # Rendering is now handled automatically by Rich Live's background thread
        # at 15 FPS using get_renderable=self._build_layout.
        pass

    def _fmt_elapsed(self) -> str:
        elapsed = time.time() - self.start_time
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        return f"{mins:02d}:{secs:02d}"

    def _build_layout(self):
        """Compose the Rich live dashboard — military-tactical 3-column design."""
        with self._lock:
            snap_target = self.target
            snap_mode = self.mode
            snap_phase = self.phase
            snap_status = self.status
            snap_start = self.start_time
            snap_metrics = self.metrics.copy()
            snap_pipeline = [dict(stg) for stg in self.pipeline]
            snap_events = list(self.recent_events)
            snap_recent_findings = list(self.recent_findings)
            snap_sev = self.severity_counts.copy()
            snap_version = self.version
    
        tw = _get_term_width()

        # Single Source of Truth for Active Module & Phase
        active_stage_obj = None
        for stg in snap_pipeline:
            if stg["status"] == "active":
                active_stage_obj = stg
                break

        if active_stage_obj:
            active_module_name = active_stage_obj["name"].upper()
            active_detail = active_stage_obj["detail"] or _get_stage_description(active_stage_obj["name"])
        elif snap_status == "COMPLETED":
            active_module_name = "COMPLETE"
            active_detail = "All scan modules completed."
        elif snap_status in ("ERROR", "FAILED"):
            active_module_name = "FAILED"
            active_detail = "Scan execution failed."
        else:
            active_module_name = "INITIALIZING"
            active_detail = "Initializing scanner..."

        # Progress calculations (UNCHANGED logic)
        total_stages = len(snap_pipeline) if snap_pipeline else 1
        completed_stages = sum(1 for s in snap_pipeline if s["status"] in ("completed", "skipped"))
        active_stages = sum(1 for s in snap_pipeline if s["status"] == "active")

        if completed_stages > getattr(self, '_last_completed_count', 0):
            self._last_completed_count = completed_stages
            self._flash_until = time.monotonic() + 1.5

        if snap_status == "COMPLETED":
            progress_ratio = 1.0
        elif snap_status in ("ERROR", "FAILED"):
            progress_ratio = completed_stages / total_stages if total_stages > 0 else 0.0
        else:
            progress_ratio = (completed_stages + (0.5 if active_stages else 0.0)) / total_stages if total_stages > 0 else 0.0

        target_pct = progress_ratio * 100.0
        curr_display = getattr(self, '_display_pct', 0.0)
        curr_display += (target_pct - curr_display) * 0.25
        self._display_pct = curr_display
        pct = int(round(curr_display))

        elapsed = time.time() - snap_start
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        elapsed_str = f"{mins:02d}:{secs:02d}"
        dt = max(time.time() - snap_start, 0.1)
        reqs = snap_metrics["Requests"]
        rps = reqs / dt if reqs > 0 else 0.0
        kb_s = rps * 1.8

        if snap_status in ("STARTING", "SCANNING"):
            self._rps_history.append(rps)

        active_stage_num = min(total_stages, completed_stages + (1 if active_stages else 0))

#  TOP HEADER BAR
        hdr_grid = Table.grid(expand=True)
        hdr_grid.add_column(ratio=2)
        hdr_grid.add_column(ratio=3, justify="right")

        brand_t = Text()
        brand_t.append("  💀 ", style="bold red")
        brand_t.append("VERDAMT-SNIPE\n", style="bold #c8a832")
        brand_t.append("     RECON / ENUM / EXPLOIT / REPORT", style="#666050")

        info_t = Text()
        info_t.append("TARGET ", style="#666050")
        info_t.append(f"⊙ {snap_target}   ", style="bold #c8a832")
        info_t.append("MODE ", style="#666050")
        info_t.append(f"{snap_mode.upper()}   ", style="bold white")
        info_t.append("ELAPSED ", style="#666050")
        info_t.append(f"{elapsed_str}   ", style="bold white")

        if snap_status in ("STARTING", "SCANNING"):
            _hdr_spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
            _hdr_sp = _hdr_spinners[int(time.monotonic() * 10) % len(_hdr_spinners)]
            info_t.append(f"● RUNNING {_hdr_sp}", style="bold #4a8a5e")
        elif snap_status == "COMPLETED":
            info_t.append("● COMPLETED ✓", style="bold #4a8a5e")
        else:
            info_t.append("● FAILED ✗", style="bold red")

        hdr_grid.add_row(brand_t, info_t)
        header_panel = Panel(hdr_grid, border_style="#3a3a2a", box=box.HEAVY, padding=(0, 1))

#  LEFT COLUMN — PIPELINE
        max_visible = 10
        total_stg_count = len(snap_pipeline)
        if total_stg_count <= max_visible:
            visible_pipeline = snap_pipeline
            vis_start = 0
        else:
            a_idx = 0
            for idx_p, stg_p in enumerate(snap_pipeline):
                if stg_p["status"] == "active":
                    a_idx = idx_p
                    break
            s_idx = max(0, min(a_idx - (max_visible // 2), total_stg_count - max_visible))
            visible_pipeline = snap_pipeline[s_idx:s_idx + max_visible]
            vis_start = s_idx

        pipe_t = Text()
        for pi, stage in enumerate(visible_pipeline):
            st = stage["status"]
            name = stage["name"]
            detail = stage.get("detail", "")
            icon = _get_stage_icon(name)
            det_display = detail if detail else "0/0"

            if st == "completed":
                pipe_t.append("  ", style="#666050")
                pipe_t.append(f"{icon} ", style="#4a8a5e")
                pipe_t.append(f"· ", style="dim #4a8a5e")
                pipe_t.append(f"{name:<18}", style="#4a8a5e")
                pipe_t.append(f" {det_display:>10}", style="dim #4a8a5e")
                pipe_t.append("  ✓\n", style="bold #4a8a5e")
            elif st == "active":
                pipe_t.append("  ", style="bold #c8a832")
                pipe_t.append(f"{icon} ", style="bold #c8a832")
                pipe_t.append(f"· ", style="bold #c8a832")
                pipe_t.append(f"{name:<18}", style="bold white")
                pipe_t.append(f" {det_display:>10}\n", style="bold #c8a832")
            elif st == "failed":
                pipe_t.append("  ", style="#666050")
                pipe_t.append(f"{icon} ", style="bold red")
                pipe_t.append(f"· ", style="bold red")
                pipe_t.append(f"{name:<18}", style="bold red")
                pipe_t.append(f" {det_display:>10}", style="dim red")
                pipe_t.append("  ✗\n", style="bold red")
            elif st == "skipped":
                pipe_t.append("  ", style="#3a3a3a")
                pipe_t.append(f"{icon} ", style="#3a3a3a")
                pipe_t.append(f"· ", style="#3a3a3a")
                pipe_t.append(f"{name:<18}", style="dim #3a3a3a")
                pipe_t.append("  —\n", style="dim #3a3a3a")
            else:  # pending
                pipe_t.append("  ", style="#3a3a3a")
                pipe_t.append(f"{icon} ", style="#3a3a3a")
                pipe_t.append(f"· ", style="#3a3a3a")
                pipe_t.append(f"{name:<18}", style="#3a3a3a")
                pipe_t.append(f" {det_display:>10}\n", style="dim #3a3a3a")

        pipe_panel = Panel(
            pipe_t,
            title=f"[bold #c8a832]☠ PIPELINE[/bold #c8a832]",
            title_align="left",
            subtitle=f"[#666050]{active_stage_num}/{total_stages}[/#666050]",
            subtitle_align="right",
            border_style="#3a3a2a",
            box=box.ROUNDED,
            padding=(0, 0),
        )

#  CENTER COLUMN — SCAN ACTIVITY
        center_parts = []

        # Stage header + percentage
        stage_hdr = Text()
        stage_hdr.append(f"STAGE {active_stage_num}/{total_stages} · {active_module_name}", style="bold #d0c8a0")
        stage_hdr.append(f"   ◎ {pct:.1f}%\n", style="bold #c8a832")
        center_parts.append(stage_hdr)

        # Progress bar (Tactical HUD Bracket with Solid Blocks)
        bar_len = 32
        filled_len = int(round(bar_len * (curr_display / 100.0)))
        prog_bar = Text()
        prog_bar.append("[", style="bold #666050")
        if snap_status in ("STARTING", "SCANNING"):
            filled_len = max(1, min(bar_len, filled_len))
            frame = int(time.monotonic() * 8) % filled_len
            for i in range(filled_len):
                if i == frame or i == (frame - 1) % filled_len:
                    prog_bar.append("█", style="bold #f0d050")
                else:
                    prog_bar.append("█", style="#c8a832")
            unfilled = bar_len - filled_len
            if unfilled > 0:
                prog_bar.append("░" * unfilled, style="#2a2a2a")
        elif snap_status in ("ERROR", "FAILED"):
            prog_bar.append("█" * max(filled_len, 0), style="bold red")
            unfilled = bar_len - filled_len
            if unfilled > 0:
                prog_bar.append("░" * unfilled, style="#2a2a2a")
        else:
            prog_bar.append("█" * bar_len, style="bold #4a8a5e")
        prog_bar.append("]", style="bold #666050")
        prog_bar.append(f"  {pct:.1f}%\n", style="bold #c8a832")

        if time.monotonic() < getattr(self, '_flash_until', 0.0):
            prog_bar.append("  ✦ STAGE COMPLETE!\n", style="bold #e8d060")
        center_parts.append(prog_bar)
        center_parts.append(Text(""))

        # Metric cards row (bordered sub-table)
        cards = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_header=True,
            show_edge=True,
            padding=(0, 1),
            border_style="#3a3a2a",
        )
        cards.add_column("◻ REQ/S", justify="center", header_style="#666050", style="bold white")
        cards.add_column("◻ TOTAL REQ", justify="center", header_style="#666050", style="bold white")
        cards.add_column("◻ ELAPSED", justify="center", header_style="#666050", style="bold white")
        cards.add_row(f"{rps:.1f}", f"{reqs}", elapsed_str)
        center_parts.append(cards)
        center_parts.append(Text(""))

        # Request Rate Sparkline
        _spark_blocks = [" ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        spark_t = Text()
        spark_t.append("REQUEST RATE ", style="bold #666050")
        spark_t.append("(req/s)\n", style="#666050")
        if self._rps_history:
            max_r = max(max(self._rps_history), 1.0)
            spark_str = "".join(_spark_blocks[min(7, int((v / max_r) * 7))] for v in self._rps_history)
            spark_t.append(f"  {spark_str}", style="#c8a832")
            avg_rps = sum(self._rps_history) / len(self._rps_history)
            spark_t.append(f"  {avg_rps:.1f}\n", style="bold white")
            spark_t.append(f"{' ':>24}avg\n", style="#666050")
        else:
            spark_t.append("  ··········  0.0\n", style="#3a3a3a")
        center_parts.append(spark_t)
        center_parts.append(Text(""))

        # Metrics section (3-column)
        met_hdr = Text("METRICS\n", style="bold #666050")
        center_parts.append(met_hdr)

        met_grid = Table.grid(expand=True, padding=(0, 1))
        met_grid.add_column(justify="center")
        met_grid.add_column(justify="center")
        met_grid.add_column(justify="center")

        sub_t = Text()
        sub_t.append("⊙ ", style="#c8a832")
        sub_t.append("SUBDOMAINS\n", style="#666050")
        sub_t.append(f"  {snap_metrics['Subdomains']}\n", style="bold white")
        sub_t.append("  discovered", style="dim #666050")

        ep_t = Text()
        ep_t.append("⊕ ", style="#c8a832")
        ep_t.append("ENDPOINTS\n", style="#666050")
        ep_t.append(f"  {snap_metrics['Endpoints']}\n", style="bold white")
        ep_t.append("  found", style="dim #666050")

        tgt_t = Text()
        tgt_t.append("◎ ", style="#c8a832")
        tgt_t.append("TARGETS\n", style="#666050")
        tgt_t.append(f"  {snap_metrics['Live Hosts'] or 1}\n", style="bold white")
        tgt_t.append("  domain", style="dim #666050")

        met_grid.add_row(sub_t, ep_t, tgt_t)
        center_parts.append(met_grid)
        center_parts.append(Text(""))

        # Bottom scan progress bar (tactical segmented HUD bar)
        sp_t = Text()
        sp_t.append("SCAN PROGRESS  ", style="bold #666050")
        sp_bar_len = 22
        sp_filled = int(round(sp_bar_len * (curr_display / 100.0)))
        sp_t.append("[", style="#666050")
        if snap_status in ("STARTING", "SCANNING"):
            sp_filled = max(0, min(sp_bar_len, sp_filled))
            for si in range(sp_bar_len):
                if si < sp_filled:
                    c = "#c8a832" if si % 2 == 0 else "#b09028"
                    sp_t.append("▮", style=c)
                else:
                    sp_t.append("▯", style="#2a2a2a")
        elif snap_status in ("ERROR", "FAILED"):
            for si in range(sp_bar_len):
                if si < sp_filled:
                    sp_t.append("▮", style="red")
                else:
                    sp_t.append("▯", style="#2a2a2a")
        else:
            for si in range(sp_bar_len):
                sp_t.append("▮", style="#4a8a5e")
        sp_t.append("]", style="#666050")
        sp_t.append(f"  {reqs}/{snap_metrics['Endpoints'] or reqs}", style="bold #d0c8a0")
        center_parts.append(sp_t)

        scan_activity_panel = Panel(
            Group(*center_parts),
            title="[bold #c8a832]☠ SCAN ACTIVITY[/bold #c8a832]",
            title_align="left",
            subtitle="[bold #4a8a5e]// LIVE[/bold #4a8a5e]" if snap_status in ("STARTING", "SCANNING") else "[#666050]// DONE[/#666050]",
            subtitle_align="right",
            border_style="#3a3a2a",
            box=box.ROUNDED,
            padding=(0, 1),
        )

#  RIGHT COLUMN — FINDINGS + RECENT ACTIVITY

        # -- FINDINGS Panel --
        sc = snap_sev
        total_findings = sum(sc.values())
        find_t = Text()

        sev_items = [
            ("CRITICAL", sc.get("Critical", 0), "bold red"),
            ("HIGH", sc.get("High", 0), "bold #e08040"),
            ("MEDIUM", sc.get("Medium", 0), "bold #c0a020"),
            ("LOW", sc.get("Low", 0), "bold #4a8a5e"),
            ("INFO", sc.get("Info", 0), "bold #5a8a9e"),
        ]

        for label, count, dot_style in sev_items:
            pct_val = (count / total_findings * 100) if total_findings > 0 else 0.0
            find_t.append("  ● ", style=dot_style)
            find_t.append(f"{label:<10}", style=dot_style)
            find_t.append(f"{count:>3}", style="bold white")
            find_t.append(f"  {pct_val:>5.1f}%\n", style="#666050")

        # Threat risk bar
        risk_score = (sc.get('Critical', 0) * 4) + (sc.get('High', 0) * 2) + (sc.get('Medium', 0) * 1)
        if risk_score == 0:
            t_label, t_color, t_bar = "LOW", "#4a8a5e", "░░░░░░░░░░"
        elif risk_score <= 3:
            t_label, t_color, t_bar = "MODERATE", "#c0a020", "███░░░░░░░"
        elif risk_score <= 7:
            t_label, t_color, t_bar = "HIGH", "#e08040", "██████░░░░"
        else:
            t_label, t_color, t_bar = "CRITICAL", "bold red", "██████████"

        find_t.append(f"\n  [{t_bar}] ", style=t_color)
        find_t.append(f"{t_label}", style=t_color)

        findings_panel = Panel(
            find_t,
            title="[bold #c8a832]FINDINGS[/bold #c8a832]",
            title_align="left",
            border_style="#3a3a2a",
            box=box.ROUNDED,
            padding=(0, 0),
        )

        # -- RECENT ACTIVITY Panel --
        act_t = Text()

        # Critical alert banner
        crit_finding = next((f for f in reversed(snap_recent_findings) if f.get("severity") == "Critical"), None)
        if crit_finding:
            act_t.append(f" ⚡ CRITICAL: {crit_finding['title'][:28]}\n", style="bold white on red")

        events_snapshot = snap_events
        if not events_snapshot:
            act_t.append("  Waiting for events...\n", style="dim #3a3a3a")
        else:
            for evt_text, evt_style, ev_time in events_snapshot[-7:]:
                t_str = time.strftime("%H:%M:%S", time.localtime(ev_time))
                # Determine icon based on event content
                if any(ch in evt_text for ch in ("✔", "✓")) or "found" in evt_text.lower():
                    ev_icon, ev_ic_style = "✓", "bold #4a8a5e"
                elif "!" in evt_text[:3] or "critical" in evt_text.lower():
                    ev_icon, ev_ic_style = "⚡", "bold red"
                elif "⚠" in evt_text or "warning" in evt_text.lower():
                    ev_icon, ev_ic_style = "·", "bold #c0a020"
                elif "✖" in evt_text or "error" in evt_text.lower() or "fail" in evt_text.lower():
                    ev_icon, ev_ic_style = "✗", "bold red"
                else:
                    ev_icon, ev_ic_style = "▸", "#c8a832"

                act_t.append(f" [{t_str}] ", style="#666050")
                act_t.append(f"{ev_icon} ", style=ev_ic_style)
                disp_text = evt_text[:30] if len(evt_text) > 30 else evt_text
                act_t.append(f"{disp_text}\n", style=evt_style)

        act_panel = Panel(
            act_t,
            title="[bold #c8a832]☠ RECENT ACTIVITY[/bold #c8a832]",
            title_align="left",
            subtitle=f"[#666050]{min(len(events_snapshot), 7)} latest[/#666050]",
            subtitle_align="right",
            border_style="#3a3a2a",
            box=box.ROUNDED,
            padding=(0, 0),
        )

        right_col = Group(findings_panel, act_panel)

#  3-COLUMN or STACKED LAYOUT
        if tw >= 100:
            mid_grid = Table.grid(expand=True)
            mid_grid.add_column(ratio=3)
            mid_grid.add_column(ratio=5)
            mid_grid.add_column(ratio=3)
            mid_grid.add_row(pipe_panel, scan_activity_panel, right_col)
            mid_section = mid_grid
        else:
            # Narrower: 2-column or stacked
            top_mid = Table.grid(expand=True)
            top_mid.add_column(ratio=1)
            top_mid.add_column(ratio=1)
            top_mid.add_row(pipe_panel, Group(scan_activity_panel, findings_panel))
            mid_section = Group(top_mid, act_panel)

#  BOTTOM FOOTER BAR
        ftr_grid = Table.grid(expand=True)
        ftr_grid.add_column(ratio=3)
        ftr_grid.add_column(ratio=2, justify="center")
        ftr_grid.add_column(ratio=4, justify="right")

        # System status (psutil if available, graceful fallback)
        sys_t = Text()
        sys_t.append("⚙ SYSTEM STATUS\n", style="bold #666050")
        _now = time.time()
        if _now - getattr(self, '_sys_stats_time', 0) > 2.0:
            try:
                import psutil as _psutil
                _cpu = _psutil.cpu_percent(interval=0)
                _ram = _psutil.virtual_memory().percent
                _disk = _psutil.disk_usage('/').percent
                _net = _psutil.net_io_counters()
                _total_bytes = _net.bytes_sent + _net.bytes_recv
                _prev = getattr(self, '_prev_net_bytes', _total_bytes)
                _dt_s = _now - getattr(self, '_sys_stats_time', _now)
                _net_spd = ((_total_bytes - _prev) / _dt_s / (1024 * 1024)) if _dt_s > 0 else 0.0
                self._prev_net_bytes = _total_bytes
                self._sys_cache = (_cpu, _ram, _disk, _net_spd)
            except Exception:
                self._sys_cache = None
            self._sys_stats_time = _now

        _sc = getattr(self, '_sys_cache', None)
        if _sc:
            sys_t.append(f"⊙ CPU {_sc[0]:.0f}%  ", style="#d0c8a0")
            sys_t.append(f"⊙ RAM {_sc[1]:.0f}%  ", style="#d0c8a0")
            sys_t.append(f"⊙ DISK {_sc[2]:.0f}%  ", style="#d0c8a0")
            sys_t.append(f"⊙ NET {_sc[3]:.1f} MB/s", style="#d0c8a0")
        else:
            sys_t.append("⊙ CPU --  ⊙ RAM --  ⊙ DISK --  ⊙ NET --", style="#3a3a3a")

        # Center branding
        brand_c = Text()
        brand_c.append("💀 ", style="bold red")
        brand_c.append("VERDAMT-SNIPE\n", style="bold #c8a832")
        brand_c.append("SILENT · PRECISE · RELENTLESS", style="#666050")

        # Target summary
        summ_t = Text()
        summ_t.append("◎ TARGET SUMMARY\n", style="bold #666050")
        summ_t.append("⊙ HOSTS ", style="#666050")
        summ_t.append(f"{snap_metrics.get('Live Hosts', 0) or 1}  ", style="bold white")
        summ_t.append("⊙ ENDPOINTS ", style="#666050")
        summ_t.append(f"{snap_metrics.get('Endpoints', 0)}  ", style="bold white")
        summ_t.append("⊙ SUBDOMAINS ", style="#666050")
        summ_t.append(f"{snap_metrics.get('Subdomains', 0)}  ", style="bold white")
        summ_t.append("⊙ PARAMS ", style="#666050")
        summ_t.append(f"{snap_metrics.get('Parameters', 0)}", style="bold white")

        ftr_grid.add_row(sys_t, brand_c, summ_t)
        footer_panel = Panel(ftr_grid, border_style="#3a3a2a", box=box.HEAVY, padding=(0, 1))

#  COMPOSE FULL DASHBOARD
        return Group(header_panel, mid_section, footer_panel)


# BANNER

def count_request() -> None:
    """Count one actually-dispatched HTTP request (dashboard TOTAL REQ/REQ-S).

    Called from client dispatch points — replaces the old behaviour of
    incrementing 'Requests' for every log line (which measured log volume,
    not traffic).
    """
    dash = ScanDashboard._instance
    if dash is not None:
        with dash._lock:
            dash.metrics["Requests"] += 1


def print_banner(version, author):
    if os.name == 'posix':
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    else:
        os.system('cls')
    tw = _get_term_width()
    print()

    # Glitch-animated banner render
    glitch_chars = "!<>-_\\\\/[]{}—=+*^?#@$%&"
    for idx, line in enumerate(_BANNER_LINES):
        # Glitch pass: briefly show corrupted line
        clean = strip_ansi(line)
        if len(clean) > 4 and random.random() > 0.3:
            corrupted = list(clean)
            for _ in range(random.randint(2, 5)):
                pos = random.randint(0, len(corrupted) - 1)
                corrupted[pos] = random.choice(glitch_chars)
            sys.stdout.write(f"\r{M}{''.join(corrupted)}{N}")
            sys.stdout.flush()
            time.sleep(0.02)
        sys.stdout.write(f"\r{line}\n")
        sys.stdout.flush()
        time.sleep(0.01)

    print()
    console.print(Rule(style="bright_black"))
    print()

    # Flags panel using Rich
    flags_content = Text()
    flags_content.append("  FLAGS\n", style="bold white")
    flags_content.append(f"  {'━'*28}\n", style="bright_black")
    flag_items = [
        ("--stealth", "Stealth jitter & headers"),
        ("--turbo", "Max concurrency"),
        ("--impersonate", "TLS fingerprint spoof"),
        ("--proxy", "Proxy URL (socks5://ip:port)"),
        ("--proxy-list", "Proxy list file path"),
        ("--max-time", "Time budget in seconds"),
        ("--resume", "Resume from saved state"),
        ("--bearer", "Auth header"),
        ("--cookie", "Cookie header"),
        ("-H / -H2", "Custom role headers"),
    ]
    for flag, desc in flag_items:
        flags_content.append(f"  {flag:<16}", style="cyan")
        flags_content.append(f"{desc}\n", style="white")

    console.print(Panel(
        flags_content,
        border_style="bright_black",
        box=box.ROUNDED,
        expand=False,
        padding=(0, 1),
    ))

    print()
    # Version line with style
    console.print(f"  [cyan]v{version}[/] [bright_black]•[/] [magenta]{author}[/] [bright_black]•[/] [bright_black]recon[/][dim]·[/][bright_black]scan[/][dim]·[/][bright_black]assault[/]")
    console.print(Rule(style="bright_black"))
    print()


# THREAD-SAFE RICH OUTPUT FUNCTIONS

def _rich_print(msg):
    console.print(msg)

def p(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(f"{_RARROW} {strip_ansi(str(msg))}", "cyan")
    else:
        _rich_print(f"  [bold #5a8a9e]{_RARROW}[/] {msg}")

def i(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(f"{_INFO} {strip_ansi(str(msg))}", "bright_black")
    else:
        _rich_print(f"  [#555555]{_INFO}[/] {msg}")

def w(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_warning(strip_ansi(str(msg)))
    else:
        _rich_print(f"  [bold #c0a020]{_WARN}[/] [#c0a020]{msg}[/]")

def e(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_error(strip_ansi(str(msg)))
    else:
        _rich_print(f"  [bold red]{_CROSS}[/] [red]{msg}[/]")

def s(msg):
    if ScanDashboard.active():
        ScanDashboard.get().log_event(f"{_CHECK} {strip_ansi(str(msg))}", "#4a8a5e")
    else:
        _rich_print(f"  [bold #4a8a5e]{_CHECK}[/] {msg}")

def ph(msg):
    """Animated phase transition header with brutalist styling."""
    if ScanDashboard.active():
        ScanDashboard.get().set_phase(msg)
        return

    console.print()
    tw = _get_term_width()

    # Build the phase header content
    phase_text = Text()
    phase_text.append(f" {_SKULL} ", style="bold red")
    phase_text.append(msg.upper(), style="bold white")

    panel = Panel(
        Align.center(phase_text),
        border_style="#C6A15B",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(0, 0),
    )
    console.print(panel)

def draw_box(title, lines, color=None):
    """Draw a labeled box with content lines using rich."""
    c = "cyan"
    if color == G: c = "green"
    elif color == R: c = "red"
    elif color == Y: c = "yellow"
    elif color == C: c = "cyan"

    text = "\n".join(lines)
    panel = Panel(
        Text.from_ansi(text),
        title=f"[bold white] {_DIAMOND} {title} [/]",
        title_align="left",
        border_style=c,
        expand=False,
        padding=(1, 3),
        box=box.HEAVY
    )
    console.print(panel)


def draw_table(headers, rows, padding=2, title=None):
    """Animated table rendering with premium styling."""
    if not rows: return
    table = Table(
        title=f" {_TARGET} {title} " if title else None,
        title_style="bold white",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_black",
        box=box.SIMPLE_HEAVY,
        row_styles=["", "dim"],
        padding=(0, 2),
        show_lines=False,
    )
    for h in headers:
        table.add_column(h)

    for i, r in enumerate(rows):
        table.add_row(*[Text.from_ansi(str(x)) for x in r])

    console.print(table)


# ANIMATED COMPONENTS

class Spinner:
    """Enhanced multi-task capable Spinner using rich.progress.

    When a ScanDashboard is active, the Spinner delegates to the
    dashboard's activity indicator instead of creating its own
    Rich Progress (avoids nested Live conflicts).
    """
    def __init__(self, message="Processing", interval=0.1):
        self.message = message
        self._dashboard_mode = ScanDashboard.active()
        self._running = False
        self._live = None

        if not self._dashboard_mode:
            self.progress = Progress(
                SpinnerColumn(spinner_name="dots", style="magenta"),
                TextColumn("  [bold cyan]{task.description}[/]"),
                TimeElapsedColumn(),
                console=console,
                transient=True
            )
            self.task_id = None
        else:
            self.progress = None
            self.task_id = None

    def start(self):
        if self._running:
            return
        if self._dashboard_mode:
            ScanDashboard.get().set_activity(self.message)
            self._running = True
        else:
            self.task_id = self.progress.add_task(self.message, total=None)
            self.progress.start()
            self._running = True

    def stop(self):
        if not self._running:
            return
        if self._dashboard_mode:
            ScanDashboard.get().set_activity("")
            self._running = False
        else:
            self.progress.stop()
            self._running = False

    def update(self, message):
        self.message = message
        if self._dashboard_mode:
            if self._running:
                ScanDashboard.get().set_activity(message)
        else:
            if self._running and self.task_id is not None:
                self.progress.update(self.task_id, description=message)

    def next(self):
        if self._dashboard_mode:
            return
        if not self._running:
            self.start()

def loading_animation(stop_flag=None, timeout=30):
    """Progress bar style loading animation using rich."""
    start = time.time()

    # Phase 1: Quick initialization steps
    init_steps = [
        "Loading modules...",
        "Initializing async engine...",
        "Warming up TLS stack...",
        "Ready to engage.",
    ]

    with Progress(
        SpinnerColumn(spinner_name="dots", style="magenta"),
        TextColumn("  [bold cyan]{task.description}[/]"),
        BarColumn(bar_width=40, complete_style="magenta", finished_style="green", pulse_style="cyan"),
        TimeElapsedColumn(),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(init_steps[0], total=len(init_steps))
        for idx, step in enumerate(init_steps):
            progress.update(task, description=step, completed=idx)
            time.sleep(random.uniform(0.05, 0.15))
        progress.update(task, completed=len(init_steps))

    elapsed = time.time() - start
    console.print(f"  [bold green]{_CHECK}[/] [white]Engine initialized[/] [bright_black]({elapsed:.1f}s)[/]")
    print()


def progress_bar(iterable, total=0, prefix='', length=30):
    """Simple progress bar wrapping an iterable using rich.

    When a ScanDashboard is active, yields items normally but routes
    progress updates through the dashboard instead of creating a
    separate Rich Progress bar.
    """
    if not total:
        total = 100 # fallback

    if ScanDashboard.active():
        dashboard = ScanDashboard.get()
        count = 0
        for item in iterable:
            yield item
            count += 1
            if count % max(1, total // 50) == 0 or count == total:
                dashboard.set_activity(f"{prefix} {count}/{total}")
        dashboard.set_activity("")
        dashboard.log_event(f"{_CHECK} {prefix} {total}/{total}", "green")
    else:
        with Progress(
            SpinnerColumn(spinner_name="dots", style="magenta"),
            TextColumn(f"  [bright_black]{prefix}[/]"),
            BarColumn(bar_width=length, complete_style="cyan", finished_style="green"),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task("Working", total=total)
            for item in iterable:
                yield item
                progress.update(task, advance=1)

        console.print(f"  [bold green]{_CHECK}[/] [bright_black]{prefix}[/] [white]{total}/{total}[/]")


# INTERACTIVE TUI

def draw_interactive_menu(target, settings, selected_mode=None):
    """Draw the interactive TUI using Rich panels."""
    if os.name == 'posix':
        sys.stdout.write('\033[2J\033[H')
        sys.stdout.flush()
    else:
        os.system('cls')

    # Banner (compact)
    banner_text = Text()
    banner_text.append("  VERDAMMT", style="bold white")
    banner_text.append("-", style="bright_black")
    banner_text.append("SNIPE", style="bold magenta")
    banner_text.append("  ", style="")
    banner_text.append(_SKULL, style="bold magenta")

    console.print()
    console.print(Panel(
        Align.center(banner_text),
        border_style="magenta",
        box=box.DOUBLE_EDGE,
        expand=True,
        padding=(0, 0),
    ))
    console.print()

    # Mode Selection Panel
    mode_lines = []
    for key, (mode_id, label, desc) in _MODES.items():
        icon = _MODE_ICONS.get(key, "")
        if selected_mode == key:
            mode_lines.append(f"  [bold magenta]{_DIAMOND}[/] [bold cyan][{key}][/] [bold white]{label:<13}[/] [white]{desc}[/]")
        else:
            mode_lines.append(f"    [cyan][{key}][/] [white]{label:<13}[/] [bright_black]{desc}[/]")
    mode_content = "\n".join(mode_lines)

    # Settings Panel
    st_val = "[bold green]ON[/]" if settings.get('stealth') else "[bold red]OFF[/]"
    tb_val = "[bold green]ON[/]" if settings.get('turbo') else "[bold red]OFF[/]"
    pr_val = f"[white]{settings.get('proxy')}[/]" if settings.get('proxy') else "[bright_black]none[/]"
    im_val = f"[white]{settings.get('impersonate')}[/]" if settings.get('impersonate') else "[bright_black]chrome[/]"

    settings_lines = [
        f"  [cyan]\\[S][/] Stealth     {st_val}",
        f"  [cyan]\\[T][/] Turbo       {tb_val}",
        f"  [cyan]\\[P][/] Proxy       {pr_val}",
        f"  [cyan]\\[I][/] Impersonate {im_val}",
    ]
    settings_content = "\n".join(settings_lines)

    # Print panels side by side using Columns
    mode_panel = Panel(
        mode_content,
        title="[bold white] SCAN MODES [/]",
        title_align="left",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(1, 1),
        expand=True,
    )
    settings_panel = Panel(
        settings_content,
        title="[bold white] SETTINGS [/]",
        title_align="left",
        border_style="bright_black",
        box=box.ROUNDED,
        padding=(1, 1),
        expand=True,
    )

    console.print(Columns([mode_panel, settings_panel], expand=True, padding=(0, 1)))
    console.print()

    # Target Info Bar
    target_line = Text()
    target_line.append(f"  {_TARGET} ", style="cyan")
    target_line.append("Target: ", style="bright_black")
    target_line.append(target, style="bold white")

    if selected_mode and selected_mode in _MODES:
        _, label, _ = _MODES[selected_mode]
        target_line.append("  │  ", style="bright_black")
        target_line.append("Mode: ", style="bright_black")
        target_line.append(label, style="bold green")

    console.print(target_line)
    console.print()

    if selected_mode:
        console.print(f"  [bold green]{_CHECK}[/] Mode selected. Press [bold green]\\[G][/] to [bold green]GAS[/] or [cyan]\\[Q][/] to cancel")
    mode_hint = f"1-{max(int(k) for k in _MODES)}"
    console.print(f"  [cyan]{_RARROW}[/] Select mode [cyan]\\[{mode_hint}][/] or toggle [cyan]\\[S/T/P/I/H][/]: ", end="")


def draw_help_screen():
    help_text = Text()

    # Usage section
    help_text.append("  USAGE\n", style="bold white")
    help_text.append(f"  {'━'*40}\n", style="bright_black")
    help_text.append("  snipe", style="cyan")
    help_text.append(" <target>             ", style="white")
    help_text.append("→ interactive mode\n", style="bright_black")
    help_text.append("  snipe", style="cyan")
    help_text.append(" <mode> <target>      ", style="white")
    help_text.append("→ direct mode\n\n", style="bright_black")

    # Modes section
    help_text.append("  MODES\n", style="bold white")
    help_text.append(f"  {'━'*40}\n", style="bright_black")
    for key, (mode_id, label, desc) in _MODES.items():
        icon = _MODE_ICONS.get(key, "")
        help_text.append(f"  {icon} ", style="")
        help_text.append(f"[{key}]", style="cyan")
        help_text.append(f"  {label:<13}", style="white")
        help_text.append(f"{desc}\n", style="bright_black")

    help_text.append("\n", style="")

    # Flags section
    help_text.append("  FLAGS\n", style="bold white")
    help_text.append(f"  {'━'*40}\n", style="bright_black")
    flags = [
        ("-s  --stealth", "Camouflage + jitter + headers"),
        ("-t  --turbo", "Max concurrency (no delays)"),
        ("-p  --proxy", "Proxy URL (socks5://ip:port)"),
        ("-i  --impersonate", "TLS fingerprint spoof"),
        ("-r  --resume", "Resume from saved state"),
        ("    --max-time", "Global scan timeout in seconds"),
        ("    --passive", "Allow passive methods/tools only"),
        ("    --max-requests", "Maximum target HTTP requests"),
        ("    --max-concurrency", "Maximum concurrent target requests"),
        ("    --request-timeout", "Maximum timeout per target request"),
        ("    --allowed-hosts", "Additional exact hosts/IPs in scope"),
        ("    --allowed-ports", "Comma-separated ports (default: 80,443)"),
        ("    --proxy-list", "Load proxies from file"),
        ("    --proxy-rotate", "Rotate proxy every N requests"),
        ("    --bearer", "Bearer token for authenticated scans"),
        ("    --cookie", "Cookie header for authenticated scans"),
        ("    -H / -H2", "Custom headers for role 1 / role 2"),
        ("    --jwt", "Enable JWT module focus"),
        ("    --idor", "Enable IDOR module focus"),
        ("    --crlf", "Enable CRLF module focus"),
        ("    --host-inject", "Enable Host header module focus"),
        ("    --stored-xss", "Enable stored XSS module focus"),
    ]
    for flag, desc in flags:
        help_text.append(f"  {flag:<24}", style="cyan")
        help_text.append(f"{desc}\n", style="white")

    help_text.append("\n", style="")

    # Examples section
    help_text.append("  EXAMPLES\n", style="bold white")
    help_text.append(f"  {'━'*40}\n", style="bright_black")
    examples = [
        "snipe 6 target.com                 → fast baseline",
        "snipe 4 target.com -s -p socks5://1.2.3.4:1080",
        "python3 verd.py target.com --nuclei --max-time 180",
        "snipe target.com                 → interactive",
    ]
    for ex in examples:
        help_text.append(f"  $ {ex}\n", style="cyan")

    panel = Panel(
        help_text,
        title=f"[bold white] {_SKULL} HELP — VERDAMT SNIPE [/]",
        title_align="left",
        border_style="cyan",
        box=box.HEAVY,
        expand=False,
        padding=(1, 2),
    )
    console.print(panel)
    print()

def draw_confirm_bar(mode, target, settings):
    st = f"{G}{_CHECK} ON{N}" if settings.get('stealth') else f"{R}{_CROSS} OFF{N}"
    tb = f"{G}{_CHECK} ON{N}" if settings.get('turbo') else f"{R}{_CROSS} OFF{N}"
    pr = settings.get('proxy') or f"{GY}none{N}"
    im = settings.get('impersonate') or f"{GY}chrome{N}"

    lines = [
        f"  {C}{_ARROW_R} Mode:{N}       {W}{mode.upper()}{N}",
        f"  {C}{_ARROW_R} Target:{N}     {W}{target}{N}",
        f"  {C}{_ARROW_R} Stealth:{N}    {st}",
        f"  {C}{_ARROW_R} Turbo:{N}      {tb}",
        f"  {C}{_ARROW_R} Proxy:{N}      {pr}",
        f"  {C}{_ARROW_R} Impersonate:{N} {im}",
    ]
    draw_box(f"{_SKULL} READY TO ENGAGE", lines, color=G)
    print(f"\n  {G}{_CHECK}{N} Confirm & start? [{G}Y{N}/n]: ", end="")
