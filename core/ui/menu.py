"""menu — verbatim split from ui.py (no logic changes)."""
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

from .banner import _MODES, _MODE_ICONS
from .styles import C, G, GY, N, R, W, _ARROW_R, _CHECK, _CROSS, _DIAMOND, _INFO, _RARROW, _SKULL, _TARGET, _WARN, _get_term_width, console, strip_ansi
from .tables import ScanDashboard, draw_box



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
        ("    --no-proxy", "Ignore VERDAMT_PROXY env fallback"),
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
