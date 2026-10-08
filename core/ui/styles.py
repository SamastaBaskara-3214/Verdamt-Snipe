"""styles — verbatim split from ui.py (no logic changes)."""
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
