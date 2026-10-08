"""wave — verbatim split from poison.py (no logic changes)."""
import asyncio
import os
import re
import subprocess
import tempfile
import time
from collections import deque
from statistics import median
from urllib.parse import urlparse, urlencode
from typing import Dict, List, Optional, Set, Tuple
from core.external_tools import _find_tool
from core.ui import ph, i, w, s, p, G, C, B, N
from core.proxy_manager import get_global_proxy_manager
from modules.wordlists import WordlistProvider, PROVIDER
from runners.shared import inject_query_payload




def _hold_for_backoff(state, what: str) -> bool:
    """True while the target host sits inside a 429/403 backoff window.

    AsyncNetworkEngine already refuses its own requests during backoff, but
    ffuf and the raw-socket modules bypass the engine — without this check,
    'backoff' only throttles half the traffic while the other half keeps
    hammering a host that just said no. Logs once per wave.
    """
    if not state.services:
        return False
    limiter = getattr(state.async_engine, "host_limiter", None)
    checker = getattr(limiter, "is_backing_off", None)
    if not callable(checker):
        return False
    host = urlparse(state.services[0]["url"]).hostname or ""
    try:
        held = checker(host) is True
    except Exception:
        return False
    if held and state._backoff_notice_wave != state.wave:
        state._backoff_notice_wave = state.wave
        w(f"Host in 429/403 backoff — holding {what}")
    return held
