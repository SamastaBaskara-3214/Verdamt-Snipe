"""state — verbatim split from poison.py (no logic changes)."""
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



from core.external_tools import _find_tool
from core.ui import ph, i, w, s, p, G, C, B, N
from core.proxy_manager import get_global_proxy_manager
from modules.wordlists import WordlistProvider, PROVIDER
from runners.shared import inject_query_payload


# Credential wordlists live in modules/wordlists.py (PROVIDER).

COMMON_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "letmein"), ("admin", "pass"),
    ("user", "user"), ("test", "test"), ("guest", "guest"),
    ("root", "root"), ("admin", "changeme"), ("admin", "password123"),
    ("administrator", "password"), ("admin", "qwerty"),
    ("admin", "admin1234"), ("admin", "12345678"),
    ("admin", ""), ("admin", "admin1"), ("admin", "P@ssw0rd"),
    ("admin", "administrator"), ("admin", "owasp"),
]

# Shared helpers: deadline / budget / auth classification

REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Phase 0 (origin hunt + 9 bypass categories) legitimately needs 40-50s
# through a proxy; this is the runaway cap so it can never hold the whole run.
PHASE0_TIME_CAP = 90

# Adaptive concurrency — decisions run on the rolling MEDIAN of real request
# latencies (fed by AsyncNetworkEngine), never on a phase duration.
LATENCY_WINDOW = 64          # request samples kept for the median
LATENCY_WARMUP = 16          # samples needed before any decision
LATENCY_ADAPT_EVERY = 8      # re-evaluate every N samples (anti-flap)
LATENCY_SLOW_FACTOR = 2.0    # median > 2x baseline  → -30% concurrency
LATENCY_STRAIN_FACTOR = 5.0  # median > 5x baseline  → strained + halve
WAVE_ESCALATION_COOLDOWN = 20  # s without a reduction before +50 is allowed

# ffuf sends one request per word plus a handful of -ac calibration probes —
# this allowance is added to the exact wordlist count when debiting budget.
FFUF_CALIBRATION_OVERHEAD = 10

_FAIL_LOGIN_KEYWORDS = [
    "invalid", "incorrect", "wrong", "error", "failed",
    "password salah", "username tidak", "not found",
]

_COOKIE_NAME_RE = re.compile(r"(?:^|,)\s*([^=;,\s]+)=")


def _get_header(headers, name: str) -> str:
    """Case-insensitive header lookup.

    httpx lowercases keys in ``dict(response.headers)``, other transports keep
    the wire casing — callers must not depend on one of them.
    """
    if not headers:
        return ""
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    for key in (name, name.lower(), name.title()):
        try:
            value = getter(key)
        except Exception:
            value = None
        if isinstance(value, str) and value:
            return value
    return ""


def _cookie_names(raw: str) -> Set[str]:
    """Cookie names from a (possibly comma-joined) Set-Cookie header.

    Splits on a comma only when ``name=`` follows it, so an attribute value
    like ``Expires=Wed, 21 Oct 2015 07:28:00 GMT`` is not parsed as a cookie.
    """
    return set(_COOKIE_NAME_RE.findall(raw or ""))


def _loc_path(location: str) -> str:
    """Path part of a Location header — identity of a redirect target."""
    return (urlparse(location or "").path or "/").rstrip("/") or "/"


def _budget_ok(state) -> bool:
    """False once the scan policy request budget is exhausted.

    ffuf / connection exhaust / smuggling never reach AsyncNetworkEngine, so
    the policy gate has to be consulted before they are dispatched.
    """
    policy = state.policy
    if policy is None:
        return True
    remaining = policy.requests_remaining
    return remaining is None or remaining > 0


def _ffuf_timeout(state) -> int:
    """ffuf wall-clock budget, never beyond the remaining scan duration."""
    return max(1, min(45, int(state.time_left)))


def _charge_external(state, n: int, what: str) -> bool:
    """Debit n requests for a generator that bypasses ahttp_send.

    Returns False when the budget cannot afford n — the caller must then NOT
    start that generator, because running it would push total traffic past
    max_requests. n must be an exact count or a documented upper bound.
    """
    policy = state.policy
    if policy is None:
        return True
    remaining = policy.requests_remaining
    if remaining is None:
        return True
    if remaining < n:
        return False
    return policy.charge(n, reason=what) == n


def _classify_login_attempt(status: int, headers, body: str,
                             baseline: dict) -> Optional[Tuple[str, str]]:
    """Multi-signal login success detection against a failed-login baseline.

    Returns (confidence, detail) or None.

    Signal 1 (redirect) only counts when the redirect DIFFERS from the one the
    failed login produced, or when no baseline exists at all (then it is
    "suspected", not "confirmed"). The previous version accepted any 3xx and
    reported "confirmed" credentials on endpoints that always redirect.
    """
    location = _get_header(headers, "location")

    if status in REDIRECT_STATUSES:
        if baseline.get("status") in REDIRECT_STATUSES:
            differs = _loc_path(location) != baseline.get("loc_path", "")
        else:
            # Baseline did not redirect (2xx/4xx/5xx) or was never captured.
            differs = True
        if differs:
            suffix = "" if baseline.get("status") else " (no failed-login baseline)"
            confidence = "confirmed" if baseline.get("status") else "suspected"
            return confidence, f"Status {status} → {location[:60]}{suffix}"

    new_cookies = (_cookie_names(_get_header(headers, "set-cookie"))
                   - baseline.get("cookies", set()))
    if new_cookies and status == 200:
        return "suspected", f"New cookies: {','.join(sorted(new_cookies))}"

    fail_body = baseline.get("body", "")
    if fail_body and body and status == 200:
        if not any(k in body for k in _FAIL_LOGIN_KEYWORDS):
            len_diff = abs(len(body) - len(fail_body)) / max(len(fail_body), 1)
            if len_diff > 0.3:
                return "suspected", f"Body diff {len_diff:.0%} vs failed attempt"
    return None


# Shared State

class PoisonState:
    """Live state shared across all phases — mutations propagate immediately."""
    def __init__(self, target, seed_url, services, subs, scan_urls, scope_guard,
                 session_manager, async_engine, is_turbo, auth_headers=None,
                 policy=None):
        self.target = target
        self.seed_url = seed_url
        self.services = services
        self.subs = subs
        self.scan_urls = set(scan_urls)
        self.scope_guard = scope_guard
        self.session_manager = session_manager
        self.async_engine = async_engine
        self.policy = policy
        self.is_turbo = is_turbo
        self.auth_headers = auth_headers or {}
        self.module_flags = {}

        self.findings: List[Dict] = []
        self.params: Dict[str, List[str]] = {}
        self.target_wafs: Set[str] = set()
        self.poisoned_headers: List[str] = []
        self.origin_ip: Optional[str] = None
        self.smuggle_confirmed: bool = False
        self.baseline_time: float = 0.0
        # Baseline bodies captured in earlier waves — reused when a wave is
        # too short to fetch fresh ones (avoids empty-baseline FP markers).
        self._url_baselines: Dict[str, str] = {}
        self.last_phase_duration: float = 0.0
        self.current_concurrency: int = 100
        self.server_strained: bool = False
        self.wave: int = 1
        self.start_time: float = time.time()
        self.max_duration: int = 120

        # Session rotation tracking
        self.session_cookies: Dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._sync_lock = __import__("threading").Lock()
        # Dedup index: O(1) membership instead of rebuilding the key set on
        # every insertion (that was O(n) per insert, O(n^2) cumulative).
        self._finding_keys: Set[tuple] = set()
        # URLs whose hidden params were already fuzzed this run — the top-N
        # target list is stable, so A1/A3/later waves would repeat identical
        # param discovery without it.
        self._param_scanned: Set[str] = set()
        # Adaptive concurrency: rolling window of real per-request latencies
        # plus the timestamp of the last downscale (hysteresis for escalation).
        self.latency_window = deque(maxlen=LATENCY_WINDOW)
        self._latency_samples = 0
        self._last_reduce_ts = 0.0
        self._strain_ticks = 0
        self._backoff_notice_wave = -1

    @staticmethod
    def _finding_key(f: dict) -> tuple:
        """Dedup key — matches phase_verify_report dedup logic."""
        return (f.get("type", ""), f.get("url", ""), f.get("detail", "")[:120])

    @property
    def elapsed(self) -> float:
        return time.time() - self.start_time

    @property
    def time_left(self) -> float:
        return max(0, self.max_duration - self.elapsed)

    async def add_finding_async(self, f: dict):
        async with self._lock:
            key = self._finding_key(f)
            if key not in self._finding_keys:
                self.findings.append(f)
                self._finding_keys.add(key)

    def add_finding(self, f: dict):
        with self._sync_lock:
            key = self._finding_key(f)
            if key not in self._finding_keys:
                self.findings.append(f)
                self._finding_keys.add(key)

    async def extend_findings_async(self, flist: list):
        async with self._lock:
            for f in flist:
                key = self._finding_key(f)
                if key not in self._finding_keys:
                    self.findings.append(f)
                    self._finding_keys.add(key)

    def extend_findings(self, flist: list):
        with self._sync_lock:
            for f in flist:
                key = self._finding_key(f)
                if key not in self._finding_keys:
                    self.findings.append(f)
                    self._finding_keys.add(key)

    async def add_urls_async(self, urls: list):
        if self.scope_guard:
            urls = self.scope_guard.filter_urls(urls)
        async with self._lock:
            new_urls = set(urls) - self.scan_urls
            self.scan_urls.update(new_urls)
            return new_urls

    def add_urls(self, urls: list):
        with self._sync_lock:
            if self.scope_guard:
                urls = self.scope_guard.filter_urls(urls)
            new_urls = set(urls) - self.scan_urls
            self.scan_urls.update(new_urls)
            return new_urls

    def track_latency(self, start_time: float):
        """Record how long a PHASE took — observability only, no decisions.

        Phase duration is not request latency. Feeding it to the controller
        made a normal 45s ffuf run look like a strained server and locked the
        baseline to whatever phase finished first. Decisions live in
        track_request_latency(), fed per request by AsyncNetworkEngine.
        """
        elapsed = time.time() - start_time
        if elapsed > 0:
            self.last_phase_duration = elapsed

    def track_request_latency(self, latency: float):
        """Feed ONE real request latency (seconds) — the adaptive controller.

        current  = median of the last LATENCY_WARMUP samples (reacts fast,
                   still ignores single outliers)
        baseline = median of the first LATENCY_WARMUP samples, frozen until
                   either a strain event re-arms it or the server proves
                   faster (slow EMA drift downward)

        Decisions only run every LATENCY_ADAPT_EVERY samples, so neither a
        single slow request nor a burst of fast ones can flap concurrency.
        """
        if latency is None or latency <= 0:
            return
        self.latency_window.append(latency)
        self._latency_samples += 1

        if self._latency_samples < LATENCY_WARMUP:
            return
        if self._latency_samples == LATENCY_WARMUP:
            # Reference locked in from real samples (median, not first one).
            self.baseline_time = median(self.latency_window)
            return
        if self._latency_samples % LATENCY_ADAPT_EVERY:
            return

        recent = list(self.latency_window)[-LATENCY_WARMUP:]
        current = median(recent)
        if self.baseline_time <= 0:
            self.baseline_time = current
            return

        if current > self.baseline_time * LATENCY_STRAIN_FACTOR:
            self.server_strained = True
            self.current_concurrency = max(5, self.current_concurrency // 2)
            self._last_reduce_ts = time.time()
            self._strain_ticks += 1
            # Re-arm the baseline only once the slow level is CONFIRMED by a
            # second tick: the first tick's window still mixes old fast
            # samples with the new slow ones, and re-arming to that mixed
            # median would clear "strained" while the server still struggles.
            if self._strain_ticks >= 2:
                self.baseline_time = current
                self._strain_ticks = 0
        elif current > self.baseline_time * LATENCY_SLOW_FACTOR:
            self.current_concurrency = max(10, int(self.current_concurrency * 0.7))
            self._last_reduce_ts = time.time()
        else:
            self._strain_ticks = 0
            if self.server_strained:
                self.server_strained = False
            # Healthy: drift the baseline toward what the server is actually
            # doing now, so an old spike stops dictating sensitivity.
            self.baseline_time = self.baseline_time * 0.9 + current * 0.1

    def start_wave(self):
        self.wave += 1
        # Escalation is earned, not automatic. A blind +50 per wave undid
        # whatever the controller had just reduced (up → overload → down).
        if self.server_strained:
            return
        if time.time() - self._last_reduce_ts < WAVE_ESCALATION_COOLDOWN:
            return
        if (self.baseline_time > 0
                and len(self.latency_window) >= LATENCY_WARMUP
                and median(list(self.latency_window)[-LATENCY_WARMUP:])
                > self.baseline_time * LATENCY_SLOW_FACTOR):
            return
        # Each healthy wave: mutate wordlist entries, increase aggression
        self.current_concurrency = min(500, self.current_concurrency + 50)

    def get_high_value_targets(self, limit: int = 10) -> List[str]:
        """Prioritize targets: login pages, APIs, admin panels, config files."""
        priority_patterns = [
            (10, ["login", "signin", "auth", "admin"]),
            (9, ["api", "graphql", "rest", "v1", "v2"]),
            (8, ["config", "settings", "env", "debug"]),
            (7, ["upload", "import", "export", "download"]),
            (6, ["dashboard", "panel", "console", "manager"]),
            (5, ["search", "query", "filter", "sort"]),
        ]
        scored = []
        for url in self.scan_urls:
            url_lower = url.lower()
            score = 0
            for weight, patterns in priority_patterns:
                if any(p in url_lower for p in patterns):
                    score = weight
                    break
            scored.append((score, url))

        # Sort by score descending, then by URL length (shorter = more likely root)
        scored.sort(key=lambda x: (-x[0], len(x[1])))
        return [url for _, url in scored[:limit]]


# Helpers

def _get_proxy_flag() -> str:
    """Proxy URL for external runners (ffuf -x, WAF pipeline).

    ffuf rejects ``socks5h://`` ("Expected http, https or socks5 url") — Go's
    SOCKS5 client already sends hostnames to the proxy, so remote DNS is kept
    while the scheme is normalized to what the tool accepts.
    """
    pm = get_global_proxy_manager()
    proxy = pm.current_proxy if (pm and pm.current_proxy) else ""
    if proxy.startswith("socks5h://"):
        return "socks5://" + proxy[len("socks5h://"):]
    if proxy.startswith("socks4a://"):
        return "socks4://" + proxy[len("socks4a://"):]
    return proxy


# Phase: Payload Flood

# Inline vulnerability detection markers
_SQL_ERRORS = [r"sql syntax", r"unclosed quotation", r"warning: mysql",
               r"sqlite_error", r"postgresql.*error", r"ora-[0-9]{5}"]
_LFI_MARKERS = [r"root:x:0:0:", r"daemon:x:", r"bin:x:", r"\[fonts\]"]
_RCE_MARKERS = [r"uid=\d+\(\w+\)", r"gid=\d+\(\w+\)", r"www-data"]
_XSS_TRIGGERS = [r"alert\(1\)", r"prompt\(1\)", r"confirm\(1\)",
                 r"onerror=", r"onload=", r"onfocus=", r"ontoggle="]
_SSTI_EXPECTED = ["9801547", "49", "7777777"]


# POST body pass — bounded so the extra traffic stays small; every request
# goes through ahttp_send, so it is debited to max_requests and gated by
# budget / backoff / deadline like the rest of the flood.
POST_MAX_URLS = 5
POST_MAX_PARAMS = 3
POST_FALLBACK_PARAMS = ["q", "search", "comment", "message", "name"]
