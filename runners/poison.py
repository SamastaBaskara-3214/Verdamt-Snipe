"""
POISON MODE — Event-Driven Orchestrator
===================================================
All phases run PARALLEL with intelligent orchestration.
Adaptive: real latency tracking → auto-scale concurrency.
Persistent: wave-based with smart mutation.
Intelligent: target prioritization, WAF-aware, session rotation.

Wave Architecture:
  Block A: Discovery (param flood + bruteforce + cache + smuggle + exhaust)
  Block B: Detection (OOB + payload flood + auto-chain)
  Block C: Assault (vuln modules + plugins)
  Block D: Intelligence (session rotation + target reprioritization)
"""
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


# Phase: Connection Exhaust

async def phase_connection_exhaust(state: PoisonState):
    """Connection Exhaust + adaptive monitoring."""
    from modules.web.connection_exhaust import ConnectionExhaust, EXHAUST_SOCKETS

    # Exhaust uses raw sockets (never billed by the policy), so it must stop
    # when the budget that governs every other generator is spent — and hold
    # while the host is already answering 429/403.
    if not _budget_ok(state):
        return
    if _hold_for_backoff(state, "connection exhaust"):
        return

    for sv in state.services[:2]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Exact debit: run() always attempts EXHAUST_SOCKETS connections.
        if not _charge_external(state, EXHAUST_SOCKETS, "connection-exhaust"):
            w(f"Budget cannot cover {EXHAUST_SOCKETS} exhaust sockets — skipping")
            break
        exhauster = ConnectionExhaust(
            sv["url"],
            timeout=min(30, int(state.time_left) // 2) if state.time_left > 5 else 10,
        )
        start = time.time()
        results = await exhauster.run()
        state.track_latency(start)

        if results.get("server_downgrade"):
            state.server_strained = True
        # Findings
        if results.get("total_time", 0) > 0:
            sl = results["slowloris"]
            pf = results["pool_flood"]
            cb = results["chunked_bomb"]
            total_refused = sl["refused"] + pf["refused"] + cb["refused"]
            total_open = sl["opened"] + cb["opened"]
            if total_refused > 50:
                state.add_finding({
                    "type": "conn_exhaust_pressure",
                    "title": "Connection Pool Under Pressure",
                    "url": sv["url"][:200],
                    "detail": f"{total_refused}/{total_open+total_refused} connections refused — pool exhaustion detected",
                    "confidence": "confirmed",
                })


# Phase: Cache Poisoning

async def phase_cache_poison(state: PoisonState):
    """Cache poisoning probe + delivery."""
    from modules.web.cache_poison import probe_unkeyed_headers, deliver_poisoned_payload

    if not _budget_ok(state):
        return

    base_urls = state.get_high_value_targets(5)
    for url in base_urls:
        if state.time_left < 5 or not _budget_ok(state):
            break
        start = time.time()
        findings = await probe_unkeyed_headers(url, state.async_engine, state.session_manager)
        state.track_latency(start)
        state.extend_findings(findings)

        # Extract poisoned headers from findings
        for f in findings:
            detail = f.get("detail", "")
            if "Header:" in detail:
                hdr = detail.split("Header: ", 1)[1].split(" — ", 1)[0].strip()
                if hdr and hdr not in state.poisoned_headers:
                    state.poisoned_headers.append(hdr)

        # Attempt cache delivery with poisoned headers
        if state.poisoned_headers:
            delivery = await deliver_poisoned_payload(
                url, state.async_engine, state.poisoned_headers,
                session_manager=state.session_manager,
            )
            state.extend_findings(delivery)


# Phase: Smuggling

async def phase_smuggling(state: PoisonState):
    """HTTP smuggling scan."""
    from modules.web.smuggling import scan_smuggling, SMUGGLE_REQUEST_BOUND

    if not _budget_ok(state):
        return
    if _hold_for_backoff(state, "smuggling probes"):
        return

    base_urls = [sv["url"] for sv in state.services[:3]]
    for url in base_urls:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Documented upper bound per host (see SMUGGLE_REQUEST_BOUND).
        if not _charge_external(state, SMUGGLE_REQUEST_BOUND, "smuggling"):
            w(f"Budget cannot cover {SMUGGLE_REQUEST_BOUND} smuggle probes — skipping")
            break
        start = time.time()
        findings = await scan_smuggling(url, state.async_engine, state.session_manager)
        state.track_latency(start)
        state.extend_findings(findings)
        if findings:
            state.smuggle_confirmed = True


# Phase: Bruteforce

async def _run_ffuf(base_url: str, wordlist: List[str], extension: str,
                    concurrency: int, timeout: int = 45, policy=None) -> List[str]:
    """Run ffuf, return discovered paths.

    ffuf never touches AsyncNetworkEngine, so the scan-policy gate has to live
    here: no dispatch once the request budget is spent, and -t is capped to
    what the budget can still afford.
    """
    ffuf_path = _find_tool("ffuf")
    if not ffuf_path:
        return []

    if policy is not None:
        remaining = policy.requests_remaining
        if remaining is not None:
            if remaining <= 0:
                return []
            concurrency = min(concurrency, remaining)
            # Debit the exact wordlist count (+ calibration allowance) and
            # only fuzz what the budget still covers — otherwise ffuf's
            # traffic stays invisible to max_requests. Charged only AFTER we
            # know the tool exists, so a missing ffuf costs no budget.
            affordable = min(len(wordlist),
                             max(0, remaining - FFUF_CALIBRATION_OVERHEAD))
            if affordable <= 0:
                return []
            wordlist = wordlist[:affordable]
            if policy.charge(len(wordlist) + FFUF_CALIBRATION_OVERHEAD,
                             reason=f"ffuf:{urlparse(base_url).netloc}") <= 0:
                return []

    wl_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    for word in wordlist:
        wl_file.write(word + "\n")
    wl_file.close()

    url_parts = urlparse(base_url)
    base = f"{url_parts.scheme}://{url_parts.netloc}"
    ffuf_url = f"{base}/FUZZ{extension}"

    proxy = _get_proxy_flag()
    args = [
        ffuf_path, "-u", ffuf_url, "-w", wl_file.name,
        "-t", str(concurrency), "-ac", "-fc", "404,301,302", "-s",
    ]
    if proxy:
        args.extend(["-x", proxy])

    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []
        except asyncio.CancelledError:
            # Wave deadline hit: ffuf must not outlive max_duration.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception:
                pass
            raise
        found = []
        for line in stdout.decode(errors="replace").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                found.append(f"{base}{line}")
            elif line.startswith("http"):
                found.append(line)
            else:
                found.append(f"{base}/{line}")
        return found
    finally:
        os.unlink(wl_file.name)


async def phase_bruteforce(state: PoisonState):
    """Aggressive ffuf bruteforce — dirs, auth, extensions."""
    if not state.services:
        return
    if state.time_left < 5 or not _budget_ok(state):
        return
    if _hold_for_backoff(state, "ffuf bruteforce"):
        return

    base_url = state.services[0]["url"]
    concurrency = state.current_concurrency
    ffuf_timeout = _ffuf_timeout(state)
    wl = PROVIDER.get_dir_wordlist(wave=state.wave, limit=3000)

    # Dir bruteforce
    start = time.time()
    dirs = await _run_ffuf(base_url, wl, "", concurrency,
                           timeout=ffuf_timeout, policy=state.policy)
    state.track_latency(start)
    if dirs:
        state.add_urls(dirs)

    # Auth endpoints
    if state.time_left >= 5 and _budget_ok(state):
        auth_found = await _run_ffuf(
            base_url, PROVIDER.get_auth_wordlist(wave=state.wave, limit=500),
            "", concurrency, timeout=ffuf_timeout, policy=state.policy)
        state.add_urls(auth_found)

    # Extension bruteforce (shorter wordlist for speed)
    for ext in PROVIDER.get_extension_wordlist()[:8]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "ffuf extension run"):
            break
        ext_found = await _run_ffuf(base_url, PROVIDER.get_dir_wordlist(limit=100),
                                    ext, concurrency // 2,
                                    timeout=_ffuf_timeout(state), policy=state.policy)
        state.add_urls([u for u in ext_found if u])

    # Auth bruteforce on discovered login pages
    login_urls = [u for u in state.scan_urls
                  if any(x in u.lower() for x in ["login", "admin", "auth", "signin"])]
    for url in login_urls[:3]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Failed-login baseline: status + redirect target + cookies + body.
        # All four are needed for comparison — the old version kept only body
        # and cookie names, so any 3xx looked like a successful login.
        bad_data = urlencode({"username": "___nonexistent___", "password": "___wrong___", "submit": "1"})
        cred_headers = dict(state.auth_headers or {})
        cred_headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            fail_r = await state.async_engine.ahttp_send(
                url, method="POST", data=bad_data,
                headers=cred_headers, timeout=6,
                state_context=state.session_manager)
        except Exception:
            fail_r = {}
        if not isinstance(fail_r, dict):
            fail_r = {}
        fail_headers = fail_r.get("headers") or {}
        baseline = {
            "status": fail_r.get("status", 0) or 0,
            "loc_path": _loc_path(_get_header(fail_headers, "location")),
            "cookies": _cookie_names(_get_header(fail_headers, "set-cookie")),
            "body": (fail_r.get("body") or "").lower()[:2000],
        }

        found_creds = None
        for username, password in COMMON_CREDS:
            if state.time_left < 3:
                break
            form_data = urlencode({"username": username, "password": password, "submit": "1"})
            r = await state.async_engine.ahttp_send(
                url, method="POST", data=form_data,
                headers=cred_headers, timeout=5,
                state_context=state.session_manager)

            if not isinstance(r, dict):
                continue

            signal = _classify_login_attempt(
                r.get("status", 0), r.get("headers") or {},
                (r.get("body") or "").lower()[:2000], baseline,
            )
            if signal:
                found_creds = (username, password, signal[0], signal[1])
                break

        if found_creds:
            username, password, confidence, detail = found_creds
            state.add_finding({
                "type": "weak_credentials",
                "title": f"Weak Credentials: {username}:{password}",
                "url": url[:200],
                "detail": detail,
                "confidence": confidence,
            })
            # Store session cookies for rotation
            if confidence == "confirmed":
                state.session_cookies[url] = {"username": username, "password": password}


# Phase: Param Flood

async def phase_param_flood(state: PoisonState):
    """Massive Arjun param discovery."""
    from modules.extras.arjun import AsyncParamBruteforcer

    urls_to_scan = [u for u in state.get_high_value_targets(10)
                    if u not in state._param_scanned]
    for url in urls_to_scan:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Mark before the run so a wave that ends mid-scan does not restart it.
        state._param_scanned.add(url)
        bruteforcer = AsyncParamBruteforcer(
            url, state.async_engine,
            concurrency=state.current_concurrency // 2,
            chunk_size=20,
            session_manager=state.session_manager,
        )
        start = time.time()
        discovered = await bruteforcer.run()
        state.track_latency(start)
        if discovered:
            base_path = urlparse(url).path or "/"
            if base_path not in state.params:
                state.params[base_path] = []
            state.params[base_path].extend(discovered)


# Phase: Payload Flood

# Inline vulnerability detection markers
_SQL_ERRORS = [r"sql syntax", r"unclosed quotation", r"warning: mysql",
               r"sqlite_error", r"postgresql.*error", r"ora-[0-9]{5}"]
_LFI_MARKERS = [r"root:x:0:0:", r"daemon:x:", r"bin:x:", r"\[fonts\]"]
_RCE_MARKERS = [r"uid=\d+\(\w+\)", r"gid=\d+\(\w+\)", r"www-data"]
_XSS_TRIGGERS = [r"alert\(1\)", r"prompt\(1\)", r"confirm\(1\)",
                 r"onerror=", r"onload=", r"onfocus=", r"ontoggle="]
_SSTI_EXPECTED = ["9801547", "49", "7777777"]


def _detect_from_response(resp: dict, ptype: str, payload: str,
                          baseline_body: str) -> dict | None:
    """Quick inline detection — mirrors VulnVerifier but batched."""
    body = (resp.get("body") or "") if isinstance(resp, dict) else ""
    status = resp.get("status", 0) if isinstance(resp, dict) else 0
    if not body or status <= 0:
        return None

    if ptype == "xss":
        for t in _XSS_TRIGGERS:
            if re.search(t, body, re.I) and not re.search(t, baseline_body, re.I):
                return {"type": "reflected_xss", "title": "Reflected XSS",
                        "detail": f"Trigger: {t}", "confidence": "suspected"}
    elif ptype == "sqli":
        for ep in _SQL_ERRORS:
            if re.search(ep, body, re.I) and not re.search(ep, baseline_body, re.I):
                return {"type": "sqli_error", "title": "SQL Injection (Error-based)",
                        "detail": f"Error: {ep}", "confidence": "suspected"}
    elif ptype == "lfi":
        for ind in _LFI_MARKERS:
            if re.search(ind, body, re.I) and not re.search(ind, baseline_body, re.I):
                return {"type": "lfi", "title": "Local File Inclusion",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "rce":
        for ind in _RCE_MARKERS:
            if re.search(ind, body, re.I) and not re.search(ind, baseline_body, re.I):
                return {"type": "rce", "title": "RCE / Command Injection",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "ssti":
        for expected in _SSTI_EXPECTED:
            if expected in body and expected not in baseline_body:
                return {"type": "ssti", "title": "SSTI",
                        "detail": f"Computed: {expected}",
                        "confidence": "suspected"}
    return None


# POST body pass — bounded so the extra traffic stays small; every request
# goes through ahttp_send, so it is debited to max_requests and gated by
# budget / backoff / deadline like the rest of the flood.
POST_MAX_URLS = 5
POST_MAX_PARAMS = 3
POST_FALLBACK_PARAMS = ["q", "search", "comment", "message", "name"]


async def _post_payload_pass(state, targets, payload_types, bypass,
                             generate) -> int:
    """Form-body pass — the GET-only flood cannot see reflected POST sinks.

    ONE canary POST per candidate URL; only URLs that echo the canary value
    (the endpoint parses AND reflects form fields) are worth fuzzing, capped
    at POST_MAX_URLS x POST_MAX_PARAMS x types x 3 payloads. Returns the
    number of findings added. Findings are not auto-chained: the chain
    helpers inject via query string, which a POST-only param does not have.
    """
    import uuid

    found = 0
    reflectors = 0
    for url in targets[:POST_MAX_URLS]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "POST payload pass"):
            break

        path = urlparse(url).path or "/"
        params = state.params.get(path) or POST_FALLBACK_PARAMS
        canary = "vt" + uuid.uuid4().hex[:10]
        try:
            probe = await state.async_engine.ahttp_send(
                url, method="POST",
                data=urlencode({params[0]: canary}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5, state_context=state.session_manager)
        except Exception:
            continue
        if not isinstance(probe, dict):
            continue
        status = probe.get("status", 0)
        probe_body = probe.get("body") or ""
        if status <= 0 or status in (404, 405, 501) or not probe_body:
            continue
        if canary not in probe_body:
            continue           # field not parsed/reflected → POST fuzz = noise
        reflectors += 1

        post_jobs = []
        for param in params[:POST_MAX_PARAMS]:
            for ptype in payload_types:
                for payload in generate(ptype, bypass=bypass)[:3]:
                    form = urlencode({param: payload})
                    post_jobs.append(
                        (url, param, ptype, payload, probe_body,
                         lambda _u=url, _f=form: state.async_engine.ahttp_send(
                             _u, method="POST", data=_f,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=4, bypass=bypass,
                             state_context=state.session_manager)))

        for idx in range(0, len(post_jobs), 50):
            if state.time_left < 3 or not _budget_ok(state):
                break
            batch = post_jobs[idx:idx + 50]
            results = await asyncio.gather(*[j[5]() for j in batch],
                                            return_exceptions=True)
            for k, res in enumerate(results):
                if isinstance(res, Exception) or not isinstance(res, dict):
                    continue
                job_url, job_param, job_ptype, job_payload, baseline, _ = batch[k]
                finding = _detect_from_response(res, job_ptype, job_payload,
                                                baseline)
                if finding:
                    found += 1
                    finding["url"] = job_url[:200]
                    finding["detail"] = f"POST {job_param} | {finding['detail']}"
                    finding["waf"] = "/".join(res.get("waf") or [])
                    state.add_finding(finding)

    if reflectors:
        i(f"POST body pass: {reflectors} reflector(s), {found} hit(s)")
    return found


async def phase_payload_flood(state: PoisonState):
    """Mass injection + inline vulnerability detection with auto-chaining."""
    from modules.scanners.scanner import SmartPayloadGenerator

    if not _budget_ok(state):
        return

    payload_types = ["xss", "sqli", "lfi", "rce", "ssti"]
    bypass = state.wave % 2 == 1
    jobs = []

    # Use high-value targets first
    targets = state.get_high_value_targets(15)

    for url in targets:
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        params_to_test = state.params.get(base_path, [])
        if not params_to_test:
            params_to_test = ["q", "id", "url", "page", "file",
                              "redirect", "cmd", "search", "debug", "action"]

        for param in params_to_test[:5]:
            for ptype in payload_types:
                payloads = SmartPayloadGenerator.generate(ptype, bypass=bypass)
                for payload in payloads[:3]:
                    target = inject_query_payload(url, param, payload)
                    jobs.append((url, param, ptype, payload,
                                 lambda _t=target: state.async_engine.ahttp_send(
                                     _t, timeout=4, bypass=bypass,
                                     state_context=state.session_manager)))

    if not jobs:
        return

    total = len(jobs)
    found = 0
    i(f"[Wave {state.wave}] Payload Flood: {B}{total}{N} ({'bypass' if bypass else 'raw'}) + detection")

    # Get baseline per unique URL — PARALLEL with bounded concurrency.
    # A sequential loop here (the original shape) scales to unique_urls x 6s
    # timeout per wave; gather + Semaphore(20) keeps it to a few rounds.
    url_baselines = {}
    unique_urls = list(dict.fromkeys(j[0] for j in jobs))[:100]

    async def _fetch_baseline(u, sem):
        async with sem:
            try:
                start = time.time()
                br = await state.async_engine.ahttp_send(
                    u, timeout=6, state_context=state.session_manager)
                state.track_latency(start)
                return u, (br.get("body") or "") if isinstance(br, dict) else ""
            except Exception:
                return u, ""

    if unique_urls and state.time_left > 10:
        _bsem = asyncio.Semaphore(20)
        for res in await asyncio.gather(
                *[_fetch_baseline(u, _bsem) for u in unique_urls],
                return_exceptions=True):
            if isinstance(res, tuple):
                url_baselines[res[0]] = res[1]
        # Cache only non-empty bodies: a transient fetch failure ("") must
        # not wipe a good baseline captured in an earlier wave.
        state._url_baselines.update(
            {k: v for k, v in url_baselines.items() if v})
    else:
        # Wave almost over — reuse baselines from earlier waves instead of
        # emptying them (an empty baseline makes every guarded marker fire).
        url_baselines = {u: state._url_baselines.get(u, "")
                         for u in unique_urls}

    # Collect auto-chain targets (don't block the batch loop)
    auto_chain_targets = {"sqli": [], "lfi": []}

    batch_size = 200
    for idx in range(0, total, batch_size):
        if state.time_left < 5:
            break
        batch = jobs[idx:idx + batch_size]

        # Fire batch
        tasks = [j[4]() for j in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Detect from results
        for res_idx, result in enumerate(results):
            if isinstance(result, Exception) or result is None:
                continue
            url, param, ptype, payload, _ = batch[res_idx]
            baseline = url_baselines.get(url, "")
            if not baseline:
                # No baseline for this URL (new URL, fetch failed, and no
                # cached copy) — guarded markers would fire on ordinary
                # pages. Skip rather than fabricate a finding.
                continue
            finding = _detect_from_response(result, ptype, payload, baseline)
            if finding:
                finding["url"] = url[:200]
                finding["detail"] = f"Param: {param} | {finding['detail']}"
                finding["waf"] = "/".join(result.get("waf", [])) if isinstance(result, dict) else ""
                state.add_finding(finding)
                found += 1

                # Queue auto-chain targets (don't block batch)
                if ptype == "sqli":
                    auto_chain_targets["sqli"].append((url, param))
                elif ptype == "lfi":
                    auto_chain_targets["lfi"].append((url, param))

    # POST body pass — GET jobs above can only hit query-string sinks
    if targets and state.time_left > 5:
        found += await _post_payload_pass(state, targets, payload_types,
                                          bypass,
                                          SmartPayloadGenerator.generate)

    # Run auto-chains AFTER all batches complete (non-blocking)
    if auto_chain_targets["sqli"] and state.time_left > 8:
        for url, param in auto_chain_targets["sqli"][:3]:
            try:
                from modules.web.sqli_extractor import SQLiExtractor
                extractor = SQLiExtractor(state.async_engine, state.session_manager)
                extracted = await extractor.extract(url, param)
                if extracted:
                    state.extend_findings(extracted)
            except Exception as e:
                w(f"SQLi auto-chain error on {url[:60]}: {str(e)[:60]}")

    if auto_chain_targets["lfi"] and state.time_left > 12:
        for url, param in auto_chain_targets["lfi"][:3]:
            try:
                from modules.web.lfi_rce_chain import LFItoRCE
                chain = LFItoRCE(state.async_engine, state.session_manager)
                rce_findings = await chain.exploit(url, param)
                if rce_findings:
                    state.extend_findings(rce_findings)
            except Exception as e:
                w(f"LFI→RCE chain error on {url[:60]}: {str(e)[:60]}")

    if found:
        p(f"{G}{found}{N} vulns detected in payload flood wave {state.wave}")


# Phase: Vuln Assault

async def phase_vuln_assault(state: PoisonState):
    """Existing vuln modules — runs once per wave."""
    from runners.vuln_assault import run_vuln_assault

    # Pass origin IP discovered from previous waves
    if state.origin_ip:
        for sv in state.services:
            sv["origin_ip"] = state.origin_ip

    start = time.time()
    findings, wafs = await run_vuln_assault(
        state.target, state.services, list(state.scan_urls),
        state.params, state.scope_guard, state.session_manager,
        state.async_engine,
        vuln_threads=state.current_concurrency // 2,
        is_turbo=state.is_turbo,
        module_flags=state.module_flags,
        policy=state.policy,
        allow_post=True,
    )
    state.track_latency(start)
    state.extend_findings(findings)
    state.target_wafs.update(wafs)


# Phase: OOB Poll

async def phase_oob(state: PoisonState):
    """OOB/blind detection — runs once per wave."""
    from modules.extras.oob_detector import OOBDetector

    if not state.services or not state.params:
        return

    oob = OOBDetector(
        state.target, state.services, state.params,
        state.async_engine, session_manager=state.session_manager,
    )
    start = time.time()
    findings = await oob.run()
    state.track_latency(start)
    state.extend_findings(findings)

    # Inject blind XSS payloads
    if oob.interactsh.domain and state.time_left > 8:
        try:
            from modules.web.blind_xss import BlindXSSHunter
            hunter = BlindXSSHunter(
                state.async_engine,
                interactsh_domain=oob.interactsh.domain,
                session_manager=state.session_manager,
            )
            import uuid
            marker = "xss-" + uuid.uuid4().hex[:8]
            # phase_oob returns early without services, so services[0]
            # is the only base (10x identical injections were a bug).
            bases = [state.services[0]["url"]]
            for sv_url in bases:
                for path, plist in state.params.items():
                    for param in plist[:3]:
                        target = sv_url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
                        await hunter.inject_stored(target, param, marker)
        except Exception as e:
            w(f"blind XSS inject error: {str(e)[:60]}")

    # Auto-scan SSRF internal on blind_ssrf and ssrf findings
    for f in findings:
        if ("ssrf" in f.get("type", "")) and state.time_left > 10:
            param = None
            url = f.get("url", "")
            detail = f.get("detail", "")
            for part in detail.split("|"):
                part = part.strip()
                if part.startswith("Param:"):
                    param = part.split(":", 1)[1].strip()
                    break
            if param and url:
                try:
                    from modules.web.ssrf_scanner import SSRFScanner
                    scanner = SSRFScanner(state.async_engine, state.session_manager)
                    ssrf_findings = await scanner.scan(url, param)
                    if ssrf_findings:
                        state.extend_findings(ssrf_findings)
                except Exception as e:
                    w(f"SSRF auto-scan error: {str(e)[:60]}")


# Adaptive Wave Controller

async def _adaptive_wave_loop(state: PoisonState):
    """
    Core loop: phased execution with data dependencies respected.

    Block A: Discovery (param flood + bruteforce + cache + smuggle + exhaust)
    Block B: Detection (OOB + payload flood + auto-chain)
    Block C: Assault (vuln modules + plugins)
    Block D: Intelligence (session rotation + target reprioritization)
    """
    if state.time_left <= 0:
        return

    s(f"{G}========== POISON WAVE {state.wave} =========={N}")

    # Block A: Discovery
    # A1: Param discovery on high-value targets
    try:
        await phase_param_flood(state)
    except Exception as e:
        w(f"param_flood error: {str(e)[:80]}")

    # A2: Bruteforce + cache_poison + smuggling + connection_exhaust in parallel
    disc_tasks = [
        phase_bruteforce(state),
        phase_cache_poison(state),
        phase_smuggling(state),
        phase_connection_exhaust(state),
    ]
    disc_results = await asyncio.gather(*disc_tasks, return_exceptions=True)
    for idx, res in enumerate(disc_results):
        if isinstance(res, Exception):
            w(f"Discovery phase {idx} error: {str(res)[:80]}")

    # A3: Re-run param_flood on newly discovered URLs
    if state.time_left > 8:
        try:
            await phase_param_flood(state)
        except Exception as e:
            w(f"param_flood (re-run) error: {str(e)[:80]}")

    # Block B: Detection
    det_tasks = [
        phase_oob(state),
        phase_payload_flood(state),
    ]
    det_results = await asyncio.gather(*det_tasks, return_exceptions=True)
    for idx, res in enumerate(det_results):
        if isinstance(res, Exception):
            w(f"Detection phase {idx} error: {str(res)[:80]}")

    # Block C: Assault
    try:
        await phase_vuln_assault(state)
    except Exception as e:
        w(f"vuln_assault error: {str(e)[:80]}")

    # Block D: Custom Plugins
    try:
        from modules.plugin import run_plugins
        plugin_findings = await run_plugins(state)
        if plugin_findings:
            state.extend_findings(plugin_findings)
    except Exception as e:
        w(f"plugin error: {str(e)[:80]}")


# Main Entry Point

async def run_poison_assault(
    target: str,
    seed_url: str,
    services: List[Dict],
    subs: List[str],
    scan_urls: List[str],
    scope_guard,
    session_manager,
    async_engine,
    is_turbo: bool = False,
    module_flags: dict = None,
    auth_headers: dict = None,
    max_duration: int = 120,
    policy=None,
):
    """
    Event-driven poison orchestrator.

    3-block wave loop (discovery → detection → assault), each block under a
    hard deadline. Results self-feed into the next wave. Adaptive concurrency
    driven by real request latency.
    """
    if policy and policy.mode == "passive":
        return [], {}, list(scan_urls), []

    ph("POISON MODE: Event-Driven Orchestrator")

    # Auto-setup wordlists on first run (WordlistProvider already imported)
    wordlist_provider = WordlistProvider()
    wordlist_provider.scan()
    if not wordlist_provider._local:
        from modules.wordlists import auto_setup_wordlists
        await auto_setup_wordlists()
    i(PROVIDER.summary())

    # Create state
    existing_wafs = set()
    for sv in services:
        for waf_name in sv.get("waf", []):
            existing_wafs.add(waf_name)

    state = PoisonState(
        target, seed_url, services, subs, list(scan_urls),
        scope_guard, session_manager, async_engine, is_turbo,
        auth_headers=auth_headers,
        policy=policy,
    )
    state.target_wafs = existing_wafs
    state.max_duration = max_duration
    state.current_concurrency = 200 if is_turbo else 100
    state.module_flags = module_flags or {}

    # Adaptive controller input: every successful response reports its real
    # latency to the state (see PoisonState.track_request_latency). Cleared
    # again before returning so a later runner sharing this engine cannot
    # keep mutating a finished poison run.
    if hasattr(async_engine, "latency_observer"):
        async_engine.latency_observer = state.track_request_latency

    # Phase 0: WAF Bypass Engine — find origin IP + bypass techniques.
    #
    # Phase 0 gets its OWN time slice. It runs before the wave clock matters
    # but consumed it anyway (state.start_time is set at construction), and
    # through a proxy this stage alone takes 40-50s — so a 60s run ended with
    # a single wave. Cap the slice, then reset the wave clock below so
    # --max-time keeps meaning "time for the assault itself".
    from modules.waf.bypass_engine import waf_bypass_pipeline
    phase0_budget = min(max_duration, PHASE0_TIME_CAP)
    phase0_start = time.time()
    bypass_result = {}
    try:
        bypass_result = await asyncio.wait_for(
            waf_bypass_pipeline(target, subs, list(scan_urls),
                                proxy=_get_proxy_flag() or None),
            timeout=phase0_budget)
    except (asyncio.TimeoutError, TimeoutError):
        w(f"WAF bypass pipeline used its whole {phase0_budget}s slice — "
          "continuing without origin intel")
    phase0_elapsed = time.time() - phase0_start
    if isinstance(bypass_result, dict):
        if bypass_result.get("origin_ip"):
            state.origin_ip = bypass_result["origin_ip"]
            s(f"{G}Routing all phases through origin IP:{N} {B}{state.origin_ip}{N}")
            if state.policy:
                # Sekelas fix #1: tanpa authorize, policy.drop semua URL IP —
                # wave-wave awal (flood/brute/smuggle/OOB) jalan percuma.
                state.policy.authorize_host(state.origin_ip)
            for sv in services:
                sv["origin_ip"] = state.origin_ip
        if bypass_result.get("bypass_findings"):
            state.extend_findings(bypass_result["bypass_findings"])

    # Legacy origin hunt fallback — shares the rest of the Phase 0 slice
    if existing_wafs and not state.origin_ip:
        remaining_phase0 = phase0_budget - phase0_elapsed
        if remaining_phase0 >= 5:
            from modules.waf.origin_hunter import hunt_origin
            try:
                origin = await asyncio.wait_for(
                    hunt_origin(target, subs, proxy=_get_proxy_flag() or None),
                    timeout=remaining_phase0)
            except (asyncio.TimeoutError, TimeoutError):
                origin = None
                w("Origin hunt fallback hit the Phase 0 slice cap")
            if origin and origin.get("origin_ip"):
                state.origin_ip = origin["origin_ip"]
                s(f"{G}Origin IP (fallback):{N} {state.origin_ip}")
                if state.policy:
                    state.policy.authorize_host(state.origin_ip)
                for sv in services:
                    sv["origin_ip"] = state.origin_ip

    # Wave clock starts now: Phase 0 no longer eats into --max-time.
    state.start_time = time.time()
    i(f"Phase 0: {phase0_elapsed:.0f}s of {phase0_budget}s slice — "
      f"wave budget reset to {max_duration}s")

    # Main adaptive loop — waves until the duration budget is spent.
    # wait_for() is the hard deadline: inner phases (ffuf, exhaust, OOB,
    # vuln modules) can no longer run past max_duration, which the outer
    # while-condition alone could not enforce.
    try:
        while state.elapsed < state.max_duration:
            if not _budget_ok(state):
                w("Request budget exhausted — stopping poison waves")
                break
            try:
                await asyncio.wait_for(_adaptive_wave_loop(state),
                                       timeout=state.time_left)
            except (asyncio.TimeoutError, TimeoutError):
                w(f"Wave deadline reached ({max_duration}s) — stopping")
                break

            # Check if server fully degraded
            if state.server_strained:
                w("Server showing strain — continuing with adaptive aggression")

            # Start next wave with mutated params
            state.start_wave()
            s(f"{C}===== Next wave in 1s [{state.wave}] ======{N}")
            await asyncio.sleep(1)

    except asyncio.CancelledError:
        w("Poison mode interrupted")

    # Final summary
    elapsed = state.elapsed
    budget_note = ""
    if state.policy is not None:
        remaining = state.policy.requests_remaining
        if remaining is not None:
            budget_note = f" | budget left: {remaining}"
    ph(f"POISON COMPLETE — {elapsed:.0f}s | {state.wave} waves | {len(state.findings)} findings | {len(state.scan_urls)} urls{budget_note}")
    if hasattr(async_engine, "latency_observer"):
        async_engine.latency_observer = None
    return (
        state.findings,
        state.params,
        sorted(state.scan_urls),
        sorted(state.target_wafs),
    )
