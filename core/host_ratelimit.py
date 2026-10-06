"""
Per-Host Rate Limiter — Semaphore + Exponential Backoff + WAF Auto-Throttle.

Solusi buat: Cloudflare 429 → backoff, 403 → harder backoff,
server strain → auto-reduce concurrency, recovery → gradual restore.
"""
import asyncio
import threading
import time
from dataclasses import dataclass, field


@dataclass
class _HostState:
    """Rate-limit state for a single host."""
    semaphore: asyncio.Semaphore
    max_concurrent: int
    backoff_until: float = 0.0
    backoff_multiplier: float = 1.0
    consecutive_429: int = 0
    consecutive_403: int = 0
    total_requests: int = 0
    total_429: int = 0
    last_success: float = 0.0
    _last_restore: float = 0.0


class HostRateLimiter:
    """
    Per-host adaptive rate limiting integrated with AsyncNetworkEngine.

    Features:
    - Per-host semaphore → max N concurrent connections per host
    - Exponential backoff on 429 (Too Many Requests)
    - Hard backoff on 403 (Forbidden — possible IP ban)
    - Auto-throttle: reduce concurrency after 3 consecutive 429s
    - Gradual recovery: every 30s of clean requests, restore 25% concurrency
    - Timeout-based acquire: don't block forever if backoff active
    """

    def __init__(self, default_max_concurrent: int = 30, backoff_base: float = 2.0):
        self._lock = threading.Lock()
        self._async_lock = asyncio.Lock()
        self._hosts: dict[str, _HostState] = {}
        self._default_max = default_max_concurrent
        self._backoff_base = backoff_base

    def _get_or_create(self, host: str) -> _HostState:
        """Thread-safe get-or-create host state."""
        with self._lock:
            if host not in self._hosts:
                self._hosts[host] = _HostState(
                    semaphore=asyncio.Semaphore(self._default_max),
                    max_concurrent=self._default_max,
                )
            return self._hosts[host]

    # Public API

    async def acquire(self, host: str, timeout: float = 10.0) -> bool:
        """
        Wait for permission to send request to this host.

        Returns True if allowed, False if blocked (backoff active, timeout expired).
        """
        state = self._get_or_create(host)

        # Check backoff
        now = time.time()
        if state.backoff_until > now:
            wait_time = state.backoff_until - now
            if wait_time > timeout:
                return False
            # Wait out the backoff
            await asyncio.sleep(wait_time)

        # Acquire per-host semaphore (with timeout)
        try:
            await asyncio.wait_for(state.semaphore.acquire(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def release(self, host: str, status: int = 0):
        """Release semaphore + update backoff state based on response status."""
        state = self._hosts.get(host)
        if state is None:
            return

        # Release semaphore first (always)
        state.semaphore.release()
        state.total_requests += 1

        if status == 429:
            self._handle_429(state)
        elif status == 403:
            self._handle_403(state)
        elif status > 0:
            self._handle_success(state)
        # status == 0 (connection error) → no backoff change

    def is_backing_off(self, host: str) -> bool:
        """True while this host is inside a 429/403 backoff window.

        ahttp_send already refuses (acquire() returns False) during backoff,
        but ffuf and the raw-socket modules bypass the engine — they need to
        ask this before dispatching, otherwise backoff only throttles half
        the traffic.
        """
        state = self._hosts.get(host)
        if state is None:
            return False
        return state.backoff_until > time.time()

    def set_max_concurrent(self, host: str, max_n: int):
        """Dynamically adjust max concurrent for a host.

        Note: Does NOT replace the semaphore (would orphan waiters).
        Backoff timing is the primary throttling mechanism.
        """
        state = self._get_or_create(host)
        new_max = max(1, min(max_n, 500))
        state.max_concurrent = new_max

    # Internal backoff logic

    def _handle_429(self, state: _HostState):
        """Exponential backoff on rate limit."""
        state.consecutive_429 += 1
        state.consecutive_403 = 0
        state.total_429 += 1

        # Exponential: 2s, 4s, 8s, 16s, cap at 60s
        delay = min(60.0, self._backoff_base ** state.consecutive_429)
        state.backoff_until = time.time() + delay
        state.backoff_multiplier = min(10.0, state.backoff_multiplier * 1.5)

        # Auto-throttle after 3 consecutive 429s
        if state.consecutive_429 >= 3:
            new_max = max(2, state.max_concurrent // 2)
            self.set_max_concurrent_direct(state, new_max)

    def _handle_403(self, state: _HostState):
        """Hard backoff on forbidden — possible IP/request ban."""
        state.consecutive_403 += 1
        state.consecutive_429 = 0

        # Harder: 15s, 30s, 60s
        delay = min(120.0, 15.0 * (2 ** (state.consecutive_403 - 1)))
        state.backoff_until = time.time() + delay

        # Aggressive throttle
        new_max = max(1, state.max_concurrent // 3)
        self.set_max_concurrent_direct(state, new_max)

    def _handle_success(self, state: _HostState):
        """Gradual recovery on successful request."""
        now = time.time()
        state.consecutive_429 = max(0, state.consecutive_429 - 1)
        state.consecutive_403 = 0
        state.last_success = now

        # Gradual restore: every 30s of success, increase concurrency 25%
        if (now - state._last_restore) > 30:
            new_max = min(self._default_max, int(state.max_concurrent * 1.25))
            if new_max > state.max_concurrent:
                self.set_max_concurrent_direct(state, new_max)
            state._last_restore = now

    def set_max_concurrent_direct(self, state: _HostState, new_max: int):
        """Internal: set max concurrent stats without replacing semaphore.

        The semaphore is NOT replaced (would orphan waiters).
        Backoff timing is the primary throttling mechanism.
        """
        new_max = max(1, min(new_max, 500))
        if new_max != state.max_concurrent:
            old_max = state.max_concurrent
            state.max_concurrent = new_max

    # Diagnostics

    def stats(self, host: str = None) -> dict:
        """Get rate limit stats for a host or all hosts summary."""
        if host:
            s = self._hosts.get(host)
            if not s:
                return {}
            return {
                "host": host,
                "max_concurrent": s.max_concurrent,
                "backoff_remaining": max(0, s.backoff_until - time.time()),
                "consecutive_429": s.consecutive_429,
                "total_requests": s.total_requests,
                "total_429": s.total_429,
            }
        # All hosts summary
        return {
            h: {
                "max": st.max_concurrent,
                "backoff_s": max(0, st.backoff_until - time.time()),
                "429s": st.total_429,
            }
            for h, st in self._hosts.items()
        }
