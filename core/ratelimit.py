import random
import threading
import time
import asyncio
from collections import defaultdict, deque


class RateLimiter:
    """Per-host adaptive pacing with sliding-window WAF/rate-limit feedback
    and self-healing recovery.

    Adaptive Backoff Strategy:
    - Tracks a sliding window of the last N responses per host.
    - If the ratio of anomalous responses (429, WAF-403, 503) exceeds a
      configurable threshold, delay is escalated exponentially and
      GhostMode stealth headers are auto-activated for that host.
    - When consecutive successful responses (2xx/3xx) exceed the recovery
      threshold, delay is gradually reduced back to baseline (*self-healing*).

    Threading Model:
    - Uses a single threading.Lock for ALL state mutations (sync + async).
    - asyncio.Lock removed: critical sections contain no awaits, so a
      threading.Lock is safe and avoids data-race between sync callers
      and async callers sharing the same dictionaries.
    - Query methods (is_auto_stealth, is_adaptive_active) are lock-free
      for the hot path — CPython dict.get() is GIL-atomic.
    """

    # Sliding Window Constants
    WINDOW_SIZE = 50           # Track last 50 responses per host
    ANOMALY_THRESHOLD = 0.05   # 5% anomaly ratio triggers escalation
    RECOVERY_STREAK = 10       # 10 consecutive 2xx/3xx to start recovery
    ESCALATION_FACTOR = 2.0    # Multiply delay by this on escalation
    RECOVERY_FACTOR = 0.85     # Multiply delay by this during recovery
    WAF_403_KEYWORDS = [
        "blocked", "suspicious", "captcha", "security", "denied",
        "waf", "access denied", "cloudflare", "attention required",
        "checking your browser", "ray id", "ddos protection",
    ]

    def __init__(self, global_delay=0.0, per_host_delay=0.15, jitter=0.1, max_backoff=30.0):
        self.global_delay = global_delay
        self.per_host_delay = per_host_delay
        self.jitter = jitter
        self.max_backoff = max_backoff
        self._host_last_request = {}
        self._host_delay = defaultdict(lambda: self.per_host_delay)
        self._host_blocked = defaultdict(bool)
        self._host_429_count = defaultdict(int)
        self._lock = threading.Lock()

        # Sliding window & adaptive state
        self._host_window = defaultdict(lambda: deque(maxlen=self.WINDOW_SIZE))
        self._host_anomaly_count = defaultdict(int)  # Running sum — O(1) ratio calc
        self._host_success_streak = defaultdict(int)
        self._host_adaptive_active = defaultdict(bool)
        self._host_stealth_auto = defaultdict(bool)  # Auto-stealth per host
        self._notified_hosts = set()  # Avoid spamming console
        self._pending_notification = None

    # Lock-free query methods (hot path)
    # CPython dict.get() is GIL-atomic: safe to read without lock.
    # These are called on EVERY request so must not serialize threads.

    def is_adaptive_active(self, hostname: str) -> bool:
        """Check if adaptive throttle is currently engaged for a host."""
        return self._host_adaptive_active.get(hostname, False)

    def is_auto_stealth(self, hostname: str) -> bool:
        """Check if auto-stealth headers should be used for a host."""
        return self._host_stealth_auto.get(hostname, False)

    def get_host_delay(self, hostname: str) -> float:
        """Get current effective delay for a host (for Go bridge sync)."""
        return self._host_delay.get(hostname, self.per_host_delay)

    def get_adaptive_delay_ms(self, hostname: str) -> tuple:
        """Return (delay_ms, jitter_ms) for Go engine integration."""
        if self._host_adaptive_active.get(hostname, False):
            delay = self._host_delay.get(hostname, self.per_host_delay)
            return int(delay * 1000), int(self.jitter * 1000)
        return 0, 0

    # Wait methods

    async def wait_async(self, hostname):
        if not hostname:
            hostname = "default"

        # Use threading.Lock (not asyncio.Lock) — no awaits inside critical section.
        # This ensures sync callers (report_response) and async callers share
        # the same lock, preventing data races on shared dictionaries.
        with self._lock:
            if self._host_blocked[hostname]:
                return None

            delay = max(self.global_delay, self._host_delay[hostname])
            last_request = self._host_last_request.get(hostname, 0)
            elapsed = time.time() - last_request
            remaining = max(delay - elapsed, 0.0)
            actual_delay = max(remaining + random.uniform(-self.jitter, self.jitter), 0.0)
            self._host_last_request[hostname] = time.time() + actual_delay

        if actual_delay > 0:
            await asyncio.sleep(actual_delay)

        return actual_delay

    def wait(self, hostname):
        """Sync version for non-async callers (recon scanner, etc)."""
        if not hostname:
            hostname = "default"

        with self._lock:
            if self._host_blocked[hostname]:
                return None

            delay = max(self.global_delay, self._host_delay[hostname])
            last_request = self._host_last_request.get(hostname, 0)
            elapsed = time.time() - last_request
            remaining = max(delay - elapsed, 0.0)
            actual_delay = max(remaining + random.uniform(-self.jitter, self.jitter), 0.0)

        if actual_delay > 0:
            time.sleep(actual_delay)

        with self._lock:
            self._host_last_request[hostname] = time.time()

        return actual_delay

    # Response feedback with sliding window

    def report_response(self, hostname, status_code, response_body=None):
        if not hostname:
            hostname = "default"

        body = (response_body or "").lower()
        is_anomaly = False

        with self._lock:
            # Classify response
            if status_code == 429:
                is_anomaly = True
                self._host_429_count[hostname] += 1
                self._host_success_streak[hostname] = 0

                # Hard block after sustained 429 barrage
                if self._host_429_count[hostname] > 5:
                    self._host_blocked[hostname] = True

            elif status_code == 403:
                if any(kw in body for kw in self.WAF_403_KEYWORDS):
                    is_anomaly = True
                    self._host_success_streak[hostname] = 0

            elif status_code in (502, 503):
                is_anomaly = True
                self._host_success_streak[hostname] = 0

            elif 200 <= status_code < 400:
                self._host_success_streak[hostname] += 1
                self._host_429_count[hostname] = max(0, self._host_429_count[hostname] - 1)

            # Push into sliding window with O(1) running sum
            window = self._host_window[hostname]
            if len(window) == window.maxlen:
                # About to evict oldest entry — adjust running count
                evicted = window[0]
                if evicted:
                    self._host_anomaly_count[hostname] -= 1
            window.append(1 if is_anomaly else 0)
            if is_anomaly:
                self._host_anomaly_count[hostname] += 1

            # Evaluate sliding window ratio (O(1) now)
            wlen = len(window)
            if wlen >= 5:  # Need minimum samples
                anomaly_ratio = self._host_anomaly_count[hostname] / wlen

                if anomaly_ratio > self.ANOMALY_THRESHOLD:
                    # ESCALATE: WAF pressure detected
                    if not self._host_adaptive_active[hostname]:
                        self._host_adaptive_active[hostname] = True
                        self._host_stealth_auto[hostname] = True
                        if hostname not in self._notified_hosts:
                            self._notified_hosts.add(hostname)
                            self._pending_notification = (hostname, "escalate")

                    old_delay = self._host_delay[hostname]
                    new_delay = min(old_delay * self.ESCALATION_FACTOR, self.max_backoff)
                    self._host_delay[hostname] = new_delay

                elif self._host_adaptive_active[hostname]:
                    # RECOVERY: Check if conditions improved
                    streak = self._host_success_streak[hostname]
                    if streak >= self.RECOVERY_STREAK:
                        old_delay = self._host_delay[hostname]
                        new_delay = max(old_delay * self.RECOVERY_FACTOR, self.per_host_delay)
                        self._host_delay[hostname] = new_delay

                        # Fully recovered — deactivate adaptive mode
                        if new_delay <= self.per_host_delay * 1.1:
                            self._host_adaptive_active[hostname] = False
                            self._host_stealth_auto[hostname] = False
                            self._notified_hosts.discard(hostname)
                            self._pending_notification = (hostname, "recovered")

    def get_pending_notification(self):
        """Pop and return any pending console notification (hostname, event_type).
        Returns None if no notification is pending.
        Thread-safe: called from async context after report_response.
        """
        with self._lock:
            notif = self._pending_notification
            self._pending_notification = None
            return notif

    def is_blocked(self, hostname):
        # Lock-free read — CPython dict.get is GIL-atomic
        return self._host_blocked.get(hostname, False)

    def reset(self, hostname=None):
        with self._lock:
            if hostname is None:
                self._host_last_request.clear()
                self._host_delay.clear()
                self._host_blocked.clear()
                self._host_429_count.clear()
                self._host_window.clear()
                self._host_anomaly_count.clear()
                self._host_success_streak.clear()
                self._host_adaptive_active.clear()
                self._host_stealth_auto.clear()
                self._notified_hosts.clear()
                self._pending_notification = None
                return

            self._host_last_request.pop(hostname, None)
            self._host_delay.pop(hostname, None)
            self._host_blocked.pop(hostname, None)
            self._host_429_count.pop(hostname, None)
            self._host_window.pop(hostname, None)
            self._host_anomaly_count.pop(hostname, None)
            self._host_success_streak.pop(hostname, None)
            self._host_adaptive_active.pop(hostname, None)
            self._host_stealth_auto.pop(hostname, None)
            self._notified_hosts.discard(hostname)
