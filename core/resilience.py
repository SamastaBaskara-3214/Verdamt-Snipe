"""Resilience primitives — extracted verbatim from core/client.py.

AdaptivePacingSystem (AIMD pacing controller) and the per-host
CircuitBreaker / CircuitState state machine. core/client.py re-imports
these names so its public API is unchanged.
"""
import asyncio
import enum
import time
from typing import Dict


# Adaptive Pacing (AIMD controller)

class AdaptivePacingSystem:
    """AIMD (Additive Increase, Multiplicative Decrease) pacing controller."""

    def __init__(self, initial_delay: float = 0.1):
        self.current_delay = initial_delay
        self.min_delay = 0.01
        self.max_delay = 5.0
        self.latency_history = []

    async def wait(self):
        if self.current_delay > 0:
            await asyncio.sleep(self.current_delay)

    def record_latency(self, latency: float):
        self.latency_history.append(latency)
        if len(self.latency_history) > 20:
            self.latency_history.pop(0)
        avg_latency = sum(self.latency_history) / len(self.latency_history)
        if latency <= avg_latency * 1.2:
            self.current_delay = max(self.min_delay, self.current_delay - 0.01)

    def trigger_backoff(self):
        self.current_delay = min(self.max_delay, self.current_delay * 2)

    def record_error(self):
        self.trigger_backoff()


# Circuit Breaker (per-host state machine)


class CircuitState(enum.Enum):
    CLOSED = "closed"        # Normal — requests flow through
    OPEN = "open"            # Blocked — requests halted, cooling down
    HALF_OPEN = "half_open"  # Testing — 1 probe request allowed


class CircuitBreaker:
    """Per-host circuit breaker with CLOSED/OPEN/HALF-OPEN state machine.
    
    Integrates with AdaptivePacingSystem for coordinated throttling.
    
    Flow:
        CLOSED → 5x consecutive 403/429 → OPEN
        OPEN → cooldown expires → HALF_OPEN
        HALF_OPEN → probe success → CLOSED
        HALF_OPEN → probe fail → OPEN (longer cooldown)
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_base: float = 30.0,
        cooldown_max: float = 300.0,
        half_open_probe: int = 1,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_base = cooldown_base
        self.cooldown_max = cooldown_max
        self.half_open_probe = half_open_probe
        self._hosts: Dict[str, dict] = {}

    def _get_host(self, hostname: str) -> dict:
        if hostname not in self._hosts:
            self._hosts[hostname] = {
                "state": CircuitState.CLOSED,
                "consecutive_fails": 0,
                "total_fails": 0,
                "cooldown_until": 0.0,
                "cooldown_multiplier": 1,
                "half_open_probes": 0,
                "last_success": 0.0,
            }
        return self._hosts[hostname]

    def allow_request(self, hostname: str) -> bool:
        """Should we send a request to this host?"""
        h = self._get_host(hostname)
        now = time.time()

        if h["state"] == CircuitState.CLOSED:
            return True

        if h["state"] == CircuitState.OPEN:
            if now >= h["cooldown_until"]:
                # Cooldown expired → HALF_OPEN
                h["state"] = CircuitState.HALF_OPEN
                h["half_open_probes"] = 1  # This IS the first probe
                return True
            return False  # Still cooling down

        if h["state"] == CircuitState.HALF_OPEN:
            if h["half_open_probes"] < self.half_open_probe:
                h["half_open_probes"] += 1
                return True  # Allow probe
            return False  # Waiting for probe result

        return False

    def record_success(self, hostname: str):
        """Record a successful response (2xx, 3xx)."""
        h = self._get_host(hostname)
        now = time.time()

        if h["state"] == CircuitState.HALF_OPEN:
            # Probe succeeded → CLOSED
            h["state"] = CircuitState.CLOSED
            h["consecutive_fails"] = 0
            h["cooldown_multiplier"] = 1
            h["half_open_probes"] = 0

        elif h["state"] == CircuitState.CLOSED:
            h["consecutive_fails"] = max(0, h["consecutive_fails"] - 1)

        h["last_success"] = now

    def record_failure(self, hostname: str, status_code: int = 0):
        """Record a blocked/rate-limited response (403, 429)."""
        h = self._get_host(hostname)
        now = time.time()

        if h["state"] == CircuitState.HALF_OPEN:
            # Probe failed → OPEN with longer cooldown
            # (probe counter already incremented in allow_request)
            h["state"] = CircuitState.OPEN
            h["cooldown_multiplier"] = min(h["cooldown_multiplier"] * 2, 8)
            cooldown = min(
                self.cooldown_base * h["cooldown_multiplier"],
                self.cooldown_max,
            )
            h["cooldown_until"] = now + cooldown
            return

        if h["state"] == CircuitState.CLOSED:
            h["consecutive_fails"] += 1
            h["total_fails"] += 1

            if h["consecutive_fails"] >= self.failure_threshold:
                # Trip the circuit → OPEN
                h["state"] = CircuitState.OPEN
                cooldown = min(
                    self.cooldown_base * h["cooldown_multiplier"],
                    self.cooldown_max,
                )
                h["cooldown_until"] = now + cooldown

    def get_state(self, hostname: str) -> CircuitState:
        """Get current circuit state for a host."""
        return self._get_host(hostname)["state"]

    def get_cooldown_remaining(self, hostname: str) -> float:
        """Seconds remaining in cooldown (0 if not in OPEN state)."""
        h = self._get_host(hostname)
        if h["state"] != CircuitState.OPEN:
            return 0.0
        return max(0.0, h["cooldown_until"] - time.time())

    def get_stats(self, hostname: str) -> dict:
        """Get circuit breaker stats for a host."""
        h = self._get_host(hostname)
        return {
            "state": h["state"].value,
            "consecutive_fails": h["consecutive_fails"],
            "total_fails": h["total_fails"],
            "cooldown_remaining": self.get_cooldown_remaining(hostname),
            "cooldown_multiplier": h["cooldown_multiplier"],
        }

    def reset(self, hostname: str = None):
        """Reset circuit breaker state."""
        if hostname:
            self._hosts.pop(hostname, None)
        else:
            self._hosts.clear()
