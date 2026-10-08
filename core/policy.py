"""Operational policy enforced before scan requests leave the process."""

from dataclasses import dataclass
from threading import Lock
from typing import Dict, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from core.scope import ScopeGuard
from core.audit import AuditLogger


PASSIVE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SUPPORTED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
PASSIVE_EXTERNAL_TOOLS = frozenset({"subfinder", "httpx", "gau", "waybackurls", "katana"})


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating a URL, request, or external-tool invocation."""

    allowed: bool
    reason: str = ""


class ScanPolicy:
    """Define and enforce the authorized boundary of one scan.

    The policy is deliberately independent from the CLI and UI. It can be
    shared by the HTTP transport and external-tool adapters, so a target is
    checked at the last responsible point before work is dispatched.
    """

    def __init__(
        self,
        root_host: str,
        *,
        include_subdomains: bool = True,
        allowed_hosts: Optional[Iterable[str]] = None,
        allowed_ports: Optional[Iterable[int]] = None,
        mode: str = "active",
        max_requests: Optional[int] = 10_000,
        max_concurrency: Optional[int] = 100,
        max_timeout: float = 30.0,
        dry_run: bool = False,
    ):
        if mode not in {"passive", "active"}:
            raise ValueError("mode must be 'passive' or 'active'")
        if max_requests is not None and max_requests < 1:
            raise ValueError("max_requests must be at least 1 or None")
        if max_concurrency is not None and max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1 or None")
        if max_timeout <= 0:
            raise ValueError("max_timeout must be greater than 0")

        ports = allowed_ports if allowed_ports is not None else (80, 443)
        self.allowed_ports = frozenset(self._validate_port(port) for port in ports)
        if not self.allowed_ports:
            raise ValueError("allowed_ports cannot be empty")

        # `parse_target()` may provide a netloc (including a port). ScopeGuard
        # compares hostnames, so normalize the input before constructing it.
        raw_root = str(root_host or "").strip()
        parsed_root = urlparse(raw_root if "://" in raw_root else f"//{raw_root}")
        normalized_root = parsed_root.hostname or raw_root.split(":", 1)[0]
        self.scope = ScopeGuard(normalized_root, include_subdomains=include_subdomains)
        self.allowed_hosts = frozenset(
            self._normalize_host(host) for host in (allowed_hosts or ())
            if self._normalize_host(host)
        )
        self.mode = mode
        self.max_requests = max_requests
        self.max_concurrency = max_concurrency
        self.max_timeout = float(max_timeout)
        self.dry_run = bool(dry_run)
        self._requests_sent = 0
        self._lock = Lock()

    @staticmethod
    def _validate_port(port: int) -> int:
        try:
            value = int(port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid port: {port!r}") from exc
        if not 1 <= value <= 65535:
            raise ValueError(f"port must be between 1 and 65535: {value}")
        return value

    @staticmethod
    def _normalize_host(host: str) -> str:
        raw = str(host or "").strip()
        if not raw:
            return ""
        parsed = urlparse(raw if "://" in raw else f"//{raw}")
        return (parsed.hostname or raw.split(":", 1)[0]).strip().lower().rstrip(".")

    @property
    def root_host(self) -> str:
        return self.scope.root_host

    @property
    def requests_sent(self) -> int:
        with self._lock:
            return self._requests_sent

    @property
    def requests_remaining(self) -> Optional[int]:
        if self.max_requests is None:
            return None
        with self._lock:
            return max(0, self.max_requests - self._requests_sent)

    def allows_host(self, host: str) -> bool:
        normalized = self._normalize_host(host)
        return normalized in self.allowed_hosts or self.scope.host_in_scope(normalized)

    def authorize_host(self, host: str) -> None:
        """Grant exact-host access for this run (e.g. a discovered origin IP).

        The origin IP is the same in-scope asset behind the WAF; without this
        the scope filter silently drops every IP-based URL (and finding) from
        tool runners and transports.
        """
        normalized = self._normalize_host(host)
        if normalized:
            self.allowed_hosts = frozenset(self.allowed_hosts | {normalized})

    def check_url(self, url: str) -> PolicyDecision:
        if not url:
            return PolicyDecision(False, "empty_url")
        try:
            parsed = urlparse(str(url).strip())
            port = parsed.port
        except ValueError:
            return PolicyDecision(False, "invalid_port")

        if parsed.scheme.lower() not in {"http", "https"}:
            return PolicyDecision(False, "unsupported_scheme")
        if not parsed.hostname:
            return PolicyDecision(False, "missing_host")
        if not self.allows_host(parsed.hostname):
            return PolicyDecision(False, "out_of_scope_host")

        effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
        if effective_port not in self.allowed_ports:
            return PolicyDecision(False, f"port_not_allowed:{effective_port}")
        return PolicyDecision(True)

    def allows_url(self, url: str) -> bool:
        return self.check_url(url).allowed

    def canonical_url(self, url: str, base_url: str = None) -> str:
        candidate = str(url or "").strip()
        if base_url:
            candidate = urljoin(base_url, candidate)
        elif candidate.startswith("//"):
            candidate = f"https:{candidate}"

        # Validate first so malformed ports and explicit additional hosts are
        # handled consistently with direct transport authorization.
        if not self.allows_url(candidate):
            return ""

        # Keep ScopeGuard's canonical form for the normal root/subdomain path.
        canonical = self.scope.canonical_url(candidate)
        if canonical:
            return canonical

        # ScopeGuard intentionally knows only the primary scope.  Preserve
        # policy-approved exact hosts (for example an authorized IP) here.
        parsed = urlparse(candidate)
        host = parsed.hostname.lower().rstrip(".")
        netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
        port = parsed.port
        if port and not ((parsed.scheme.lower() == "https" and port == 443) or
                         (parsed.scheme.lower() == "http" and port == 80)):
            netloc = f"{netloc}:{port}"
        path = parsed.path or "/"
        if path == "/":
            path = ""
        return urlunparse((
            parsed.scheme.lower(),
            netloc,
            path,
            "",
            parsed.query,
            "",
        ))

    def filter_urls(self, urls: Iterable[str], base_url: str = None) -> list[str]:
        kept = set()
        for url in urls or []:
            canonical = self.canonical_url(url, base_url=base_url)
            if canonical:
                kept.add(canonical)
        return sorted(kept)

    def clamp_timeout(self, timeout: Optional[float]) -> float:
        """Return a timeout that cannot exceed this scan's policy budget."""
        if timeout is None:
            return self.max_timeout
        try:
            requested = float(timeout)
        except (TypeError, ValueError):
            requested = self.max_timeout
        return max(0.1, min(requested, self.max_timeout))

    def check_tool(self, tool_name: str) -> PolicyDecision:
        normalized = (tool_name or "").strip().lower()
        if self.mode == "passive" and normalized not in PASSIVE_EXTERNAL_TOOLS:
            return PolicyDecision(False, f"tool_not_allowed_in_passive_mode:{normalized}")
        return PolicyDecision(True)

    def authorize_request(self, url: str, method: str = "GET",
                          headers: Optional[Dict] = None,
                          body: Optional[str] = None,
                          trace_id: Optional[str] = None) -> PolicyDecision:
        """Authorize an outgoing request; audit entry carries headers/body so
        denied AND allowed requests stay curl-replayable from the .jsonl."""
        decision = self.check_url(url)
        if not decision.allowed:
            AuditLogger.get_instance().log_request(
                url=url, method=method, allowed=False, reason=decision.reason,
                dry_run=self.dry_run, headers=headers, body=body, trace_id=trace_id
            )
            return decision

        normalized_method = (method or "GET").upper()
        if normalized_method not in SUPPORTED_METHODS:
            d = PolicyDecision(False, f"unsupported_method:{normalized_method}")
            AuditLogger.get_instance().log_request(
                url=url, method=method, allowed=False, reason=d.reason,
                dry_run=self.dry_run, headers=headers, body=body, trace_id=trace_id
            )
            return d
        if self.mode == "passive" and normalized_method not in PASSIVE_METHODS:
            d = PolicyDecision(False, f"method_not_allowed_in_passive_mode:{normalized_method}")
            AuditLogger.get_instance().log_request(
                url=url, method=method, allowed=False, reason=d.reason,
                dry_run=self.dry_run, headers=headers, body=body, trace_id=trace_id
            )
            return d

        with self._lock:
            if self.max_requests is not None and self._requests_sent >= self.max_requests:
                d = PolicyDecision(False, "request_budget_exhausted")
                AuditLogger.get_instance().log_request(
                    url=url, method=method, allowed=False, reason=d.reason,
                    dry_run=self.dry_run, headers=headers, body=body, trace_id=trace_id
                )
                return d
            self._requests_sent += 1

        AuditLogger.get_instance().log_request(
            url=url, method=method, allowed=True, reason="authorized",
            dry_run=self.dry_run, headers=headers, body=body, trace_id=trace_id
        )
        return PolicyDecision(True)

    def refund_request(self) -> None:
        """Return one budget unit when an authorized request never dispatches.

        Covers dry-run simulation, host-backoff, concurrency timeout and
        circuit-open paths — otherwise max_requests could exhaust with zero
        packets sent (or a dry-run burning real budget).
        """
        with self._lock:
            if self._requests_sent > 0:
                self._requests_sent -= 1

    def charge(self, n: int, reason: str = "tool") -> int:
        """Debit n requests for a generator that bypasses ahttp_send.

        ffuf, connection exhaust and smuggling never reach authorize_request()
        — without this their traffic is invisible to max_requests. Callers may
        only pass an EXACT count or a documented upper bound; inventing
        numbers would turn requests_sent into fiction. Returns how much was
        actually charged (0 when the budget cannot afford n).
        """
        if n <= 0:
            return 0
        with self._lock:
            if self.max_requests is None:
                self._requests_sent += n
                charged = n
            else:
                room = self.max_requests - self._requests_sent
                charged = min(n, room) if room > 0 else 0
                self._requests_sent += charged
        if charged:
            AuditLogger.get_instance().log_request(
                url=f"bulk://{reason}",
                method="BULK",
                allowed=True,
                reason=f"charged {charged}/{n} for generator",
                dry_run=self.dry_run,
            )
        return charged
