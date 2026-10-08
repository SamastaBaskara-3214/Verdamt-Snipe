"""Proxy Manager — Unified proxy routing, rotation, and health checks.

Centralizes all proxy logic for verdamt-snipe:
- Load proxies from file, env, or inline
- Auto-rotate every N requests
- Health check (is proxy alive?)
- Fallback (proxy dead → next one)
- Set env vars so ALL tools route through proxy

Usage:
    from core.proxy_manager import ProxyManager

    pm = ProxyManager()
    pm.load_from_file("proxies.txt")
    pm.set_env_vars()  # ALL_PROXY, HTTP_PROXY, etc.
    
    # Or auto-rotate:
    pm.enable_rotation(interval=5)  # switch every 5 requests
    pm.record_request()  # call after each request
    # Auto-switches proxy when interval reached
"""

import os
import random
import time
import socket
import asyncio
import threading
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote


# Supported proxy schemes
PROXY_SCHEMES = {"socks5", "socks5h", "socks4", "socks4a", "http", "https"}


class ProxyManager:
    """Unified proxy management for all verdamt-snipe tools."""

    def __init__(self, initial_proxy: str = None):
        self._lock = threading.Lock()
        self.proxies: List[str] = []
        self.current_index: int = 0
        self.current_proxy: Optional[str] = initial_proxy
        self.request_count: int = 0
        self.rotation_interval: int = 0  # 0 = disabled
        self.dead_proxies: set = set()
        self.proxy_stats: Dict[str, Dict] = {}  # proxy → {requests, errors, last_used}
        self._enabled: bool = False

    def load_from_file(self, path: str) -> int:
        """Load proxies from file (one per line).
        
        Supports formats:
            socks5://ip:port
            socks5://user:pass@ip:port
            http://ip:port
            ip:port (assumes socks5)
        
        Returns number of proxies loaded.
        """
        if not os.path.exists(path):
            return 0

        loaded = 0
        tmp_proxies = []
        tmp_stats = {}
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "://" not in line:
                    line = f"socks5://{line}"
                if self._validate_proxy(line):
                    tmp_proxies.append(line)
                    tmp_stats[line] = {"requests": 0, "errors": 0, "last_used": 0}
                    loaded += 1

        if loaded > 0:
            with self._lock:
                self.proxies.extend(tmp_proxies)
                self.proxy_stats.update(tmp_stats)
                if not self.current_proxy:
                    self.current_proxy = self.proxies[0]
                    self._enabled = True

        return loaded

    def load_from_env(self) -> bool:
        """Load proxy from VERDAMT_PROXY env var."""
        proxy = os.environ.get("VERDAMT_PROXY")
        if proxy and self._validate_proxy(proxy):
            with self._lock:
                self.proxies.insert(0, proxy)
                self.current_proxy = proxy
                self._enabled = True
            return True
        return False

    def add_proxy(self, proxy: str) -> bool:
        """Add a single proxy."""
        if self._validate_proxy(proxy):
            with self._lock:
                self.proxies.append(proxy)
                self.proxy_stats[proxy] = {
                    "requests": 0, "errors": 0, "last_used": 0
                }
                if not self.current_proxy:
                    self.current_proxy = proxy
                    self._enabled = True
            return True
        return False

    def enable_rotation(self, interval: int = 5):
        """Enable auto-rotation every N requests."""
        with self._lock:
            self.rotation_interval = max(1, interval)

    def record_request(self, error: bool = False):
        """Record a request. Auto-rotates if interval reached."""
        with self._lock:
            self.request_count += 1

            if self.current_proxy:
                stats = self.proxy_stats.get(self.current_proxy, {})
                stats["requests"] = stats.get("requests", 0) + 1
                stats["last_used"] = time.time()
                if error:
                    stats["errors"] = stats.get("errors", 0) + 1
                self.proxy_stats[self.current_proxy] = stats

            # Auto-rotate
            if self.rotation_interval > 0 and len(self.proxies) > 1:
                if self.request_count % self.rotation_interval == 0:
                    self._rotate_locked()

    def _rotate_locked(self) -> Optional[str]:
        """Switch to next proxy (caller must hold lock)."""
        if len(self.proxies) <= 1:
            return self.current_proxy

        # Skip dead proxies
        attempts = 0
        while attempts < len(self.proxies):
            self.current_index = (self.current_index + 1) % len(self.proxies)
            candidate = self.proxies[self.current_index]
            if candidate not in self.dead_proxies:
                self.current_proxy = candidate
                return self.current_proxy
            attempts += 1

        # All dead? Reset and try again
        self.dead_proxies.clear()
        self.current_index = 0
        self.current_proxy = self.proxies[0]
        return self.current_proxy

    def rotate(self) -> Optional[str]:
        """Switch to next proxy. Returns new proxy URL."""
        with self._lock:
            return self._rotate_locked()

    def mark_dead(self, proxy: str = None):
        """Mark a proxy as dead (will be skipped)."""
        with self._lock:
            proxy = proxy or self.current_proxy
            if proxy:
                self.dead_proxies.add(proxy)

    def get_current(self) -> Optional[str]:
        """Get current active proxy."""
        with self._lock:
            return self.current_proxy

    def get_stats(self) -> Dict:
        """Get proxy usage statistics."""
        with self._lock:
            return {
                "total_proxies": len(self.proxies),
                "dead_proxies": len(self.dead_proxies),
                "current": self.current_proxy,
                "requests": self.request_count,
                "rotation_interval": self.rotation_interval,
                "per_proxy": dict(self.proxy_stats),
            }

    def set_env_vars(self, proxy: str = None):
        """Set environment variables so ALL tools use this proxy.
        
        Affects: curl, subfinder, httpx, nuclei, gau, katana, etc.
        """
        with self._lock:
            proxy = proxy or self.current_proxy
            if not proxy:
                return

        env_vars = [
            "VERDAMT_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
        ]
        for var in env_vars:
            os.environ[var] = proxy

    def clear_env_vars(self):
        """Remove all proxy env vars."""
        env_vars = [
            "VERDAMT_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
            "http_proxy", "https_proxy", "all_proxy",
        ]
        for var in env_vars:
            os.environ.pop(var, None)

    async def health_check(self, proxy: str = None, timeout: float = 5.0) -> bool:
        """Check if proxy is alive by attempting a SOCKS5/HTTP connect.
        
        Returns True if proxy is reachable.
        """
        proxy = proxy or self.current_proxy
        if not proxy:
            return False

        try:
            parsed = urlparse(proxy)
            host = parsed.hostname
            port = parsed.port or 1080

            # Quick TCP connect test
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def health_check_all(self) -> Dict[str, bool]:
        """Check all loaded proxies. Returns {proxy: is_alive}."""
        proxies = list(self.proxies)
        results = {}
        for proxy in proxies:
            alive = await self.health_check(proxy)
            results[proxy] = alive
            if not alive:
                self.mark_dead(proxy)
        return results

    def get_random_alive(self) -> Optional[str]:
        """Get a random alive proxy."""
        with self._lock:
            alive = [p for p in self.proxies if p not in self.dead_proxies]
            if alive:
                return random.choice(alive)
            return self.current_proxy

    @staticmethod
    def _validate_proxy(proxy: str) -> bool:
        """Basic proxy URL validation."""
        if not proxy:
            return False
        try:
            parsed = urlparse(proxy)
            if parsed.scheme and parsed.scheme not in PROXY_SCHEMES:
                return False
            if not parsed.hostname:
                return False
            return True
        except Exception:
            return False

    def __repr__(self):
        with self._lock:
            return (
                f"ProxyManager(proxies={len(self.proxies)}, "
                f"current={self.current_proxy}, "
                f"rotation={'on' if self.rotation_interval > 0 else 'off'})"
            )


GLOBAL_PROXY_MGR = None


def get_global_proxy_manager() -> Optional[ProxyManager]:
    """Retrieve the active global ProxyManager singleton."""
    return GLOBAL_PROXY_MGR


def setup_proxy(
    proxy: str = None,
    proxy_file: str = None,
    rotate: int = 0,
    check_health: bool = False,
    use_env: bool = True,
) -> ProxyManager:
    """One-liner proxy setup. Returns configured ProxyManager.
    
    Args:
        proxy: Single proxy URL (socks5://ip:port)
        proxy_file: File with proxy list
        rotate: Rotate every N requests (0=disabled)
        check_health: Run health check on load
    
    Returns:
        Configured ProxyManager with env vars set.
    """
    global GLOBAL_PROXY_MGR, _ENV_FALLBACK_OK
    _ENV_FALLBACK_OK = use_env
    pm = ProxyManager()

    # Only load from --proxy flag, NOT from env auto
    if proxy:
        pm.add_proxy(proxy)
        pm.current_proxy = proxy

    # Load from file
    if proxy_file:
        count = pm.load_from_file(proxy_file)
        if count > 0:
            pm.current_proxy = pm.proxies[0]

    # Fall back to VERDAMT_PROXY: load_from_env() had no callers, so an
    # env-configured proxy was silently ignored unless --proxy was passed.
    # use_env=False (--no-proxy) keeps the scan direct even when the env
    # is configured — the OPSEC escape hatch.
    if use_env and not pm.current_proxy:
        pm.load_from_env()

    # Enable rotation
    if rotate > 0 and len(pm.proxies) > 1:
        pm.enable_rotation(rotate)

    # Set env vars for all tools
    if pm.current_proxy:
        pm.set_env_vars()

    GLOBAL_PROXY_MGR = pm
    return pm


# ---------------------------------------------------------------------------
# Proxy-tunneled raw sockets
#
# asyncio.open_connection() always dials the target directly, which put
# connection-exhaust and smuggling traffic on the real IP even when a proxy
# was configured. Every raw-socket module goes through this instead.
# ---------------------------------------------------------------------------

# resolve_proxy() env fallback gate: setup_proxy(use_env=False) (--no-proxy)
# must also stop OUR code from picking VERDAMT_PROXY up later.
_ENV_FALLBACK_OK = True


def resolve_proxy(proxy: str = None) -> Optional[str]:
    """Proxy to use: explicit argument > global manager > VERDAMT_PROXY."""
    if proxy:
        return proxy
    mgr = get_global_proxy_manager()
    if mgr and mgr.current_proxy:
        return mgr.current_proxy
    if not _ENV_FALLBACK_OK:
        return None
    return os.environ.get("VERDAMT_PROXY") or None


def _blocking_proxied_socket(proxy_url: str, host: str, port: int,
                             timeout: float):
    """Connect to (host, port) through a SOCKS4/5 or HTTP proxy.

    Blocking — always run in a worker thread, never on the event loop.
    """
    import socks as _socks

    parsed = urlparse(proxy_url)
    scheme = (parsed.scheme or "socks5").lower()
    ptype = {
        "socks5": _socks.SOCKS5,
        "socks5h": _socks.SOCKS5,
        "socks4": _socks.SOCKS4,
        "socks4a": _socks.SOCKS4,
        "http": _socks.HTTP,
        "https": _socks.HTTP,
    }.get(scheme)
    if ptype is None:
        raise ValueError(f"unsupported proxy scheme: {scheme}")

    proxy_host = parsed.hostname or ""
    if not proxy_host:
        raise ValueError(f"proxy url has no host: {proxy_url}")
    proxy_port = parsed.port or (443 if scheme == "https" else 1080)
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None

    sock = _socks.socksocket()
    sock.set_proxy(
        ptype,
        proxy_host,
        proxy_port,
        rdns=scheme in ("socks5h", "socks4a", "http", "https"),
        # ^ http(s) CONNECT forwards the NAME — no local DNS query (no leak,
        #   and fake/test hostnames reach the proxy for resolution).
        username=username,
        password=password,
    )
    sock.settimeout(timeout)
    sock.connect((host, port))
    sock.settimeout(None)
    sock.setblocking(False)
    return sock


async def open_proxied_connection(host: str, port: int, *, ssl=None,
                                  server_hostname: str = None,
                                  timeout: float = 10.0,
                                  proxy: str = None):
    """Open a TCP (optionally TLS) stream, tunneled through the active proxy.

    With no proxy configured this is exactly ``asyncio.open_connection``.
    The proxy handshake runs in a worker thread so it cannot stall the loop.
    """
    proxy_url = resolve_proxy(proxy)
    if not proxy_url:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl,
                                    server_hostname=server_hostname),
            timeout=timeout,
        )

    loop = asyncio.get_running_loop()
    sock = await loop.run_in_executor(
        None, _blocking_proxied_socket, proxy_url, host, port, timeout)
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(
                sock=sock,
                ssl=ssl,
                server_hostname=(server_hostname or host) if ssl else None,
            ),
            timeout=timeout,
        )
    except BaseException:
        try:
            sock.close()
        except Exception:
            pass
        raise
