"""
HTTP Client — merged from http_client.py, network.py, async_network.py
Single source of truth for all HTTP operations.
"""
import asyncio
import gzip
import json
import random
import re
import socket
import ssl
import time
import zlib
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlencode, urljoin, urlparse

import enum
import httpx
from core.policy import ScanPolicy

try:
    import brotli
except ImportError:
    brotli = None

_POLICY_DENY_WARNED: set = set()


def _warn_policy_deny(reason: str) -> None:
    """One-shot loud warning when ScanPolicy denies a request.

    Budget exhaustion used to be SILENT: ahttp_send returned status=0
    which downstream reads as 'no response' (Arjun even printed
    'Target unreachable'), so scans quietly stopped finding anything.
    Warn once per reason — no log spam across thousands of denials.
    """
    if reason in _POLICY_DENY_WARNED:
        return
    _POLICY_DENY_WARNED.add(reason)
    try:
        from core.ui import w as _lw
        extra = (" — raise --max-requests for longer runs"
                 if "budget" in reason else "")
        _lw(f"[policy] request denied: {reason}{extra} "
            "(downstream reads this as 'no response')")
    except Exception:
        pass

# Constants

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Encoding": "gzip, deflate, br",
}

TIMEOUT = 20


# Dataclasses

@dataclass
class HTTPResponse:
    """Structured HTTP response from HTTPClient."""
    status_code: int
    headers: dict
    text: str
    content: bytes
    url: str
    elapsed: float = 0.0
    error: str = None


# GhostMode (stealth/evasion)

class GhostMode:
    """Stealth & Evasion Engine — Minimal Tracking.
    
    Supports two activation modes:
    1. Manual: User passes --stealth flag → ENABLED = True (global).
    2. Auto-Evasion: RateLimiter detects WAF pressure on a specific host
       → stealth headers are activated for that host only (adaptive).
    """
    ENABLED = False
    JITTER_RANGE = (0.5, 2.5)
    _rate_limiter = None  # Injected reference to global RateLimiter

    @classmethod
    def set_rate_limiter(cls, rate_limiter):
        """Inject RateLimiter reference for auto-evasion integration."""
        cls._rate_limiter = rate_limiter

    @staticmethod
    def apply_jitter_sync():
        if GhostMode.ENABLED:
            time.sleep(random.uniform(*GhostMode.JITTER_RANGE))

    @staticmethod
    async def apply_jitter():
        if GhostMode.ENABLED:
            await asyncio.sleep(random.uniform(*GhostMode.JITTER_RANGE))

    @classmethod
    def should_stealth(cls, host: str) -> bool:
        """Check if stealth headers should be used for a given host.
        Returns True if:
        - Global --stealth flag is enabled, OR
        - RateLimiter has auto-activated stealth for this host due to WAF pressure.
        """
        if cls.ENABLED:
            return True
        if cls._rate_limiter and cls._rate_limiter.is_auto_stealth(host):
            return True
        return False

    @staticmethod
    def get_stealth_headers(host: str) -> dict:
        browsers = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ]
        return {
            "Host": host,
            "User-Agent": random.choice(browsers),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }


# HTTPClient (httpx + raw socket fallback)

class HTTPClient:
    """HTTP adapter with httpx first and raw-socket fallback for awkward servers."""

    def __init__(self, timeout=30, follow_redirects=True, max_retries=2):
        self.session = None
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_retries = max_retries

    def _ensure_session(self):
        if self.session is not None:
            return
        transport = httpx.HTTPTransport(
            verify=False,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=50),
            retries=0,
        )
        self.session = httpx.Client(
            transport=transport,
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
        )

    def request(self, method, url, **kwargs) -> HTTPResponse:
        self._ensure_session()
        headers = dict(DEFAULT_HEADERS)
        headers.update(kwargs.pop("headers", {}) or {})
        follow_redirects = kwargs.pop("follow_redirects", self.follow_redirects)

        start = time.time()
        try:
            resp = self.session.request(method, url, headers=headers,
                                        follow_redirects=follow_redirects, **kwargs)
            content = self._decode_content(resp.content, resp.headers)
            text = self._to_text(content, resp.encoding)
            return HTTPResponse(
                status_code=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=text, content=content, url=str(resp.url),
                elapsed=time.time() - start,
            )
        except (
            httpx.RemoteProtocolError, httpx.ConnectError,
            httpx.UnsupportedProtocol, httpx.ReadTimeout, httpx.ConnectTimeout,
        ):
            return self._raw_socket_request(method, url, headers=headers,
                                            follow_redirects=follow_redirects, **kwargs)

    def _decode_content(self, content: bytes, headers: dict) -> bytes:
        te = (headers.get("transfer-encoding") or headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te and content:
            content = _dechunk(content)
        encoding = (headers.get("content-encoding") or headers.get("Content-Encoding") or "").lower()
        try:
            if "gzip" in encoding:
                return zlib.decompress(content, zlib.MAX_WBITS | 16)
            if "deflate" in encoding:
                return zlib.decompress(content)
            if "br" in encoding and brotli:
                return brotli.decompress(content)
        except Exception:
            return content
        return content

    def _to_text(self, content: bytes, encoding=None) -> str:
        for enc in [encoding, "utf-8", "latin-1"]:
            if not enc:
                continue
            try:
                return content.decode(enc, "replace")
            except Exception:
                pass
        return content.decode("utf-8", "replace")

    def _raw_socket_request(self, method, url, **kwargs) -> HTTPResponse:
        return self._raw_socket_request_inner(method, url, kwargs, redirects_left=5)

    def _raw_socket_request_inner(self, method, url, kwargs, redirects_left) -> HTTPResponse:
        start = time.time()
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return HTTPResponse(0, {}, "", b"", url, time.time() - start, "unsupported_url")

        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        headers = dict(kwargs.get("headers") or {})
        data = kwargs.get("data") or kwargs.get("content") or b""
        if isinstance(data, str):
            data = data.encode()
        elif isinstance(data, dict):
            data = urlencode(data).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        req_headers = {
            "Host": host + (f":{port}" if port not in (80, 443) else ""),
            "User-Agent": headers.pop("User-Agent", headers.pop("user-agent", "Mozilla/5.0")),
            "Accept": headers.pop("Accept", headers.pop("accept", "*/*")),
            "Connection": "close",
        }
        req_headers.update(headers)
        if data:
            req_headers["Content-Length"] = str(len(data))

        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(self.timeout)

            crlf = "\r\n"
            request = f"{method.upper()} {path} HTTP/1.1{crlf}"
            request += crlf.join(f"{k}: {v}" for k, v in req_headers.items())
            request += crlf * 2
            sock.sendall(request.encode() + data)

            raw = b""
            MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50MB safety limit
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > MAX_RESPONSE_SIZE:
                    break
            sock.close()
        except Exception as exc:
            return HTTPResponse(0, {}, "", b"", url, time.time() - start, str(exc))

        status_code, headers, body = self._parse_raw_response(raw)
        body = self._decode_content(body, headers)
        final_url = url

        if redirects_left > 0 and status_code in (301, 302, 303, 307, 308):
            location = headers.get("location")
            if location:
                next_url = urljoin(url, location)
                next_method = "GET" if status_code in (301, 302, 303) else method
                return self._raw_socket_request_inner(next_method, next_url, kwargs, redirects_left - 1)

        return HTTPResponse(
            status_code=status_code, headers=headers,
            text=self._to_text(body), content=body,
            url=final_url, elapsed=time.time() - start,
        )

    async def _async_raw_socket_request(self, method, url, **kwargs) -> HTTPResponse:
        return await self._async_raw_socket_request_inner(method, url, kwargs, redirects_left=5)

    async def _async_raw_socket_request_inner(self, method, url, kwargs, redirects_left) -> HTTPResponse:
        start = time.time()
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return HTTPResponse(0, {}, "", b"", url, time.time() - start, "unsupported_url")

        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        headers = dict(kwargs.get("headers") or {})
        data = kwargs.get("data") or kwargs.get("content") or b""
        if isinstance(data, str):
            data = data.encode()
        elif isinstance(data, dict):
            data = urlencode(data).encode()
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        req_headers = {
            "Host": host + (f":{port}" if port not in (80, 443) else ""),
            "User-Agent": headers.pop("User-Agent", headers.pop("user-agent", "Mozilla/5.0")),
            "Accept": headers.pop("Accept", headers.pop("accept", "*/*")),
            "Connection": "close",
        }
        req_headers.update(headers)
        if data:
            req_headers["Content-Length"] = str(len(data))

        try:
            crlf = "\r\n"
            request = f"{method.upper()} {path} HTTP/1.1{crlf}"
            request += crlf.join(f"{k}: {v}" for k, v in req_headers.items())
            request += crlf * 2
            request_bytes = request.encode() + data

            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )

            writer.write(request_bytes)
            await asyncio.wait_for(writer.drain(), timeout=self.timeout)

            raw = b""
            MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50MB safety limit
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=self.timeout)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > MAX_RESPONSE_SIZE:
                    break
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            return HTTPResponse(0, {}, "", b"", url, time.time() - start, str(exc))

        status_code, headers, body = self._parse_raw_response(raw)
        body = self._decode_content(body, headers)
        final_url = url

        if redirects_left > 0 and status_code in (301, 302, 303, 307, 308):
            location = headers.get("location")
            if location:
                next_url = urljoin(url, location)
                next_method = "GET" if status_code in (301, 302, 303) else method
                return await self._async_raw_socket_request_inner(next_method, next_url, kwargs, redirects_left - 1)

        return HTTPResponse(
            status_code=status_code, headers=headers,
            text=self._to_text(body), content=body,
            url=final_url, elapsed=time.time() - start,
        )

    def _parse_raw_response(self, raw: bytes):
        header_blob, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            header_blob, sep, body = raw.partition(b"\n\n")
        header_text = header_blob.decode("iso-8859-1", "replace")
        lines = header_text.splitlines()
        status_code = 0
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2 and parts[1].isdigit():
                status_code = int(parts[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = self._decode_chunked(body)
        return status_code, headers, body

    def _decode_chunked(self, body: bytes) -> bytes:
        out = bytearray()
        idx = 0
        while idx < len(body):
            line_end = body.find(b"\r\n", idx)
            if line_end == -1:
                break
            size_line = body[idx:line_end].split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                break
            idx = line_end + 2
            if size == 0:
                break
            out.extend(body[idx:idx + size])
            idx += size + 2
        return bytes(out)

    def close(self):
        if self.session is not None:
            self.session.close()
            self.session = None


def _dechunk(data: bytes) -> bytes:
    """Decode HTTP/1.1 chunked transfer-encoding framing (raw-socket path)."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j == -1:
            return bytes(data)  # malformed framing — hand back untouched
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(data)
        if size == 0:
            break
        start = j + 2
        out += data[start:start + size]
        i = start + size + 2  # skip chunk data + trailing CRLF
    return bytes(out)


# Raw Socket HTTP (zero-dependency sync)

def http_send(url: str, method: str = "GET", headers: dict = None,
              data: str = None, timeout: int = TIMEOUT,
              bypass: bool = False, raw: bool = False,
              max_retries: int = 3,
              impersonate: str = None,
              policy: Optional[ScanPolicy] = None) -> dict:
    """HTTP(S) request with optional TLS fingerprint impersonation.
    
    Args:
        impersonate: Browser target for TLS spoofing ('chrome', 'safari', 'firefox')
                     None = use raw socket (default behavior)
    """
    if policy:
        decision = policy.authorize_request(url, method)
        if not decision.allowed:
            _warn_policy_deny(decision.reason)
            return {
                "status": 0,
                "error": f"policy_denied:{decision.reason}",
                "body": "",
                "headers": {},
                "url": url,
                "time": 0,
                "waf": [],
            }
        if getattr(policy, "dry_run", False):
            policy.refund_request()  # simulation must not burn real budget
            return {
                "status": 200,
                "error": None,
                "body": "[DRY RUN] Request authorized but not dispatched to network.",
                "headers": {"content-type": "text/html; charset=utf-8", "x-verdamt-dry-run": "1"},
                "url": url,
                "time": 0.001,
                "waf": [],
            }
        timeout = policy.clamp_timeout(timeout)

    # Local import to avoid circular dep (core.client → modules.auth → ...)
    from modules.auth.bypass import WAFBypass
    from core.ui import w as log_warn, count_request
    count_request()

    p = urlparse(url)
    host = p.hostname or (p.netloc.split(":")[0] if ":" in p.netloc else p.netloc) or ""

    # curl_cffi path (TLS impersonation — default)
    try:
        from core.curl_cffi_transport import CurlCffiSession, CURL_CFFI_AVAILABLE
        if CURL_CFFI_AVAILABLE:
            target = impersonate or "chrome"
            session = CurlCffiSession(
                impersonate=target,
                timeout=timeout,
                verify=False,
                follow_redirects=policy is None,
            )
            hdrs = dict(headers or {})
            if bypass:
                hdrs.update(WAFBypass.get_bypass_headers())
            elif GhostMode.should_stealth(host):
                hdrs.update(GhostMode.get_stealth_headers(host))

            GhostMode.apply_jitter_sync()
            result = session.request(method, url, headers=hdrs, data=data)
            session.close()

            # Rate limit retry
            if result.get("status") == 429 and max_retries > 0:
                retry_after = result.get("headers", {}).get("retry-after", "")
                try:
                    wait_time = min(int(retry_after), 30)
                except (ValueError, TypeError):
                    wait_time = 5
                log_warn(f"Rate limited (429). Backing off {wait_time}s... ({max_retries} retries left)")
                time.sleep(wait_time)
                return http_send(url, method=method, headers=headers, data=data,
                                 timeout=timeout, bypass=bypass, raw=raw,
                                 max_retries=max_retries - 1,
                                 impersonate=impersonate, policy=policy)
            if policy and result.get("url") and not policy.allows_url(result["url"]):
                result.update(
                    status=0,
                    error="policy_denied:redirect_out_of_scope",
                    body="",
                    waf=[],
                )
            return result
    except ImportError:
        log_warn("curl_cffi not available, falling back to raw socket")

    # Raw socket path (fallback)

    out = {"status": 0, "headers": {}, "body": "", "url": url,
           "error": None, "time": 0, "waf": [], "raw": ""}
    t0 = time.time()
    try:
        p = urlparse(url)
        host = p.hostname or p.netloc.split(":")[0]
        port = p.port or (443 if p.scheme == "https" else 80)
        path = (p.path or "/") + ("?" + p.query if p.query else "")

        hdrs = {
            "Host": host + (f":{port}" if port not in (80, 443) else ""),
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)

        if bypass:
            bypass_hdrs = WAFBypass.get_bypass_headers()
            for k, v in bypass_hdrs.items():
                if k not in hdrs or k.lower() in ("user-agent", "accept", "accept-language"):
                    hdrs[k] = v
        elif GhostMode.should_stealth(host):
            stealth_hdrs = GhostMode.get_stealth_headers(host)
            for k, v in stealth_hdrs.items():
                if k not in hdrs:
                    hdrs[k] = v

        GhostMode.apply_jitter_sync()

        if data:
            if isinstance(data, dict) and not raw:
                data = urlencode(data)
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            d = data.encode() if isinstance(data, str) else data
            hdrs["Content-Length"] = str(len(d))
        else:
            d = b""

        crlf = b"\r\n"
        req_line = f"{method} {path} HTTP/1.1".encode()
        header_lines = crlf.join(f"{k}: {v}".encode() for k, v in hdrs.items())
        req_bytes = req_line + crlf + header_lines + crlf * 2
        if d:
            req_bytes += d if isinstance(d, bytes) else d.encode()
        out["raw"] = req_bytes.decode("latin-1", errors="replace")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        sock.sendall(req_bytes)

        resp = b""
        MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50MB limit
        while True:
            try:
                c = sock.recv(32768)
                if not c:
                    break
                resp += c
                if len(resp) > MAX_RESPONSE_SIZE:
                    break
            except Exception:
                break
        sock.close()

        # Split headers first, decompress body only
        crlf_bytes = b"\r\n\r\n"
        if crlf_bytes in resp:
            hp_raw, body_raw = resp.split(crlf_bytes, 1)
        else:
            hp_raw, body_raw = resp, b""
        try:
            if body_raw[:2] == b'\x1f\x8b':
                body_raw = gzip.decompress(body_raw)
            elif body_raw[:3] == b'\x1f\x9d':
                body_raw = zlib.decompress(body_raw)
        except Exception:
            pass
        hp = hp_raw.decode("iso-8859-1", "replace")
        body = body_raw.decode("utf-8", "replace")

        lines = hp.split("\r\n")
        m = re.match(r'HTTP/\d\.\d+\s+(\d+)', lines[0]) if lines else None
        if m:
            out["status"] = int(m.group(1))
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                out["headers"][k.strip().lower()] = v.strip()
        out["body"] = body
        out["time"] = time.time() - t0
        out["waf"] = WAFBypass.detect_waf(out["headers"], out["body"])

        # Rate Limit Detection & Auto-Backoff
        if out["status"] == 429:
            retry_after = out["headers"].get("retry-after", "")
            try:
                wait_time = int(retry_after)
            except (ValueError, TypeError):
                wait_time = 5
            wait_time = min(wait_time, 30)
            if max_retries > 0:
                log_warn(f"Rate limited (429). Backing off {wait_time}s... ({max_retries} retries left)")
                time.sleep(wait_time)
                return http_send(url, method=method, headers=headers, data=data,
                                 timeout=timeout, bypass=bypass, raw=raw,
                                 max_retries=max_retries - 1,
                                 impersonate=impersonate, policy=policy)
            else:
                out["error"] = "rate_limited"
    except Exception as ex:
        out["error"] = str(ex)
    return out


def thttp(*a, **kw):
    """Legacy alias for http_send with blanket exception safety."""
    try:
        return http_send(*a, **kw)
    except Exception as ex:
        return {"status": 0, "headers": {}, "body": "", "url": "",
                "error": str(ex) or type(ex).__name__, "waf": []}


def dns_resolve(domain: str) -> List[str]:
    """Resolve domain to IPs (IPv4 + IPv6)."""
    ips = set()
    for af in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo(domain, 80, af, socket.SOCK_STREAM):
                ips.add(info[4][0])
        except Exception:
            pass
    return list(ips)


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

class AsyncNetworkEngine:
    """High-performance, multiplexed HTTP/2 asynchronous network engine.
    
    Supports curl_cffi impersonation for TLS fingerprint spoofing.
    Circuit breaker + adaptive pacing integrated for smart throttling.
    Integrates dynamically with ProxyManager for per-request proxy rotation.
    """

    def __init__(self, max_connections: int = 100, impersonate: str = None,
                 browser: str = None, policy=None):
        self.impersonate = impersonate
        self.browser = browser
        self.policy = policy
        # Optional callback(latency_seconds) invoked once per successful
        # response. Poison mode wires it to PoisonState.track_request_latency
        # so adaptive concurrency reacts to real request latency instead of
        # whole-phase durations. None = no overhead, no behavior change.
        self.latency_observer = None
        policy_limit = getattr(policy, "max_concurrency", None)
        self.max_connections = min(max_connections, policy_limit) if policy_limit else max_connections
        self._use_curl_cffi = False
        self._curl_cffi_session = None
        self._active_proxy = None
        self.client = None
        self._rebuild_lock = asyncio.Lock()
        self._request_semaphore = asyncio.Semaphore(self.max_connections)

        # Check if curl_cffi is available to set the default _use_curl_cffi flag
        try:
            from core.curl_cffi_transport import CURL_CFFI_AVAILABLE
            if CURL_CFFI_AVAILABLE:
                self._use_curl_cffi = True
        except ImportError:
            pass

        # Build initial client synchronously (no old session to close yet)
        self._build_client(None)

        # Per-host rate limiter (primary) + legacy global pacing (fallback)
        from core.host_ratelimit import HostRateLimiter
        self.host_limiter = HostRateLimiter(default_max_concurrent=max_connections)
        self.rate_limiter = AdaptivePacingSystem()
        self.circuit_breaker = CircuitBreaker()

    def _build_client(self, proxy: Optional[str]):
        """Builds a new HTTP client with the given proxy (no old session closing)."""
        self._active_proxy = proxy

        try:
            from core.curl_cffi_transport import CurlCffiAsyncSession, CURL_CFFI_AVAILABLE
            if CURL_CFFI_AVAILABLE:
                self._curl_cffi_session = CurlCffiAsyncSession(
                    impersonate=self.impersonate,
                    browser=self.browser or "chrome",
                    timeout=30,
                    verify=False,
                    # Redirects are disabled when policy enforcement is active:
                    # a transport client must never silently follow an
                    # out-of-scope Location header.
                    follow_redirects=self.policy is None,
                    proxy=proxy,
                )
                self._use_curl_cffi = True
                return
        except ImportError:
            pass

        self._use_curl_cffi = False
        self.limits = httpx.Limits(
            max_keepalive_connections=self.max_connections,
            max_connections=self.max_connections,
        )
        self.client = httpx.AsyncClient(
            http2=True, verify=False, follow_redirects=self.policy is None,
            limits=self.limits, timeout=httpx.Timeout(10.0),
            proxy=proxy,
        )

    async def _rebuild_client_with_proxy(self, proxy: Optional[str]):
        """Closes existing sessions and rebuilds the HTTP client with the new proxy."""
        if self._use_curl_cffi and self._curl_cffi_session:
            old = self._curl_cffi_session
            self._curl_cffi_session = None
            try:
                await old.close()
            except Exception:
                pass
        elif self.client:
            old = self.client
            self.client = None
            try:
                await old.aclose()
            except Exception:
                pass

        self._build_client(proxy)

    async def ahttp_send(self, url: str, method: str = "GET", headers: dict = None,
                          data=None, json=None, bypass: bool = False,
                          state_context=None,
                          timeout: Optional[float] = None) -> dict:
        """Async HTTP request with per-host rate limiting + circuit breaker."""
        from modules.auth.bypass import WAFBypass
        from urllib.parse import urlparse as _urlparse
        from core.proxy_manager import get_global_proxy_manager
        from core.ui import count_request

        if self.policy:
            decision = self.policy.authorize_request(url, method)
            if not decision.allowed:
                _warn_policy_deny(decision.reason)
                return {
                    "status": 0,
                    "error": f"policy_denied:{decision.reason}",
                    "time": 0,
                    "waf": [],
                    "body": "",
                    "headers": {},
                    "url": url,
                }
            if getattr(self.policy, "dry_run", False):
                self.policy.refund_request()  # simulation must not burn budget
                return {
                    "status": 200,
                    "error": None,
                    "body": "[DRY RUN] Request authorized but not dispatched to network.",
                    "headers": {"content-type": "text/html; charset=utf-8", "x-verdamt-dry-run": "1"},
                    "url": url,
                    "time": 0.001,
                    "waf": [],
                }
            timeout = self.policy.clamp_timeout(timeout)

        # Dynamic Proxy Check: Re-build client if active proxy has changed in manager
        proxy_mgr = get_global_proxy_manager()
        if proxy_mgr and proxy_mgr.get_current() != self._active_proxy:
            async with self._rebuild_lock:
                # Double-check after acquiring lock
                if proxy_mgr.get_current() != self._active_proxy:
                    await self._rebuild_client_with_proxy(proxy_mgr.get_current())

        hostname = _urlparse(url).hostname or "unknown"

        # Per-host rate limit acquire (with timeout = request timeout + 5s)
        acquire_timeout = min(timeout + 5, 30) if timeout else 15
        if not await self.host_limiter.acquire(hostname, timeout=acquire_timeout):
            if self.policy:
                self.policy.refund_request()  # never dispatched
            return {
                "status": 0, "error": f"rate_limited: host {hostname} backoff active",
                "time": 0, "waf": [], "body": "", "headers": {},
            }

        global_acquired = False
        try:
            await asyncio.wait_for(self._request_semaphore.acquire(), timeout=acquire_timeout)
            global_acquired = True
        except asyncio.TimeoutError:
            self.host_limiter.release(hostname, 0)
            if self.policy:
                self.policy.refund_request()  # never dispatched
            return {
                "status": 0, "error": "concurrency_budget_exhausted",
                "time": 0, "waf": [], "body": "", "headers": {},
            }

        status = 0
        start_time = time.time()
        try:
            # Circuit breaker check — block if OPEN
            if not self.circuit_breaker.allow_request(hostname):
                cooldown = self.circuit_breaker.get_cooldown_remaining(hostname)
                if proxy_mgr:
                    proxy_mgr.record_request(error=True)
                if self.policy:
                    self.policy.refund_request()  # never dispatched
                return {
                    "status": 0, "error": f"circuit_open: cooling down ({cooldown:.0f}s remaining)",
                    "time": 0, "waf": [], "body": "", "headers": {},
                }

            count_request()  # actual dispatch point (post policy/limiter/circuit)

            req_headers = dict(headers or {})

            if state_context:
                state_context.inject_auth(url, req_headers)

            if bypass:
                req_headers.update(WAFBypass.get_bypass_headers())

            # NOTE: rate_limiter.wait() removed — host_limiter already handles
            # per-host pacing. Keeping record_latency/trigger_backoff for metrics.

            is_error = False

            if self._use_curl_cffi:
                response = await self._curl_cffi_session.request(
                    method, url, headers=req_headers,
                    data=data, json=json,
                    timeout=int(timeout) if timeout else None,
                )
            else:
                response = await self.client.request(
                    method, url, headers=req_headers,
                    data=data, json=json, timeout=timeout,
                )
                waf = WAFBypass.detect_waf(dict(response.headers), response.text)
                response = {
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                    "url": str(response.url),
                    "time": time.time() - start_time,
                    "error": None,
                    "waf": waf,
                }

            if self.policy and response.get("url") and not self.policy.allows_url(response["url"]):
                return {
                    "status": 0,
                    "error": "policy_denied:redirect_out_of_scope",
                    "time": time.time() - start_time,
                    "waf": [],
                    "body": "",
                    "headers": {},
                    "url": response.get("url", url),
                }

            latency = response.get("time", time.time() - start_time)
            if self.latency_observer is not None:
                try:
                    self.latency_observer(latency)
                except Exception:
                    pass
            status = response.get("status", 0)

            # Update circuit breaker + pacing based on response
            if status in (403, 429):
                self.circuit_breaker.record_failure(hostname, status)
                self.rate_limiter.trigger_backoff()
                is_error = True
            elif status > 0:
                self.circuit_breaker.record_success(hostname)

            if proxy_mgr:
                proxy_mgr.record_request(error=is_error)

            # Passive Secret Scanning
            if response.get("body") and response.get("status") == 200:
                try:
                    from core.secret_scanner import SecretScanner
                    sec_findings = SecretScanner.scan_response(url, response["body"])
                    if sec_findings:
                        from core.audit import AuditLogger
                        for sf in sec_findings:
                            AuditLogger.get_instance().log_finding(
                                sf["title"], sf["severity"], sf["url"], sf["detail"]
                            )
                except Exception:
                    pass

            return response
        except Exception as e:
            self.rate_limiter.record_error()
            # Transport-level errors (DNS/connect/TLS/timeout) are NOT server
            # rejections — counting them opened the circuit after 5 flaky
            # packets and stalled the scan for the cooldown.
            if proxy_mgr:
                proxy_mgr.record_request(error=True)
            status = 0
            return {"status": 0, "error": str(e), "time": time.time() - start_time,
                    "waf": [], "body": "", "headers": {}}
        finally:
            # Always release per-host semaphore + update backoff state
            self.host_limiter.release(hostname, status)
            if global_acquired:
                self._request_semaphore.release()

    async def close(self):
        if self._use_curl_cffi and self._curl_cffi_session:
            try:
                await self._curl_cffi_session.close()
            except Exception:
                pass
            self._curl_cffi_session = None
        elif self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass
            self.client = None
