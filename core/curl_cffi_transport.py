"""curl_cffi Transport — TLS fingerprint impersonation for WAF bypass.

Drop-in HTTP client that spoofs browser TLS fingerprints (JA3/JA4).
Bypasses WAF challenges triggered by non-browser TLS stacks.

Supported impersonate targets:
    chrome, edge, safari, firefox, opera
    chrome110, chrome116, chrome120, chrome124, chrome131, chrome136
    safari15_3, safari15_5, safari17_0, safari18_0, safari18_4
    firefox133, firefox135
    edge101

Usage:
    from core.curl_cffi_transport import CurlCffiSession, CurlCffiAsyncSession

    # Sync
    session = CurlCffiSession(impersonate="chrome")
    response = session.request("GET", "https://target.com")
    session.close()

    # Async
    session = CurlCffiAsyncSession(impersonate="chrome")
    response = await session.request("GET", "https://target.com")
    await session.close()
"""

import time
import random
from typing import Dict, Optional
from dataclasses import dataclass

try:
    from curl_cffi.requests import Session, AsyncSession
    CURL_CFFI_AVAILABLE = True
except Exception as e:
    import traceback
    import tempfile
    import os
    try:
        log_path = os.path.join(tempfile.gettempdir(), "curl_cffi_debug.log")
        with open(log_path, "w") as f:
            f.write(traceback.format_exc())
    except Exception:
        pass
    CURL_CFFI_AVAILABLE = False

# Browser impersonation targets (sorted by stealth effectiveness)
BROWSER_TARGETS = {
    "chrome":   ["chrome136", "chrome131", "chrome124", "chrome120", "chrome116", "chrome110"],
    "safari":   ["safari18_4", "safari18_0", "safari17_0", "safari15_5", "safari15_3"],
    "firefox":  ["firefox135", "firefox133"],
    "edge":     ["edge101"],
    "opera":    ["chrome"],  # Opera uses Chrome engine
}

# Default: random Chrome version (most common, least suspicious)
DEFAULT_TARGET = "chrome"


def get_impersonate_target(browser: str = None) -> str:
    """Get a specific or random impersonate target.

    Args:
        browser: 'chrome', 'safari', 'firefox', 'edge', 'opera', or None (random)
    """
    if browser and browser in BROWSER_TARGETS:
        targets = BROWSER_TARGETS[browser]
        return random.choice(targets) if len(targets) > 1 else targets[0]
    # Random Chrome version
    return random.choice(BROWSER_TARGETS["chrome"])




class CurlCffiSession:
    """Sync HTTP session with TLS fingerprint impersonation.

    Drop-in replacement for httpx.Client with impersonation support.
    """

    def __init__(
        self,
        impersonate: str = None,
        browser: str = None,
        timeout: int = 30,
        verify: bool = False,
        follow_redirects: bool = True,
        proxy: str = None,
    ):
        if not CURL_CFFI_AVAILABLE:
            raise ImportError("curl_cffi not installed. Run: pip install curl_cffi")

        target = impersonate or get_impersonate_target(browser)
        self._session = Session(
            impersonate=target,
            timeout=timeout,
            verify=verify,
            allow_redirects=follow_redirects,
        )
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._target = target

    @property
    def impersonate_target(self) -> str:
        return self._target

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        data=None,
        json=None,
        timeout: int = None,
        **kwargs,
    ) -> dict:
        """Send request. Returns dict matching thttp format."""
        from modules.auth.bypass import WAFBypass

        t0 = time.time()
        try:
            resp = self._session.request(
                method, url,
                headers=headers or {},
                data=data,
                json=json,
                timeout=timeout,
            )
            elapsed = time.time() - t0
            resp_headers = dict(resp.headers)
            return {
                "status": resp.status_code,
                "headers": resp_headers,
                "body": resp.text,
                "url": str(resp.url),
                "time": elapsed,
                "error": None,
                "waf": WAFBypass.detect_waf(resp_headers, resp.text),
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "time": time.time() - t0,
                "error": str(e),
                "waf": [],
            }

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def close(self):
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class CurlCffiAsyncSession:
    """Async HTTP session with TLS fingerprint impersonation.

    Drop-in replacement for httpx.AsyncClient with impersonation support.
    """

    def __init__(
        self,
        impersonate: str = None,
        browser: str = None,
        timeout: int = 30,
        verify: bool = False,
        follow_redirects: bool = True,
        proxy: str = None,
    ):
        if not CURL_CFFI_AVAILABLE:
            raise ImportError("curl_cffi not installed. Run: pip install curl_cffi")

        target = impersonate or get_impersonate_target(browser)
        self._session = AsyncSession(
            impersonate=target,
            timeout=timeout,
            verify=verify,
            allow_redirects=follow_redirects,
        )
        if proxy:
            self._session.proxies = {"http": proxy, "https": proxy}
        self._target = target

    @property
    def impersonate_target(self) -> str:
        return self._target

    async def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        data=None,
        json=None,
        timeout: int = None,
        **kwargs,
    ) -> dict:
        """Send async request. Returns dict matching ahttp_send format."""
        from modules.auth.bypass import WAFBypass

        t0 = time.time()
        try:
            resp = await self._session.request(
                method, url,
                headers=headers or {},
                data=data,
                json=json,
                timeout=timeout,
            )
            elapsed = time.time() - t0
            resp_headers = dict(resp.headers)
            return {
                "status": resp.status_code,
                "headers": resp_headers,
                "body": resp.text,
                "url": str(resp.url),
                "time": elapsed,
                "error": None,
                "waf": WAFBypass.detect_waf(resp_headers, resp.text),
            }
        except Exception as e:
            return {
                "status": 0,
                "headers": {},
                "body": "",
                "url": url,
                "time": time.time() - t0,
                "error": str(e),
                "waf": [],
            }

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
