"""Singleton Shared Playwright Browser Instance Pool.

Prevents browser startup/teardown bottleneck by reusing a single Chromium process
across all Playwright security modules (CSRF, PostMessage, Clickjacking, WS, Proto, etc).
"""

import asyncio
from typing import Optional, Dict, Any

try:
    from playwright.async_api import async_playwright, Playwright, Browser, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class SharedBrowserPool:
    """Thread-safe & Async-safe Playwright Browser Singleton Pool."""

    _instance: Optional["SharedBrowserPool"] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self._pw: Optional[Any] = None
        self._browser: Optional[Any] = None

    @classmethod
    async def get_browser(cls) -> Optional[Any]:
        """Get or initialize shared browser instance."""
        if not PLAYWRIGHT_AVAILABLE:
            return None

        if cls._instance is None:
            async with cls._lock:
                if cls._instance is None:
                    pool = cls()
                    await pool._init_browser()
                    cls._instance = pool

        return cls._instance._browser

    async def _init_browser(self):
        try:
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--blink-settings=imagesEnabled=false",
                ]
            )
        except Exception:
            self._browser = None

    @classmethod
    async def new_context(cls, proxy: Optional[str] = None) -> Optional[Any]:
        """Create an isolated lightweight BrowserContext from the shared browser pool."""
        browser = await cls.get_browser()
        if not browser:
            return None

        kwargs: Dict[str, Any] = {
            "viewport": {"width": 1280, "height": 720},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "ignore_https_errors": True,
        }
        if proxy:
            kwargs["proxy"] = {"server": proxy}

        context = await browser.new_context(**kwargs)
        # Block non-essential media & CSS assets globally across all Playwright modules
        await context.route(
            "**/*.{png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,webm,pdf}",
            lambda route: route.abort()
        )
        return context

    @classmethod
    async def shutdown(cls):
        """Clean shutdown of the shared browser process."""
        if cls._instance and cls._instance._browser:
            async with cls._lock:
                if cls._instance and cls._instance._browser:
                    try:
                        await cls._instance._browser.close()
                        if cls._instance._pw:
                            await cls._instance._pw.stop()
                    except Exception:
                        pass
                    cls._instance = None
