import asyncio
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, urljoin

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class SPACrawler:
    """
    Playwright-assisted Dynamic Form & SPA Multi-Step Crawler.
    Simulates button clicks, form inputs, and frontend router state changes
    to discover hidden endpoints & inputs unattainable by static HTTP crawlers.
    """

    def __init__(self, target_url: str, max_depth: int = 2):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.discovered_urls: Set[str] = set()
        self.discovered_params: Dict[str, List[str]] = {}

    async def run(self) -> Dict[str, Any]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping SPA dynamic crawler.")
            return {"urls": [], "params": {}}

        ph("SPA CRAWLER: Dynamic Form & Router Interaction Engine")

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return {"urls": [], "params": {}}

            try:
                # Block heavy assets to speed up crawl
                await context.route("**/*.{png,jpg,jpeg,gif,css,woff,mp4}", lambda route: route.abort())

                page = await context.new_page()

                # Record all network requests
                def handle_request(request):
                    url = request.url
                    if self.domain in urlparse(url).netloc:
                        self.discovered_urls.add(url)
                        parsed = urlparse(url)
                        if parsed.query:
                            from urllib.parse import parse_qs
                            q_dict = parse_qs(parsed.query)
                            for k in q_dict.keys():
                                self.discovered_params.setdefault(parsed.path or "/", []).append(k)

                page.on("request", handle_request)

                try:
                    await page.goto(self.target_url, wait_until="domcontentloaded", timeout=4000)
                    await page.wait_for_timeout(1000)

                    # Extract & interact with forms/inputs
                    inputs = await page.query_selector_all("input[name]")
                    for inp in inputs[:10]:
                        name = await inp.get_attribute("name")
                        if name:
                            self.discovered_params.setdefault("/", []).append(name)

                    # Simulate clicking interactive buttons & links
                    clickable = await page.query_selector_all("button, a[href^='/'], [role='button']")
                    for elem in clickable[:8]:
                        try:
                            await elem.click(timeout=800)
                            await page.wait_for_timeout(300)
                        except Exception:
                            pass
                except Exception:
                    pass
            finally:
                await context.close()
        except Exception as e:
            w(f"SPA Crawler error: {e}")

        s(f"SPA Crawler Discovered {W}{len(self.discovered_urls)}{N} endpoints via DOM interaction")
        return {"urls": list(self.discovered_urls), "params": self.discovered_params}
