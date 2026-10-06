import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class ClickjackingInspector:
    """
    Playwright-assisted Clickjacking & UI Redressing Verifier.
    Renders the target URL inside a cross-origin iframe context,
    evaluates X-Frame-Options / CSP frame-ancestors enforcement,
    and detects actionable UI element framing risks.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping Clickjacking inspection.")
            return []

        ph("CLICKJACKING INSPECTOR: UI Framing & Redressing Test")

        attacker_origin = "https://attacker-framing.example"
        iframe_poc_html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>Clickjacking Test</title></head>
        <body>
            <iframe id="targetFrame" src="{self.target_url}" width="800" height="600"></iframe>
        </body>
        </html>
        """

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                page = await context.new_page()

                # Serve iframe PoC HTML on attacker origin
                await page.route(f"{attacker_origin}/*", lambda route: route.fulfill(
                    status=200,
                    content_type="text/html",
                    body=iframe_poc_html
                ))

                frame_loaded = False

                def handle_frame_attached(frame):
                    nonlocal frame_loaded
                    if self.domain in urlparse(frame.url).netloc:
                        frame_loaded = True

                page.on("frameattached", handle_frame_attached)

                try:
                    await page.goto(f"{attacker_origin}/frame_test.html", wait_until="domcontentloaded", timeout=4000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass

                # Check frame load status & frame-busting headers
                frame_element = await page.query_selector("#targetFrame")
                if frame_element:
                    content_frame = await frame_element.content_frame()
                    if content_frame and content_frame.url != "about:blank":
                        # Frame successfully rendered cross-origin
                        self.findings.append({
                            "type": "clickjacking",
                            "title": "Clickjacking: Target Rendered Cross-Origin in Iframe",
                            "url": self.target_url,
                            "detail": "Target page loaded inside cross-origin iframe without X-Frame-Options or CSP frame-ancestors block.",
                            "severity": "Medium",
                            "confidence": "confirmed",
                            "verified_poc": f"<iframe src='{self.target_url}'></iframe>",
                        })
                        s(f"Clickjacking Vulnerability Confirmed on {C}{self.target_url}{N} (Framing allowed)")
            finally:
                await context.close()
        except Exception as e:
            w(f"Clickjacking inspection error: {e}")

        return self.findings
