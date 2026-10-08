import asyncio
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class WebSocketSniffer:
    """
    Playwright-assisted WebSocket & EventStream Traffic Interceptor.
    Attaches to page.on('websocket') to capture active ws:// and wss:// endpoints,
    inspect initial handshake auth headers, and sniff real-time frames.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.ws_endpoints: Set[str] = set()
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping WebSocket sniffer.")
            return []

        ph("WEBSOCKET RECON: Real-Time Traffic & Handshake Interceptor")

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                page = await context.new_page()

                def handle_websocket(ws):
                    self.ws_endpoints.add(ws.url)
                    s(f"Captured Active WebSocket Endpoint: {C}{ws.url}{N}")

                    def on_framesent(payload):
                        if isinstance(payload, str) and ("token" in payload.lower() or "auth" in payload.lower() or "bearer" in payload.lower()):
                            self.findings.append({
                                "type": "websocket_auth",
                                "title": "WebSocket Sensitive Auth Frame",
                                "url": ws.url,
                                "detail": f"Sensitive auth string detected in outbound WS frame: {payload[:60]}...",
                                "severity": "Low",
                                "confidence": "confirmed",
                            })

                    ws.on("framesent", on_framesent)

                page.on("websocket", handle_websocket)

                try:
                    await page.goto(self.target_url, wait_until="domcontentloaded", timeout=5000)
                    await page.wait_for_timeout(2000)
                except Exception:
                    pass

                for ws_url in self.ws_endpoints:
                    if ws_url.startswith("ws://"):
                        self.findings.append({
                            "type": "websocket_cleartext",
                            "title": "Cleartext WebSocket Connection (ws://)",
                            "url": ws_url,
                            "detail": "WebSocket connection initialized over unencrypted ws:// protocol instead of wss://",
                            "severity": "Medium",
                            "confidence": "confirmed",
                        })
            finally:
                await context.close()
        except Exception as e:
            w(f"WebSocket sniffer error: {e}")

        return self.findings
