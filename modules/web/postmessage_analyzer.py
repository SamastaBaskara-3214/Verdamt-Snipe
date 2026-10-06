import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class PostMessageAnalyzer:
    """
    Playwright-assisted Cross-Origin PostMessage Inspector.
    Attaches runtime JS listeners to intercept window.postMessage calls,
    evaluate targetOrigin wildcard usage ('*'), and check handler event.origin checks.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping PostMessage analysis.")
            return []

        ph("POSTMESSAGE ANALYZER: Cross-Window Communication Audit")

        init_script = """
        (() => {
            window.__verdamt_postmessages = [];
            window.__verdamt_listeners = [];

            // Hook postMessage
            const origPostMessage = window.postMessage;
            window.postMessage = function(message, targetOrigin, transfer) {
                window.__verdamt_postmessages.push({
                    type: 'send',
                    data: typeof message === 'object' ? JSON.stringify(message) : String(message),
                    targetOrigin: targetOrigin,
                });
                return origPostMessage.apply(this, arguments);
            };

            // Hook addEventListener for 'message'
            const origAddEventListener = window.addEventListener;
            window.addEventListener = function(type, listener, options) {
                if (type === 'message') {
                    const funcStr = listener ? listener.toString() : '';
                    window.__verdamt_listeners.push({
                        handler: funcStr.substring(0, 300),
                        hasOriginCheck: funcStr.includes('origin') || funcStr.includes('source'),
                    });
                }
                return origAddEventListener.apply(this, arguments);
            };
        })();
        """

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                await context.add_init_script(init_script)
                page = await context.new_page()

                try:
                    await page.goto(self.target_url, wait_until="domcontentloaded", timeout=5000)
                    await page.wait_for_timeout(1500)
                except Exception:
                    pass

                # Perform active postMessage PoC dispatch test
                try:
                    await page.evaluate("""() => {
                        window.postMessage({ type: 'VERDAMT_POC_TEST', data: 'verdamt_payload' }, '*');
                    }""")
                    await page.wait_for_timeout(300)
                except Exception:
                    pass

                results = await page.evaluate("() => ({ msgs: window.__verdamt_postmessages || [], listeners: window.__verdamt_listeners || [] })")
                msgs = results.get("msgs", [])
                listeners = results.get("listeners", [])

                # Check for postMessage(msg, "*") wildcard exposure
                for msg in msgs:
                    if msg.get("targetOrigin") == "*":
                        self.findings.append({
                            "type": "postmessage",
                            "title": "PostMessage Leak: Wildcard Target Origin (*)",
                            "url": self.target_url,
                            "detail": f"postMessage sent with targetOrigin='*'. Data preview: {msg.get('data')[:60]}...",
                            "severity": "Medium",
                            "confidence": "confirmed",
                        })
                        s(f"PostMessage Wildcard Origin (*) detected on {C}{self.target_url}{N}")

                # Check for message listeners lacking event.origin validation
                for lst in listeners:
                    if not lst.get("hasOriginCheck"):
                        self.findings.append({
                            "type": "postmessage",
                            "title": "Unvalidated PostMessage Handler",
                            "url": self.target_url,
                            "detail": f"Message listener registered without origin validation in handler: {lst.get('handler')[:80]}...",
                            "severity": "Medium",
                            "confidence": "suspected",
                        })
            finally:
                await context.close()
        except Exception as e:
            w(f"PostMessage analysis error: {e}")

        return self.findings
