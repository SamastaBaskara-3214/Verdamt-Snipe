import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class ProtoPollutionVerifier:
    """
    Playwright-assisted Prototype Pollution Dynamic Verifier.
    Injects __proto__ vector payloads into URL parameters & hash fragments,
    then inspects Object.prototype at runtime in the live Playwright JS context.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping Prototype Pollution verification.")
            return []

        ph("PROTOTYPE POLLUTION: Dynamic Runtime Verification")

        pollute_key = "verdamt_polluted"
        pollute_val = "VERDAMT_PROTO_TEST"

        payload_urls = [
            f"{self.target_url}#__proto__[{pollute_key}]={pollute_val}",
            f"{self.target_url}?__proto__[{pollute_key}]={pollute_val}",
            f"{self.target_url}?constructor[prototype][{pollute_key}]={pollute_val}",
            f"{self.target_url}#constructor[prototype][{pollute_key}]={pollute_val}",
        ]

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                for p_url in payload_urls:
                    page = await context.new_page()
                    try:
                        await page.goto(p_url, wait_until="domcontentloaded", timeout=3500)
                        await page.wait_for_timeout(500)

                        is_polluted = await page.evaluate(
                            f"() => {{ const polluted = Object.prototype['{pollute_key}'] === '{pollute_val}'; delete Object.prototype['{pollute_key}']; return polluted; }}"
                        )

                        if is_polluted:
                            self.findings.append({
                                "type": "proto_pollution",
                                "title": "Client-Side Prototype Pollution (Object.prototype Polluted)",
                                "url": p_url,
                                "detail": f"Successfully polluted Object.prototype.{pollute_key} via payload URL: {p_url}",
                                "severity": "Critical",
                                "confidence": "confirmed",
                                "verified_poc": p_url,
                            })
                            s(f"Prototype Pollution CONFIRMED on {C}{self.target_url}{N} (Object.prototype polluted!)")
                            await page.close()
                            break
                    except Exception:
                        pass
                    await page.close()
            finally:
                await context.close()
        except Exception as e:
            w(f"Prototype pollution verifier error: {e}")

        return self.findings
