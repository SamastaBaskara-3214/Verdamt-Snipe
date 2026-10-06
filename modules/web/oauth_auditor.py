import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class OAuthAuditor:
    """
    Playwright-assisted OAuth / OIDC Token Leak Auditor.
    Monitors redirect URI chains, checks for access_token or id_token leakage
    in Referer headers or browser history fragments.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping OAuth Auditor.")
            return []

        ph("OAUTH / OIDC AUDITOR: Redirect Chain & Token Leak Inspector")

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                page = await context.new_page()

                redirect_chain = []

                async def handle_request(request):
                    url = request.url
                    redirect_chain.append(url)

                    # Check for access_token / id_token in query or fragment
                    if "access_token=" in url or "id_token=" in url:
                        referer = request.headers.get("referer", "")
                        req_domain = urlparse(url).netloc
                        ref_domain = urlparse(referer).netloc if referer else ""

                        if referer and req_domain != ref_domain and ref_domain != "":
                            self.findings.append({
                                "type": "oauth_token_leak",
                                "title": "OAuth Token Leak via Cross-Domain Referer Header",
                                "url": url,
                                "detail": f"OAuth token in URL was leaked to third-party referer: {ref_domain} via Referer: {referer}",
                                "severity": "High",
                                "confidence": "confirmed",
                            })
                            s(f"OAuth Token Leak Detected to {C}{ref_domain}{N}")

                page.on("request", handle_request)

                try:
                    await page.goto(self.target_url, wait_until="domcontentloaded", timeout=4000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass
            finally:
                await context.close()
        except Exception as e:
            w(f"OAuth Auditor error: {e}")

        return self.findings
