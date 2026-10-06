import asyncio
from typing import List, Dict, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY


class CORSVerifier:
    """
    Playwright-assisted CORS Credentials & Origin Live Tester.
    Executes cross-origin fetch requests with credentials from an isolated domain origin
    inside Playwright to test if Access-Control-Allow-Origin: * / reflect + Access-Control-Allow-Credentials: true holds.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping CORS live verifier.")
            return []

        ph("CORS VERIFIER: Live Cross-Origin Credentials Test")

        attacker_origin = "https://evil-attacker.example"
        cors_test_html = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <script>
                fetch('{self.target_url}', {{ credentials: 'include' }})
                    .then(r => {{
                        window.__cors_acao = r.headers.get('access-control-allow-origin');
                        window.__cors_acac = r.headers.get('access-control-allow-credentials');
                        return r.text();
                    }})
                    .then(txt => {{
                        window.__cors_body = txt.substring(0, 100);
                    }})
                    .catch(err => {{
                        window.__cors_err = String(err);
                    }});
            </script>
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

                # Serve test HTML on attacker origin
                await page.route(f"{attacker_origin}/*", lambda route: route.fulfill(
                    status=200,
                    content_type="text/html",
                    body=cors_test_html
                ))

                try:
                    await page.goto(f"{attacker_origin}/cors_test.html", wait_until="domcontentloaded", timeout=4000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass

                cors_res = await page.evaluate("() => ({ acao: window.__cors_acao, acac: window.__cors_acac, err: window.__cors_err, body: window.__cors_body })")
                acao = cors_res.get("acao")
                acac = cors_res.get("acac")

                if acao and (acao == attacker_origin or acao == "*") and acac == "true":
                    self.findings.append({
                        "type": "cors_misconfig",
                        "title": "CORS Misconfiguration: Arbitrary Origin with Credentials Allowed",
                        "url": self.target_url,
                        "detail": f"Target endpoint responded with ACAO: {acao} and ACAC: true to cross-origin request from {attacker_origin}.",
                        "severity": "High",
                        "confidence": "confirmed",
                        "verified_poc": f"fetch('{self.target_url}', {{ credentials: 'include' }}) from {attacker_origin}",
                    })
                    s(f"CORS Misconfiguration Confirmed on {C}{self.target_url}{N} (ACAO: {acao}, ACAC: true)")
            finally:
                await context.close()
        except Exception as e:
            w(f"CORS Verifier error: {e}")

        return self.findings
