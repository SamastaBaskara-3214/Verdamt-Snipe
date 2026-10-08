import asyncio
from typing import Dict, List, Set, Any
from urllib.parse import urlparse

try:
    from playwright.async_api import async_playwright, Request, Response, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    # Keep annotations resolvable so the class body (and module import)
    # survives when playwright is absent — the original fallback crashed
    # with NameError at `request: Request`.
    from typing import Any as _Any
    async_playwright = Request = Response = BrowserContext = Page = _Any

from core.state import SessionManager
from core.ui import ph, i, p, s, w, R, G, Y, N, W, C, GY

class BrowserRecon:
    """
    Playwright-assisted discovery layer for Single Page Applications (SPAs).
    Captures XHR/Fetch API endpoints, dumps local storage, and extracts JWTs.
    """
    
    def __init__(self, target_url: str, session_manager: SessionManager, timeout: int = 15000):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.session_manager = session_manager
        self.timeout = timeout
        
        self.discovered_endpoints: Set[str] = set()
        self.intercepted_tokens: Set[str] = set()

    async def _handle_request(self, request: Request):
        """Intercept outbound requests to find API endpoints and Auth tokens."""
        if request.resource_type in ["fetch", "xhr"]:
            url = request.url
            if self.domain in urlparse(url).netloc:
                self.discovered_endpoints.add(url)
            
            # Sniff for Bearer tokens in headers
            auth_header = request.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                token = auth_header.split(" ")[1]
                if token not in self.intercepted_tokens:
                    self.intercepted_tokens.add(token)
                    self.session_manager.register_token(self.domain, "bearer", token)
                    s(f"Captured Bearer Token via XHR: {C}{token[:15]}...{N}")

    async def run(self) -> Dict[str, Any]:
        """Execute the headless browser reconnaissance."""
        if not PLAYWRIGHT_AVAILABLE:
            w("Playwright is not installed. Skipping browser-assisted recon.")
            w(f"Install with: {C}pip install playwright && playwright install{N}")
            return {"endpoints": [], "local_storage": {}}

        ph("BROWSER RECON: SPA Discovery & State Extraction")
        i(f"Launching headless context for {W}{self.target_url}{N}...")
        
        results = {"endpoints": [], "local_storage": {}}
        
        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return {"endpoints": [], "local_storage": {}}
                
            # Inject session cookies into browser context
            cookies_to_add = []
            sm_cookies = getattr(self.session_manager, "cookies", {}).get(self.domain, {})
            for name, value in sm_cookies.items():
                cookies_to_add.append({
                    "name": name,
                    "value": value,
                    "domain": self.domain,
                    "path": "/",
                })
            if cookies_to_add:
                await context.add_cookies(cookies_to_add)

            page = await context.new_page()

            # Inject Authorization header ONLY for requests to the target domain
            # Never inject into third-party CDN/analytics requests — that's a data leak
            auth_token = getattr(self.session_manager, "auth_tokens", {}).get(self.domain)
            if auth_token:
                _target_domain = self.domain  # capture for closure
                _auth_token = auth_token
                async def inject_auth(route, request):
                    req_host = urlparse(request.url).netloc
                    if _target_domain in req_host:
                        headers = {**request.headers, "Authorization": _auth_token}
                        await route.continue_(headers=headers)
                    else:
                        await route.continue_()
                await page.route("**/*", inject_auth)

            # Attach event listeners
            page.on("request", self._handle_request)

            try:
                # Navigate with domcontentloaded to avoid SPA networkidle timeout traps
                await page.goto(self.target_url, wait_until="domcontentloaded", timeout=self.timeout)
                await page.wait_for_timeout(2000)
            
                # Extract LocalStorage
                ls_data = await page.evaluate("() => JSON.stringify(localStorage)")
                import json
                if ls_data:
                    parsed_ls = json.loads(ls_data)
                    results["local_storage"] = parsed_ls
                    self.session_manager.local_storage[self.domain] = parsed_ls

                    # Look for obvious JWTs in local storage
                    for key, value in parsed_ls.items():
                        if isinstance(value, str) and (value.startswith("eyJ") or "token" in key.lower() or "auth" in key.lower()):
                            s(f"Extracted possible token from LocalStorage [{W}{key}{N}]")
                            if value.startswith("eyJ"):
                                self.session_manager.register_token(self.domain, "bearer", value)
            
                # Extract Cookies and feed to SessionManager
                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies}
                if cookie_dict:
                    self.session_manager.update_cookies(self.domain, cookie_dict)
                    i(f"Captured {W}{len(cookies)}{N} cookies.")

                # Extract dynamically rendered hrefs that regex misses
                links = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
            }''')
                for link in links:
                    if self.domain in urlparse(link).netloc:
                        self.discovered_endpoints.add(link)

            except Exception as e:
                return {"endpoints": [], "cookies": [], "error": str(e)}
            finally:
                # new_context() returns a BrowserContext (browser stays in
                # the shared pool) — closing the pool browser here would kill
                # every other scan's context. There is no local `browser`.
                await context.close()
        except Exception as e:
            w(f"Browser recon unavailable: {str(e)[:120]}")
                
        results["endpoints"] = list(self.discovered_endpoints)
        
        # Summary
        p(f"XHR/Fetch API endpoints discovered: {G}{len(results['endpoints'])}{N}")
        if results["local_storage"]:
            p(f"LocalStorage keys extracted: {Y}{len(results['local_storage'])}{N}")
            
        return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        sm = SessionManager()
        recon = BrowserRecon(target, sm)
        asyncio.run(recon.run())
        print(f"\\nDiscovered: {len(recon.discovered_endpoints)}")
        print(f"Tokens in SM: {sm.auth_tokens}")
