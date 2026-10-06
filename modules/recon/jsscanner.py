import sys
import os
import re
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import asyncio
from urllib.parse import urlparse
from typing import List, Dict, Set, Optional
from core.ui import ph, i, p, w, draw_table, Spinner, G, Y, R, N, GY, W, C
from core.go_bridge import go_bridge

class JSScanner:
    """Scan Javascript files for secrets, API keys, internal endpoints, and hidden API routes."""

    REGEX_PATTERNS = {
        "google_api":     r"AIza[0-9A-Za-z-_]{35}",
        "firebase":       r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"(?i)(?:aws_secret|aws_secret_key|secret_key)[\s:=]+(['\"])([a-zA-Z0-9/+=]{40})\1",
        "amazon_mws":     r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "slack_token":    r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "slack_webhook":  r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "github_token":   r"ghp_[a-zA-Z0-9]{36}",
        "stripe_key":     r"sk_live_[0-9a-zA-Z]{24}",
        "ssh_key":        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        "jwt_token":      r"ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]*",
        "email":          r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "internal_ip":    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}",
        "generic_secret": r"(?i)(key|secret|token|password|auth|creds|api_key|access_key)[\s:=]+(['\"])([a-zA-Z0-9_\-]{16,})\2"
    }

# ENDPOINT EXTRACTION PATTERNS
    ENDPOINT_PATTERNS = [
        # API routes in strings: "/api/v1/users", '/api/admin'
        r'''['"](/api/[a-zA-Z0-9_\-/.]+)['"]''',
        r'''['"](/v[0-9]+/[a-zA-Z0-9_\-/.]+)['"]''',
        
        # fetch() calls: fetch("/endpoint"), fetch('/endpoint')
        r'''fetch\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        r'''fetch\s*\(\s*[`](/[a-zA-Z0-9_\-/.?&=${}]+)[`]''',
        
        # axios calls: axios.get('/endpoint'), axios.post("/endpoint")
        r'''axios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        r'''axios\s*\(\s*\{[^}]*?url\s*:\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        
        # XMLHttpRequest: xhr.open("GET", "/endpoint")
        r'''\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        
        # jQuery AJAX: $.ajax({url: "/endpoint"})
        r'''(?:\$\.ajax|\$\.get|\$\.post|\$\.getJSON)\s*\(\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        r'''url\s*:\s*['"](/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        
        # GraphQL endpoints
        r'''['"](/graphql[a-zA-Z0-9_\-/]*)['"]''',
        
        # WebSocket endpoints
        r'''['"](wss?://[a-zA-Z0-9_\-./]+)['"]''',
        
        # Full URL endpoints with domain
        r'''['"]((https?://[a-zA-Z0-9_\-.]+)/[a-zA-Z0-9_\-/.?&=]+)['"]''',
        
        # Route definitions (Express, Flask-like): app.get('/route'), router.post('/route')
        r'''(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*['"](/[a-zA-Z0-9_\-/.:]+)['"]''',
        
        # Path assignments: path: "/admin", endpoint: "/api/users"
        r'''(?:path|endpoint|route|uri|href|action|redirect)\s*(?::|=)\s*['"](/[a-zA-Z0-9_\-/.]+)['"]''',
        
        # Relative paths that look like endpoints
        r'''['"](/(?:admin|dashboard|internal|debug|config|settings|console|api|auth|login|register|upload|download|export|import|webhook|callback|notify|health|status|metrics|graphql)[a-zA-Z0-9_\-/]*)['"]''',
    ]

    # Noise patterns to filter out
    ENDPOINT_NOISE = [
        r'^/$',
        r'^/[a-z]$',  # Single char paths
        r'\.(?:css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$',
        r'^/node_modules/',
        r'^/bower_components/',
        r'^/static/(?:css|js|img|fonts)/',
    ]

    def __init__(self, urls: List[str], threads: int = 10, scope_guard=None, async_engine=None):
        self.urls = urls
        self.threads = threads
        self.scope_guard = scope_guard
        self.async_engine = async_engine
        self._sem = asyncio.Semaphore(threads)
        self.js_urls = self._extract_js_urls()
        self.findings = []
        self.discovered_endpoints: Set[str] = set()

    CUSTOM_JS_KEYWORDS = ['app', 'main', 'index', 'core', 'api', 'auth', 'user', 'config', 'util', 'script', 'service', 'worker']
    LIBRARY_KEYWORDS = [
        'jquery', 'bootstrap', 'vue', 'react', 'angular', 'moment', 'lodash', 'axios',
        'google', 'analytics', 'facebook', 'webpack', 'owl.carousel', 'venobox',
        'swiper', 'lightbox', 'slick', 'fancybox', 'magnific-popup', 'isotope',
        'masonry', 'select2', 'datatables', 'chart.js', 'three.js', 'gsap'
    ]

    def _extract_js_urls(self) -> List[str]:
        custom_js = []
        lib_js = []
        for u in self.urls:
            path = u.split("?")[0].lower()
            if path.endswith(".js"):
                filename = path.split("/")[-1]
                if any(lib in filename for lib in self.LIBRARY_KEYWORDS):
                    lib_js.append(u)
                else:
                    custom_js.append(u)
                    
        # Prioritize custom JS, then add some libs just in case (max 10 total)
        merged = list(set(custom_js))
        if len(merged) < 20:
            merged.extend(list(set(lib_js))[:10])
        return merged

    def _is_noise(self, endpoint: str) -> bool:
        """Filter out noise endpoints (static assets, single chars, etc.)."""
        if any(ch in endpoint for ch in ["{", "}", "`", "\\"]):
            return True
        parsed = urlparse(endpoint)
        if parsed.scheme in ("http", "https"):
            if self.scope_guard and not self.scope_guard.host_in_scope(parsed.hostname or ""):
                return True
            if parsed.netloc.lower() in {
                "www.w3.org", "w3.org", "react.dev", "github.com", "instagram.com",
                "facebook.com", "twitter.com", "x.com",
            }:
                return True
        for pattern in self.ENDPOINT_NOISE:
            if re.search(pattern, endpoint, re.I):
                return True
        return False

    def _extract_endpoints(self, content: str) -> Set[str]:
        """Extract API endpoints and routes from JavaScript content."""
        endpoints = set()
        
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content, re.I)
            for match in matches:
                endpoint = match.group(1)
                # Normalize
                endpoint = endpoint.strip().rstrip("/")
                if not endpoint:
                    continue
                
                # Filter noise
                if self._is_noise(endpoint):
                    continue
                
                # Must be at least 3 chars and look like a path
                if len(endpoint) >= 3 and ("/" in endpoint or endpoint.startswith("http")):
                    endpoints.add(endpoint)
        
        return endpoints

    def _analyze_content(self, url: str, content: str, waf: list, resp_time: float, status: int) -> tuple:
        """Analyze JS content for secrets and endpoints (CPU-bound, safe for to_thread)."""
        local_findings = []
        local_endpoints = set()

        # Secret scanning
        for name, pattern in self.REGEX_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                match_text = match.group(0)
                # Avoid duplicates in the same file
                if not any(f["detail"] == match_text for f in local_findings):
                    local_findings.append({
                        "type": f"js_secret_{name}",
                        "title": f"JS Secret: {name.replace('_', ' ').title()}",
                        "url": url,
                        "detail": match_text,
                        "waf": "/".join(waf),
                        "time": resp_time,
                        "status": status
                    })

        # Endpoint extraction
        local_endpoints = self._extract_endpoints(content)
        for ep in local_endpoints:
            local_findings.append({
                "type": "js_endpoint",
                "title": f"JS Endpoint: {ep[:60]}",
                "url": url,
                "detail": ep,
                "waf": "/".join(waf),
                "time": resp_time,
                "status": status
            })

        return local_findings, local_endpoints

    async def _download_url_async(self, url: str) -> Optional[dict]:
        """Download JS file content asynchronously."""
        async with self._sem:
            try:
                r = await self.async_engine.ahttp_send(url, timeout=5)
                if r["status"] == 200 and r.get("body"):
                    waf = "/".join(r.get("waf", [])) if isinstance(r.get("waf"), list) else str(r.get("waf", ""))
                    return {
                        "url": url,
                        "content": r["body"],
                        "waf": waf,
                        "time": r.get("time", 0.0),
                        "status": r["status"]
                    }
            except Exception as e:
                w(f"JS download failed: {url} — {e}")
        return None

    async def run(self) -> tuple:
        """Run JS scanner asynchronously. Returns (findings_list, discovered_endpoints_list)."""
        if not self.js_urls:
            return [], []
        ph("PHASE 1.5: JS SECRET & ENDPOINT ANALYSIS")
        i(f"Scanning {W}{len(self.js_urls)}{N} High-Interest JS files...")
        
        downloaded = []
        spin = Spinner("Downloading JavaScript files...")
        spin.start()
        tasks = []
        for url in self.js_urls:
            async def _wrap(u=url):
                res = await self._download_url_async(u)
                spin.next()
                return res
            tasks.append(_wrap())

        download_results = await asyncio.gather(*tasks, return_exceptions=True)
        spin.stop()

        for item in download_results:
            if isinstance(item, dict) and item.get("content"):
                downloaded.append(item)

        if not downloaded:
            return [], []

        findings = []
        all_endpoints = set()

        # Go-accelerated scanning attempt
        go_processed = False
        if go_bridge.is_available():
            try:
                go_res = await asyncio.to_thread(go_bridge.js_scan_batch, downloaded)
                if go_res and isinstance(go_res, dict):
                    findings = go_res.get("findings", [])
                    raw_endpoints = go_res.get("endpoints", [])
                    for ep in raw_endpoints:
                        if not self._is_noise(ep):
                            all_endpoints.add(ep)
                    go_processed = True
            except Exception as e:
                w(f"Go JS scanning fallback to Python: {e}")

        # Fallback to Python scanning if Go unavailable or failed
        if not go_processed:
            spin_analyze = Spinner("Analyzing JavaScript files (Python fallback)...")
            spin_analyze.start()
            analyze_tasks = []
            for item in downloaded:
                waf_list = item["waf"].split("/") if item["waf"] else []
                async def _wrap_py(it=item, w_list=waf_list):
                    res = await asyncio.to_thread(
                        self._analyze_content,
                        it["url"], it["content"], w_list, it["time"], it["status"]
                    )
                    spin_analyze.next()
                    return res
                analyze_tasks.append(_wrap_py())

            py_results = await asyncio.gather(*analyze_tasks, return_exceptions=True)
            spin_analyze.stop()

            for r in py_results:
                if isinstance(r, tuple) and len(r) == 2:
                    secret_findings, endpoints = r
                    if secret_findings:
                        findings.extend(secret_findings)
                    for ep in endpoints:
                        if not self._is_noise(ep):
                            all_endpoints.add(ep)
        
        self.findings = findings
        self.discovered_endpoints = all_endpoints
        
        # Display secrets
        secret_findings = [f for f in self.findings if f["type"].startswith("js_secret_")]
        if secret_findings:
            rows = []
            for f in secret_findings:
                rows.append([f"{R}!!{N}", f"{Y}{f['title'].replace('JS Secret: ', '')}{N}", f"{W}{f['detail'][:40]}...{N}", f"{C}{f['url'].split('/')[-1]}{N}"])
            draw_table(["TYPE", "SECRET", "CONTENT PREVIEW", "SOURCE"], rows, title="Discovered Secrets in JS")
        
        # Display endpoints
        endpoint_findings = [f for f in self.findings if f["type"] == "js_endpoint"]
        if endpoint_findings:
            rows = []
            for f in endpoint_findings[:100]:  # Top 100
                rows.append([f"{C}EP{N}", f"{W}{f['detail'][:50]}{N}", f"{GY}{f['url'].split('/')[-1]}{N}"])
            draw_table(["TYPE", "ENDPOINT", "SOURCE FILE"], rows, title="Extracted JS Endpoints")
        
        p(f"JS Secrets found: {len(secret_findings)}")
        p(f"JS Endpoints extracted: {G}{len(all_endpoints)}{N}")
        
        return self.findings, sorted(all_endpoints)
