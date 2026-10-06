import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import re
import asyncio
from typing import List, Dict, Set, Tuple, Optional
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from core.ui import ph, i, p, w, s, draw_table, Spinner, G, Y, R, N, GY, W, C, B

# DOM XSS STATIC TAINT ANALYSIS

# Sources: user-controllable inputs that can inject into DOM
DOM_SOURCES = [
    # Location-based
    r'document\.URL',
    r'document\.documentURI',
    r'document\.baseURI',
    r'location(?:\.href|\.search|\.hash|\.pathname|\.protocol|\.host|\.hostname|\.port)?',
    r'window\.location(?:\.href|\.search|\.hash|\.pathname)?',
    r'location\.toString\(\)',
    
    # Referrer
    r'document\.referrer',
    
    # Window
    r'window\.name',
    r'window\.opener',
    
    # Storage
    r'localStorage\.[a-zA-Z]+',
    r'sessionStorage\.[a-zA-Z]+',
    r'localStorage\.getItem\([^\)]+\)',
    r'sessionStorage\.getItem\([^\)]+\)',
    
    # Message
    r'(?:e|event|evt|msg)\.data',
    r'postMessage',
    
    # URL API
    r'URLSearchParams',
    r'new\s+URL\(',
    
    # Cookies
    r'document\.cookie',
    
    # Input elements
    r'\.value',
    r'\.textContent',
    r'\.innerText',
]

# Sinks: dangerous functions that execute or render user input
DOM_SINKS = [
    # HTML injection
    (r'\.innerHTML\s*=', "innerHTML assignment", "High"),
    (r'\.outerHTML\s*=', "outerHTML assignment", "High"),
    (r'document\.write\s*\(', "document.write()", "Critical"),
    (r'document\.writeln\s*\(', "document.writeln()", "Critical"),
    
    # JS execution
    (r'eval\s*\(', "eval()", "Critical"),
    (r'setTimeout\s*\(\s*["\']', "setTimeout(string)", "High"),
    (r'setInterval\s*\(\s*["\']', "setInterval(string)", "High"),
    (r'new\s+Function\s*\(', "new Function()", "Critical"),
    (r'execScript\s*\(', "execScript()", "Critical"),
    (r'msSetImmediate\s*\(', "msSetImmediate()", "High"),
    
    # URL/Navigation
    (r'location\s*=', "location assignment", "High"),
    (r'location\.href\s*=', "location.href assignment", "High"),
    (r'location\.replace\s*\(', "location.replace()", "High"),
    (r'location\.assign\s*\(', "location.assign()", "High"),
    (r'window\.open\s*\(', "window.open()", "Medium"),
    
    # DOM manipulation
    (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML()", "High"),
    (r'\.append\s*\(', "append()", "Medium"),
    (r'\.prepend\s*\(', "prepend()", "Medium"),
    (r'\.after\s*\(', "after()", "Medium"),
    (r'\.before\s*\(', "before()", "Medium"),
    
    # Attribute manipulation
    (r'\.src\s*=', "src attribute assignment", "High"),
    (r'\.href\s*=', "href attribute assignment", "High"),
    (r'\.action\s*=', "action attribute assignment", "High"),
    (r'\.setAttribute\s*\(\s*["\'](?:src|href|action|onclick|onerror|onload)', "setAttribute(dangerous)", "High"),
    
    # jQuery
    (r'\$\s*\(\s*["\']?\s*<', "jQuery HTML injection", "High"),
    (r'\.html\s*\(', "jQuery .html()", "High"),
    (r'\.append\s*\(\s*["\']?\s*<', "jQuery .append(HTML)", "High"),
    (r'\.prepend\s*\(\s*["\']?\s*<', "jQuery .prepend(HTML)", "High"),
    (r'\.after\s*\(\s*["\']?\s*<', "jQuery .after(HTML)", "High"),
    (r'\.before\s*\(\s*["\']?\s*<', "jQuery .before(HTML)", "High"),
    (r'\.replaceWith\s*\(\s*["\']?\s*<', "jQuery .replaceWith(HTML)", "High"),
    (r'\.wrap\s*\(\s*["\']?\s*<', "jQuery .wrap(HTML)", "Medium"),
]


class DOMXSSScanner:
    """Static taint analysis scanner for DOM-based XSS vulnerabilities.
    
    Analyzes JavaScript source code to find source → sink data flows
    without requiring a headless browser.
    """

    def __init__(self, urls: List[str], threads: int = 10, network_engine=None):
        self.urls = urls
        self.threads = threads
        self.engine = network_engine
        self._sem = asyncio.Semaphore(self.threads)
        self.js_urls = self._filter_js_urls()
        self.findings: List[Dict] = []

    def _filter_js_urls(self) -> List[str]:
        """Extract JS file URLs from the URL pool."""
        js_urls = []
        # Known vendor library filenames to skip (reduces noise & false positives)
        skip_libs = [
            'jquery', 'bootstrap', 'angular', 'react', 'vue', 'moment',
            'lodash', 'underscore', 'popper', 'polyfill', 'modernizr',
            'analytics', 'gtag', 'fbevents', 'hotjar', 'owl.carousel',
            'venobox', 'swiper', 'lightbox', 'slick', 'fancybox',
            'magnific-popup', 'isotope', 'masonry', 'select2', 'datatables',
            'chart.js', 'three.js', 'gsap', 'fontawesome', 'feather'
        ]
        
        for u in self.urls:
            path = u.split("?")[0].lower()
            if path.endswith(".js"):
                filename = path.split("/")[-1]
                if not any(lib in filename for lib in skip_libs):
                    js_urls.append(u)
        
        return list(set(js_urls))

    def _find_sources(self, content: str) -> List[Tuple[str, int, str]]:
        """Find all DOM XSS sources in JavaScript content.
        Returns: [(source_pattern, line_number, code_snippet), ...]
        """
        found = []
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            
            for source_pattern in DOM_SOURCES:
                if re.search(source_pattern, line):
                    # Get context (surrounding code)
                    snippet = line.strip()[:120]
                    found.append((source_pattern, line_num, snippet))
        
        return found

    def _find_sinks(self, content: str) -> List[Tuple[str, str, str, int, str]]:
        """Find all DOM XSS sinks in JavaScript content.
        Returns: [(sink_pattern, sink_name, severity, line_number, code_snippet), ...]
        """
        found = []
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue
            
            for sink_pattern, sink_name, severity in DOM_SINKS:
                if re.search(sink_pattern, line):
                    snippet = line.strip()[:120]
                    found.append((sink_pattern, sink_name, severity, line_num, snippet))
        
        return found

    def _extract_function_scopes(self, content: str) -> List[Dict]:
        """
        Extract function boundaries from JavaScript.
        Works on both formatted and semi-minified code by tracking brace depth.
        Returns: [{"start": line, "end": line, "name": "funcName"}, ...]
        """
        scopes = []
        lines = content.split("\n")
        func_pattern = re.compile(
            r'(?:function\s+([a-zA-Z_$][\w$]*)\s*\(|'   # function foo(
            r'([a-zA-Z_$][\w$]*)\s*[=:]\s*(?:async\s+)?function\s*\(|'  # foo = function(
            r'([a-zA-Z_$][\w$]*)\s*[=:]\s*(?:async\s+)?\([^)]*\)\s*=>|'  # foo = (x) =>
            r'([a-zA-Z_$][\w$]*)\s*[=:]\s*(?:async\s+)?\w+\s*=>)'  # foo = x =>
        )

        brace_depth = 0
        current_func = None
        func_start = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Check for function definition
            if current_func is None:
                m = func_pattern.search(stripped)
                if m:
                    name = m.group(1) or m.group(2) or m.group(3) or m.group(4) or "anonymous"
                    current_func = name
                    func_start = line_num
                    brace_depth = 0

            # Track brace depth
            if current_func is not None:
                brace_depth += stripped.count("{") - stripped.count("}")
                if brace_depth <= 0 and line_num > func_start:
                    scopes.append({
                        "start": func_start,
                        "end": line_num,
                        "name": current_func,
                    })
                    current_func = None

        return scopes

    def _get_scope_for_line(self, line_num: int, scopes: List[Dict]) -> Optional[Dict]:
        """Find the innermost function scope containing a given line."""
        best = None
        for scope in scopes:
            if scope["start"] <= line_num <= scope["end"]:
                if best is None or (scope["end"] - scope["start"]) < (best["end"] - best["start"]):
                    best = scope
        return best

    def _trace_taint(self, content: str, sources: list, sinks: list) -> List[Dict]:
        """
        Scope-aware taint tracking with transitive propagation.
        
        Strategy:
        1. Direct: source and sink on the same line
        2. Variable tracking: source assigned to var, var used in sink
        3. Transitive: var_a = source; var_b = var_a; sink(var_b)
        4. Scope-aware proximity: source→sink in same function only
        5. Sanitizer filtering: skip sinks guarded by sanitize/encode/escape
        """
        tainted_flows = []
        lines = content.split("\n")
        scopes = self._extract_function_scopes(content)

        # Known sanitizer patterns (reduces false positives)
        sanitizer_patterns = [
            r'(?:sanitize|escape|encode|purify|clean|strip|htmlEntities|DOMPurify)',
            r'textContent\s*=',  # textContent is safe (no HTML parsing)
            r'createTextNode\s*\(',
        ]

        # Build tainted variable set with transitive propagation
        tainted_vars = {}  # var_name -> (source_description, line_num)

        for source_pattern, line_num, snippet in sources:
            # Extract direct assignments: var x = location.hash
            for var_match in re.finditer(
                r'(?:var|let|const)?\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*.*' + source_pattern,
                snippet
            ):
                var_name = var_match.group(1)
                tainted_vars[var_name] = (f"source '{source_pattern}'", line_num)

            # Bare assignment: x = location.hash
            for var_match in re.finditer(
                r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*.*' + source_pattern,
                snippet
            ):
                var_name = var_match.group(1)
                if var_name not in tainted_vars:
                    tainted_vars[var_name] = (f"source '{source_pattern}'", line_num)

        # Transitive propagation: track var_b = var_a chains
        propagation_rounds = 3  # Limit to prevent infinite loops
        for _ in range(propagation_rounds):
            new_tainted = {}
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*"):
                    continue
                # Look for assignments like: var_b = transform(var_a)
                assign_match = re.match(
                    r'(?:var|let|const)?\s*([a-zA-Z_$][\w$]*)\s*=\s*(.*)',
                    stripped
                )
                if assign_match:
                    target_var = assign_match.group(1)
                    rhs = assign_match.group(2)
                    if target_var not in tainted_vars:
                        for tv in tainted_vars:
                            if re.search(r'\b' + re.escape(tv) + r'\b', rhs):
                                new_tainted[target_var] = (
                                    f"propagated from '{tv}'",
                                    line_num,
                                )
                                break
            tainted_vars.update(new_tainted)
            if not new_tainted:
                break

        # Match sinks against tainted data
        for sink_pattern, sink_name, severity, sink_line, sink_snippet in sinks:
            # Check if sink line has a sanitizer guard
            is_sanitized = False
            for san_pat in sanitizer_patterns:
                if re.search(san_pat, sink_snippet, re.I):
                    is_sanitized = True
                    break
            if is_sanitized:
                continue

            flow_found = False
            flow_source = None
            sink_scope = self._get_scope_for_line(sink_line, scopes)

            # Check 1: Direct — source on same line as sink
            for source_pattern, src_line, src_snippet in sources:
                if src_line == sink_line:
                    flow_found = True
                    flow_source = src_snippet
                    break

            # Check 2: Tainted variable (direct or transitive) used in sink
            if not flow_found:
                for var, (origin, var_line) in tainted_vars.items():
                    if re.search(r'\b' + re.escape(var) + r'\b', sink_snippet):
                        # Verify scope: var and sink should be in same function
                        var_scope = self._get_scope_for_line(var_line, scopes)
                        if sink_scope and var_scope and sink_scope != var_scope:
                            continue  # Different function scope, skip
                        flow_found = True
                        flow_source = f"tainted var '{var}' ({origin})"
                        break

            # Check 3: Scope-aware proximity (same function, source before sink)
            if not flow_found:
                for source_pattern, src_line, src_snippet in sources:
                    if 0 < (sink_line - src_line) <= 15:
                        src_scope = self._get_scope_for_line(src_line, scopes)
                        # Must be in same scope (or both global)
                        if sink_scope == src_scope:
                            flow_found = True
                            flow_source = f"nearby source (line {src_line})"
                            break

            if flow_found:
                tainted_flows.append({
                    "sink": sink_name,
                    "severity": severity,
                    "sink_line": sink_line,
                    "sink_code": sink_snippet,
                    "source": flow_source,
                })

        return tainted_flows

    def _detect_prototype_pollution(self, content: str) -> List[Dict]:
        """
        Detect Prototype Pollution patterns in JavaScript.
        Looks for dangerous object merge/extend patterns with user input.
        """
        findings = []
        lines = content.split("\n")

        # Dangerous merge/extend patterns
        merge_patterns = [
            (r'Object\.assign\s*\(\s*\{\}', "Object.assign with empty target"),
            (r'(?:_\.merge|_\.extend|_\.defaultsDeep)\s*\(', "Lodash deep merge"),
            (r'(?:\$\.extend|\$\.merge)\s*\(\s*true', "jQuery deep extend"),
            (r'(?:deepmerge|deepExtend|merge)\s*\(', "Deep merge function"),
            (r'for\s*\(\s*(?:var|let|const)\s+\w+\s+in\s+', "for-in loop (property injection)"),
        ]

        # Check if user input flows to merge target
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            for pat, desc in merge_patterns:
                if re.search(pat, stripped):
                    # Check if any source is nearby (within 5 lines)
                    context_start = max(0, line_num - 6)
                    context_end = min(len(lines), line_num + 1)
                    context = "\n".join(lines[context_start:context_end])

                    has_user_input = False
                    for src in DOM_SOURCES[:10]:  # Top sources
                        if re.search(src, context):
                            has_user_input = True
                            break

                    if has_user_input:
                        findings.append({
                            "sink": f"Prototype Pollution: {desc}",
                            "severity": "Critical",
                            "sink_line": line_num,
                            "sink_code": stripped[:120],
                            "source": "user-controlled input near merge/extend",
                        })

        # Direct __proto__ / constructor.prototype access
        proto_patterns = [
            (r'__proto__', "__proto__ access"),
            (r'constructor\s*\[\s*["\']prototype', "constructor[prototype] access"),
            (r'\[(["\'])constructor\1\]', "bracket notation constructor access"),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            for pat, desc in proto_patterns:
                if re.search(pat, stripped):
                    findings.append({
                        "sink": f"Prototype Pollution: {desc}",
                        "severity": "Critical",
                        "sink_line": line_num,
                        "sink_code": stripped[:120],
                        "source": "direct prototype manipulation",
                    })

        return findings

    def _analyze_js_content(self, content: str) -> List[Dict]:
        """Analyze JS content for DOM XSS and Prototype Pollution."""
        all_sources = self._find_sources(content)
        all_sinks = self._find_sinks(content)
        
        flows = []
        if all_sources and all_sinks:
            flows = self._trace_taint(content, all_sources, all_sinks)
        
        # Also check for Prototype Pollution
        proto_flows = self._detect_prototype_pollution(content)
        flows.extend(proto_flows)
        
        return flows

    async def _scan_url(self, url: str) -> List[Dict]:
        """Scan a single JS file for DOM XSS patterns with chunked parsing for minified JS."""
        local_findings = []
        try:
            async with self._sem:
                r = await self.engine.ahttp_send(url, timeout=15)
            if not r or r.get("status") != 200 or not r.get("body"):
                return []

            content = r["body"]
            flows = await asyncio.to_thread(self._analyze_js_content, content)
            
            for flow in flows:
                local_findings.append({
                    "type": "dom_xss",
                    "title": f"DOM XSS: {flow['sink']}",
                    "url": url,
                    "detail": f"Sink: {flow['sink']} (Line {flow['sink_line']}), Source: {flow['source']}, Code: {flow['sink_code'][:80]}",
                    "severity": flow["severity"],
                    "waf": "",
                    "time": r.get("time", 0),
                    "status": r.get("status", 0),
                    "confidence": "suspected",
                })
        except Exception as e:
            w(f"DOM XSS scan failed: {url} — {e}")
        
        return local_findings

    def _analyze_inline_scripts(self, body: str) -> List[Dict]:
        flows = []
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.I)
        for script_content in scripts:
            if len(script_content.strip()) < 10:
                continue
            sources = self._find_sources(script_content)
            sinks = self._find_sinks(script_content)
            if sources and sinks:
                flows.extend(self._trace_taint(script_content, sources, sinks))
        return flows

    async def _scan_inline_scripts(self, url: str) -> List[Dict]:
        """Scan inline <script> blocks in HTML pages for DOM XSS."""
        local_findings = []
        try:
            async with self._sem:
                r = await self.engine.ahttp_send(url, timeout=10)
            if not r or r.get("status") != 200 or not r.get("body"):
                return []
            
            flows = await asyncio.to_thread(self._analyze_inline_scripts, r["body"])
            for flow in flows:
                local_findings.append({
                    "type": "dom_xss",
                    "title": f"DOM XSS (Inline): {flow['sink']}",
                    "url": url,
                    "detail": f"Sink: {flow['sink']}, Source: {flow['source']}, Code: {flow['sink_code'][:80]}",
                    "severity": flow["severity"],
                    "waf": "",
                    "time": r.get("time", 0),
                    "status": r.get("status", 0),
                    "confidence": "suspected",
                })
        except Exception as e:
            w(f"Inline script scan failed: {url} — {e}")
        
        return local_findings

    async def run(self) -> List[Dict]:
        if not self.js_urls and not self.urls:
            return []
        
        ph("DOM XSS SCANNER: Static Taint Analysis")

        async def _wrap_scan(url, func, spin):
            try:
                res = await func(url)
                if spin: spin.next()
                return res
            except Exception as e:
                if spin: spin.next()
                return e
        
        # Phase 1: External JS files
        if self.js_urls:
            i(f"Scanning {W}{len(self.js_urls)}{N} external JS files...")
            spin = Spinner("Analyzing JavaScript source code...")
            tasks = [_wrap_scan(u, self._scan_url, spin) for u in self.js_urls]
            results = await asyncio.gather(*tasks)
            spin.stop()
            for u, r in zip(self.js_urls, results):
                if isinstance(r, Exception):
                    w(f"JS scan failed: {u} — {r}")
                else:
                    self.findings.extend(r)

        # Phase 2: Inline scripts in HTML pages
        html_urls = [u for u in self.urls if not u.split("?")[0].lower().endswith(
            ('.js', '.css', '.jpg', '.png', '.gif', '.pdf', '.svg', '.woff', '.ico')
        )][:20]  # Top 20 HTML pages
        
        if html_urls:
            i(f"Scanning {W}{len(html_urls)}{N} HTML pages for inline scripts...")
            spin = Spinner("Analyzing inline JavaScript...")
            tasks = [_wrap_scan(u, self._scan_inline_scripts, spin) for u in html_urls]
            results = await asyncio.gather(*tasks)
            spin.stop()
            for u, r in zip(html_urls, results):
                if isinstance(r, Exception):
                    w(f"Inline script scan failed: {u} — {r}")
                else:
                    self.findings.extend(r)

        # Deduplicate
        seen = set()
        unique = []
        for f in self.findings:
            key = (f["url"], f["title"], f.get("detail", "")[:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        # Phase 3: Dynamic Verification via Playwright (Auto-PoC Validator)
        if self.findings and PLAYWRIGHT_AVAILABLE:
            i(f"Running {W}Playwright Auto-PoC Validator{N} on {len(self.findings)} suspected DOM XSS findings...")
            await self._verify_dynamic_pocs()

        # Summary
        if self.findings:
            rows = []
            for f in self.findings[:15]:
                sev = f.get("severity", "Medium")
                c = R if sev in ["Critical", "High"] else (Y if sev == "Medium" else G)
                conf = f.get("confidence", "suspected")
                conf_str = f"{G}confirmed{N}" if conf == "confirmed" else (f"{Y}suspected{N}" if conf == "suspected" else f"{GY}unverified{N}")
                rows.append([
                    f"{c}{sev}{N}",
                    f"{W}{f['title'][:35]}{N}",
                    conf_str,
                    f"{C}{f['url'].split('/')[-1][:25]}{N}",
                ])
            draw_table(["SEVERITY", "VULNERABILITY", "CONFIDENCE", "SOURCE FILE"], rows, title="DOM XSS Findings")
        else:
            p("No DOM XSS patterns detected.")

        confirmed_count = sum(1 for f in self.findings if f.get("confidence") == "confirmed")
        p(f"DOM XSS findings: {R if self.findings else G}{len(self.findings)}{N} ({G}{confirmed_count} confirmed via Playwright PoC{N})")
        return self.findings

    async def _verify_dynamic_pocs(self):
        """
        Spawns Headless Chromium via Playwright with JS sink instrumentation,
        resource route aborting (5-10x speedup), and parallel worker pools.
        """
        if not PLAYWRIGHT_AVAILABLE or not self.findings:
            return

        canary_token = "VERDAMT_DOMXSS_POC"
        poc_payloads = [
            f"<img src=x onerror=\"window.__dom_xss='{canary_token}'\">",
            f"<svg/onload=\"window.__dom_xss='{canary_token}'\">",
            f"javascript:window.__dom_xss='{canary_token}'",
            f"'-window.__dom_xss='{canary_token}'-'",
            f"\";window.__dom_xss='{canary_token}';//",
            f"<iframe src=\"javascript:window.__dom_xss='{canary_token}'\"></iframe>",
            f"<input autofocus onfocus=\"window.__dom_xss='{canary_token}'\">",
            f"<details open toggle=\"window.__dom_xss='{canary_token}'\">",
            f"<form id=__dom_xss><input name=attributes></form>",  # DOM Clobbering
            f"<a id=__dom_xss href=\"javascript:window.__dom_xss='{canary_token}'\">test</a>",
        ]

        # JS Instrumentation Script injected into every page context before any page script executes
        init_sink_hook = f"""
        (() => {{
            window.__dom_xss = null;
            window.__verdamt_sink_hit = null;
            const CANARY = "{canary_token}";
            
            function checkValue(val, sinkName) {{
                if (typeof val === 'string' && val.includes(CANARY)) {{
                    window.__dom_xss = CANARY;
                    window.__verdamt_sink_hit = sinkName;
                }}
            }}

            // Hook eval
            const origEval = window.eval;
            window.eval = function(code) {{
                checkValue(code, "eval");
                return origEval.apply(this, arguments);
            }};

            // Hook Function constructor
            const origFunction = window.Function;
            window.Function = function(...args) {{
                checkValue(args.join(";"), "Function");
                return origFunction.apply(this, args);
            }};

            // Hook document.write
            const origWrite = document.write;
            document.write = function(str) {{
                checkValue(str, "document.write");
                return origWrite.apply(this, arguments);
            }};

            // Hook innerHTML setter
            const innerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
            if (innerHTMLDesc && innerHTMLDesc.set) {{
                const origSet = innerHTMLDesc.set;
                Object.defineProperty(Element.prototype, 'innerHTML', {{
                    set: function(val) {{
                        checkValue(val, "innerHTML");
                        return origSet.call(this, val);
                    }}
                }});
            }}
        }})();
        """

        # Filter to max 10 highest severity findings for dynamic verification to avoid timeout
        target_findings = [f for f in self.findings if f.get("severity") in ("Critical", "High")][:10]
        if not target_findings:
            target_findings = self.findings[:5]

        try:
            from core.browser_pool import SharedBrowserPool
            context = await SharedBrowserPool.new_context()
            if not context:
                return

            try:
                # Abort heavy network resources (images, fonts, stylesheets, media) for 5x-10x speedup
                await context.route("**/*", lambda route: route.abort() if route.request.resource_type in ["image", "font", "media", "stylesheet"] else route.continue_())

                # Inject sink monitoring hook into all frames
                await context.add_init_script(init_sink_hook)

                sem = asyncio.Semaphore(3)  # Max 3 concurrent Playwright page verifications

                async def verify_finding(finding):
                    async with sem:
                        target_url = finding["url"]
                        if target_url.split("?")[0].lower().endswith(".js"):
                            base_urls = [u for u in self.urls if not u.split("?")[0].lower().endswith(
                                ('.js', '.css', '.png', '.jpg', '.svg', '.woff', '.ico')
                            )]
                            target_url = base_urls[0] if base_urls else target_url.rsplit('/', 1)[0] + '/'

                        is_verified = False
                        successful_poc = ""
                        detected_sink = ""

                        # Priority payloads first (fastest indicators)
                        for payload in poc_payloads[:5]:
                            page = await context.new_page()
                            executed = False

                            def handle_dialog(dialog):
                                nonlocal executed
                                executed = True
                                asyncio.create_task(dialog.dismiss())

                            page.on("dialog", handle_dialog)

                            test_urls = [
                                f"{target_url}#{payload}",
                                f"{target_url}?q={payload}#{payload}",
                            ]

                            for t_url in test_urls:
                                try:
                                    await page.goto(t_url, wait_until="domcontentloaded", timeout=1500)
                                    await page.wait_for_timeout(200)

                                    res = await page.evaluate("() => ({ canary: window.__dom_xss, sink: window.__verdamt_sink_hit, html: document.body ? document.body.innerHTML : '' })")
                                    canary_val = res.get("canary")
                                    sink_val = res.get("sink")
                                    html_val = res.get("html", "")

                                    if canary_val == canary_token or executed or "VERDAMT_DOMXSS" in html_val:
                                        is_verified = True
                                        successful_poc = t_url
                                        detected_sink = sink_val or "DOM Event"
                                        break
                                except Exception:
                                    pass

                            await page.close()
                            if is_verified:
                                break

                        if is_verified:
                            finding["confidence"] = "confirmed"
                            finding["verified_poc"] = successful_poc
                            finding["detail"] += f" | Verified PoC ({detected_sink}): {successful_poc}"
                            s(f"Brutal PoC Confirmed DOM XSS [{C}{detected_sink}{N}] on {C}{target_url}{N}")
                        else:
                            finding["confidence"] = "unverified (FP candidate)"

                tasks = [verify_finding(f) for f in target_findings]
                await asyncio.gather(*tasks)
            finally:
                await context.close()
        except Exception as e:
            w(f"Playwright DOM XSS verification error: {e}")


