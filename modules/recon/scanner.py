import sys
import os
import threading
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import time
import re
import socket
import concurrent.futures
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
from core.http_client import HTTPClient
from core.ratelimit import RateLimiter
from core.network import http_send, thttp
from core.ui import ph, i, p, s, w, draw_table, Spinner, G, Y, R, M, C, N, GY, W, B

RECON_THREADS = 10
_CHECK = "✓"

class SubdomainFinder:
    def __init__(self, domain: str):
        self.domain = domain.lower().strip()
        self.subs: Set[str] = set()
        self.lock = threading.Lock()
    
    def _crtsh(self):
        try:
            r = http_send(f"https://crt.sh/?q=%25.{self.domain}&output=json", timeout=20)
            if r["status"]==200:
                for m in re.finditer(r'"name_value":"([^"]+)"', r["body"]):
                    for s in m.group(1).split("\n"):
                        s = s.strip().lower().replace("*.","")
                        if s.endswith(self.domain) and s!=self.domain:
                            with self.lock: self.subs.add(s)
        except Exception as e:
            w(f"crt.sh failed: {str(e)[:80]}")
    
    def _hackertarget(self):
        try:
            r = http_send(f"https://api.hackertarget.com/hostsearch/?q={self.domain}", timeout=20)
            if r["status"]==200:
                for ln in r["body"].split("\n"):
                    if "."+self.domain in ln:
                        s = ln.split(",")[0].strip().lower()
                        if s.endswith("."+self.domain):
                            with self.lock: self.subs.add(s)
        except Exception as e:
            w(f"hackertarget failed: {str(e)[:80]}")
    
    def _bufferover(self):
        try:
            r = http_send(f"https://dns.bufferover.run/dns?q=.{self.domain}", timeout=20)
            if r["status"]==200:
                for m in re.finditer(r'"([^"]+\.'+re.escape(self.domain)+r')"', r["body"]):
                    s = m.group(1).lower().split(",")[-1].strip()
                    if s.endswith("."+self.domain):
                        with self.lock: self.subs.add(s)
        except Exception as e:
            w(f"bufferover failed: {str(e)[:80]}")
    
    def _rapiddns(self):
        try:
            r = http_send(f"https://rapiddns.io/subdomain/{self.domain}?full=1", timeout=20)
            if r["status"]==200:
                for m in re.finditer(r'<td>([a-zA-Z0-9._-]+\.'+re.escape(self.domain)+r')</td>', r["body"]):
                    with self.lock: self.subs.add(m.group(1).lower())
        except Exception as e:
            w(f"rapiddns failed: {str(e)[:80]}")
    
    def _alienvault(self):
        try:
            r = http_send(f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns", timeout=20)
            if r["status"]==200:
                for m in re.finditer(r'"hostname":"([^"]+)"', r["body"]):
                    s = m.group(1).lower()
                    if s.endswith("."+self.domain):
                        with self.lock: self.subs.add(s)
        except Exception as e:
            w(f"alienvault failed: {str(e)[:80]}")
    
    def run(self) -> List[str]:
        ph("SUBDOMAIN ENUMERATION")
        i(f"Target: {self.domain}")
        
        sources = [self._crtsh, self._hackertarget, self._bufferover, self._rapiddns, self._alienvault]
        threads = []
        for fn in sources:
            t = threading.Thread(target=fn)
            t.start(); threads.append(t)
            time.sleep(0.2)
        for t in threads: t.join()
        
        i(f"Raw: {len(self.subs)} found, validating via DNS...")
        valid = set()
        spin = Spinner("Resolving DNS records...")
        def check(s):
            spin.next()
            try:
                socket.getaddrinfo(s, 80, socket.AF_INET, socket.SOCK_STREAM)
                return s
            except (socket.herror, socket.gaierror, OSError):
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=RECON_THREADS) as ex:
            for r in ex.map(check, list(self.subs)):
                if r: valid.add(r)
        spin.stop()
        valid.add(self.domain)
        p(f"Live Subdomains: {G}{len(valid)}{N}")
        return sorted(valid)

def probe_seed_url(seed_url, http_client=None) -> Dict:
    http = http_client or HTTPClient(timeout=15, follow_redirects=True)
    try:
        resp = http.request("GET", seed_url, follow_redirects=True)
    except Exception as exc:
        print(f"[-] failed seed probe {seed_url}: {exc}")
        return None

    if not (200 <= resp.status_code <= 499):
        return None

    parsed = urlparse(str(resp.url))
    title = HTTPProber._extract_title(resp.text)
    headers = dict(resp.headers or {})
    service = {
        "url": seed_url.rstrip("/"),
        "final_url": str(resp.url).rstrip("/"),
        "host": parsed.hostname or urlparse(seed_url).hostname or "",
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "scheme": parsed.scheme or urlparse(seed_url).scheme,
        "status": resp.status_code,
        "status_code": resp.status_code,
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "title": title,
        "tech": headers.get("server", "Unknown") or "Unknown",
        "headers": headers,
        "body": resp.text,
        "waf": [],
    }
    print(f"[+] Seed URL aktif: {service['final_url']}")
    return service


import asyncio
import httpx

class HTTPProber:
    def __init__(self, subs: List[str], seed_url=None, timeout=10, rate_limiter=None,
                 proxy=None, policy=None):
        self.subs = subs
        self.seed_url = seed_url
        self.timeout = timeout
        self.ratelimit = rate_limiter
        self.proxy = proxy
        self.policy = policy
        self.services: List[Dict] = []

    @staticmethod
    def _extract_title(html) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.DOTALL)
        if not match:
            return ""
        return re.sub(r"\s+", " ", match.group(1)).strip()[:100]

    async def _probe_single(self, client, url) -> Optional[Dict]:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        if not hostname:
            return None

        urls = [url]
        if parsed.scheme == "https":
            urls.append("http://" + parsed.netloc + (parsed.path or ""))
        elif parsed.scheme == "http":
            urls.append("https://" + parsed.netloc + (parsed.path or ""))

        strategies = [
            (urls[0], None),
            (urls[1] if len(urls) > 1 else urls[0], None),
            (urls[0], {"Host": hostname}),
            (urls[1] if len(urls) > 1 else urls[0], {"User-Agent": "curl/8.0.0", "Connection": "close"}),
        ]

        for candidate_url, headers in strategies:
            if self.policy:
                decision = self.policy.authorize_request(candidate_url, "GET")
                if not decision.allowed:
                    continue

            if self.ratelimit:
                if self.ratelimit.is_blocked(hostname):
                    continue
                await self.ratelimit.wait_async(hostname)

            try:
                resp = await client.get(
                    candidate_url,
                    headers=headers,
                    follow_redirects=self.policy is None,
                    timeout=self.policy.clamp_timeout(self.timeout) if self.policy else self.timeout,
                )
                if self.policy and not self.policy.allows_url(str(resp.url)):
                    continue
                body_len = len(resp.content or b"")
                if 200 <= resp.status_code <= 499 and body_len > 50:
                    final_parsed = urlparse(str(resp.url))
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    title = self._extract_title(resp.text)
                    server = resp_headers.get("server", "")

                    if self.ratelimit:
                        self.ratelimit.report_response(hostname, resp.status_code, resp.text)

                    return {
                        "url": candidate_url.rstrip("/"),
                        "final_url": str(resp.url).rstrip("/"),
                        "host": final_parsed.hostname or hostname,
                        "port": final_parsed.port or (443 if final_parsed.scheme == "https" else 80),
                        "scheme": final_parsed.scheme,
                        "status": resp.status_code,
                        "status_code": resp.status_code,
                        "server": server,
                        "content_type": resp_headers.get("content-type", ""),
                        "title": title,
                        "tech": server or "Unknown",
                        "headers": resp_headers,
                        "body": resp.text,
                        "waf": [],
                    }
            except Exception:
                continue
        return None

    async def run(self) -> List[Dict]:
        ph("VERDAMT-HTTPX v4: Probing & Validation (Async)")
        targets = []
        if self.seed_url:
            targets.append(self.seed_url)
        for sub in self.subs:
            targets.append(f"https://{sub}")
            targets.append(f"http://{sub}")

        print(f"[*] info checking {len(targets)} HTTP targets")
        results = []
        seen = set()

        # Try Go Engine Daemon first for ultra-fast multi-threaded probing
        from core.go_bridge import go_bridge
        if go_bridge.is_available() and not self.proxy:
            i(f"Using {G}Go Probing Engine (Unix Domain Socket){N} for ultra-fast surface scan...")
            try:
                concurrency = self.policy.max_concurrency if self.policy else 100
                delay_ms, jitter_ms = (0, 0)
                if self.ratelimit and targets:
                    from urllib.parse import urlparse
                    host = urlparse(targets[0]).hostname or "default"
                    delay_ms, jitter_ms = self.ratelimit.get_adaptive_delay_ms(host)
                go_results = await asyncio.to_thread(
                    go_bridge.probe_batch,
                    targets,
                    concurrency=concurrency,
                    timeout=int(self.timeout),
                    delay_ms=delay_ms,
                    jitter_ms=jitter_ms,
                )
                if go_results:
                    for r in go_results:
                        sc = r.get("status_code", 0)
                        if 200 <= sc <= 499:
                            final_url = (r.get("final_url") or r.get("url") or "").rstrip("/")
                            if final_url and final_url not in seen:
                                if self.policy and not self.policy.allows_url(final_url):
                                    continue
                                seen.add(final_url)
                                parsed = urlparse(final_url)
                                results.append({
                                    "url": r.get("url", "").rstrip("/"),
                                    "final_url": final_url,
                                    "host": parsed.hostname or "",
                                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                                    "scheme": parsed.scheme,
                                    "status": sc,
                                    "status_code": sc,
                                    "server": r.get("server", ""),
                                    "content_type": r.get("content_type", ""),
                                    "title": r.get("title", ""),
                                    "tech": r.get("server", "Unknown") or "Unknown",
                                    "headers": {"server": r.get("server", "")},
                                    "body": "",
                                    "waf": [],
                                })
                    if results:
                        self.services = sorted(results, key=lambda x: x["final_url"])
                        s(f"Go Engine scanned {W}{len(targets)}{N} targets in parallel — {G}{len(results)}{N} live services found.")
                        return self.services
            except Exception as e:
                w(f"Go Probing Engine encounter: {e} — falling back to Async Python Client")

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
        from core.ui import console

        max_connections = self.policy.max_concurrency if self.policy else 100
        limits = httpx.Limits(
            max_keepalive_connections=min(50, max_connections),
            max_connections=max_connections,
        )
        async with httpx.AsyncClient(limits=limits, timeout=self.timeout, verify=False, proxy=self.proxy) as client:
            sem = asyncio.Semaphore(min(40, max_connections))

            async def _sem_probe(target, task_id, progress):
                async with sem:
                    try:
                        res = await self._probe_single(client, target)
                        if res:
                            sc = res["status_code"]
                            c = G if sc < 300 else (Y if sc < 400 else (M if sc < 500 else R))
                            print(f"  [bold green]{_CHECK}[/] [cyan]{sc}[/] [white]{res['final_url']}[/] [bright_black]{res['title'][:60]}[/]")
                        return res
                    except Exception:
                        return None
                    finally:
                        progress.advance(task_id)

            with Progress(
                SpinnerColumn(spinner_name="dots", style="magenta"),
                TextColumn("  [bold cyan]Probing HTTP/S services...[/]"),
                BarColumn(bar_width=30, complete_style="magenta", finished_style="green"),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeElapsedColumn(),
                console=console,
                transient=True
            ) as progress:
                task_id = progress.add_task("Probing", total=len(targets))
                tasks = [_sem_probe(target, task_id, progress) for target in targets]
                raw_results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in raw_results:
                if r and not isinstance(r, Exception):
                    if r["final_url"] not in seen:
                        seen.add(r["final_url"])
                        results.append(r)

        self.services = sorted(results, key=lambda x: x["final_url"])

        rows = []
        for r in self.services:
            sc = r["status_code"]
            c = G if sc < 300 else (Y if sc < 400 else (M if sc < 500 else R))
            tech = r["tech"] if len(r["tech"]) < 25 else r["tech"][:22] + "..."
            rows.append([
                f"{c}{sc}{N}",
                f"{W}{r['final_url']}{N}",
                f"{GY}{tech}{N}",
                f"{R if r['waf'] else G}{'/'.join(r['waf']) if r['waf'] else 'Clean'}{N}"
            ])

        print()
        draw_table(["CODE", "URL (ACTIVE)", "TECH STACK", "WAF"], rows, title="Validated Active Services")

        p(f"Total Active: {B}{len(self.services)}{N}")
        return self.services

class WaybackCollector:
    def __init__(self, domain: str):
        self.domain = domain
        self.urls: Set[str] = set()
    
    def run(self) -> List[str]:
        ph("WAYBACK MACHINE: Time Travel")
        i(f"Fetching historical archives for {W}{self.domain}{N}...")
        spin = Spinner("Mining Wayback Machine...")
        sources = [
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=txt&fl=original&collapse=urlkey",
            f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=1000",
        ]
        if self.domain.count(".")<=2:
            sources.append(f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&limit=100000")
        
        for src in sources:
            spin.next()
            try:
                r = thttp(src, timeout=30)
                if r["status"]==200:
                    for ln in r["body"].split("\n"):
                        ln = ln.strip().strip('"')
                        if ln.startswith("http"):
                            self.urls.add(ln)
            except Exception as e:
                w(f"wayback source failed: {str(e)[:80]}")
        spin.stop()
        
        p(f"URLs collected: {len(self.urls)}")
        return sorted(self.urls)

class ParamExtractor:
    def __init__(self, urls: List[str], extra_params: List[str] = None):
        self.urls = urls
        self.extra_params = extra_params or []
        self.params: Dict[str, Set[str]] = {}
    
    def run(self) -> Dict[str, List[str]]:
        from collections import defaultdict
        from urllib.parse import parse_qs
        self.params = defaultdict(set)
        ph("PARAMETER EXTRACTION: Data Mining")
        i(f"Analyzing {W}{len(self.urls)}{N} endpoints for input vectors...")
        
        spin = Spinner("Extracting unique parameters...")
        for u in self.urls:
            spin.next()
            p_parsed = urlparse(u)
            path = p_parsed.path if p_parsed.path else "/"
            
            # 1. Extract from Query String
            if p_parsed.query:
                for k in parse_qs(p_parsed.query):
                    self.params[path].add(k)
            
            # 2. Inject Extra Params found via Regex/JS into active paths
            for ep in self.extra_params:
                self.params[path].add(ep)
                
        spin.stop()
        
        # Deduplicate and limit per path to avoid bloat
        final_params = {}
        for path, plist in self.params.items():
            final_params[path] = sorted(list(plist))[:15] # Top 15 params per path
            
        total = sum(len(v) for v in final_params.values())
        p(f"Unique paths mapped: {len(final_params)}")
        p(f"Total unique parameters identified: {G}{total}{N}")
        
        return final_params
