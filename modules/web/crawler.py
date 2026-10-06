import sys
import os
import re
import asyncio
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set
from core.ui import ph, i, p, w, draw_table, Spinner, G, Y, R, N, GY, W, C

class DeepCrawler:
    """Advanced crawler for deeper endpoint discovery and hidden path extraction."""

    def __init__(self, target_url: str, max_depth: int = 2, max_urls: int = 300, async_engine=None):
        self.target_url = target_url.rstrip("/") or target_url
        self.base_url = self.target_url
        self.domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.async_engine = async_engine
        self.visited = set()
        self.endpoints = set()
        self.params = set()
        self._queue = asyncio.Queue()

    HIGH_SIGNAL_PARAMS = {
        "id", "uid", "user_id", "account_id", "org_id", "team_id", "order_id",
        "file", "path", "url", "redirect", "redirect_url", "return", "return_to",
        "next", "callback", "q", "query", "search", "token", "code", "state",
        "page", "limit", "offset", "sort", "filter", "lang", "locale",
    }

    def _looks_like_static_js_noise(self, value: str) -> bool:
        if not value: return True
        if value.startswith("javascript:") or value.startswith("mailto:") or value.startswith("tel:") or value.startswith("#"):
            return True
        if any(ch in value for ch in ["+", "{", "}", "(", ")", "'", '"', "`", "\\"]):
            return True
        if len(value) > 180 or re.search(r"\s", value):
            return True
        return False

    def _add_param_candidate(self, name: str):
        name = (name or "").strip()
        lower = name.lower()
        if len(name) < 2 or len(name) > 40:
            return
        if lower in ["true", "false", "null", "undefined", "class", "style", "href", "src", "action"]:
            return
        if lower in self.HIGH_SIGNAL_PARAMS or lower.endswith("_id") or lower.endswith("id"):
            self.params.add(name)

    async def _crawl_worker(self, stop_event):
        while not stop_event.is_set():
            try:
                url, depth = await asyncio.wait_for(self._queue.get(), timeout=2.0)
            except asyncio.TimeoutError:
                # No new items for 2s — check if we should stop
                continue
            except asyncio.CancelledError:
                break

            if url in self.visited or len(self.visited) >= self.max_urls:
                self._queue.task_done()
                continue

            self.visited.add(url)

            try:
                r = await self.async_engine.ahttp_send(url, timeout=7, bypass=True)
                if r.get("status") == 200 and r.get("body"):
                    body = r["body"]

                    # Extract from attributes, NOW INCLUDES RELATIVE PATHS
                    tags = re.findall(r'(?:href|src|action|data-url|data-href)=["\']([^"\']+)["\']', body, re.I)
                    for link in tags:
                        if self._looks_like_static_js_noise(link):
                            continue
                        if any(ext in link.lower() for ext in ['.jpg','.jpeg','.png','.css','.gif','.pdf','.woff','.woff2','.svg','.ico','.ttf','.otf']):
                            continue

                        full_url = urljoin(url, link).split("#")[0].rstrip("/")
                        if self.domain in urlparse(full_url).netloc:
                            if full_url not in self.visited and full_url not in self.endpoints:
                                self.endpoints.add(full_url)
                                if depth < self.max_depth and len(self.visited) + self._queue.qsize() < self.max_urls:
                                    self._queue.put_nowait((full_url, depth + 1))

                    # Extract parameters
                    found_params = re.findall(r'(?:name|id|data-param|data-field)=["\']([a-zA-Z0-9_\-]+)["\']', body)
                    found_params += re.findall(r'[?&]([a-zA-Z0-9_\-]+)=', body)

                    for m in found_params:
                        self._add_param_candidate(m)
            except Exception:
                pass

            self._queue.task_done()

    async def run(self) -> Dict:
        ph("PHASE 1.2: DEEP CRAWLER (Async Recursive)")
        i(f"Starting crawl from {W}{self.base_url}{N} (Max Depth: {self.max_depth})")

        if not self.async_engine:
            w("DeepCrawler requires async_engine. Aborting.")
            return {"endpoints": [], "params": []}

        spin = Spinner("Crawling endpoints concurrently...")
        stop_event = asyncio.Event()
        self._queue.put_nowait((self.base_url, 0))

        num_workers = min(15, self.max_urls)
        workers = []
        for _ in range(num_workers):
            workers.append(asyncio.create_task(self._crawl_worker(stop_event)))

        # Wait for queue to drain or max urls to be reached
        while len(self.visited) < self.max_urls:
            spin.next()
            await asyncio.sleep(0.2)
            # If queue is empty and no items are being processed, we're done
            if self._queue.empty() and self._queue._unfinished_tasks == 0:
                break

        # Signal workers to stop and wait for graceful shutdown
        stop_event.set()
        for w_task in workers:
            w_task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
            
        spin.stop()
        
        # 1. Check robots.txt
        robots_url = urljoin(self.target_url, "/robots.txt")
        r = await self.async_engine.ahttp_send(robots_url, timeout=5)
        if r.get("status") == 200:
            p(f"Found {Y}robots.txt{N}. Extracting hidden paths...")
            paths = re.findall(r'Disallow:\s*(/[^\s#]+)', r.get("body", ""))
            for path in paths:
                self.endpoints.add(urljoin(self.target_url, path))
        
        # 2. Check Sitemap
        sitemap_url = urljoin(self.target_url, "/sitemap.xml")
        r = await self.async_engine.ahttp_send(sitemap_url, timeout=5)
        if r.get("status") == 200:
            p(f"Found {Y}sitemap.xml{N}. Mapping structure...")
            locs = re.findall(r'<loc>(https?://[^<]+)</loc>', r.get("body", ""))
            for loc in locs:
                self.endpoints.add(loc)
        
        p(f"Crawl finished. Discovered {G}{len(self.endpoints)}{N} endpoints and {Y}{len(self.params)}{N} unique parameters.")
        
        if self.endpoints:
            rows = [[f"{G}Found{N}", f"{W}{u[:60]}...{N}"] for u in list(self.endpoints)[:15]]
            draw_table(["TYPE", "DISCOVERED PATH"], rows, title="Top Crawled Endpoints")
            
        return {"endpoints": list(self.endpoints), "params": list(self.params)}
