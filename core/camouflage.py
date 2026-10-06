"""Session Mimicry — Browse normal paths before scanning to look human.

Before scanning sensitive paths (/admin, /.env, /config), first visit
normal pages (/, /about, /contact) to establish a legitimate session.
This makes the scanner look like a normal user who then "stumbled" onto
interesting paths.

Usage:
    from core.camouflage import CamouflageBrowser

    camo = CamouflageBrowser(engine)
    await camo.warm_up("https://target.com")  # Visit normal pages first
    # Now scan — target sees "user browsed normally, then found something"
"""

import asyncio
import random
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin


# Common "normal" paths that real users visit
BENIGN_PATHS = [
    "/",
    "/about",
    "/about-us",
    "/contact",
    "/contact-us",
    "/help",
    "/faq",
    "/privacy",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/sitemap",
    "/sitemap.xml",
    "/robots.txt",
    "/news",
    "/blog",
    "/services",
    "/products",
    "/login",
    "/register",
    "/search",
]

# Common search queries that real users type
SEARCH_QUERIES = [
    "beranda",
    "kontak",
    "layanan",
    "tentang",
    "informasi",
    "bantuan",
    "cari",
    "login",
    "daftar",
]


class CamouflageBrowser:
    """Simulate normal browsing behavior before scanning.
    
    Visits benign paths, follows links, respects delays —
    making the scanner's IP look like a legitimate user in target's logs.
    """

    def __init__(self, engine, proxy: str = None):
        self.engine = engine
        self.proxy = proxy
        self.visited = []
        self.session_cookies = {}

    async def warm_up(
        self,
        base_url: str,
        num_visits: int = 3,
        delay_range: tuple = (1.0, 3.0),
    ) -> List[Dict]:
        """Visit normal pages to establish a "human" session.
        
        Args:
            base_url: Target base URL (e.g. https://target.com)
            num_visits: Number of benign pages to visit
            delay_range: Random delay between visits (seconds)
        
        Returns:
            List of responses from benign pages
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        
        # Select random benign paths
        paths = random.sample(BENIGN_PATHS, min(num_visits, len(BENIGN_PATHS)))
        
        # Always start with /
        if "/" not in paths:
            paths.insert(0, "/")

        results = []
        
        for path in paths:
            url = urljoin(origin, path)
            
            # Random delay (mimic human browsing speed)
            delay = random.uniform(*delay_range)
            await asyncio.sleep(delay)
            
            try:
                response = await self.engine.ahttp_send(
                    url, method="GET", bypass=False,
                    timeout=10,
                )
                self.visited.append({
                    "url": url,
                    "status": response.get("status", 0),
                    "time": response.get("time", 0),
                })
                results.append(response)
                
                # If page has links, randomly follow 1
                if response.get("status") == 200 and response.get("body"):
                    links = self._extract_links(response["body"], origin)
                    if links and random.random() > 0.5:
                        link = random.choice(links[:5])
                        await asyncio.sleep(random.uniform(0.5, 2.0))
                        link_resp = await self.engine.ahttp_send(
                            link, method="GET", bypass=False,
                            timeout=10,
                        )
                        self.visited.append({
                            "url": link,
                            "status": link_resp.get("status", 0),
                            "time": link_resp.get("time", 0),
                        })
                        
            except Exception:
                continue

        return results

    def _extract_links(self, body: str, origin: str) -> List[str]:
        """Extract same-origin links from HTML body."""
        import re
        links = []
        for match in re.finditer(r'href=["\']([^"\']+)["\']', body, re.I):
            href = match.group(1)
            if href.startswith("/"):
                links.append(urljoin(origin, href))
            elif href.startswith(origin):
                links.append(href)
        # Filter out non-page links
        return [
            l for l in links
            if not any(l.endswith(ext) for ext in [
                ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                ".pdf", ".zip", ".tar", ".gz",
            ])
        ]

    def get_stats(self) -> Dict:
        """Get camouflage browsing stats."""
        return {
            "pages_visited": len(self.visited),
            "urls": [v["url"] for v in self.visited],
            "avg_time": (
                sum(v["time"] for v in self.visited) / len(self.visited)
                if self.visited else 0
            ),
        }

