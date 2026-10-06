import asyncio
import re
from urllib.parse import urljoin, urlparse

from core.ui import ph, i, p, w, s, Spinner, G, Y, R, N, GY, W, C
from modules.scanners import AsyncVulnEngine
from runners.shared import normalize_urls, validate_recon_urls


def _extract_links(html: str, base_url: str) -> list:
    """Extract all same-domain <a href> links from HTML."""
    urls = set()
    for match in re.finditer(r'href=["\'](https?://[^"\']+)["\']', html, re.I):
        urls.add(match.group(1).split("#")[0])
    for match in re.finditer(r'href=["\'](/[^"\']+)["\']', html, re.I):
        urls.add(urljoin(base_url, match.group(1)).split("#")[0])
    return list(urls)


async def run_recon_light(
    target: str, seed_url: str, services, subs, base_urls, scope_guard, async_engine, is_turbo=False, session_manager=None
):
    """
    Lightweight recon for static/simple sites.
    Crawls homepage → extracts links → validates → basic security checks.
    NO gau, NO wayback, NO google dorking, NO subdomain takeover.
    Designed to finish in <60s for a typical static site.
    """
    ph("PHASE 1: RECON LIGHT")
    findings = []
    urls = list(base_urls)

    # Step 1: Crawl homepage + all discovered service URLs for links
    ph("Crawling: Link Extraction")
    spin = Spinner("Fetching pages and extracting links...")
    crawl_targets = [seed_url] + [sv["url"] for sv in services if sv.get("url")]
    
    async def _crawl_url(url):
        spin.next()
        try:
            r = await async_engine.ahttp_send(url, timeout=10)
            if r["status"] == 200 and r.get("body"):
                return _extract_links(r["body"], url)
        except Exception as e:
            w(f"crawl failed {url[:60]}: {str(e)[:60]}")
        return []

    crawl_tasks = [_crawl_url(url) for url in set(crawl_targets)]
    crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
    
    for links in crawl_results:
        if isinstance(links, list):
            urls.extend(links)
            
    spin.stop()
    p(f"Raw URLs collected: {C}{len(urls)}{N}")

    # Step 2: Normalize + validate
    urls = normalize_urls(urls, scope_guard=scope_guard)
    scan_urls = await validate_recon_urls(urls, scope_guard, async_engine, session_manager=session_manager, max_urls=1000)

    # Step 3: Baseline security checks on services
    orig_delay = 0.0
    orig_threshold = 0
    if services:
        ph("Baseline: Security Checks")
        engine = AsyncVulnEngine(async_engine)
        if is_turbo:
            # Save original values for restoration
            orig_delay = async_engine.rate_limiter.current_delay
            orig_threshold = async_engine.circuit_breaker.failure_threshold
            async_engine.rate_limiter.current_delay = 0
            async_engine.circuit_breaker.failure_threshold = 999999

        async def _check_service(service):
            """Run all 3 checks for a service in parallel."""
            url = service["url"]
            conf, head, cors = await asyncio.gather(
                engine.config_checks(url),
                engine.header_checks(url),
                engine.cors_checks(url),
            )
            results = []
            if conf: results.extend(conf if isinstance(conf, list) else [conf])
            if head: results.extend(head if isinstance(head, list) else [head])
            if cors: results.extend(cors if isinstance(cors, list) else [cors])
            return results

        # Run all services in parallel
        tasks = [_check_service(s) for s in services]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                ph(f"Baseline check error: {r}")
            elif isinstance(r, list):
                findings.extend(r)

        # Restore original values after turbo mode
        if is_turbo:
            async_engine.rate_limiter.current_delay = orig_delay
            async_engine.circuit_breaker.failure_threshold = orig_threshold

    s(f"Recon Light complete: {G}{len(scan_urls)}{N} endpoints, {G}{len(findings)}{N} findings")
    return findings, scan_urls
