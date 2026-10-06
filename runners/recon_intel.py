import asyncio
from urllib.parse import urljoin

from core.external_tools import run_gau, run_waybackurls
from core.ui import Spinner, ph
from modules.recon.dorking import GoogleDorker
from modules.recon.jsscanner import JSScanner
from modules.recon import WaybackCollector
from modules.scanners import AsyncVulnEngine
from modules.extras.takeover import TakeoverChecker
from runners.shared import (
    collect_js_assets,
    concrete_js_findings,
    normalize_takeover_findings,
    normalize_urls,
    validate_recon_urls,
)


async def run_recon_intel(target: str, services, subs, base_urls, scope_guard,
                          async_engine, is_turbo=False, session_manager=None,
                          policy=None):
    """Option 1: passive recon, JS analysis, and baseline checks."""
    ph("PHASE 1: RECON INTEL")
    findings = []
    urls = list(base_urls)

    async def _run_gau():
        try:
            return await asyncio.to_thread(run_gau, target, 30, policy)
        except Exception:
            return []

    async def _run_wayback():
        try:
            return await asyncio.to_thread(run_waybackurls, target, 30, policy)
        except Exception:
            return []

    async def _run_takeovers():
        try:
            raw = await asyncio.to_thread(TakeoverChecker(subs).run)
            return normalize_takeover_findings(raw)
        except Exception:
            return []

    async def _run_dorking():
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(GoogleDorker(target).run),
                timeout=30
            )
        except (asyncio.TimeoutError, Exception):
            return {}

    async def _run_js_analysis(current_urls):
        js_urls = await asyncio.to_thread(collect_js_assets, current_urls, services)
        all_urls = normalize_urls(current_urls + js_urls, scope_guard=scope_guard)
        
        js_result = await JSScanner(all_urls, scope_guard=scope_guard, async_engine=async_engine).run()
        js_findings = []
        new_urls = list(current_urls)
        
        if isinstance(js_result, tuple):
            js_findings, js_endpoints = js_result
            for endpoint in js_endpoints:
                if endpoint.startswith("/"):
                    for service in services:
                        new_urls.extend(scope_guard.filter_urls([urljoin(service["url"].rstrip("/") + "/", endpoint.lstrip("/"))]))
                elif endpoint.startswith("http"):
                    new_urls.extend(scope_guard.filter_urls([endpoint]))
        else:
            js_findings = js_result if isinstance(js_result, list) else []
            
        new_urls = normalize_urls(new_urls, scope_guard=scope_guard)
        return js_findings, new_urls

    async def _run_baseline_checks():
        results_findings = []
        orig_delay = 0.0
        orig_threshold = 0
        if services:
            engine = AsyncVulnEngine(async_engine)
            if is_turbo:
                # Save original values for restoration
                orig_delay = engine.engine.rate_limiter.current_delay
                orig_threshold = engine.engine.circuit_breaker.failure_threshold
                engine.engine.rate_limiter.current_delay = 0
                engine.engine.circuit_breaker.failure_threshold = 999999

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
                    results_findings.extend(r)

            # Restore original values after turbo mode
            if is_turbo:
                engine.engine.rate_limiter.current_delay = orig_delay
                engine.engine.circuit_breaker.failure_threshold = orig_threshold

        return results_findings

    spin = Spinner("Gathering OSINT, JS Analysis & Baseline Checks...")
    spin.start()
    gau_urls, wb_urls, takeover_findings, dork_result, js_tuple, baseline_findings = await asyncio.gather(
        _run_gau(),
        _run_wayback(),
        _run_takeovers(),
        _run_dorking(),
        _run_js_analysis(urls),
        _run_baseline_checks(),
        return_exceptions=True
    )
    spin.stop()

    if not isinstance(gau_urls, Exception):
        urls.extend(gau_urls or [])
    if not isinstance(wb_urls, Exception):
        urls.extend(wb_urls or [])
    if not isinstance(takeover_findings, Exception):
        findings.extend(takeover_findings or [])
    if not isinstance(dork_result, Exception) and isinstance(dork_result, dict):
        findings.extend(dork_result.get("findings", []))
        urls.extend(dork_result.get("urls", []))

    if not isinstance(baseline_findings, Exception):
        findings.extend(baseline_findings or [])

    if not isinstance(js_tuple, Exception) and isinstance(js_tuple, tuple):
        js_findings, js_urls = js_tuple
        urls.extend(js_urls)
    else:
        js_findings = []

    urls = normalize_urls(urls, scope_guard=scope_guard)
    scan_urls = await validate_recon_urls(urls, scope_guard, async_engine, session_manager=session_manager)
    findings.extend(concrete_js_findings(js_findings, services, scan_urls, scope_guard))

    return findings, scan_urls
