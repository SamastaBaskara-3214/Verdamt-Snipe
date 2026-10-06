import asyncio
from core.external_tools import run_httpx, run_subfinder
from core.ui import ph
from modules.recon import HTTPProber, SubdomainFinder
from runners.shared import normalize_urls


async def run_surface_scan(target: str, seed_url: str, scope_guard, proxy=None,
                           policy=None):
    """Mandatory surface scan used before every mode."""
    ph("PHASE 0: SURFACE SCAN")

    try:
        subs = await asyncio.wait_for(
            asyncio.to_thread(run_subfinder, target, timeout=30, policy=policy,
                                 proxy=proxy),
            timeout=30
        )
    except (asyncio.TimeoutError, Exception):
        subs = []
    subs = subs or []
    if not subs:
        try:
            sub_finder = SubdomainFinder(target)
            subs = await asyncio.wait_for(
                asyncio.to_thread(sub_finder.run),
                timeout=20
            )
        except (asyncio.TimeoutError, Exception):
            subs = []
        subs = subs or []
    if not subs:
        subs = [target]  # Always include root domain as minimum

    # Dedup targets
    targets_set = set()
    for sub in subs:
        targets_set.add(f"https://{sub}")
        targets_set.add(f"http://{sub}")
    targets_to_probe = list(targets_set)
    if seed_url not in targets_to_probe:
        targets_to_probe.append(seed_url)

    # Probe with timeout
    try:
        services = await asyncio.wait_for(
            asyncio.to_thread(run_httpx, targets_to_probe, timeout=60, proxy=proxy, policy=policy),
            timeout=60
        )
    except (asyncio.TimeoutError, Exception):
        services = []
    services = services or []
    if not services:
        probe_subs = list(set(subs + [target]))
        if policy:
            probe_subs = [sub for sub in probe_subs if policy.allows_host(sub)]
        try:
            services = await asyncio.wait_for(
                HTTPProber(probe_subs, proxy=proxy, policy=policy).run(),
                timeout=60
            )
        except (asyncio.TimeoutError, Exception):
            services = []
        services = services or []

    urls = []
    for service in services:
        final_url = service.get("final_url") or ""
        candidates = [service.get("url", "")]
        if final_url and final_url != candidates[0]:
            candidates.append(final_url)
        urls.extend(scope_guard.filter_urls(candidates))

    return subs, services, normalize_urls(urls, scope_guard=scope_guard)
