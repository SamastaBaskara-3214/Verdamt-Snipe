
"""IDOR Mass Enumeration — detect accessible user data via ID iteration."""

import re
import asyncio
from typing import Dict, List, Optional
from core.async_network import AsyncNetworkEngine

async def scan_idor(url: str, engine: AsyncNetworkEngine, session_manager=None) -> List[Dict]:
    """Enumerate numeric IDs and check for accessible data."""
    findings = []

    # Find numeric ID in URL
    match = re.search(r'[/=](\d+)(?:\b|[/?&])', url)
    if not match:
        return findings

    base_id = int(match.group(1))
    base_url = url[:match.start(1)] + "{}" + url[match.end(1):]

    # Test IDs around the base
    test_ids = list(range(max(1, base_id - 5), base_id + 15))
    if base_id in test_ids:
        test_ids.remove(base_id)
    test_ids = test_ids[:20]  # Max 20 requests

    baseline = await engine.ahttp_send(url, timeout=10, state_context=session_manager)
    baseline_body = baseline.get("body", "") or ""
    baseline_size = len(baseline_body)

    accessible = []
    
    async def _test_idor(tid: int):
        test_url = base_url.format(tid)
        r = await engine.ahttp_send(test_url, timeout=10, state_context=session_manager)
        if r["status"] == 200:
            body = r.get("body", "") or ""
            # Check if response is different from baseline (different user data)
            if len(body) > 50 and abs(len(body) - baseline_size) > 100:
                body_lower = body.lower()
                denied_keywords = ["access denied", "unauthorized", "not found", "error", "login", "permission"]
                if any(kw in body_lower for kw in denied_keywords) and not any(kw in baseline_body.lower() for kw in denied_keywords):
                    return None
                return tid
        return None

    # Limit concurrency to avoid overwhelming the target
    semaphore = asyncio.Semaphore(10)
    async def _limited_test(id_val):
        async with semaphore:
            return await _test_idor(id_val)
    tasks = [_limited_test(id_val) for id_val in test_ids]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for res in results:
        if isinstance(res, int):
            accessible.append(res)

    if accessible:
        findings.append({
            "type": "idor_mass",
            "title": "IDOR Mass Enumeration",
            "url": url[:200],
            "detail": f"Accessible IDs: {accessible[:10]} (from {base_url.format('ID')})",
            "accessible_count": len(accessible),
            "confidence": "confirmed",
        })

    return findings
