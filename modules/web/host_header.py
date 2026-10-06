"""Host Header Injection + Password Reset Poisoning."""

import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.async_network import AsyncNetworkEngine


async def scan_host_header(url: str, engine: AsyncNetworkEngine, session_manager=None) -> List[Dict]:
    """Test Host header injection on target."""
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.hostname or ""

    # Test 1: Basic Host header reflection
    evil_host = "evil.attacker.com"
    r = await engine.ahttp_send(url, headers={"Host": evil_host}, timeout=10, state_context=session_manager)
    if r["status"] > 0:
        body = r.get("body", "") or ""
        if evil_host in body or evil_host in str(r.get("headers", {})):
            findings.append({"type": "host_header_injection", "title": "Host Header Injection",
                             "url": url[:200], "detail": f"Host: {evil_host} reflected in response",
                             "confidence": "confirmed"})

    # Test 2: Password reset poisoning
    reset_paths = ["/forgot-password", "/reset-password", "/forgot", "/reset",
                   "/password/reset", "/account/reset", "/forgot_password"]
    
    async def _test_reset_path(path):
        target = f"{parsed.scheme}://{domain}{path}"
        r = await engine.ahttp_send(target, headers={"Host": evil_host}, timeout=10, state_context=session_manager)
        if r and r.get("status", 0) not in (0, 404):
            body = r.get("body", "") or ""
            if evil_host in body:
                return {"type": "password_reset_poisoning", "title": "Password Reset Poisoning",
                        "url": target[:200], "detail": f"Host: {evil_host} — reset link poisoned",
                        "confidence": "confirmed"}
        return None
    
    # Test all reset paths in parallel
    reset_tasks = [_test_reset_path(path) for path in reset_paths]
    reset_results = await asyncio.gather(*reset_tasks, return_exceptions=True)
    for r in reset_results:
        if r and not isinstance(r, Exception):
            findings.append(r)

    return findings
