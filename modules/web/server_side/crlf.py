"""CRLF Injection + Log Poisoning."""

from typing import Dict, List, Optional
from urllib.parse import quote

from core.async_network import AsyncNetworkEngine


async def scan_crlf(url: str, engine: AsyncNetworkEngine, session_manager=None) -> List[Dict]:
    """Test CRLF injection via URL parameters."""
    findings = []

    # CRLF test payloads
    payloads = [
        ("%0d%0aX-Injected:test", "header_injection"),
        ("%0d%0a<script>fetch('http://collab/crlf')</script>", "log_poisoning"),
        ("%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>", "response_splitting"),
    ]

    for payload, vuln_type in payloads:
        # Inject in URL param
        test_url = f"{url}?q={payload}&x={payload}"
        r = await engine.ahttp_send(test_url, timeout=10, state_context=session_manager)
        if r["status"] > 0:
            headers = {k.lower(): v for k, v in r.get("headers", {}).items()}

            # Check for injected header
            if vuln_type == "header_injection" and "x-injected" in headers:
                findings.append({"type": "crlf_injection", "title": "CRLF Injection",
                                 "url": test_url[:200], "detail": "Header injection confirmed via X-Injected",
                                 "confidence": "confirmed"})

            # Check for response splitting (multiple HTTP responses)
            if vuln_type == "response_splitting":
                body = r.get("body", "") or ""
                if "HTTP/1.1 200 OK" in body and "Content-Type: text/html" in body:
                    findings.append({"type": "crlf_response_splitting", "title": "CRLF Response Splitting",
                                     "url": test_url[:200], "detail": "Multiple HTTP responses in single request",
                                     "confidence": "suspected"})

    return findings
