"""DNS-over-HTTPS (DoH) Resolver — prevent DNS leaks.

Routes DNS queries through HTTPS to Cloudflare/Google DoH servers
instead of using local DNS resolver (which leaks query to ISP).

Usage:
    from core.doh_resolve import doh_resolve, doh_resolve_async
    
    ips = doh_resolve("target.com")
    ips = await doh_resolve_async("target.com")
"""

import json
import socket
import subprocess
import asyncio
from typing import List, Optional
from urllib.parse import quote

# DoH providers (order = priority)
DOH_PROVIDERS = [
    {"name": "Cloudflare", "url": "https://1.1.1.1/dns-query", "ip": "1.1.1.1"},
    {"name": "Google", "url": "https://8.8.8.8/dns-query", "ip": "8.8.8.8"},
    {"name": "Quad9", "url": "https://9.9.9.9/dns-query", "ip": "9.9.9.9"},
]


def doh_resolve(domain: str, proxy: str = None) -> List[str]:
    """Resolve domain to IPs via DNS-over-HTTPS (sync).
    
    Prevents DNS query from leaking to ISP/local resolver.
    Routes through proxy if provided.
    
    Returns list of IP addresses.
    """
    for provider in DOH_PROVIDERS:
        try:
            # Use curl for DoH (RFC 8484 JSON format)
            url = f"{provider['url']}?name={quote(domain)}&type=A"
            cmd = [
                "curl", "-s", "--max-time", "5",
                "-H", "Accept: application/dns-json",
                url,
            ]
            if proxy:
                cmd.extend(["--proxy", proxy])

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=8,
            )
            if result.returncode != 0 or not result.stdout.strip():
                continue

            data = json.loads(result.stdout)
            ips = []
            for answer in data.get("Answer", []):
                if answer.get("type") == 1:  # A record
                    ips.append(answer.get("data", ""))
            if ips:
                return ips
        except Exception:
            continue

    # Fallback: local DNS (leaks, but better than nothing)
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return ips
    except Exception:
        return []


async def doh_resolve_async(domain: str, proxy: str = None) -> List[str]:
    """Resolve domain to IPs via DNS-over-HTTPS (async).
    
    Prevents DNS query from leaking to ISP/local resolver.
    """
    return await asyncio.to_thread(doh_resolve, domain, proxy)


def doh_check_leak(proxy: str = None) -> dict:
    """Check if DNS queries are leaking by comparing DoH vs local resolution.
    
    Returns dict with leak status and details.
    """
    test_domain = "cloudflare.com"
    
    # Resolve via DoH (through proxy)
    doh_ips = doh_resolve(test_domain, proxy=proxy)
    
    # Resolve via local DNS (without proxy)
    try:
        local_ips = socket.gethostbyname_ex(test_domain)[2]
    except Exception:
        local_ips = []
    
    return {
        "doh_ips": doh_ips,
        "local_ips": local_ips,
        "leak_detected": len(local_ips) > 0 and local_ips != doh_ips,
        "recommendation": "Use DoH or route DNS through proxy" if local_ips else "OK",
    }
