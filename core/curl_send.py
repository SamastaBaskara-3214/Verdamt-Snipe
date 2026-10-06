"""curl-based HTTP sender with --resolve support for origin IP scanning.

Resolves SNI issue: when scanning origin IP via HTTPS, curl --resolve
sends the domain as SNI while routing traffic to the origin IP.
"""

import os
import subprocess
import tempfile
from typing import Dict, Optional
from urllib.parse import urlparse


def curl_send(url: str, resolve_domain: str = None, resolve_ip: str = None,
              method: str = "GET", headers: dict = None, data: str = None,
              timeout: int = 10, proxy: str = None) -> Dict:
    """HTTP request via curl with optional --resolve for origin IP scan.

    When resolve_domain + resolve_ip are set, uses curl's --resolve flag:
      curl --resolve domain:443:origin_ip https://domain/path
    This sends the domain as SNI (correct TLS), but routes to origin IP.

    Uses a single curl call (body saved to temp file, metadata via -w).
    """
    fd, body_file = tempfile.mkstemp(suffix=".curl_body")
    os.close(fd)
    cmd = ["curl", "-s", "--max-time", str(timeout), "-o", body_file,
           "-w", "%{http_code}:%{time_total}:%{size_download}"]

    # Proxy
    if proxy:
        cmd.extend(["--proxy", proxy])

    # Resolve: domain -> origin IP (fixes SNI issue)
    if resolve_domain and resolve_ip:
        parsed = urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        cmd.extend(["--resolve", f"{resolve_domain}:{port}:{resolve_ip}"])
        cmd.extend(["-k"])  # Skip cert verification (IP != domain)

    # Method
    if method != "GET":
        cmd.extend(["-X", method])

    # Headers
    for k, v in (headers or {}).items():
        cmd.extend(["-H", f"{k}: {v}"])

    # Data
    if data:
        cmd.extend(["--data", data])

    cmd.append(url)

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        if r.returncode != 0:
            return {"status": 0, "error": r.stderr.strip()[:100], "body": "", "headers": {}, "time": 0}

        parts = r.stdout.strip().split(":")
        code = int(parts[0]) if parts and parts[0].isdigit() else 0
        elapsed = float(parts[1]) if len(parts) > 1 else 0
        size = int(parts[2]) if len(parts) > 2 else 0

        # Read body from temp file
        body = ""
        if os.path.exists(body_file):
            try:
                with open(body_file, "r", errors="replace") as f:
                    body = f.read()
            except Exception:
                body = ""

        return {
            "status": code,
            "body": body,
            "headers": {},
            "time": elapsed,
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"status": 0, "error": "timeout", "body": "", "headers": {}, "time": timeout}
    except Exception as e:
        return {"status": 0, "error": str(e)[:100], "body": "", "headers": {}, "time": 0}
    finally:
        # Clean up temp file
        if os.path.exists(body_file):
            try:
                os.unlink(body_file)
            except Exception:
                pass
