import os
import re
import sys
import asyncio
from difflib import SequenceMatcher
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.ui import C, G, N, R, W, draw_table, i, p, ph, s


SENSITIVE_PATHS = [
    "/admin", "/api", "/users", "/config", "/.env", "/backup", "/wp-admin",
    "/administrator", "/debug", "/swagger", "/api/docs", "/graphql",
    "/internal", "/panel", "/dashboard", "/api/v1/users", "/api/v1/admin",
]

PATH_BYPASSES = ["/admin", "/Admin", "/ADMIN", "/admin/", "/admin%00"]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("root", "root"), ("root", "toor"),
    ("user", "user"), ("user", "password"), ("user", "pass"),
    ("administrator", "administrator"), ("admin", "123456"),
    ("guest", "guest"), ("test", "test"),
]

NUMERIC_PARAM_NAMES = {
    "id", "user_id", "userid", "uid", "account_id", "accountid",
    "profile_id", "member_id", "memberid", "customer_id", "order_id",
}

SENSITIVE_BODY_MARKERS = [
    "name", "email", "role", "user", "users", "account", "profile",
    "token", "permission", "permissions", "dashboard", "admin",
]


class AuthTester:
    """State-aware authentication and authorization tester."""

    def __init__(self, services_or_urls, session_manager=None, network_engine=None,
                 probe_defaults=False, probe_bypass=False, auth_headers2=None):
        self.input_data = services_or_urls or []
        self.session_manager = session_manager
        self.engine = network_engine
        self.probe_defaults = probe_defaults
        self.probe_bypass = probe_bypass
        self.auth_headers2 = auth_headers2
        self.findings = []
        self._seen = set()
        self._sem = asyncio.Semaphore(15)

    async def run(self):
        if not self.input_data:
            return []

        ph("AUTH TESTER v4: State-Aware Access Control")

        base_urls = set()
        test_urls = []
        for item in self.input_data:
            u = item.get("final_url") or item.get("url") if isinstance(item, dict) else item
            if u:
                test_urls.append(u)
                base_urls.add(self._base_url(u))

        tasks = [self._test_service(base_url, test_urls) for base_url in base_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                p(f"[!] AuthTester worker error: {r}")

        # Deduplicate findings
        seen_keys = set()
        unique_findings = []
        for f in self.findings:
            k = (f.get("url"), f.get("type"), f.get("title"))
            if k not in seen_keys:
                seen_keys.add(k)
                unique_findings.append(f)
        self.findings = unique_findings

        if self.findings:
            rows = []
            for f in self.findings[:15]:
                rows.append([
                    f"{R}{f['type'].replace('_', ' ').title()}{N}",
                    f"{W}{f['title'][:42]}{N}",
                    f"{C}{f.get('url', '')[:52]}{N}",
                ])
            draw_table(["TYPE", "FINDING", "TARGET"], rows, title="Auth/AuthZ Findings")
        else:
            p("No authentication bypasses found.")

        p(f"Findings: {R if self.findings else G}{len(self.findings)}{N}")
        return self.findings

    async def _test_service(self, base_url, all_urls):
        i(f"Testing: {W}{base_url}{N}")

        unauth = await self._baseline_unauthenticated(base_url)
        auth_headers = self._session_headers(base_url)
        
        if auth_headers:
            authed = await self._authenticated_requests(base_url, auth_headers)
            self._compare_authed_vs_unauth(base_url, unauth, authed)

            if self.auth_headers2:
                authed2 = await self._authenticated_requests(base_url, self.auth_headers2)
                self._compare_privilege_escalation(base_url, authed, authed2)

            matching_urls = [u for u in all_urls if u.startswith(base_url)]
            idor_candidates = []
            for u in matching_urls:
                if self._numeric_param_candidates(u):
                    idor_candidates.append(u)
            
            for u in idor_candidates[:50]:
                findings = await self._check_idor(u, auth_headers, None)
                for f in findings:
                    self._add_finding(f)

        if self.probe_defaults:
            findings = await self._try_default_creds(base_url)
            for f in findings:
                self._add_finding(f)

        if self.probe_bypass:
            findings = await self._method_tampering(base_url)
            for f in findings:
                self._add_finding(f)
            findings = await self._path_bypass(base_url)
            for f in findings:
                self._add_finding(f)

        return self.findings

    def _base_url(self, url):
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    async def _request(self, method, url, headers=None, data=None):
        try:
            async with self._sem:
                r = await self.engine.ahttp_send(url, method=method, headers=headers or {}, data=data, state_context=self.session_manager)
            if not r: return None
            class DummyResp:
                def __init__(self, rdict):
                    self.status_code = rdict.get("status", 0)
                    self.headers = rdict.get("headers", {})
                    self.text = rdict.get("body", "")
                    self.content = self.text.encode() if self.text else b""
                    self.elapsed = rdict.get("time", 0)
            return DummyResp(r)
        except Exception as exc:
            print(f"[-] failed auth request {method} {url}: {exc}")
            return None

    def _session_headers(self, service_url):
        if not self.session_manager:
            return {}

        headers = {}
        parsed = urlparse(service_url)
        host = parsed.netloc
        hostname = parsed.hostname or host

        for key in [host, hostname]:
            token = getattr(self.session_manager, "auth_tokens", {}).get(key)
            if token:
                headers["Authorization"] = token
                break

        cookies = {}
        for key in [host, hostname]:
            cookies.update(getattr(self.session_manager, "cookies", {}).get(key, {}))
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        return headers

    async def _baseline_unauthenticated(self, base_url):
        results = {}
        fallback_resp = await self._request("GET", urljoin(base_url + "/", "__verd_snipe_spa_probe__"))
        root_resp = await self._request("GET", base_url + "/")
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = await self._request("GET", url)
            if resp:
                results[path] = resp
                if self._is_spa_fallback(resp, fallback_resp):
                    continue
                if root_resp and self._response_similarity(resp.text, root_resp.text) > 0.92:
                    continue
                if self._looks_sensitive_success(resp):
                    self._add_finding({
                        "type": "broken_auth",
                        "title": f"Unauthenticated Access: {path}",
                        "url": url,
                        "detail": f"Sensitive endpoint accessible without auth. Status: {resp.status_code}, Size: {len(resp.content)}b",
                        "waf": "",
                        "time": resp.elapsed,
                        "status": resp.status_code,
                        "confidence": "confirmed",
                    })
        return results

    async def _authenticated_requests(self, base_url, headers):
        results = {}
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url + "/", path.lstrip("/"))
            resp = await self._request("GET", url, headers=headers)
            if resp:
                results[path] = resp
        return results

    def _compare_authed_vs_unauth(self, base_url, unauth, authed):
        for path, auth_resp in authed.items():
            unauth_resp = unauth.get(path)
            if not unauth_resp:
                continue
            if not self._looks_sensitive_success(auth_resp):
                continue

            similarity = self._response_similarity(unauth_resp.text, auth_resp.text)
            if unauth_resp.status_code == auth_resp.status_code == 200 and similarity > 0.80:
                self._add_finding({
                    "type": "broken_access_control",
                    "title": f"Protected Data Exposed Without Auth: {path}",
                    "url": urljoin(base_url + "/", path.lstrip("/")),
                    "detail": f"Authenticated and unauthenticated responses are {similarity:.2f} similar.",
                    "waf": "",
                    "time": unauth_resp.elapsed,
                    "status": unauth_resp.status_code,
                    "confidence": "confirmed",
                })

    def _compare_privilege_escalation(self, base_url, authed1, authed2):
        for path, auth1_resp in authed1.items():
            auth2_resp = authed2.get(path)
            if not auth2_resp:
                continue
            if not self._looks_sensitive_success(auth1_resp):
                continue
            
            similarity = self._response_similarity(auth1_resp.text, auth2_resp.text)
            if auth1_resp.status_code == auth2_resp.status_code == 200 and similarity > 0.85:
                self._add_finding({
                    "type": "horizontal_privilege_escalation",
                    "title": f"Privilege Escalation: {path}",
                    "url": urljoin(base_url + "/", path.lstrip("/")),
                    "detail": f"User A and User B can access the exact same data. Similarity: {similarity:.2f}.",
                    "waf": "",
                    "time": auth2_resp.elapsed,
                    "status": auth2_resp.status_code,
                    "confidence": "confirmed",
                })

    def _response_similarity(self, body1, body2) -> float:
        first = re.sub(r"\s+", "", (body1 or "").lower())[:6000]
        second = re.sub(r"\s+", "", (body2 or "").lower())[:6000]
        if not first and not second:
            return 1.0
        if not first or not second:
            return 0.0
        # SequenceMatcher is a practical LCS-style ratio for scanner comparisons.
        return SequenceMatcher(None, first, second).ratio()

    def _is_spa_fallback(self, resp, fallback_resp) -> bool:
        if not resp or not fallback_resp:
            return False
        if resp.status_code != 200 or fallback_resp.status_code != 200:
            return False
        content_type = (resp.headers.get("content-type", "") or "").lower()
        if "html" not in content_type and not (resp.text or "").lstrip().lower().startswith("<!doctype html"):
            return False
        return self._response_similarity(resp.text, fallback_resp.text) > 0.97

    async def _check_idor(self, service_url, session, params) -> list:
        findings = []
        candidates = self._numeric_param_candidates(service_url)
        if params:
            candidates.extend(params)

        for param_name, original_value in candidates:
            original_url = service_url
            original_resp = await self._request("GET", original_url, headers=session)
            if not original_resp or original_resp.status_code != 200:
                continue

            for new_value in {original_value + 1, original_value + 100, max(original_value - 1, 0)}:
                if new_value == original_value:
                    continue
                test_url = self._replace_param_value(original_url, param_name, new_value)
                resp = await self._request("GET", test_url, headers=session)
                if not resp or resp.status_code != 200:
                    continue

                similarity = self._response_similarity(original_resp.text, resp.text)
                if similarity > 0.65 and self._body_has_sensitive_markers(resp.text):
                    findings.append({
                        "type": "idor_vulnerability",
                        "title": f"Possible IDOR: {param_name}",
                        "url": test_url,
                        "detail": f"Changed {param_name} from {original_value} to {new_value}; response similarity {similarity:.2f}.",
                        "waf": "",
                        "time": resp.elapsed,
                        "status": resp.status_code,
                        "confidence": "suspected",
                    })
                    break
        return findings

    def _numeric_param_candidates(self, url):
        parsed = urlparse(url)
        candidates = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() in NUMERIC_PARAM_NAMES and value.isdigit():
                candidates.append((key, int(value)))

        path_parts = parsed.path.strip("/").split("/")
        for idx, part in enumerate(path_parts):
            if part.isdigit():
                name = path_parts[idx - 1].rstrip("s") + "_id" if idx > 0 else "id"
                candidates.append((name, int(part)))
        return candidates

    def _replace_param_value(self, url, param_name, new_value):
        parsed = urlparse(url)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if query:
            updated = [(key, str(new_value) if key == param_name else value) for key, value in query]
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(updated), parsed.fragment))

        parts = parsed.path.strip("/").split("/")
        for idx, part in enumerate(parts):
            if part.isdigit():
                parts[idx] = str(new_value)
                break
        path = "/" + "/".join(parts)
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

    async def _try_default_creds(self, url) -> list:
        findings = []
        login_paths = ["/login", "/admin/login", "/wp-login.php", "/administrator", "/api/auth/login"]
        fail_words = ["invalid", "wrong", "failed", "incorrect", "denied", "unauthorized", "forbidden"]
        lockout_words = ["locked", "too many", "account disabled", "temporarily", "blocked"]

        for path in login_paths:
            login_url = urljoin(url.rstrip("/") + "/", path.lstrip("/"))
            probe = await self._request("GET", login_url)
            if not probe or probe.status_code not in (200, 401, 403):
                continue
            if probe.status_code == 200 and not re.search(r"login|username|password|email|sign in", probe.text, re.I):
                continue

            for username, password in DEFAULT_CREDS:
                # Minimum delay between credential attempts to avoid instant lockout
                await asyncio.sleep(1.0)

                data = f"username={quote(username)}&password={quote(password)}"
                resp = await self._request(
                    "POST",
                    login_url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=data,
                )
                if not resp:
                    continue

                # 429 = rate limited — abort this path immediately, don't cause lockout
                if resp.status_code == 429:
                    break

                body_lower = (resp.text or "").lower()

                # Account lockout detected — stop testing this endpoint
                if any(w in body_lower for w in lockout_words):
                    break

                if resp.status_code == 200 and not any(word in body_lower for word in fail_words):
                    findings.append({
                        "type": "broken_auth",
                        "title": f"Default Credentials: {username}:{password}",
                        "url": login_url,
                        "detail": f"Login accepted default credential candidate {username}:{password}",
                        "waf": "",
                        "time": resp.elapsed,
                        "status": resp.status_code,
                        "method": "POST",
                        "confidence": "suspected",
                    })
                    break
        return findings

    async def _method_tampering(self, base_url):
        findings = []
        for path in ["/admin", "/api/admin", "/dashboard", "/internal", "/config"]:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            baseline = await self._request("GET", url)
            if not baseline or baseline.status_code not in (401, 403, 405):
                continue
            for method in ["POST", "PUT", "DELETE"]:
                resp = await self._request(method, url)
                if resp and resp.status_code == 200 and self._looks_sensitive_success(resp):
                    findings.append({
                        "type": "auth_bypass",
                        "title": f"Method Tampering Bypass: {method} {path}",
                        "url": url,
                        "detail": f"GET returned {baseline.status_code}, {method} returned 200.",
                        "waf": "",
                        "time": resp.elapsed,
                        "status": resp.status_code,
                        "method": method,
                        "confidence": "confirmed",
                    })
                    break
        return findings

    async def _path_bypass(self, base_url):
        findings = []
        baseline = await self._request("GET", urljoin(base_url.rstrip("/") + "/", "admin"))
        if not baseline or baseline.status_code not in (401, 403, 404):
            return findings

        for path in PATH_BYPASSES:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self._request("GET", url)
            if resp and resp.status_code == 200 and self._looks_sensitive_success(resp):
                findings.append({
                    "type": "auth_bypass",
                    "title": f"Path Bypass: {path}",
                    "url": url,
                    "detail": f"Baseline /admin returned {baseline.status_code}, bypass returned 200.",
                    "waf": "",
                    "time": resp.elapsed,
                    "status": resp.status_code,
                    "confidence": "confirmed",
                })
                break
        return findings

    def _looks_sensitive_success(self, resp):
        if resp.status_code != 200 or len(resp.content or b"") < 60:
            return False
        body = (resp.text or "").lower()
        if re.search(r"login|sign in|sign-in|username|password|access denied|unauthorized|forbidden|not found|404|halaman tidak ditemukan|halaman tidak ada", body):
            return False
        return self._body_has_sensitive_markers(body)

    def _body_has_sensitive_markers(self, body):
        body = (body or "").lower()
        return any(marker in body for marker in SENSITIVE_BODY_MARKERS)

    def _add_finding(self, finding):
        key = (finding.get("type"), finding.get("url"), finding.get("title"), finding.get("detail", "")[:80])
        if key in self._seen:
            return False
        self._seen.add(key)
        self.findings.append(finding)
        if finding.get("confidence") == "confirmed":
            s(f"{R}AUTH:{N} {W}{finding['title']}{N}")
        return True
