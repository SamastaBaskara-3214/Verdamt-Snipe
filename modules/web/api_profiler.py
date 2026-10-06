import json
import re
import asyncio
from difflib import SequenceMatcher
from urllib.parse import urlparse

from core.ui import C, G, N, R, W, draw_table, i, p, ph


AUTH_DENY_RE = re.compile(
    r"unauthorized|forbidden|access denied|not authenticated|login required|invalid token|missing token",
    re.I,
)

SENSITIVE_KEYS = {
    "email", "role", "roles", "permission", "permissions", "token", "secret",
    "api_key", "apikey", "password", "admin", "user", "users", "account",
    "accounts", "quota", "balance", "command", "stats", "id",
}

HIGH_IMPACT_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "credential", "credentials", "session",
}

IDENTITY_KEYS = {"email", "role", "roles", "permission", "permissions", "user", "users", "account", "accounts"}

INTERESTING_PATH_MARKERS = (
    "/api", "/graphql", "/admin", "/internal", "/debug", "/swagger", "/openapi",
)


class APIProfiler:
    """Probe discovered app endpoints and promote concrete API evidence."""

    def __init__(self, urls, threads=10, network_engine=None, auth_headers=None, session_manager=None):
        self.urls = sorted(set(urls or []))
        self.threads = threads
        self.engine = network_engine
        self.auth_headers = auth_headers or {}
        self.session_manager = session_manager
        self.findings = []
        self._sem = asyncio.Semaphore(self.threads)

    async def run(self):
        targets = [u for u in self.urls if self._interesting(u)]
        if not targets:
            return []

        ph("API PROFILER: Concrete Endpoint Evidence")
        auth_note = " with auth context" if self.auth_headers else ""
        i(f"Profiling {W}{len(targets)}{N} app/API endpoints{auth_note}")

        tasks = [self._profile_url(url) for url in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                p(f"[!] APIProfiler worker error: {r}")

        if self.findings:
            rows = []
            for f in self.findings[:20]:
                rows.append([
                    f"{R if f.get('cvss_severity') in ['High', 'Medium'] else C}{f.get('cvss_severity', 'Info')}",
                    f"{W}{f['title'][:44]}",
                    f"{C}{f['url'][:58]}",
                ])
            draw_table(["SEV", "EVIDENCE", "URL"], rows, title="API Evidence")

        p(f"API findings: {G}{len(self.findings)}")
        return self.findings

    def _interesting(self, url):
        path = urlparse(url).path.lower()
        return any(marker in path for marker in INTERESTING_PATH_MARKERS)

    async def _profile_url(self, url):
        get_resp = await self._request("GET", url)
        if not get_resp or get_resp.status_code <= 0:
            return
        auth_resp = await self._request("GET", url, headers=self.auth_headers) if self.auth_headers else None

        options_resp = await self._request("OPTIONS", url)
        allow = self._allowed_methods(options_resp)
        evidence = self._classify_response(get_resp)
        parsed_json = evidence["json"]
        path = urlparse(url).path.lower()

        self._add_endpoint_profile(url, get_resp, allow, evidence)
        if auth_resp:
            self._compare_auth_context(url, get_resp, auth_resp)

        if "/graphql" in path:
            await self._check_graphql_introspection(url)

        if self._is_schema_endpoint(path, get_resp.text or "", parsed_json):
            self._add({
                "type": "api_schema_exposed",
                "title": "API Schema Exposed",
                "url": url,
                "detail": f"Status {get_resp.status_code}; OpenAPI/Swagger-like schema is reachable.",
                "status": get_resp.status_code,
                "confidence": "confirmed",
                "cvss_score": 5.3,
                "cvss_severity": "Medium",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            })

        if self._is_real_public_data(evidence):
            if "/admin" in path or "/internal" in path:
                self._add({
                    "type": "public_admin_api",
                    "title": "Unauthenticated Admin/Internal API",
                    "url": url,
                    "detail": self._detail(get_resp, evidence, allow, impact="Unauthenticated users can read admin/internal API data."),
                    "status": get_resp.status_code,
                    "confidence": "confirmed",
                    "cvss_score": 8.1,
                    "cvss_severity": "High",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                })
            elif evidence["sensitivity"] >= 2:
                self._add({
                    "type": "unauthenticated_api_data",
                    "title": "Unauthenticated API Data Exposure",
                    "url": url,
                    "detail": self._detail(get_resp, evidence, allow, impact="Unauthenticated users can read data-bearing API response."),
                    "status": get_resp.status_code,
                    "confidence": "confirmed",
                    "cvss_score": 6.5,
                    "cvss_severity": "Medium",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                })

        dangerous = sorted(set(allow) & {"PUT", "PATCH", "DELETE"})
        if dangerous and any(x in path for x in ["/admin", "/internal", "/api"]):
            self._add({
                "type": "dangerous_methods_allowed",
                "title": "Dangerous HTTP Methods Advertised",
                "url": url,
                "detail": f"Allow header includes: {', '.join(dangerous)}",
                "status": options_resp.status_code if options_resp else 0,
                "confidence": "suspected",
                "cvss_score": 3.7,
                "cvss_severity": "Low",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            })

    async def _request(self, method, url, **kwargs):
        try:
            headers = kwargs.pop("headers", {}) or {}
            json_data = kwargs.pop("json", None)
            async with self._sem:
                if json_data:
                    import json as json_lib
                    r = await self.engine.ahttp_send(url, method=method, headers=headers, data=json_lib.dumps(json_data), state_context=self.session_manager, **kwargs)
                else:
                    r = await self.engine.ahttp_send(url, method=method, headers=headers, state_context=self.session_manager, **kwargs)
            
            if not r:
                return None
                
            class DummyResp:
                def __init__(self, rdict):
                    self.status_code = rdict.get("status", 0)
                    self.headers = rdict.get("headers", {})
                    self.text = rdict.get("body", "")
                    self.content = self.text.encode() if self.text else b""
                    self.elapsed = rdict.get("time", 0)
            return DummyResp(r)
        except Exception:
            return None

    def _allowed_methods(self, resp):
        if not resp:
            return []
        allow = resp.headers.get("allow") or resp.headers.get("access-control-allow-methods") or ""
        return [m.strip().upper() for m in allow.split(",") if m.strip()]

    def _parse_json(self, body, content_type):
        if "json" not in (content_type or "").lower() and not (body or "").strip().startswith(("{", "[")):
            return None
        try:
            return json.loads(body)
        except Exception:
            return None


    def _is_real_public_data(self, evidence):
        if evidence["status"] not in (200, 201, 202):
            return False
        if evidence["auth_denied"] or evidence["spa_fallback"] or evidence["empty"]:
            return False
        return evidence["kind"] == "json_sensitive" and evidence["sensitivity"] >= 2

    def _compare_auth_context(self, url, unauth_resp, auth_resp):
        auth_evidence = self._classify_response(auth_resp)
        unauth_evidence = self._classify_response(unauth_resp)
        auth_has_data = self._is_real_public_data(auth_evidence)
        unauth_denied = unauth_evidence["auth_denied"] or unauth_resp.status_code in (401, 403)
        auth_ok = auth_resp.status_code in (200, 201, 202)
        similarity = self._response_similarity(unauth_resp.text, auth_resp.text)

        if auth_ok and unauth_denied:
            self._add({
                "type": "protected_api_endpoint",
                "title": f"Protected API Endpoint: {urlparse(url).path or '/'}",
                "url": url,
                "detail": f"Guest is denied, authenticated request returns data. Auth keys={auth_evidence['keys']}; Impact: confirms this endpoint is protected, not a vulnerability by itself.",
                "status": auth_resp.status_code,
                "confidence": "confirmed",
                "cvss_score": 0.0,
                "cvss_severity": "Info",
                "cvss_vector": "N/A",
            })
            return

        if auth_has_data and self._is_real_public_data(unauth_evidence) and similarity > 0.96:
            severity = "High" if any(x in urlparse(url).path.lower() for x in ["/admin", "/internal"]) else "Medium"
            self._add({
                "type": "auth_data_publicly_accessible",
                "title": "Authenticated API Data Also Public",
                "url": url,
                "detail": f"Auth and guest responses are {similarity:.2f} similar; keys={auth_evidence['keys']}; Impact: protected data appears reachable without authentication.",
                "status": unauth_resp.status_code,
                "confidence": "confirmed",
                "cvss_score": 8.1 if severity == "High" else 6.5,
                "cvss_severity": severity,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            })
            return

        if auth_has_data and unauth_resp.status_code in (200, 201, 202) and similarity < 0.80:
            self._add({
                "type": "api_auth_delta",
                "title": f"API Auth Response Delta: {urlparse(url).path or '/'}",
                "url": url,
                "detail": f"Guest {unauth_resp.status_code}, auth {auth_resp.status_code}, similarity {similarity:.2f}; auth keys={auth_evidence['keys']}; Impact: useful auth boundary evidence for manual review.",
                "status": auth_resp.status_code,
                "confidence": "confirmed",
                "cvss_score": 0.0,
                "cvss_severity": "Info",
                "cvss_vector": "N/A",
            })

    def _response_similarity(self, body1, body2):
        first = re.sub(r"\s+", "", (body1 or "").lower())[:8000]
        second = re.sub(r"\s+", "", (body2 or "").lower())[:8000]
        if not first and not second:
            return 1.0
        if not first or not second:
            return 0.0
        return SequenceMatcher(None, first, second).ratio()

    def _json_keys(self, value):
        if isinstance(value, dict):
            return sorted(str(k) for k in list(value.keys())[:12])
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return sorted(str(k) for k in list(value[0].keys())[:12])
        return []

    def _classify_response(self, resp):
        body = resp.text or ""
        content_type = resp.headers.get("content-type", "")
        parsed_json = self._parse_json(body, content_type)
        keys = self._json_keys(parsed_json)
        sensitive_keys = self._collect_sensitive_keys(parsed_json)
        high_impact_keys = sorted(set(sensitive_keys) & HIGH_IMPACT_KEYS)
        identity_keys = sorted(set(sensitive_keys) & IDENTITY_KEYS)
        auth_denied = resp.status_code in (401, 403) or bool(AUTH_DENY_RE.search(body))
        empty = len(body.strip()) == 0 or resp.status_code in (204, 304)
        spa_fallback = self._looks_like_spa_shell(body, content_type)
        sensitivity = 0
        if high_impact_keys:
            sensitivity = 3
        elif identity_keys:
            sensitivity = 2
        elif sensitive_keys:
            sensitivity = 1

        if auth_denied:
            kind = "auth_denied"
        elif empty:
            kind = "empty"
        elif spa_fallback:
            kind = "spa_fallback"
        elif parsed_json is not None and sensitivity >= 2:
            kind = "json_sensitive"
        elif parsed_json is not None:
            kind = "json_public"
        elif "html" in content_type.lower() or body.lstrip().lower().startswith("<!doctype html"):
            kind = "html"
        else:
            kind = "text"

        return {
            "status": resp.status_code,
            "kind": kind,
            "json": parsed_json,
            "keys": keys,
            "sensitive_keys": sorted(set(sensitive_keys)),
            "high_impact_keys": high_impact_keys,
            "identity_keys": identity_keys,
            "sensitivity": sensitivity,
            "auth_denied": auth_denied,
            "empty": empty,
            "spa_fallback": spa_fallback,
            "content_type": content_type,
            "preview": self._preview(body),
        }

    def _looks_like_spa_shell(self, body, content_type):
        lower = (body or "").lower()
        if "html" not in (content_type or "").lower() and not lower.lstrip().startswith("<!doctype html"):
            return False
        return (
            "<div id=\"root\"" in lower
            or "<div id='root'" in lower
            or "/assets/index-" in lower
            or "type=\"module\"" in lower and "<script" in lower
        )

    def _collect_sensitive_keys(self, value, depth=0):
        found = []
        if depth > 5:
            return found
        if isinstance(value, dict):
            for key, item in value.items():
                lower = str(key).lower()
                if lower in SENSITIVE_KEYS or any(marker in lower for marker in ["token", "secret", "admin", "permission", "credential"]):
                    found.append(lower)
                found.extend(self._collect_sensitive_keys(item, depth + 1))
        elif isinstance(value, list):
            for item in value[:10]:
                found.extend(self._collect_sensitive_keys(item, depth + 1))
        return found

    def _json_has_sensitive_keys(self, value, depth=0):
        if depth > 4:
            return False
        if isinstance(value, dict):
            for key, item in value.items():
                lower = str(key).lower()
                if lower in SENSITIVE_KEYS or any(marker in lower for marker in ["token", "secret", "admin", "permission"]):
                    return True
                if self._json_has_sensitive_keys(item, depth + 1):
                    return True
        elif isinstance(value, list):
            return any(self._json_has_sensitive_keys(item, depth + 1) for item in value[:10])
        return False

    def _is_schema_endpoint(self, path, body, parsed_json):
        if any(x in path for x in ["/swagger", "/openapi", "/api/docs"]):
            return True
        if isinstance(parsed_json, dict):
            return "openapi" in parsed_json or "swagger" in parsed_json or "paths" in parsed_json
        return "openapi" in (body or "").lower() and "\"paths\"" in (body or "").lower()

    async def _check_graphql_introspection(self, url):
        payload = {"query": "{__schema{queryType{name} mutationType{name} types{name}}}"}
        resp = await self._request("POST", url, headers={"Content-Type": "application/json"}, json=payload)
        if not resp or resp.status_code not in (200, 400):
            return
        if "__schema" in (resp.text or "") and "types" in (resp.text or ""):
            self._add({
                "type": "graphql_introspection",
                "title": "GraphQL Introspection Enabled",
                "url": url,
                "detail": f"Introspection query returned schema data. Status {resp.status_code}.",
                "status": resp.status_code,
                "confidence": "confirmed",
                "cvss_score": 5.3,
                "cvss_severity": "Medium",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            })

    def _add_endpoint_profile(self, url, resp, allow, evidence):
        self._add({
            "type": "api_endpoint",
            "title": f"API Endpoint: {urlparse(url).path or '/'}",
            "url": url,
            "detail": (
                f"GET {resp.status_code}; kind={evidence['kind']}; methods={','.join(allow) or 'unknown'}; "
                f"keys={evidence['keys']}; sensitive_keys={evidence['sensitive_keys']}; preview={evidence['preview']}"
            ),
            "status": resp.status_code,
            "confidence": "confirmed",
            "cvss_score": 0.0,
            "cvss_severity": "Info",
            "cvss_vector": "N/A",
        })

    def _detail(self, resp, evidence, allow, impact=""):
        suffix = f" Impact: {impact}" if impact else ""
        return (
            f"GET {resp.status_code}; kind={evidence['kind']}; keys={evidence['keys']}; "
            f"sensitive_keys={evidence['sensitive_keys']}; methods={','.join(allow) or 'unknown'}; "
            f"preview={evidence['preview']}.{suffix}"
        )

    def _preview(self, body):
        return re.sub(r"\s+", " ", (body or ""))[:180]

    def _add(self, finding):
        key = (finding.get("type"), finding.get("url"), finding.get("title"))
        if key in {(f.get("type"), f.get("url"), f.get("title")) for f in self.findings}:
            return
        finding.setdefault("waf", "")
        finding.setdefault("time", 0)
        self.findings.append(finding)
