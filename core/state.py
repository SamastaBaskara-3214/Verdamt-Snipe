import threading
from typing import Dict, List, Any
from urllib.parse import urlparse

# Multi-part public suffixes for the eTLD+1 sibling heuristic in
# inject_auth (api.x vs www.x share no parent-child relation).
_MULTI_PART_TLD = frozenset({
    "co.uk", "com.au", "co.id", "net.id", "or.id", "web.id", "ac.id",
    "sch.id", "go.id", "mil.id", "biz.id", "my.id",
    "com.br", "co.jp", "co.in", "com.sg", "com.my", "co.nz", "co.za",
    "com.mx", "com.tr", "com.tw", "com.hk", "com.cn", "com.ar", "com.pl",
})

class SessionManager:
    """
    Manages complex application states, tokens, and cookies across multi-step workflows.
    Bridges the gap between Playwright's headless discovery and the Async HTTP fuzzer.
    """
    def __init__(self):
        self._lock = threading.Lock()
        self.auth_tokens: Dict[str, str] = {}  # domain -> bearer token
        self.cookies: Dict[str, Dict[str, str]] = {} # domain -> cookie dict
        self.local_storage: Dict[str, Dict[str, Any]] = {}
        
    def register_token(self, domain: str, token_type: str, token_value: str):
        """Register an extracted token (e.g., from Playwright's network interceptor)."""
        clean_domain = domain.strip().lower()
        with self._lock:
            if token_type.lower() == "bearer":
                self.auth_tokens[clean_domain] = f"Bearer {token_value}"
            elif token_type.lower() == "basic":
                self.auth_tokens[clean_domain] = f"Basic {token_value}"

    def update_cookies(self, domain: str, new_cookies: Dict[str, str]):
        clean_domain = domain.strip().lower()
        with self._lock:
            if clean_domain not in self.cookies:
                self.cookies[clean_domain] = {}
            self.cookies[clean_domain].update(new_cookies)

    def inject_auth(self, url: str, headers: dict):
        """Inject stored auth tokens/cookies into headers for a given URL.

        Lookup: exact hostname -> suffix match either direction (www.x vs x
        vs api.x). Exact-only here silently sent UNAUTHENTICATED requests
        whenever seed host != service host (verified REAL, 2026-10-06).
        Deliberately NO sorted-first fallback (unlike auth_headers_for):
        never attach another domain's credentials."""
        domain = urlparse(url).hostname or urlparse(url).netloc

        def _match(mapping):
            if not mapping:
                return None
            host = (domain or "").strip().lower()
            if host and host in mapping:
                return mapping[host]
            for key in sorted(mapping):
                k = key.lower().split(":")[0]
                if host and (host.endswith("." + k) or k.endswith("." + host)):
                    return mapping[key]
            # Sibling hosts under the same registrable domain
            # (api.example.com vs www.example.com): parent-child suffix
            # matching cannot relate them — compare eTLD+1 instead.
            if host:
                parts = host.split(".")
                e = (".".join(parts[-3:])
                     if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_PART_TLD
                     else ".".join(parts[-2:]))
                if "." in e:
                    for key in sorted(mapping):
                        k = key.lower().split(":")[0]
                        kp = k.split(".")
                        ke = (".".join(kp[-3:])
                              if len(kp) >= 3 and ".".join(kp[-2:]) in _MULTI_PART_TLD
                              else ".".join(kp[-2:]))
                        if ke == e:
                            return mapping[key]
            return None

        with self._lock:
            auth_token = _match(self.auth_tokens)
            cookie_dict = _match(self.cookies)

        # Inject Bearer/Auth Token
        if auth_token:
            if "Authorization" not in headers:
                headers["Authorization"] = auth_token

        # Inject Cookies
        if cookie_dict:
            cookie_str = "; ".join([f"{k}={v}" for k, v in cookie_dict.items()])
            if "Cookie" in headers:
                headers["Cookie"] += f"; {cookie_str}"
            else:
                headers["Cookie"] = cookie_str

    def auth_headers_for(self, domain: str) -> Dict[str, str]:
        """Authorization + Cookie headers best matching domain.

        Lookup order: exact key -> suffix match (either direction) -> sorted
        first entry. Never raw dict-iteration order (the old callers took
        whichever token happened to come first/last, silently authenticating
        every target with the wrong domain's credentials).
        """
        host = (domain or "").strip().lower().split(":")[0]

        def _best(mapping):
            if not mapping:
                return None
            if host and host in mapping:
                return mapping[host]
            for key in sorted(mapping):
                k = key.lower().split(":")[0]
                if host and (host.endswith("." + k) or k.endswith("." + host)):
                    return mapping[key]
            return mapping[sorted(mapping)[0]]

        with self._lock:
            token = _best(self.auth_tokens)
            cookie_dict = _best(self.cookies)

        headers = {}
        if token:
            headers["Authorization"] = token
        if cookie_dict:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie_dict.items())
        return headers
