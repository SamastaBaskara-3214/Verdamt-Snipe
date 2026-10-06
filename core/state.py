import threading
from typing import Dict, List, Any
from urllib.parse import urlparse

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
        """Inject stored auth tokens/cookies into headers for a given URL."""
        domain = urlparse(url).hostname or urlparse(url).netloc

        with self._lock:
            auth_token = self.auth_tokens.get(domain)
            cookie_dict = self.cookies.get(domain)

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
