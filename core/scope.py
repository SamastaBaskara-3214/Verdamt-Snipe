from urllib.parse import urljoin, urlparse, urlunparse


STATIC_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp4", ".webm", ".avi", ".zip", ".tar", ".gz",
)


class ScopeGuard:
    """Keep recon and scanning anchored to the intended target scope."""

    def __init__(self, root_host: str, include_subdomains: bool = True):
        self.root_host = self._clean_host(root_host)
        self.include_subdomains = include_subdomains

    @staticmethod
    def _clean_host(host: str) -> str:
        return (host or "").strip().lower().rstrip(".")

    def host_in_scope(self, host: str) -> bool:
        host = self._clean_host(host)
        if not host:
            return False
        if host == self.root_host:
            return True
        return self.include_subdomains and host.endswith(f".{self.root_host}")

    def canonical_url(self, raw_url: str, base_url: str = None) -> str:
        if not raw_url:
            return ""

        url = str(raw_url).strip()
        if base_url:
            url = urljoin(base_url, url)
        elif url.startswith("//"):
            url = f"https:{url}"
        elif not urlparse(url).scheme:
            return ""

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return ""
        if not self.host_in_scope(parsed.hostname):
            return ""

        netloc = self._clean_host(parsed.hostname)
        if parsed.port:
            if not ((parsed.scheme.lower() == "https" and parsed.port == 443) or 
                    (parsed.scheme.lower() == "http" and parsed.port == 80)):
                netloc = f"{netloc}:{parsed.port}"

        path = parsed.path or "/"
        if path == "/":
            path = ""

        return urlunparse((
            parsed.scheme.lower(),
            netloc,
            path,
            "",
            parsed.query,
            "",
        ))

    def filter_urls(self, urls, base_url: str = None, keep_static: bool = True):
        kept = set()
        for raw_url in urls or []:
            url = self.canonical_url(raw_url, base_url=base_url)
            if not url:
                continue
            if not keep_static and urlparse(url).path.lower().endswith(STATIC_EXTENSIONS):
                continue
            kept.add(url)
        return sorted(kept)
