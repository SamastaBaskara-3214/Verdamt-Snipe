"""
Wordlist Manager — Auto-detect local wordlists, fallback download from SecLists/Assetnote.
"""
import asyncio
import os
import gzip
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.request import urlopen
from urllib.error import URLError

from core.ui import i, s, w, p, ph, Spinner, G, R, Y, C, W, N, B


# Config

WORDLIST_DIR = os.path.expanduser("~/.wordlists")

# Source URLs (small/medium wordlists for quick download)
_SOURCES = {
    "common.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "size_hint": "50KB",
        "entries_hint": "~4,600",
    },
    "directories_small.txt": {
        "url": "https://wordlists-cdn.assetnote.io/data/manual/dicc.txt",
        "size_hint": "200KB",
        "entries_hint": "~18,000",
    },
    "_auth.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-PHP-Filenames.txt",
        "size_hint": "10KB",
        "entries_hint": "~500",
    },
    "_extensions.txt": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Extensions.txt",
        "size_hint": "5KB",
        "entries_hint": "~200",
    },
}

# Common local wordlist locations
_LOCAL_PATHS = [
    os.path.expanduser("~/.wordlists"),
    "/usr/share/wordlists",
    "/usr/share/dirb/wordlists",
    "/usr/share/seclists/Discovery/Web-Content",
    "/usr/share/assetnote/data",
]

# Embedded fallback (if no download possible)
_FALLBACK_DIRS = [
    "admin", "api", "v1", "v2", "backup", "config", "debug", "dev",
    "health", "info", "internal", "logs", "metrics", "monitor", "prod",
    "status", "test", "tools", "upload", "download", "export", "import",
    "graphql", "docs", "swagger", "api-docs", "openapi.json", ".env",
    ".git", ".git/config", ".git/HEAD", ".DS_Store", "sitemap.xml",
    "robots.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    "wp-admin", "wp-content", "wp-includes", "administrator",
    "phpmyadmin", "pma", "mysql", "dbadmin", "adminer",
    "login", "portal", "dashboard", "panel", "console", "manager", "webadmin",
    "api/v1", "api/v2", "api/v3", "api/health", "api/status",
    "api/users", "api/admin", "api/config", "api/internal",
    "api/metrics", "api/logs", "api/debug", "api/graphql",
    ".aws", ".azure", ".gcp", "credentials", "secret",
    "jenkins", "kibana", "grafana", "prometheus", "elasticsearch",
    "s3", "bucket", "storage", "cdn", "assets",
    "deploy", "staging", "prod", "beta", "release",
    "webhook", "callback", "notify", "notification", "mail",
    "ws", "websocket", "socket.io", "sockjs",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/metrics", "actuator/beans", "actuator/mappings",
    "user", "admin", "moderator", "superadmin",
    "index.php", "index.html", "default.aspx",
    "register", "signup", "login", "signin",
    "forgot", "reset", "forgot-password", "reset-password",
    "oauth", "oauth2", "oauth/callback", "oauth/token",
    "api/login", "api/register", "api/auth",
    "admin/login", "admin/dashboard",
]

_FALLBACK_AUTH = [
    "login", "signin", "auth", "oauth", "oauth2", "oauth/callback",
    "token", "api/token", "auth/token", "oauth/token",
    "register", "signup", "create-account",
    "forgot-password", "reset-password", "forgot", "reset",
    "logout", "signout", "revoke", "deauthorize",
    "api/login", "api/signin", "api/auth", "api/register",
    "api/forgot", "api/reset", "api/token/refresh",
    "admin/login", "admin/auth", "administrator/login",
    "user/login", "user/auth", "user/profile",
    "graphql", "api/graphql", "graph", "api/graph",
    "oauth/authorize", "oauth/token", "oauth/revoke",
]

# Scanner

def scan_local_wordlists() -> Dict[str, str]:
    """Scan common locations for existing wordlist files.
    
    Returns: {category: filepath} for found wordlists.
    """
    found = {}
    for base_dir in _LOCAL_PATHS:
        if not os.path.isdir(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            for f in files:
                if not f.endswith(".txt"):
                    continue
                fp = os.path.join(root, f)
                fname = f.lower()

                # Categorize by filename patterns
                if any(k in fname for k in ["common", "directory", "dir", "discovery", "path"]):
                    if "dir" not in found or len(open(fp, errors="ignore").read(1000)) > len(open(found.get("dir", fp), errors="ignore").read(1000)):
                        found["dir"] = fp
                if any(k in fname for k in ["auth", "login", "admin"]):
                    found.setdefault("auth", fp)
                if any(k in fname for k in ["extension", "ext"]):
                    found.setdefault("extension", fp)
                if any(k in fname for k in ["subdomain", "sub"]):
                    found.setdefault("subdomain", fp)
                if any(k in fname for k in ["param", "parameter"]):
                    found.setdefault("param", fp)
    return found


def count_entries(filepath: str) -> int:
    """Count non-empty lines in a wordlist file."""
    try:
        with open(filepath, "r", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def load_words(filepath: str, limit: int = 0) -> List[str]:
    """Load words from a file, optionally limited."""
    words = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    words.append(word)
                    if limit and len(words) >= limit:
                        break
    except Exception:
        pass
    return words


# Downloader

def download_wordlist(name: str, force: bool = False) -> Optional[str]:
    """Download a wordlist from predefined sources. Returns path or None."""
    source = _SOURCES.get(name)
    if not source:
        return None

    dest = os.path.join(WORDLIST_DIR, name)
    if os.path.exists(dest) and not force:
        return dest  # Already have it

    os.makedirs(WORDLIST_DIR, exist_ok=True)
    url = source["url"]

    try:
        i(f"Downloading {C}{name}{N} ({source['size_hint']})...")
        with urlopen(url, timeout=30) as resp:
            data = resp.read()
            # Handle gzipped responses
            if resp.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            # Handle raw .gz files
            if name.endswith(".gz"):
                data = gzip.decompress(data)
                name = name[:-3]  # Remove .gz
                dest = os.path.join(WORDLIST_DIR, name)

        with open(dest, "wb") as f:
            f.write(data)

        entries = count_entries(dest)
        s(f"Downloaded {C}{name}{N} ({G}{entries}{N} entries)")
        return dest
    except (URLError, Exception) as e:
        w(f"Download failed: {e}")
        return None


async def auto_setup_wordlists(force: bool = False) -> Dict[str, str]:
    """Auto-detect local wordlists, download missing ones."""
    ph("WORDLIST MANAGER: Setup")
    os.makedirs(WORDLIST_DIR, exist_ok=True)

    # Scan what we already have
    local = scan_local_wordlists()
    if local:
        for cat, fp in local.items():
            s(f"Found {C}{cat}{N}: {G}{fp}{N} ({count_entries(fp)} entries)")

    # Download missing assets
    needed = []
    if "dir" not in local:
        needed.extend(["common.txt", "directories_small.txt"])
    if "auth" not in local:
        needed.append("_auth.txt")
    if "extension" not in local:
        needed.append("_extensions.txt")

    if needed:
        p(f"Downloading {len(needed)} wordlist(s)...")
        for name in needed:
            path = download_wordlist(name, force=force)
            if path:
                cat = "dir" if "directory" in name or "common" in name else \
                      "auth" if "auth" in name else \
                      "extension" if "ext" in name else "misc"
                local[cat] = path

    # Re-scan to include newly downloaded
    if not local:
        local = scan_local_wordlists()

    if local:
        total = sum(count_entries(p) for p in local.values())
        s(f"{G}Wordlists ready:{N} {len(local)} files, {total} total entries")
    else:
        w("No wordlists available — using embedded fallback")

    return local


# Integration API

class WordlistProvider:
    """Provides wordlists for bruteforce phases — auto-selects best available."""

    def __init__(self):
        self._local = {}
        self._scanned = False

    def scan(self):
        if not self._scanned:
            self._local = scan_local_wordlists()
            self._scanned = True
        return self._local

    def get_dir_wordlist(self, wave: int = 1, limit: int = 0) -> List[str]:
        """Get directory bruteforce wordlist. Returns list of words."""
        self.scan()
        path = self._local.get("dir", "")
        if path and os.path.exists(path):
            # Wave mutation: further down the list each wave
            offset = (wave - 1) * 200
            words = load_words(path, limit=(limit or 5000))
            if offset > 0:
                words = words[offset:] + words[:min(offset, len(words))]
            return words[:max(limit, 3000)] if limit else words
        return _FALLBACK_DIRS  # Embedded fallback

    def get_auth_wordlist(self, wave: int = 1, limit: int = 0) -> List[str]:
        """Get auth/endpoint bruteforce wordlist. Returns list of words.

        Rotates by wave like the dir wordlist — otherwise every wave re-sends
        the identical N requests (dead work, same budget spent).
        """
        self.scan()
        path = self._local.get("auth", "")
        if path and os.path.exists(path):
            words = load_words(path, limit=(limit or 1000))
            if wave > 1 and words:
                offset = ((wave - 1) * 100) % len(words)
                words = words[offset:] + words[:offset]
            return words
        return _FALLBACK_AUTH

    def get_extension_wordlist(self) -> List[str]:
        """Get file extension wordlist."""
        self.scan()
        path = self._local.get("extension", "")
        if path and os.path.exists(path):
            return load_words(path, limit=50)
        return [".php", ".asp", ".aspx", ".jsp", ".json", ".yml", ".yaml", ".xml", ".bak", ".old", ".txt"]

    def summary(self) -> str:
        """Return human-readable wordlist status."""
        self.scan()
        if not self._local:
            return f"{R}No wordlists found{N} — using {len(_FALLBACK_DIRS)} embedded entries"
        parts = []
        for cat, path in sorted(self._local.items()):
            parts.append(f"{C}{cat}{N}:{G}{count_entries(path)}{N}")
        return f"{G}Wordlist{N}: {' | '.join(parts)}"


# Singleton
PROVIDER = WordlistProvider()
