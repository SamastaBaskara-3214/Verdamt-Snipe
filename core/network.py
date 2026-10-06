"""Re-export from core.client. Original was merged into core/client.py."""
from .client import GhostMode, http_send, thttp, dns_resolve, TIMEOUT

__all__ = ["GhostMode", "http_send", "thttp", "dns_resolve", "TIMEOUT"]
