"""Re-export from core.client. Original was merged into core/client.py."""
from .client import HTTPClient, HTTPResponse, DEFAULT_HEADERS

__all__ = ["HTTPClient", "HTTPResponse", "DEFAULT_HEADERS"]
