# Re-export for backward compatibility
from .recon_crawlers.crawler import DeepCrawler
from .client_side.dom_xss import DOMXSSScanner
from .recon_crawlers.api_profiler import APIProfiler
from .recon_crawlers.browser_recon import BrowserRecon

__all__ = ["DeepCrawler", "DOMXSSScanner", "APIProfiler", "BrowserRecon"]
