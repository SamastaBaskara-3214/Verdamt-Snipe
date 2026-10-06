# Re-export for backward compatibility
from .crawler import DeepCrawler
from .dom_xss import DOMXSSScanner
from .api_profiler import APIProfiler
from .browser_recon import BrowserRecon

__all__ = ["DeepCrawler", "DOMXSSScanner", "APIProfiler", "BrowserRecon"]
