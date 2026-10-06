# Re-export for backward compatibility
from .scanner import VulnVerifier, AsyncVulnEngine, HeuristicVulnEngine

__all__ = ["VulnVerifier", "AsyncVulnEngine", "HeuristicVulnEngine"]
