"""Path Obfuscation — Randomize scan path order, mix benign + scan requests.

Instead of scanning paths in predictable order:
    /admin → /backup → /config → /.env  (obvious scanner pattern)

Randomize and interleave:
    / → /about → /.env → /contact → /admin → /help → /backup  (looks human)

Also applies to parameter fuzzing order and payload delivery.

Usage:
    from core.path_obfuscator import PathObfuscator

    obf = PathObfuscator()
    
    # Randomize path list
    paths = obf.shuffle_paths(["/admin", "/backup", "/.env", "/config"])
    
    # Mix with benign paths
    mixed = obf.mix_with_benign(paths, ratio=0.3)  # 30% benign, 70% scan
    
    # Generate randomized scan schedule
    schedule = obf.generate_schedule(scan_paths, benign_ratio=0.3, delay_range=(0.5, 2.0))
"""

import random
import time
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urljoin, urlencode


# Common benign paths to mix in
BENIGN_PATHS = [
    "/",
    "/about",
    "/contact",
    "/help",
    "/faq",
    "/privacy",
    "/terms",
    "/sitemap",
    "/robots.txt",
    "/login",
    "/search",
    "/news",
    "/blog",
    "/services",
    "/products",
]

# Common scan paths (for reference)
SCAN_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/backup",
    "/backup.sql",
    "/config",
    "/config.php",
    "/database",
    "/db",
    "/debug",
    "/deploy",
    "/dev",
    "/.env",
    "/.git",
    "/.git/config",
    "/.htaccess",
    "/info.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/shell",
    "/test",
    "/tmp",
    "/upload",
    "/uploads",
    "/wp-admin",
    "/wp-config.php",
    "/wp-login.php",
]


class PathObfuscator:
    """Obfuscate scan path ordering to look human."""

    def __init__(self, benign_paths: List[str] = None):
        self.benign_paths = benign_paths or BENIGN_PATHS

    def shuffle_paths(self, paths: List[str]) -> List[str]:
        """Randomize order of scan paths.
        
        Prevents predictable alphabetical/sequential scanning pattern.
        """
        shuffled = list(paths)
        random.shuffle(shuffled)
        return shuffled

    def mix_with_benign(
        self,
        scan_paths: List[str],
        ratio: float = 0.3,
    ) -> List[str]:
        """Mix scan paths with benign paths.
        
        Args:
            scan_paths: Paths to scan
            ratio: Fraction of benign paths (0.3 = 30% benign)
        
        Returns:
            Mixed list with benign paths interleaved
        """
        num_benign = max(1, int(len(scan_paths) * ratio))
        benign = random.sample(self.benign_paths, min(num_benign, len(self.benign_paths)))
        
        # Merge and shuffle
        combined = list(scan_paths) + benign
        random.shuffle(combined)
        return combined

    def generate_schedule(
        self,
        scan_paths: List[str],
        base_url: str = "",
        benign_ratio: float = 0.3,
        delay_range: Tuple[float, float] = (0.5, 2.0),
        burst_size: int = 3,
        burst_pause: float = (5.0, 15.0),
    ) -> List[Dict]:
        """Generate a human-like scan schedule.
        
        Instead of scanning continuously, creates bursts with pauses:
            scan 3 paths → pause 5-15s → scan 3 paths → pause → ...
        
        Args:
            scan_paths: Paths to scan
            base_url: Base URL prefix
            benign_ratio: Fraction of benign paths mixed in
            delay_range: Delay between individual requests (seconds)
            burst_size: Number of requests per burst
            burst_pause: Pause between bursts (seconds tuple)
        
        Returns:
            List of schedule items: {url, type, delay}
        """
        mixed = self.mix_with_benign(scan_paths, benign_ratio)
        
        schedule = []
        burst_count = 0
        
        for i, path in enumerate(mixed):
            url = f"{base_url.rstrip('/')}{path}" if base_url else path
            is_benign = path in self.benign_paths
            
            # Calculate delay
            if burst_count >= burst_size:
                # Burst pause (longer)
                delay = random.uniform(*burst_pause)
                burst_count = 0
            else:
                # Normal delay
                delay = random.uniform(*delay_range)
            
            schedule.append({
                "url": url,
                "path": path,
                "type": "benign" if is_benign else "scan",
                "delay": delay,
                "order": i,
            })
            burst_count += 1
        
        return schedule

    def randomize_params(self, url: str, params: List[str]) -> List[str]:
        """Randomize parameter fuzzing order.
        
        Instead of fuzzing params alphabetically:
            ?action= → ?cmd= → ?file= → ?id=  (alphabetical)
        
        Randomize:
            ?id= → ?file= → ?action= → ?cmd=  (random)
        """
        shuffled = list(params)
        random.shuffle(shuffled)
        return shuffled

    def obfuscate_payload_timing(
        self,
        payloads: List[str],
        delay_range: Tuple[float, float] = (0.5, 3.0),
        jitter: float = 0.5,
    ) -> List[Tuple[str, float]]:
        """Add human-like timing to payload delivery.
        
        Returns list of (payload, delay_before_sending).
        """
        result = []
        for payload in payloads:
            delay = random.uniform(*delay_range)
            # Add jitter
            delay += random.uniform(-jitter, jitter)
            delay = max(0.1, delay)
            result.append((payload, delay))
        return result

    def generate_benign_traffic(
        self,
        base_url: str,
        count: int = 5,
    ) -> List[Dict]:
        """Generate benign traffic requests (for noise/dilution).
        
        Returns list of {url, method, headers} dicts.
        """
        paths = random.sample(self.benign_paths, min(count, len(self.benign_paths)))
        requests = []
        
        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            requests.append({
                "url": url,
                "method": "GET",
                "delay": random.uniform(0.5, 2.0),
            })
        
        return requests
