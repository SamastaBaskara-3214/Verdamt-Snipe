"""Passive Sensitive Response Scanner (API Keys, Secrets & High-Entropy Strings).

Scans HTTP response bodies asynchronously at transport level to detect leaked credentials,
cloud API keys, private keys, and high-entropy secrets without extra requests.
"""

import re
import math
from typing import List, Dict, Any, Set


KNOWN_SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "Critical"),
    (r'(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS Secret Access Key", "Critical"),
    (r'AIzaSy[A-Za-z0-9_\-]{35}', "Google API Key", "High"),
    (r'xox[baprs]-[0-9a-zA-Z]{10,48}', "Slack Token", "Critical"),
    (r'sk_live_[0-9a-zA-Z]{24,99}', "Stripe Live Secret Key", "Critical"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token", "Critical"),
    (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token", "Critical"),
    (r'glpat-[0-9a-zA-Z_\-]{20}', "GitLab Personal Access Token", "Critical"),
    (r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----', "Private Key Header", "Critical"),
    (r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token", "Critical"),
    (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "PayPal Access Token", "Critical"),
    (r'eyJhbGciOiJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', "JWT Bearer Token", "Medium"),
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon Entropy of a string to measure randomness."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretScanner:
    """Passive response body secret scanner."""

    _compiled_patterns = [
        (re.compile(pattern, re.I if "BEGIN" in name or "aws" in pattern.lower() else 0), name, severity)
        for pattern, name, severity in KNOWN_SECRET_PATTERNS
    ]

    @classmethod
    def scan_response(cls, url: str, body: str) -> List[Dict[str, Any]]:
        if not body or len(body) < 10:
            return []

        findings: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        # 1. Regex Pattern Matching
        for regex, name, severity in cls._compiled_patterns:
            matches = regex.findall(body)
            for m in matches:
                secret_str = m if isinstance(m, str) else m[0]
                if secret_str not in seen:
                    seen.add(secret_str)
                    findings.append({
                        "type": "leaked_secret",
                        "title": f"Leaked Secret: {name}",
                        "url": url,
                        "detail": f"Detected leaked {name}: {secret_str[:12]}...",
                        "severity": severity,
                        "confidence": "confirmed",
                    })

        # 2. Entropy Analysis for API keys in JSON/JS keys
        key_value_pattern = re.compile(r'["\']([a-zA-Z0-9_\-]{15,40})["\']\s*:\s*["\']([A-Za-z0-9_\-=/+]{20,80})["\']')
        for m in key_value_pattern.finditer(body[:50000]):  # Sample first 50KB
            key_name, val = m.group(1), m.group(2)
            if any(k in key_name.lower() for k in ["secret", "token", "password", "auth", "apiKey", "api_key", "private"]):
                entropy = shannon_entropy(val)
                if entropy >= 4.5 and val not in seen:
                    seen.add(val)
                    findings.append({
                        "type": "high_entropy_secret",
                        "title": f"High Entropy Secret in Key [{key_name}]",
                        "url": url,
                        "detail": f"High Shannon entropy ({round(entropy, 2)}) secret in field '{key_name}': {val[:10]}...",
                        "severity": "High",
                        "confidence": "suspected",
                    })

        return findings
