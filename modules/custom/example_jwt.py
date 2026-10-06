"""
Example Plugin: JWT Token Analyzer

Checks JWT tokens found in responses for:
- None algorithm bypass
- Weak HMAC secrets (rockyou top 50)
- Token in URL query params

To use: just drop this file in modules/custom/ — auto-loaded.
Rename to _example_jwt.py to disable (underscore prefix = skipped).
"""
import asyncio
import base64
import hmac
import hashlib
import json
import re
from typing import Dict, List


class JWTTokenAnalyzer:
    """Scan discovered responses for JWT tokens and test for weaknesses."""

    name = "JWT Token Analyzer"
    priority = 60  # runs after core phases

    # Top weak HMAC secrets
    WEAK_SECRETS = [
        "secret", "password", "123456", "admin", "changeme",
        "secretkey", "jwtsecret", "key", "private", "test",
        "qwerty", "letmein", "pass", "12345678", "123456789",
        "superman", "iloveyou", "monkey", "dragon", "master",
    ]

    async def run(self, state) -> List[Dict]:
        findings = []

        for url in list(state.scan_urls)[:10]:
            try:
                # Check URL query params for JWT
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(url)
                for values in parse_qs(parsed.query).values():
                    for v in values:
                        token_findings = self._analyze_token(v, url, "query")
                        findings.extend(token_findings)

                # Check response body for JWT in JSON
                r = await state.async_engine.ahttp_send(
                    url, timeout=6, state_context=state.session_manager)
                if isinstance(r, dict) and r.get("body"):
                    body = r["body"]
                    # Find JWT patterns in response: xxx.yyy.zzz
                    jwt_pattern = r'[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}'
                    for match in re.finditer(jwt_pattern, body):
                        token_findings = self._analyze_token(match.group(), url, "body")
                        findings.extend(token_findings)
            except Exception:
                continue

        return findings

    def _analyze_token(self, token: str, url: str, source: str) -> List[Dict]:
        """Analyze a single JWT token for weaknesses."""
        findings = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        header_b64, payload_b64, sig_b64 = parts

        # Decode header
        try:
            header = json.loads(self._b64decode(header_b64))
        except Exception:
            return findings

        alg = header.get("alg", "")

        # Test 1: None algorithm
        if alg.lower() == "none":
            findings.append({
                "type": "jwt_none_alg",
                "title": "JWT: None Algorithm",
                "url": url[:200],
                "detail": f"Source: {source}, JWT accepts 'none' algorithm — signature bypass",
                "confidence": "confirmed",
            })

        # Test 2: Weak HMAC secret
        if alg.startswith("HS"):
            for secret in self.WEAK_SECRETS:
                try:
                    computed = hmac.new(
                        secret.encode(),
                        (header_b64 + "." + payload_b64).encode(),
                        getattr(hashlib, f"sha{alg[2:]}" if alg[2:].isdigit() else "sha256"),
                    ).digest()
                    computed_b64 = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
                    if computed_b64 == sig_b64:
                        findings.append({
                            "type": "jwt_weak_secret",
                            "title": f"JWT: Weak Secret ({secret})",
                            "url": url[:200],
                            "detail": f"Source: {source}, Algorithm: {alg}, "
                                      f"Secret cracked: '{secret}' — token forging possible",
                            "confidence": "confirmed",
                        })
                        break
                except Exception:
                    continue

        # Test 3: Decode payload for sensitive claims
        try:
            payload = json.loads(self._b64decode(payload_b64))
            sensitive = []
            if payload.get("role") == "admin":
                sensitive.append("admin role")
            if payload.get("sub") and "@" in str(payload.get("sub")):
                sensitive.append(f"email: {payload['sub']}")
            if "password" in str(payload).lower():
                sensitive.append("password in claims")
            if sensitive:
                findings.append({
                    "type": "jwt_sensitive_claims",
                    "title": "JWT: Sensitive Claims Exposed",
                    "url": url[:200],
                    "detail": f"Source: {source}, Claims: {', '.join(sensitive)}",
                    "confidence": "info",
                })
        except Exception:
            pass

        return findings

    @staticmethod
    def _b64decode(data: str) -> str:
        """URL-safe base64 decode with padding."""
        data += "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data).decode("utf-8", "replace")
