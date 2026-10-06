"""
OWASP Top 10 (2021) Mapper — Maps Verdamt-Snipe vulnerability types to OWASP categories.
"""

from typing import Dict, List, Optional

OWASP_TOP_10 = {
    "A01": {
        "name": "Broken Access Control",
        "desc": "Failures related to enforcement of policies such that users cannot act outside of their intended permissions.",
        "cwes": ["CWE-200", "CWE-284", "CWE-285", "CWE-352", "CWE-639"],
    },
    "A02": {
        "name": "Cryptographic Failures",
        "desc": "Failures related to cryptography which often lead to sensitive data exposure.",
        "cwes": ["CWE-259", "CWE-327", "CWE-331"],
    },
    "A03": {
        "name": "Injection",
        "desc": "User-supplied data is not validated, filtered, or sanitized, leading to hostile data being used directly.",
        "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-611"],
    },
    "A04": {
        "name": "Insecure Design",
        "desc": "Risks related to design and architectural flaws, calling for more use of threat modeling and secure design patterns.",
        "cwes": ["CWE-209", "CWE-256", "CWE-501"],
    },
    "A05": {
        "name": "Security Misconfiguration",
        "desc": "Missing security hardening, improper configurations, verbose error messages, or unnecessary features enabled.",
        "cwes": ["CWE-16", "CWE-611"],
    },
    "A06": {
        "name": "Vulnerable and Outdated Components",
        "desc": "Use of components with known vulnerabilities, outdated or unsupported software.",
        "cwes": ["CWE-1104"],
    },
    "A07": {
        "name": "Identification and Authentication Failures",
        "desc": "Weaknesses in authentication mechanisms that permit credential stuffing, brute force, or session hijacking.",
        "cwes": ["CWE-287", "CWE-384", "CWE-613"],
    },
    "A08": {
        "name": "Software and Data Integrity Failures",
        "desc": "Failures to verify integrity of software updates, critical data, or CI/CD pipelines.",
        "cwes": ["CWE-345", "CWE-502", "CWE-829"],
    },
    "A09": {
        "name": "Security Logging and Monitoring Failures",
        "desc": "Insufficient logging, detection, monitoring, and active response to breaches.",
        "cwes": ["CWE-778"],
    },
    "A10": {
        "name": "Server-Side Request Forgery (SSRF)",
        "desc": "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
        "cwes": ["CWE-918"],
    },
}

# Mapping from Verdamt-Snipe finding types to OWASP categories
_TYPE_TO_OWASP = {
    # A01 — Broken Access Control
    "broken_auth":       "A01",
    "auth_bypass":       "A01",
    "idor":              "A01",
    "cors_misconfig":    "A01",
    "csrf":              "A01",
    "clickjacking":      "A01",
    "open_redirect":     "A01",
    "protected_api_endpoint": "A01",
    "auth_data_publicly_accessible": "A01",
    "api_auth_delta":    "A01",
    "oauth":             "A01",

    # A02 — Cryptographic Failures
    "js_secret_aws_access_key": "A02",
    "js_secret_aws_secret_key": "A02",
    "js_secret_stripe_key": "A02",
    "js_secret_ssh_key": "A02",
    "js_secret_jwt_token": "A02",
    "js_secret_generic_secret": "A02",
    "js_secret_google_api": "A02",
    "js_secret_firebase": "A02",
    "js_secret_slack_token": "A02",
    "js_secret_slack_webhook": "A02",
    "js_secret_github_token": "A02",
    "js_secret_amazon_mws": "A02",

    # A03 — Injection
    "reflected_xss":     "A03",
    "stored_xss":        "A03",
    "dom_xss":           "A03",
    "sqli_error":        "A03",
    "sqli_time":         "A03",
    "sqli_blind":        "A03",
    "lfi":               "A03",
    "rce":               "A03",
    "ssti":              "A03",
    "xxe_file":          "A03",
    "blind_xxe":         "A03",
    "blind_rce":         "A03",
    "http_smuggling":    "A03",
    "postmessage":       "A03",
    "proto_pollution":   "A03",

    # A05 — Security Misconfiguration
    "misconfig_header":  "A05",
    "server_disclosure": "A05",
    "admin_panel":       "A05",
    "info_disclosure":   "A05",
    "graphql_introspection": "A05",
    "api_schema_exposed": "A05",
    "dangerous_methods_allowed": "A05",
    "public_admin_api":  "A05",

    # A07 — Auth Failures
    "unauthenticated_api_data": "A07",

    # A08 — Data Integrity
    "subdomain_takeover": "A08",

    # A10 — SSRF
    "ssrf":              "A10",
    "blind_ssrf":        "A10",
}


def map_finding_to_owasp(finding_type: str) -> Optional[Dict]:
    """
    Maps a Verdamt-Snipe finding type string to its OWASP Top 10 category.
    Returns dict with 'id', 'name', 'desc', 'cwes' or None if unmapped.
    """
    # Try exact match first
    owasp_id = _TYPE_TO_OWASP.get(finding_type)

    # Fuzzy match for partial type strings
    if not owasp_id:
        for key, val in _TYPE_TO_OWASP.items():
            if key in finding_type or finding_type in key:
                owasp_id = val
                break

    if owasp_id and owasp_id in OWASP_TOP_10:
        entry = OWASP_TOP_10[owasp_id]
        return {
            "id": owasp_id,
            "name": entry["name"],
            "desc": entry["desc"],
            "cwes": entry["cwes"],
        }
    return None


def get_owasp_summary(findings: List[Dict]) -> Dict[str, Dict]:
    """
    Aggregates findings by OWASP Top 10 category.
    Returns: { "A01": { "name": ..., "desc": ..., "count": N, "findings": [...] }, ... }
    """
    summary = {}
    for f in findings:
        ftype = f.get("type", "")
        owasp = map_finding_to_owasp(ftype)
        if not owasp:
            continue
        oid = owasp["id"]
        if oid not in summary:
            summary[oid] = {
                "name": owasp["name"],
                "desc": owasp["desc"],
                "cwes": owasp["cwes"],
                "count": 0,
                "findings": [],
            }
        summary[oid]["count"] += 1
        summary[oid]["findings"].append(f)

    # Sort by OWASP ID
    return dict(sorted(summary.items()))
