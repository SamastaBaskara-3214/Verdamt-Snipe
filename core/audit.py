"""Structured Audit Logger for Verdamt-Snipe (JSON-Lines / Audit Trail)."""

import json
import os
import sys
import time
from threading import Lock
from typing import Dict, Any, Optional
from pathlib import Path


class AuditLogger:
    """Thread-safe and async-safe structured JSON-lines logger."""

    _instance = None
    _lock = Lock()

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path
        self._file_lock = Lock()

        if self.log_path:
            p = Path(self.log_path)
            p.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_instance(cls) -> "AuditLogger":
        with cls._lock:
            if cls._instance is None:
                cls._instance = AuditLogger()
            return cls._instance

    @classmethod
    def configure(cls, log_path: str) -> "AuditLogger":
        with cls._lock:
            cls._instance = AuditLogger(log_path)
            return cls._instance

    def _write_entry(self, entry: Dict[str, Any]) -> None:
        if not self.log_path:
            return
        entry["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        line = json.dumps(entry) + "\n"
        with self._file_lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as ex:
                if not getattr(self, "_write_warned", False):
                    self._write_warned = True
                    print(f"[audit] WARNING: failed to append {self.log_path}: {ex}",
                          file=sys.stderr)

    def log_request(
        self,
        url: str,
        method: str = "GET",
        status_code: int = 0,
        elapsed: float = 0.0,
        allowed: bool = True,
        reason: str = "",
        dry_run: bool = False,
        waf: Optional[str] = None,
    ) -> None:
        """Record an HTTP request authorization / execution attempt."""
        entry = {
            "type": "request",
            "url": url,
            "method": method.upper(),
            "status_code": status_code,
            "elapsed_ms": round(elapsed * 1000, 2),
            "allowed": allowed,
            "reason": reason,
            "dry_run": dry_run,
        }
        if waf:
            entry["waf"] = waf
        self._write_entry(entry)

    def log_finding(
        self,
        title: str,
        severity: str,
        url: str,
        detail: str = "",
        cvss: Optional[float] = None,
    ) -> None:
        """Record a security finding discovery."""
        entry = {
            "type": "finding",
            "title": title,
            "severity": severity,
            "url": url,
            "detail": detail,
        }
        if cvss is not None:
            entry["cvss"] = cvss
        self._write_entry(entry)

