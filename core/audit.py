"""Structured Audit Logger for Verdamt-Snipe (JSON-Lines / Audit Trail)."""

import json
import os
import shlex
import sys
import time
from threading import Lock
from typing import Dict, Any, Optional
from pathlib import Path

BODY_CAP = 8192
EVIDENCE_CAP = 4096


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
        headers: Optional[Dict[str, Any]] = None,
        body: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Record an HTTP request authorization / execution attempt.

        headers + body make the entry curl-replayable (Phase 5 reproduce):
        the entry captures what WOULD be/was sent, not just the URL.
        """
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
        if trace_id:
            entry["trace_id"] = trace_id
        if headers:
            entry["headers"] = {str(k): str(v) for k, v in dict(headers).items()}
        if body:
            b = body if isinstance(body, str) else str(body)
            if len(b) > BODY_CAP:
                entry["body"] = b[:BODY_CAP]
                entry["body_truncated"] = True
            else:
                entry["body"] = b
        self._write_entry(entry)

    def log_response(
        self,
        url: str,
        method: str = "GET",
        status_code: int = 0,
        elapsed: float = 0.0,
        error: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Record post-dispatch outcome (real status/latency of the request)."""
        entry = {
            "type": "response",
            "url": url,
            "method": (method or "GET").upper(),
            "status_code": status_code,
            "elapsed_ms": round(elapsed * 1000, 2),
        }
        if trace_id:
            entry["trace_id"] = trace_id
        if error:
            entry["error"] = error
        self._write_entry(entry)

    def log_finding(
        self,
        title: str,
        severity: str,
        url: str,
        detail: str = "",
        cvss: Optional[float] = None,
        evidence: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        """Record a security finding discovery.

        evidence = scan-time response snippet proving the finding (capped) —
        lets the report embed real proof without re-scanning.
        """
        entry = {
            "type": "finding",
            "title": title,
            "severity": severity,
            "url": url,
            "detail": detail,
        }
        if cvss is not None:
            entry["cvss"] = cvss
        if trace_id:
            entry["trace_id"] = trace_id
        if evidence:
            ev = evidence if isinstance(evidence, str) else str(evidence)
            entry["evidence"] = ev[:EVIDENCE_CAP]
        self._write_entry(entry)


def entry_to_curl(entry: Dict[str, Any]) -> str:
    """Reconstruct a replayable curl command from a 'request' audit entry.

    Returns "" for non-replayable entries (findings, responses, bulk charges,
    denied/absent URLs). Full fidelity: method, headers (cookies, auth, Host)
    and body are quoted with shlex — paste-safe into a shell.
    """
    if entry.get("type") != "request" or not entry.get("allowed"):
        return ""
    url = entry.get("url") or ""
    if not url or url.startswith("bulk://"):
        return ""
    parts = ["curl -sk"]
    method = (entry.get("method") or "GET").upper()
    if method and method != "GET":
        parts += ["-X", method]
    for k, v in (entry.get("headers") or {}).items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    body = entry.get("body")
    if body:
        parts += ["--data-binary", shlex.quote(body)]
    parts.append(shlex.quote(url))
    return " ".join(parts)


def load_replay_index(log_path: Optional[str]) -> Dict[str, str]:
    """Map url -> replayable curl command from an audit .jsonl.

    Last entry wins per url; when a url has both GET and POST variants the
    one WITH a body wins (the payload-bearing request is the useful replay).
    """
    if not log_path or not os.path.exists(log_path):
        return {}
    index: Dict[str, tuple] = {}
    with open(log_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = e.get("url") or ""
            if e.get("type") != "request" or not url or url.startswith("bulk://"):
                continue
            cmd = entry_to_curl(e)
            if not cmd:
                continue
            has_body = bool(e.get("body"))
            prev = index.get(url)
            if prev is None or has_body or prev[1] is False:
                index[url] = (cmd, has_body)
    return {u: c for u, (c, _) in index.items()}


def inject_replay_curls(findings: list, log_path: Optional[str]) -> int:
    """Attach finding['audit_curl'] (exact recorded request) where the audit
    trail has a replayable entry for the finding's URL. Returns match count."""
    index = load_replay_index(log_path)
    if not index:
        return 0
    matched = 0
    for f in findings:
        cmd = index.get((f or {}).get("url") or "")
        if cmd:
            f["audit_curl"] = cmd
            matched += 1
    return matched


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Inspect a Verdamt-Snipe audit .jsonl: replay requests as curl "
                    "or list dispatch results.")
    ap.add_argument("file", help="path to audit_*.jsonl")
    ap.add_argument("-q", "--grep", help="substring filter (url/body/title/error)")
    ap.add_argument("-n", "--limit", type=int, default=50, help="max lines (default 50)")
    ap.add_argument("--all", action="store_true", help="no limit")
    ap.add_argument("--responses", action="store_true",
                    help="show dispatch results (status/latency) instead of curl")
    args = ap.parse_args()

    shown = 0
    with open(args.file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if args.responses:
                if e.get("type") != "response":
                    continue
                out = f"[{e.get('status_code', 0)}] {e.get('elapsed_ms', 0)}ms {e.get('url', '')}"
                if e.get("error"):
                    out += f"  error={e['error']}"
            else:
                if e.get("type") != "request":
                    continue
                out = entry_to_curl(e)
                if not out:
                    continue
            if args.grep and args.grep.lower() not in json.dumps(e).lower():
                continue
            shown += 1
            if not args.all and shown > args.limit:
                break
            print(out)
    if shown == 0:
        print("(no matching entries)", file=sys.stderr)
    elif not args.all and shown > args.limit:
        print(f"(+ more — use --all or -n)", file=sys.stderr)

