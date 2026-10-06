import json
import os
import socket
import subprocess
import time
from typing import Dict, List, Optional, Any

SOCKET_PATH = "/tmp/verdamt-engine.sock"
ENGINE_BINARY = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "go", "build", "verdamt-engine"))


class GoEngineBridge:
    """Async bridge connecting Python verdamt-snipe with the high-performance Go Engine.
    
    If the Go engine binary is present and executable, Python communicates with it via
    Unix Domain Socket (/tmp/verdamt-engine.sock) for 10x-50x faster HTTP probing and validation.
    If unavailable, it safely falls back to pure Python async_network.
    """

    def __init__(self, socket_path: str = SOCKET_PATH):
        self.socket_path = socket_path
        self.proc: Optional[subprocess.Popen] = None
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available

        if not os.path.isfile(ENGINE_BINARY) or not os.access(ENGINE_BINARY, os.X_OK):
            self._try_compile()

        if not os.path.isfile(ENGINE_BINARY) or not os.access(ENGINE_BINARY, os.X_OK):
            self._available = False
            return False

        if not os.path.exists(self.socket_path):
            self._start_daemon()

        self._available = self._ping()
        return self._available

    def _try_compile(self):
        """Attempt to build verdamt-engine if go toolchain is installed."""
        go_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "go"))
        cmd_dir = os.path.join(go_dir, "cmd", "engine")
        build_dir = os.path.dirname(ENGINE_BINARY)
        
        if not os.path.isdir(cmd_dir):
            return

        try:
            # Check if `go` command exists
            subprocess.run(["go", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            os.makedirs(build_dir, exist_ok=True)
            res = subprocess.run(
                ["go", "build", "-o", ENGINE_BINARY, cmd_dir],
                cwd=go_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30
            )
            if res.returncode == 0 and os.path.exists(ENGINE_BINARY):
                os.chmod(ENGINE_BINARY, 0o755)
        except Exception:
            pass

    def _start_daemon(self):
        try:
            self.proc = subprocess.Popen(
                [ENGINE_BINARY, "-socket", self.socket_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Wait up to 1 second for socket creation
            for _ in range(20):
                if os.path.exists(self.socket_path):
                    break
                time.sleep(0.05)
        except Exception:
            pass

    def _ping(self) -> bool:
        res = self.send_command({"action": "ping"})
        return res is not None and res.get("status") == "ok"

    def send_command(self, payload: Dict[str, Any], timeout: float = 10.0) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self.socket_path):
            self._start_daemon()
            if not os.path.exists(self.socket_path):
                return None

        s = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect(self.socket_path)
                
                data = json.dumps(payload) + "\n"
                s.sendall(data.encode("utf-8"))

                buf = b""
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if b"\n" in buf:
                        break

            if not buf:
                return None

            line = buf.split(b"\n")[0].decode("utf-8")
            return json.loads(line)

        except Exception:
            return None

    def probe_batch(self, targets: List[str], headers: Dict[str, str] = None,
                    concurrency: int = 100, timeout: int = 4,
                    delay_ms: int = 0, jitter_ms: int = 0) -> Optional[List[Dict[str, Any]]]:
        if not self.is_available():
            return None

        probe_targets = [{"url": u, "headers": headers or {}} for u in targets]
        payload = {
            "action": "probe_batch",
            "targets": probe_targets,
            "concurrency": concurrency,
            "timeout": timeout,
            "delay_ms": delay_ms,
            "jitter_ms": jitter_ms,
        }

        resp = self.send_command(payload, timeout=float(timeout * 2 + 5))
        if resp and resp.get("status") == "ok":
            return resp.get("results", [])
        return None

    def js_scan_batch(self, files: List[Dict[str, Any]], batch_size: int = 50) -> Optional[Dict[str, Any]]:
        """Send downloaded JS files to Go Engine for multi-core zero-copy regex extraction.
        
        Args:
            files: List of dicts with keys: url, content, status, time, waf
            batch_size: Max files per socket transmission batch to prevent memory spikes
        Returns:
            Dict containing 'findings' (list) and 'endpoints' (list), or None if Go bridge fails.
        """
        if not self.is_available() or not files:
            return None

        all_findings = []
        all_endpoints = set()

        for i in range(0, len(files), batch_size):
            chunk = files[i:i + batch_size]
            payload = {
                "action": "js_scan_batch",
                "files": chunk
            }
            resp = self.send_command(payload, timeout=30.0)
            if not resp or resp.get("status") != "ok":
                return None

            all_findings.extend(resp.get("findings", []))
            all_endpoints.update(resp.get("endpoints", []))

        return {
            "findings": all_findings,
            "endpoints": sorted(list(all_endpoints))
        }

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc = None


# Global singleton bridge instance
go_bridge = GoEngineBridge()
