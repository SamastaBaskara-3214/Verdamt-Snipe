"""Proxy tunnel tests — raw sockets must never dial the target directly.

Covers core.proxy_manager.open_proxied_connection(): SOCKS5 handshake, remote
DNS (socks5h), TLS over the tunnel, the no-proxy fallback, VERDAMT_PROXY
pickup, and the ffuf scheme normalization.
"""
import asyncio
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from core import proxy_manager as PM
from core.proxy_manager import open_proxied_connection, resolve_proxy
from runners.poison import _get_proxy_flag

_HTTP_REPLY = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nPONG-PX"


class _MiniSocks5:
    """Minimal SOCKS5 server: no auth, CONNECT only, records the requested
    target so tests can assert whether DNS happened locally or remotely."""

    def __init__(self):
        self.server = None
        self.port = None
        self.requests = []

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self):
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            ver_n = await reader.readexactly(2)
            await reader.readexactly(ver_n[1])          # methods
            writer.write(b"\x05\x00")                   # no auth
            await writer.drain()

            req = await reader.readexactly(4)
            atyp = req[3]
            if atyp == 1:                               # IPv4
                raw = await reader.readexactly(4)
                host = ".".join(str(b) for b in raw)
            elif atyp == 3:                             # DOMAINNAME
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode()
            elif atyp == 4:                             # IPv6
                raw = await reader.readexactly(16)
                host = ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
            else:
                return
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requests.append((host, port))

            try:
                up_reader, up_writer = await asyncio.open_connection(host, port)
            except Exception:
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return

            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            await asyncio.gather(self._pipe(reader, up_writer),
                                 self._pipe(up_reader, writer))
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    @staticmethod
    async def _pipe(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass


async def _http_handler(reader, writer):
    try:
        await reader.read(2048)
        writer.write(_HTTP_REPLY)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class ProxyTunnelTestBase(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="verdamt-tls-")
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl not available for TLS test cert")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(cls.tmp, "k.pem"),
             "-out", os.path.join(cls.tmp, "c.pem"),
             "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost"],
            check=True, capture_output=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self._saved_mgr = PM.GLOBAL_PROXY_MGR
        self._saved_env = {k: os.environ.get(k) for k in
                           ("VERDAMT_PROXY", "ALL_PROXY", "HTTP_PROXY",
                            "HTTPS_PROXY", "http_proxy", "https_proxy",
                            "all_proxy")}
        # Isolate: no global proxy and no env proxy unless a test sets them
        PM.GLOBAL_PROXY_MGR = None
        os.environ.pop("VERDAMT_PROXY", None)
        for key in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"):
            os.environ.pop(key, None)
        self.proxy = _MiniSocks5()

    async def asyncTearDown(self):
        await self.proxy.stop()
        PM.GLOBAL_PROXY_MGR = self._saved_mgr
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    async def _start_target(self, ssl_ctx=None):
        server = await asyncio.start_server(_http_handler, "127.0.0.1", 0,
                                            ssl=ssl_ctx)
        port = server.sockets[0].getsockname()[1]
        return server, port

    @staticmethod
    async def _request(reader, writer):
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        return await asyncio.wait_for(reader.read(1024), timeout=5)


class TestSocksTunnel(ProxyTunnelTestBase):
    async def test_socks5h_tunnel_with_remote_dns(self):
        target, port = await self._start_target()
        await self.proxy.start()
        try:
            reader, writer = await open_proxied_connection(
                "localhost", port,
                proxy=f"socks5h://127.0.0.1:{self.proxy.port}", timeout=5)
            body = await self._request(reader, writer)
            writer.close()
        finally:
            target.close()

        self.assertIn(b"PONG-PX", body)
        # domain reached the proxy unresolved → proxy did the DNS (no leak)
        self.assertEqual(self.proxy.requests[0], ("localhost", port))

    async def test_socks5_resolves_locally_when_not_h(self):
        target, port = await self._start_target()
        await self.proxy.start()
        try:
            reader, writer = await open_proxied_connection(
                "localhost", port,
                proxy=f"socks5://127.0.0.1:{self.proxy.port}", timeout=5)
            body = await self._request(reader, writer)
            writer.close()
        finally:
            target.close()

        self.assertIn(b"PONG-PX", body)
        requested_host = self.proxy.requests[0][0]
        self.assertNotIn(requested_host, ("localhost",),
                         "plain socks5 must resolve locally (IP form)")

    async def test_tls_tunnel_through_proxy(self):
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(os.path.join(self.tmp, "c.pem"),
                                   os.path.join(self.tmp, "k.pem"))
        target, port = await self._start_target(ssl_ctx=server_ctx)
        await self.proxy.start()
        try:
            reader, writer = await open_proxied_connection(
                "localhost", port, ssl=ssl_ctx, server_hostname="localhost",
                proxy=f"socks5h://127.0.0.1:{self.proxy.port}", timeout=5)
            body = await self._request(reader, writer)
            writer.close()
        finally:
            target.close()

        self.assertIn(b"PONG-PX", body, "TLS handshake must survive the tunnel")
        self.assertEqual(self.proxy.requests[0], ("localhost", port))

    async def test_no_proxy_means_direct_connection(self):
        target, port = await self._start_target()
        await self.proxy.start()
        try:
            reader, writer = await open_proxied_connection(
                "127.0.0.1", port, timeout=5)
            body = await self._request(reader, writer)
            writer.close()
        finally:
            target.close()

        self.assertIn(b"PONG-PX", body)
        self.assertEqual(self.proxy.requests, [], "no proxy configured → no tunnel")

    async def test_bad_proxy_scheme_fails_loudly(self):
        with self.assertRaises(ValueError):
            await open_proxied_connection(
                "127.0.0.1", 1, proxy="ftp://127.0.0.1:21", timeout=2)


class TestProxyConfig(unittest.TestCase):
    def test_socks5h_scheme_is_valid(self):
        mgr = PM.ProxyManager()
        self.assertTrue(mgr._validate_proxy("socks5h://127.0.0.1:9050"))
        self.assertTrue(mgr._validate_proxy("socks4a://1.2.3.4:1080"))

    def test_setup_proxy_falls_back_to_verdamt_env(self):
        saved_mgr = PM.GLOBAL_PROXY_MGR
        saved = {k: os.environ.get(k) for k in
                 ("VERDAMT_PROXY", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
                  "http_proxy", "https_proxy", "all_proxy")}
        try:
            os.environ["VERDAMT_PROXY"] = "socks5h://127.0.0.1:9050"
            for key in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY",
                        "http_proxy", "https_proxy", "all_proxy"):
                os.environ.pop(key, None)
            mgr = PM.setup_proxy()          # no --proxy flag
            self.assertEqual(mgr.current_proxy, "socks5h://127.0.0.1:9050")
            # set_env_vars() must have propagated it to the other tools
            self.assertEqual(os.environ.get("ALL_PROXY"), "socks5h://127.0.0.1:9050")
        finally:
            PM.GLOBAL_PROXY_MGR = saved_mgr
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_explicit_proxy_beats_env(self):
        mgr = PM.setup_proxy(proxy="http://127.0.0.1:8080")
        self.assertEqual(mgr.current_proxy, "http://127.0.0.1:8080")

    def test_resolve_proxy_priority(self):
        self.assertEqual(resolve_proxy("http://a:1"), "http://a:1")
        os.environ["VERDAMT_PROXY"] = "socks5h://env:9050"
        try:
            PM.GLOBAL_PROXY_MGR = None
            self.assertEqual(resolve_proxy(), "socks5h://env:9050")
            mgr = PM.ProxyManager(initial_proxy="socks5://mgr:1080")
            PM.GLOBAL_PROXY_MGR = mgr
            self.assertEqual(resolve_proxy(), "socks5://mgr:1080")
        finally:
            PM.GLOBAL_PROXY_MGR = None
            os.environ.pop("VERDAMT_PROXY", None)

    def test_ffuf_flag_normalizes_socks_scheme(self):
        # ffuf rejects socks5h:// outright — the flag must hand it socks5://
        saved_mgr = PM.GLOBAL_PROXY_MGR
        try:
            PM.GLOBAL_PROXY_MGR = PM.ProxyManager(
                initial_proxy="socks5h://127.0.0.1:9050")
            self.assertEqual(_get_proxy_flag(), "socks5://127.0.0.1:9050")
            PM.GLOBAL_PROXY_MGR = PM.ProxyManager(
                initial_proxy="socks4a://1.2.3.4:1080")
            self.assertEqual(_get_proxy_flag(), "socks4://1.2.3.4:1080")
            PM.GLOBAL_PROXY_MGR = PM.ProxyManager(
                initial_proxy="http://1.2.3.4:8080")
            self.assertEqual(_get_proxy_flag(), "http://1.2.3.4:8080")
        finally:
            PM.GLOBAL_PROXY_MGR = saved_mgr


if __name__ == "__main__":
    unittest.main()
