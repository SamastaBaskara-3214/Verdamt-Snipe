"""Strict QA gate — regression tests for the silent-death bug class.

Covers three bugs proven 2026-10-05 by the pyflakes audit, none of which
the original 131 tests caught:

1. `SmartPayloadGenerator.generate(bypass=True)` NameError (missing
   WAFBypass import) — killed every odd-wave payload flood silently.
2. browser_recon dead code — the whole SPA extraction block sat
   unreachable after `return` inside `if not context:` (plus a
   `browser.close()` on a name that never existed).
3. Undefined-name class in general -> static gate via pyflakes.

Also: ScanPolicy budget denial used to be silent (status=0 read as
"no response" downstream) -> one-shot loud warning, asserted here.
"""
import asyncio
import io
import pathlib
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestStaticUndefinedNames(unittest.TestCase):
    """pyflakes gate: undefined names are exactly the NameError class
    that let half the scanner run dead without any test failing."""

    def test_pyflakes_no_undefined_names(self):
        try:
            from pyflakes.api import checkPath
            from pyflakes.reporter import Reporter
        except ImportError:
            self.skipTest("pyflakes not installed — static QA gate inactive "
                          "(pip install --user --break-system-packages pyflakes)")

        out, err = io.StringIO(), io.StringIO()
        reporter = Reporter(out, err)
        files = [ROOT / "verd.py"]
        for d in ("runners", "modules", "core", "reports"):
            files.extend(p for p in (ROOT / d).rglob("*.py")
                         if "__pycache__" not in str(p))
        for f in files:
            checkPath(str(f), reporter)

        undefined = [l for l in out.getvalue().splitlines()
                     if "undefined name" in l]
        self.assertEqual(
            undefined, [],
            "pyflakes undefined names (runtime NameError waiting to happen):\n"
            + "\n".join(undefined))
        self.assertNotIn("ambiguous variable", out.getvalue())


class TestPayloadGeneratorBypassSmoke(unittest.TestCase):
    """Bug #1 guard: bypass path must execute for every payload type."""

    def test_generate_bypass_all_types(self):
        from modules.scanners.scanner import SmartPayloadGenerator as G
        for ptype in ("xss", "sqli", "lfi", "rce", "ssti"):
            base = G.generate(ptype, bypass=False)
            bypass = G.generate(ptype, bypass=True)  # raised NameError pre-fix
            self.assertTrue(base, f"{ptype}: empty base payloads")
            self.assertGreaterEqual(
                len(bypass), len(base),
                f"{ptype}: bypass variants must not shrink the set")


class TestBrowserReconExtractionLive(unittest.IsolatedAsyncioTestCase):
    """Bug #2 guard: extraction block must actually run when the pool
    returns a context. Dead-code regression => empty results => FAIL.

    MUST be IsolatedAsyncioTestCase — plain TestCase never awaits the
    async test body (it passed vacuously on first run, caught via
    RuntimeWarning 'coroutine was never awaited')."""

    def setUp(self):
        import modules.web.browser_recon as br
        self.br = br
        br.PLAYWRIGHT_AVAILABLE = True

    async def _run_with_mock_pool(self):
        sm = MagicMock()
        sm.local_storage = {}
        sm.cookies = {}
        sm.auth_tokens = {}

        ctx = MagicMock()
        ctx.add_cookies = AsyncMock()
        ctx.cookies = AsyncMock(return_value=[])
        ctx.close = AsyncMock()

        page = MagicMock()
        page.goto = AsyncMock()
        page.wait_for_timeout = AsyncMock()
        page.route = AsyncMock()
        # 1st evaluate = localStorage dump, 2nd = href extraction
        page.evaluate = AsyncMock(
            side_effect=['{"authtoken":"eyJhbGciOiJzbm9uIn0.sig"}', []])
        ctx.new_page = AsyncMock(return_value=page)

        recon = self.br.BrowserRecon("https://app.example.com/login", sm)
        with patch("core.browser_pool.SharedBrowserPool.new_context",
                   new=AsyncMock(return_value=ctx)):
            results = await recon.run()
        return results, sm, ctx

    async def test_localstorage_token_extraction_runs(self):
        results, sm, ctx = await self._run_with_mock_pool()
        self.assertEqual(
            results.get("local_storage"),
            {"authtoken": "eyJhbGciOiJzbm9uIn0.sig"},
            "localStorage extraction never ran — dead-code regression")
        sm.register_token.assert_any_call(
            "app.example.com", "bearer", "eyJhbGciOiJzbm9uIn0.sig")
        ctx.close.assert_awaited_once()

    async def test_context_falsy_returns_empty_early(self):
        with patch("core.browser_pool.SharedBrowserPool.new_context",
                   new=AsyncMock(return_value=None)):
            recon = self.br.BrowserRecon("https://app.example.com/", MagicMock())
            results = await recon.run()
        self.assertEqual(results, {"endpoints": [], "local_storage": {}})


class TestPolicyDenyWarning(unittest.TestCase):
    """Bug #3 guard: budget exhaustion must be loud, once per reason."""

    def setUp(self):
        import core.client as cl
        self.client = cl
        cl._POLICY_DENY_WARNED.clear()

    def test_warns_once_per_reason_and_points_to_max_requests(self):
        with patch("core.ui.w") as mock_w:
            self.client._warn_policy_deny("request_budget_exhausted")
            self.client._warn_policy_deny("request_budget_exhausted")
            self.client._warn_policy_deny("scope_denied")
        calls = [str(c) for c in mock_w.call_args_list]
        self.assertEqual(len(calls), 2, "must warn exactly once per reason")
        self.assertTrue(any("--max-requests" in c for c in calls),
                        "budget hint missing from warning")


class TestShortFlagAliases(unittest.TestCase):
    """Regression: direct `python3 verd.py -p X` used to parse fine but
    silently ignore the proxy (only --proxy was consumed) -> full-scan
    direct. Aliases must normalize to the long flags verd.py reads."""

    def test_proxy_short_flag_normalized(self):
        from verd import parse_scan_args
        target, flags, _ = parse_scan_args(
            ["verd.py", "-p", "socks5://1.2.3.4:9050", "example.com"])
        self.assertEqual(target, "example.com")
        self.assertIn("--proxy", flags)
        self.assertNotIn("-p", flags)
        self.assertEqual(flags[flags.index("--proxy") + 1],
                         "socks5://1.2.3.4:9050")

    def test_stealth_turbo_resume_short_flags(self):
        from verd import parse_scan_args
        target, flags, resume = parse_scan_args(
            ["verd.py", "example.com", "-s", "-t", "-r"])
        self.assertEqual(target, "example.com")
        self.assertEqual(flags, ["--stealth", "--turbo", "--resume"])
        self.assertIsNone(resume)  # bare --resume keeps default resolution

    def test_resume_short_flag_with_value_skips_target(self):
        from verd import parse_scan_args
        target, flags, resume = parse_scan_args(
            ["verd.py", "-r", "outputs/example.com.state"])
        self.assertIsNone(target)
        self.assertEqual(resume, "outputs/example.com.state")

    def test_dash_h_untouched(self):
        from verd import parse_scan_args
        target, flags, _ = parse_scan_args(
            ["verd.py", "-H", "X-Forwarded-For: 1.2.3.4", "example.com"])
        self.assertEqual(target, "example.com")
        self.assertIn("-H", flags)  # header flags keep their short form


class TestInjectAuthSuffixMatch(unittest.TestCase):
    """Regression (verdict B:205, REAL MED-LOW): exact-hostname lookup made
    requests to www/apex/subdomain variants go out WITHOUT auth silently."""

    def _session(self):
        from core.state import SessionManager
        sm = SessionManager()
        sm.register_token("www.example.com", "bearer", "TOKEN-123")
        sm.update_cookies("www.example.com", {"sid": "abc"})
        return sm

    def test_apex_url_gets_www_token(self):
        h = {}
        self._session().inject_auth("https://example.com/api", h)
        self.assertIn("TOKEN-123", h.get("Authorization", ""))

    def test_subdomain_gets_token(self):
        h = {}
        self._session().inject_auth("https://api.example.com/v1", h)
        self.assertIn("TOKEN-123", h.get("Authorization", ""))

    def test_cookie_suffix_match(self):
        h = {}
        self._session().inject_auth("https://example.com/profile", h)
        self.assertIn("sid=abc", h.get("Cookie", ""))

    def test_unrelated_domain_gets_nothing(self):
        h = {}
        self._session().inject_auth("https://evil-corp.io/login", h)
        self.assertNotIn("Authorization", h)
        self.assertNotIn("Cookie", h)


class TestOriginKeylessStatus(unittest.IsolatedAsyncioTestCase):
    """Regression (origin-hunt honest reporting): rejected keyless endpoints
    must surface as ERROR, not blend into silent zeros."""

    def setUp(self):
        from modules.waf import origin_hunter as oh
        self.oh = oh

    async def test_censys_non_200_raises(self):
        from unittest.mock import AsyncMock, patch
        with patch.object(self.oh, "_curl", new=AsyncMock(return_value={
                "status": 401, "body": "", "headers": {}, "size": 0, "time": 0})):
            with self.assertRaises(RuntimeError) as ctx:
                await self.oh._method_censys("example.com")
        self.assertIn("401", str(ctx.exception))

    async def test_fofa_non_200_raises(self):
        from unittest.mock import AsyncMock, patch
        with patch.object(self.oh, "_curl", new=AsyncMock(return_value={
                "status": 403, "body": "", "headers": {}, "size": 0, "time": 0})):
            with self.assertRaises(RuntimeError) as ctx:
                await self.oh._method_fofa("example.com")
        self.assertIn("403", str(ctx.exception))


class TestToolProcTracker(unittest.TestCase):
    """Regression (verdict A:521): tools must be tracked so --max-time can
    terminate them, and _run_tool must unregister on every exit path."""

    def test_kill_active_procs_terminates(self):
        import subprocess
        import time
        from core.external_tools import _ACTIVE_PROCS, kill_active_procs
        p = subprocess.Popen(["sleep", "30"])
        _ACTIVE_PROCS.add(p)
        try:
            n = kill_active_procs("unit test")
            self.assertEqual(n, 1)
            for _ in range(50):
                if p.poll() is not None:
                    break
                time.sleep(0.05)
            self.assertIsNotNone(p.poll(), "process was not terminated")
            self.assertEqual(len(_ACTIVE_PROCS), 0)
        finally:
            if p.poll() is None:
                p.kill()

    def test_run_tool_happy_path_unregisters(self):
        from unittest.mock import patch
        from core import external_tools as et
        with patch.object(et, "_find_tool", return_value="/bin/sh"):
            rc, out, err = et._run_tool("fake", ["-c", "echo hi"], timeout=5)
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "hi")
        self.assertEqual(len(et._ACTIVE_PROCS), 0)

    def test_run_tool_timeout_salvages_and_unregisters(self):
        from unittest.mock import patch
        from core import external_tools as et
        with patch.object(et, "_find_tool", return_value="/bin/sh"):
            rc, out, err = et._run_tool("fake", ["-c", "sleep 30"], timeout=1)
        self.assertEqual(rc, -1)
        self.assertIn("timeout after 1s", err)
        self.assertEqual(len(et._ACTIVE_PROCS), 0,
                         "timed-out process leaked out of the registry")


class TestMode7Deadline(unittest.IsolatedAsyncioTestCase):
    """Regression (A:521 follow-up): mode 7's run_nuclei used to be called
    synchronously inside _execute_mode — the blocked event loop meant
    asyncio.wait_for(--max-time) never fired and the deadline was a lie
    (live proof 2026-10-06: 3s run under timeout=1 finished "normally").
    With to_thread the wait_for timer must cancel within ~0.5s."""

    async def test_nuclei_mode_cancellable_by_wait_for(self):
        import time
        from unittest.mock import patch, MagicMock
        from core.state import SessionManager
        from verd import _execute_mode

        def slow_nuclei(*args, **kwargs):
            time.sleep(2.0)  # sync blocking work, as a real tool run is
            return []

        with patch("core.external_tools.run_nuclei", new=slow_nuclei):
            t0 = time.monotonic()
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    _execute_mode(
                        "nuclei", "example.com", "https://example.com",
                        [{"url": "https://example.com"}], [],
                        ["https://example.com"], {}, [], [], None,
                        SessionManager(), {}, {}, MagicMock(), False,
                        {}, lambda: None, 5, None),
                    timeout=0.5)
            elapsed = time.monotonic() - t0
        self.assertLess(
            elapsed, 1.5,
            "wait_for could not cancel the mode — blocking call freezes the "
            "event loop and --max-time stops working")


if __name__ == "__main__":
    unittest.main()
