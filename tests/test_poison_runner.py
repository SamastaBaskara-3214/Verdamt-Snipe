import asyncio
import time
import unittest
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from runners.poison import (
    PoisonState,
    _adaptive_wave_loop,
    _budget_ok,
    _classify_login_attempt,
    _cookie_names,
    _ffuf_timeout,
    _get_header,
    _hold_for_backoff,
    _post_payload_pass,
    _run_ffuf,
    phase_bruteforce,
    phase_connection_exhaust,
    phase_param_flood,
    phase_payload_flood,
    run_poison_assault,
)


class TestPoisonRunnerState(unittest.TestCase):
    def _create_state(self):
        return PoisonState(
            target="example.com",
            seed_url="https://example.com",
            services=[],
            subs=[],
            scan_urls=["https://example.com/"],
            scope_guard=MagicMock(),
            session_manager=MagicMock(),
            async_engine=MagicMock(),
            is_turbo=False,
        )

    def test_poison_state_sync_and_async_locks(self):
        state = self._create_state()

        # Synchronous concurrent mutations protected by _sync_lock
        f1 = {"type": "Sync XSS", "severity": "High", "url": "http://example.com/a", "detail": "detail1"}
        f2 = {"type": "Sync SQLi", "severity": "Critical", "url": "http://example.com/b", "detail": "detail2"}
        state.add_finding(f1)
        state.extend_findings([f2])

        self.assertEqual(len(state.findings), 2)

    def test_async_poison_state_dedup(self):
        async def run_async_test():
            state = self._create_state()
            f1 = {"type": "Async XSS", "severity": "High", "url": "http://example.com/c", "detail": "detail3"}
            await state.add_finding_async(f1)
            # Duplicate call
            await state.add_finding_async(f1)
            self.assertEqual(len(state.findings), 1)

        asyncio.run(run_async_test())


class TestCookieParsing(unittest.TestCase):
    def test_expires_date_is_not_a_cookie(self):
        raw = "sid=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT, csrf=abc"
        self.assertEqual(_cookie_names(raw), {"sid", "csrf"})

    def test_single_cookie(self):
        self.assertEqual(_cookie_names("session=xyz"), {"session"})

    def test_header_lookup_is_case_insensitive(self):
        self.assertEqual(_get_header({"Location": "/a"}, "location"), "/a")
        self.assertEqual(_get_header({"location": "/b"}, "Location"), "/b")
        self.assertEqual(_get_header({}, "location"), "")
        self.assertEqual(_get_header(None, "location"), "")


class TestLoginClassification(unittest.TestCase):
    REDIR_BASE = {"status": 302, "loc_path": "/login",
                  "cookies": {"sid"}, "body": "invalid credentials"}
    OK_BASE = {"status": 200, "loc_path": "",
               "cookies": {"sid"}, "body": "invalid credentials"}

    def test_same_redirect_as_failed_login_is_not_a_hit(self):
        # Endpoint that always 302s — the old code reported "confirmed" here.
        self.assertIsNone(
            _classify_login_attempt(302, {"location": "/login?e=1"},
                                    "", self.REDIR_BASE))

    def test_new_redirect_destination_is_confirmed(self):
        conf, _ = _classify_login_attempt(
            302, {"location": "/dashboard"}, "", self.REDIR_BASE)
        self.assertEqual(conf, "confirmed")

    def test_redirect_after_non_redirect_baseline_is_confirmed(self):
        conf, _ = _classify_login_attempt(
            307, {"location": "/home"}, "", self.OK_BASE)
        self.assertEqual(conf, "confirmed")

    def test_redirect_without_baseline_is_only_suspected(self):
        no_base = {"status": 0, "loc_path": "", "cookies": set(), "body": ""}
        conf, detail = _classify_login_attempt(
            302, {"location": "/dashboard"}, "", no_base)
        self.assertEqual(conf, "suspected")
        self.assertIn("no failed-login baseline", detail)

    def test_new_cookie_is_suspected(self):
        conf, detail = _classify_login_attempt(
            200, {"set-cookie": "auth=abc"}, "welcome back", self.OK_BASE)
        self.assertEqual(conf, "suspected")
        self.assertIn("auth", detail)

    def test_body_difference_is_suspected(self):
        conf, _ = _classify_login_attempt(
            200, {}, "dashboard home " * 50, self.OK_BASE)
        self.assertEqual(conf, "suspected")

    def test_failure_keywords_and_no_diff_yield_nothing(self):
        self.assertIsNone(
            _classify_login_attempt(200, {}, "invalid password", self.OK_BASE))
        self.assertIsNone(_classify_login_attempt(404, {}, "not found", self.OK_BASE))


class TestFindingIndex(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[], subs=[], scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_index_stays_consistent_and_order_is_kept(self):
        state = self._state()
        for i in range(500):
            state.add_finding({"type": "t", "url": f"https://e/{i % 100}",
                               "detail": "d"})
        state.extend_findings([{"type": "t", "url": "https://e/1", "detail": "d"},
                               {"type": "t", "url": "https://e/999", "detail": "d"}])
        self.assertEqual(len(state.findings), 101)
        self.assertEqual(len({state._finding_key(f) for f in state.findings}),
                         len(state.findings))
        self.assertEqual(state._finding_keys,
                         {state._finding_key(f) for f in state.findings})
        # first occurrence keeps its position
        self.assertEqual(state.findings[0]["url"], "https://e/0")
        self.assertEqual(state.findings[-1]["url"], "https://e/999")

    def test_async_and_sync_helpers_share_the_index(self):
        state = self._state()
        state.add_finding({"type": "x", "url": "u", "detail": "d"})
        asyncio.run(state.add_finding_async({"type": "x", "url": "u", "detail": "d"}))
        self.assertEqual(len(state.findings), 1)


class _StubPolicy:
    def __init__(self, remaining):
        self._remaining = remaining

    @property
    def requests_remaining(self):
        return self._remaining


class TestBudgetGate(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_gate_opens_without_policy_or_with_budget(self):
        state = self._state()
        self.assertTrue(_budget_ok(state))          # policy is None
        state.policy = _StubPolicy(5000)
        self.assertTrue(_budget_ok(state))
        state.policy = _StubPolicy(None)            # unlimited
        self.assertTrue(_budget_ok(state))

    def test_gate_closes_when_budget_spent(self):
        state = self._state()
        state.policy = _StubPolicy(0)
        self.assertFalse(_budget_ok(state))

    def test_ffuf_not_dispatched_after_budget_spent(self):
        state = self._state()
        state.policy = _StubPolicy(0)
        result = asyncio.run(_run_ffuf("https://example.com/", ["admin"], "",
                                       100, policy=state.policy))
        self.assertEqual(result, [])   # returns before _find_tool / subprocess

    def test_summary_budget_line(self):
        # budget reporting must not blow up on unlimited policies
        state = self._state()
        state.policy = _StubPolicy(None)
        self.assertIsNone(state.policy.requests_remaining)


class TestDeadline(unittest.TestCase):
    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"],
                           scope_guard=MagicMock(), session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_ffuf_timeout_never_exceeds_time_left(self):
        state = self._state()
        state.max_duration = 120
        self.assertLessEqual(_ffuf_timeout(state), 120)
        state.max_duration = 0
        self.assertEqual(_ffuf_timeout(state), 1)
        state.max_duration = 10_000
        self.assertEqual(_ffuf_timeout(state), 45)   # hard cap

    def test_wave_loop_is_noop_when_time_is_up(self):
        state = self._state()
        state.max_duration = 0
        asyncio.run(_adaptive_wave_loop(state))
        self.assertEqual(state.async_engine.ahttp_send.call_count, 0)
        self.assertEqual(state.findings, [])


class TestParamDiscoveryDedup(unittest.TestCase):
    def _state(self):
        # scope_guard=None: a MagicMock would swallow add_urls() results
        return PoisonState(target="example.com", seed_url="https://example.com",
                           services=[], subs=[],
                           scan_urls=["https://example.com/", "https://example.com/a"],
                           scope_guard=None, session_manager=MagicMock(),
                           async_engine=MagicMock(), is_turbo=False)

    def test_same_url_is_not_fuzzed_twice(self):
        from unittest.mock import patch
        state = self._state()
        with patch("modules.extras.arjun.AsyncParamBruteforcer") as mock_bf:
            mock_bf.return_value.run = AsyncMock(return_value=["q"])
            asyncio.run(phase_param_flood(state))   # A1
            after_first = mock_bf.call_count        # one construction per target
            asyncio.run(phase_param_flood(state))   # A3 / next wave
        self.assertEqual(after_first, 2)                     # both top targets
        self.assertEqual(mock_bf.call_count, after_first)    # nothing re-fuzzed
        self.assertEqual(state._param_scanned,
                         {"https://example.com/", "https://example.com/a"})

    def test_new_url_still_gets_scanned(self):
        from unittest.mock import patch
        state = self._state()
        with patch("modules.extras.arjun.AsyncParamBruteforcer") as mock_bf:
            mock_bf.return_value.run = AsyncMock(return_value=["q"])
            asyncio.run(phase_param_flood(state))
            self.assertEqual(mock_bf.call_count, 2)
            state.add_urls(["https://example.com/new"])
            asyncio.run(phase_param_flood(state))
        self.assertEqual(mock_bf.call_count, 3)
        self.assertIn("https://example.com/new", state._param_scanned)


class TestCancellationClosesSockets(unittest.TestCase):
    """Wave-deadline cancellation must not leak raw-socket FDs."""

    def test_cancelled_slowloris_still_closes_writer(self):
        from unittest.mock import patch
        from modules.web.server_side.connection_exhaust import ConnectionExhaust

        ex = ConnectionExhaust("https://example.com", timeout=30)
        fake_writer = MagicMock()
        fake_writer.drain = AsyncMock()

        async def fake_open():
            return None, fake_writer

        async def run():
            with patch.object(ex, "_open_connection", fake_open):
                task = asyncio.create_task(ex._slowloris_async(1))
                await asyncio.sleep(0.05)   # parked in the keep-alive sleep
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
        fake_writer.close.assert_called()

    def test_cancelled_smuggle_request_still_closes_writer(self):
        from unittest.mock import patch
        from modules.web.server_side import smuggling

        fake_writer = MagicMock()
        fake_writer.drain = AsyncMock()
        fake_reader = MagicMock()

        async def slow_read(n):
            await asyncio.sleep(30)
            return b""

        fake_reader.read = slow_read

        async def fake_tunnel(host, port, **kwargs):
            return fake_reader, fake_writer

        async def run():
            # smuggling imports open_proxied_connection at call time
            with patch("core.proxy_manager.open_proxied_connection", fake_tunnel):
                task = asyncio.create_task(
                    smuggling._async_raw_request("example.com", 443, False,
                                                 "GET / HTTP/1.1\r\n\r\n"))
                await asyncio.sleep(0.05)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        asyncio.run(run())
        fake_writer.close.assert_called()


class TestPhase0Budget(unittest.IsolatedAsyncioTestCase):
    """Phase 0 (WAF pipeline) must have its own time slice — it used to burn
    the wave clock, so --max-time runs ended with a single wave."""

    def _args(self, max_duration: int) -> dict[str, Any]:
        return dict(
            target="example.com", seed_url="https://example.com/",
            services=[{"url": "https://example.com/"}], subs=[],
            scan_urls=["https://example.com/"], scope_guard=None,
            session_manager=MagicMock(), async_engine=MagicMock(),
            is_turbo=False, max_duration=max_duration, policy=None,
        )

    async def test_phase0_time_does_not_eat_wave_budget(self):
        from unittest.mock import patch
        first_wave_elapsed = []
        wave_calls = []

        async def fast_phase0(*args, **kwargs):
            await asyncio.sleep(1.5)
            return {}

        async def recorder(state):
            wave_calls.append(state.elapsed)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline", fast_phase0), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            start = time.time()
            result = await run_poison_assault(**self._args(max_duration=2))
            wall = time.time() - start

        self.assertEqual(len(result), 4)
        # Phase 0 really ran (1.5s) …
        self.assertGreaterEqual(wall, 1.5)
        # … but the wave clock restarted after it: without the reset the
        # first wave would see elapsed >= 1.5.
        self.assertLess(min(wave_calls), 1.0,
                        "wave budget must not include Phase 0 time")
        self.assertGreaterEqual(len(wave_calls), 1)

    async def test_phase0_slice_is_enforced(self):
        from unittest.mock import patch
        wave_calls = []

        async def hung_phase0(*args, **kwargs):
            await asyncio.sleep(30)
            return {}

        async def recorder(state):
            wave_calls.append(state.elapsed)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline", hung_phase0), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            start = time.time()
            result = await run_poison_assault(**self._args(max_duration=2))
            wall = time.time() - start

        self.assertEqual(len(result), 4)
        # slice = min(max_duration, cap) = 2s → pipeline cancelled, no hang
        self.assertLess(wall, 10, "Phase 0 must be cancelled at its slice")
        self.assertGreaterEqual(len(wave_calls), 1,
                                "waves must still run after a cancelled Phase 0")


class TestAdaptiveController(unittest.TestCase):
    """The controller must react to real request latency, not phase length."""

    def _state(self, concurrency=100):
        st = PoisonState(target="example.com", seed_url="https://example.com/",
                         services=[], subs=[], scan_urls=["https://example.com/"],
                         scope_guard=None, session_manager=MagicMock(),
                         async_engine=MagicMock(), is_turbo=False)
        st.current_concurrency = concurrency
        return st

    def test_phase_duration_no_longer_changes_concurrency(self):
        # old bug: a 45s ffuf phase was treated as request latency, halving
        # concurrency and flagging a perfectly healthy server as strained
        st = self._state(100)
        st.track_latency(time.time() - 45)
        self.assertEqual(st.current_concurrency, 100)
        self.assertFalse(st.server_strained)
        self.assertEqual(st.baseline_time, 0.0)
        self.assertGreater(st.last_phase_duration, 40)

    def test_baseline_is_median_not_first_sample(self):
        st = self._state()
        st.track_request_latency(0.5)          # outlier as the very first sample
        for _ in range(15):
            st.track_request_latency(0.1)
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)

    def test_no_decision_before_warmup_and_bad_samples_ignored(self):
        st = self._state(100)
        for _ in range(15):
            st.track_request_latency(0.1)
        self.assertEqual(st.baseline_time, 0.0)
        self.assertEqual(st.current_concurrency, 100)
        st.track_request_latency(0)
        st.track_request_latency(-1)
        self.assertEqual(len(st.latency_window), 15)

    def test_slow_period_throttles_stepwise_not_endlessly(self):
        st = self._state(100)
        for _ in range(16):
            st.track_request_latency(0.1)          # baseline locked at 0.1
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)

        for _ in range(3):                         # samples 17-19: no tick yet
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 100)
        self.assertFalse(st.server_strained)

        for _ in range(5):                         # sample 24 → first tick
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 50)
        self.assertTrue(st.server_strained)
        self.assertAlmostEqual(st.baseline_time, 0.1, places=3)   # not re-armed

        for _ in range(8):                         # sample 32 → second tick
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 25)
        self.assertAlmostEqual(st.baseline_time, 1.0, places=3)   # confirmed

        for _ in range(16):                        # samples 33-48: stable slow
            st.track_request_latency(1.0)
        self.assertEqual(st.current_concurrency, 25)   # no endless halving
        self.assertFalse(st.server_strained)

    def test_recovery_lets_baseline_follow_improvement(self):
        st = self._state(100)
        for _ in range(16):
            st.track_request_latency(0.1)
        for _ in range(32):                        # strain → re-arm to 1.0
            st.track_request_latency(1.0)
        self.assertAlmostEqual(st.baseline_time, 1.0, places=3)
        for _ in range(64):                        # server recovers
            st.track_request_latency(0.1)
        self.assertLess(st.baseline_time, 0.6)
        self.assertFalse(st.server_strained)

    def test_start_wave_escalation_is_earned(self):
        st = self._state(100)
        st.start_wave()                            # wave 2, healthy → +50
        self.assertEqual(st.current_concurrency, 150)

        st.server_strained = True
        st.start_wave()
        self.assertEqual(st.current_concurrency, 150)

        st.server_strained = False
        st._last_reduce_ts = time.time()           # cooldown active
        st.start_wave()
        self.assertEqual(st.current_concurrency, 150)

        st._last_reduce_ts = time.time() - 100     # cooldown elapsed
        st.start_wave()
        self.assertEqual(st.current_concurrency, 200)

        # still-slow window blocks escalation even if the flag was cleared
        slow = self._state(100)
        for _ in range(16):
            slow.track_request_latency(0.1)
        for _ in range(8):
            slow.track_request_latency(1.0)        # tick 24 → 50 + strained
        self.assertEqual(slow.current_concurrency, 50)
        slow.server_strained = False
        slow._last_reduce_ts = time.time() - 100
        slow.start_wave()
        self.assertEqual(slow.current_concurrency, 50)

        # escalation is capped
        capped = self._state(480)
        capped.start_wave()
        self.assertEqual(capped.current_concurrency, 500)


class TestLatencyObserverWiring(unittest.IsolatedAsyncioTestCase):
    async def test_observer_is_wired_during_run_and_cleared_after(self):
        from unittest.mock import patch
        engine = MagicMock()
        captured = {}

        async def recorder(state):
            captured.setdefault("state", state)
            captured.setdefault("observer", state.async_engine.latency_observer)

        with patch("modules.waf.bypass_engine.waf_bypass_pipeline",
                   new=AsyncMock(return_value={})), \
             patch("runners.poison.orchestrator._adaptive_wave_loop", recorder), \
             patch("modules.wordlists.WordlistProvider") as wl:
            wl.return_value._local = {"dir": "x"}
            wl.return_value.summary.return_value = ""
            await run_poison_assault(
                target="example.com", seed_url="https://example.com/",
                services=[{"url": "https://example.com/"}], subs=[],
                scan_urls=["https://example.com/"], scope_guard=None,
                session_manager=MagicMock(), async_engine=engine,
                is_turbo=False, max_duration=2, policy=None)

        state = captured["state"]
        wired = captured["observer"]           # captured while the run was live
        self.assertIsNone(engine.latency_observer,
                          "observer must be cleared before returning")
        self.assertIsNotNone(wired)
        self.assertIs(wired.__func__, PoisonState.track_request_latency)

    async def test_observer_callback_feeds_the_controller(self):
        state = PoisonState(target="example.com", seed_url="https://example.com/",
                            services=[], subs=[], scan_urls=["https://example.com/"],
                            scope_guard=None, session_manager=MagicMock(),
                            async_engine=MagicMock(), is_turbo=False)
        for _ in range(16):
            state.track_request_latency(0.1)
        self.assertAlmostEqual(state.baseline_time, 0.1, places=3)


class TestBackoffGate(unittest.IsolatedAsyncioTestCase):
    """429/403 backoff must also hold the generators that bypass the engine."""

    def _state(self):
        return PoisonState(target="example.com", seed_url="https://example.com/",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"], scope_guard=None,
                           session_manager=MagicMock(), async_engine=MagicMock(),
                           is_turbo=False)

    def test_limiter_reports_backoff_window(self):
        from core.host_ratelimit import HostRateLimiter
        lim = HostRateLimiter(default_max_concurrent=5)
        self.assertFalse(lim.is_backing_off("example.com"))   # unknown host

        lim._get_or_create("example.com")
        self.assertFalse(lim.is_backing_off("example.com"))   # no incident yet
        lim.release("example.com", 429)                       # rate limited
        self.assertTrue(lim.is_backing_off("example.com"))
        # window expires
        st = lim._hosts["example.com"]
        st.backoff_until = time.time() - 1
        self.assertFalse(lim.is_backing_off("example.com"))

    def test_helper_never_false_positives_on_mock_engines(self):
        state = self._state()          # engine is a bare MagicMock
        self.assertFalse(_hold_for_backoff(state, "x"))
        self.assertEqual(state._backoff_notice_wave, -1)

    async def test_bruteforce_holds_and_notices_once(self):
        from core.host_ratelimit import HostRateLimiter
        from unittest.mock import patch

        state = self._state()
        lim = HostRateLimiter(default_max_concurrent=5)
        lim._get_or_create("example.com")
        lim.release("example.com", 429)
        state.async_engine = MagicMock()
        state.async_engine.host_limiter = lim

        with patch("runners.poison.flood._run_ffuf", new=AsyncMock(return_value=[])) as ffuf:
            await phase_bruteforce(state)
            await phase_bruteforce(state)

        ffuf.assert_not_called()        # ffuf never dispatched during backoff
        self.assertEqual(state._backoff_notice_wave, state.wave)   # logged once/wave

        # backoff expired → generator runs again
        lim._hosts["example.com"].backoff_until = time.time() - 1
        with patch("runners.poison.flood._run_ffuf", new=AsyncMock(return_value=[])) as ffuf2:
            await phase_bruteforce(state)
        self.assertGreaterEqual(ffuf2.call_count, 1)


class TestBudgetAccounting(unittest.IsolatedAsyncioTestCase):
    """Generators that bypass ahttp_send must debit max_requests."""

    def _state(self, policy):
        return PoisonState(target="example.com", seed_url="https://example.com/",
                           services=[{"url": "https://example.com/"}], subs=[],
                           scan_urls=["https://example.com/"], scope_guard=None,
                           session_manager=MagicMock(), async_engine=MagicMock(),
                           is_turbo=False, policy=policy)

    def test_charge_is_exact_and_clamped(self):
        from core.policy import ScanPolicy
        p = ScanPolicy("example.com", max_requests=100, max_concurrency=50)
        self.assertEqual(p.charge(40, reason="ffuf:x"), 40)
        self.assertEqual(p.requests_sent, 40)
        self.assertEqual(p.charge(90, reason="ffuf:x"), 60)   # clamped to room
        self.assertEqual(p.requests_sent, 100)
        self.assertEqual(p.charge(10, reason="ffuf:x"), 0)    # empty budget
        unlimited = ScanPolicy("example.com", max_requests=None)
        self.assertEqual(unlimited.charge(5000, reason="x"), 5000)

    def test_run_ffuf_debits_and_truncates_to_budget(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=120, max_concurrency=50)
        words = [f"w{i}" for i in range(1000)]
        with patch("runners.poison.flood._find_tool", return_value="/usr/bin/true"):
            out = asyncio.run(_run_ffuf("https://example.com/", words, "",
                                        10, timeout=5, policy=p))
        # 120 room - 10 calibration allowance = 110 words, charge 110+10
        self.assertEqual(p.requests_sent, 120)
        self.assertEqual(out, [])

    def test_run_ffuf_charges_nothing_below_overhead(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=5, max_concurrency=50)
        with patch("runners.poison.flood._find_tool", return_value="/usr/bin/true"):
            out = asyncio.run(_run_ffuf("https://example.com/", ["a"] * 50,
                                        "", 10, timeout=5, policy=p))
        self.assertEqual(out, [])
        self.assertEqual(p.requests_sent, 0)

    async def test_exhaust_blocked_when_budget_cannot_cover_sockets(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=700, max_concurrency=50)
        state = self._state(p)
        with patch("modules.web.server_side.connection_exhaust.ConnectionExhaust.run",
                   new=AsyncMock(return_value={})) as run_mock:
            await phase_connection_exhaust(state)
        run_mock.assert_not_called()
        self.assertEqual(p.requests_sent, 0)

    async def test_exhaust_debits_750_when_it_runs(self):
        from core.policy import ScanPolicy
        from unittest.mock import patch
        p = ScanPolicy("example.com", max_requests=5000, max_concurrency=50)
        state = self._state(p)
        with patch("modules.web.server_side.connection_exhaust.ConnectionExhaust.run",
                   new=AsyncMock(return_value={})) as run_mock:
            await phase_connection_exhaust(state)
        run_mock.assert_called_once()
        self.assertEqual(p.requests_sent, 750)

    def test_smuggle_bound_is_documented_not_invented(self):
        from modules.web.server_side.smuggling import SMUGGLE_REQUEST_BOUND, TE_TE_OBFUSCATIONS
        self.assertEqual(SMUGGLE_REQUEST_BOUND, 6 + 2 * len(TE_TE_OBFUSCATIONS) + 8)
        self.assertGreater(SMUGGLE_REQUEST_BOUND, 10)

    def test_uncounted_tool_is_gated_not_debited(self):
        from core.policy import ScanPolicy
        from core.external_tools import (_uncounted_tool_allowed,
                                         UNCOUNTED_TOOL_FLOOR, run_dalfox)
        p = ScanPolicy("example.com", max_requests=UNCOUNTED_TOOL_FLOOR - 1,
                       max_concurrency=50)
        self.assertFalse(_uncounted_tool_allowed(p, "dalfox"))
        self.assertTrue(_uncounted_tool_allowed(None, "dalfox"))
        # gate fires before any subprocess is spawned
        self.assertEqual(run_dalfox(["https://example.com/?q=1"], policy=p), [])
        self.assertEqual(p.requests_sent, 0)


class TestPostPayloadPass(unittest.IsolatedAsyncioTestCase):
    """GET-only flood misses reflected sinks in form bodies."""

    def _state(self):
        st = PoisonState(target="example.com", seed_url="https://example.com/",
                         services=[{"url": "https://example.com/"}], subs=[],
                         scan_urls=["https://example.com/search"],
                         scope_guard=None, session_manager=MagicMock(),
                         async_engine=MagicMock(), is_turbo=False)
        st.max_duration = 600
        st.params = {"/search": ["q"]}
        return st

    async def test_reflector_is_fuzzed_and_detected(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        from urllib.parse import parse_qs
        state = self._state()
        post_bodies = []

        async def fake(url, method="GET", data=None, headers=None, **kw):
            if method != "POST":
                return {"status": 200, "body": "", "headers": {}, "waf": []}
            post_bodies.append(data)
            if len(post_bodies) == 1:
                value = parse_qs(data)["q"][0]
                return {"status": 200, "body": f"echo {value}",
                        "headers": {}, "waf": ["cloudflare"]}
            return {"status": 200,
                    "body": 'echo <img src=x onerror=alert(1)>',
                    "headers": {}, "waf": ["cloudflare"]}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)

        # 1 canary + 1 param x 1 type x 3 payloads (test uses ["xss"] only)
        self.assertEqual(len(post_bodies), 4)
        self.assertGreaterEqual(found, 1)
        hits = [f for f in state.findings if f["detail"].startswith("POST q |")]
        self.assertTrue(hits, "POST finding must be labelled with its method/param")
        self.assertEqual(hits[0]["waf"], "cloudflare")

    async def test_non_reflector_costs_one_request_only(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        state = self._state()
        calls = []

        async def fake(url, method="GET", **kw):
            if method == "POST":
                calls.append(url)
                return {"status": 200, "body": "nothing echoed",
                        "headers": {}, "waf": []}
            return {"status": 200, "body": "", "headers": {}, "waf": []}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)
        self.assertEqual(len(calls), 1)      # canary only, no fuzzing
        self.assertEqual(found, 0)

    async def test_method_not_allowed_is_skipped(self):
        from modules.scanners.scanner import SmartPayloadGenerator
        state = self._state()
        calls = []

        async def fake(url, method="GET", **kw):
            if method == "POST":
                calls.append(url)
                return {"status": 405, "body": "", "headers": {}, "waf": []}
            return {"status": 200, "body": "", "headers": {}, "waf": []}

        state.async_engine.ahttp_send = fake
        found = await _post_payload_pass(
            state, ["https://example.com/search"], ["xss"], False,
            SmartPayloadGenerator.generate)
        self.assertEqual(len(calls), 1)
        self.assertEqual(found, 0)


class TestPayloadFloodBaselineGuard(unittest.IsolatedAsyncioTestCase):
    """Regression (2026-10-05): empty baselines must never make the guarded
    markers fire. The wave tail (5-10s left) reuses the per-URL cache
    instead of blanking it; URLs with no baseline at all are skipped."""

    def _state(self, time_left: float) -> PoisonState:
        st = PoisonState(
            target="example.com", seed_url="https://example.com/page",
            services=[], subs=[], scan_urls=["https://example.com/page"],
            scope_guard=None, session_manager=MagicMock(),
            async_engine=MagicMock(), is_turbo=False,
        )
        # time_left is a property: max_duration - elapsed
        st.start_time = time.time() - (st.max_duration - time_left)
        st.params = {"/page": ["q"]}
        return st

    async def test_no_baseline_no_cache_never_fires(self):
        st = self._state(time_left=7.0)  # inside the old FP window (5-10s)
        st.async_engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "headers": {}, "waf": [],
                          "body": "Order 49 confirmed"})
        await phase_payload_flood(st)
        self.assertEqual(
            st.findings, [],
            "marker matched with no baseline -> must be skipped, not reported")

    async def test_cached_baseline_keeps_detection_alive(self):
        st = self._state(time_left=7.0)
        st._url_baselines = {"https://example.com/page": "static index page"}
        st.async_engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "headers": {}, "waf": [],
                          "body": "value: 49"})
        await phase_payload_flood(st)
        self.assertTrue(
            any(f["type"] == "ssti" for f in st.findings),
            "a cached baseline must keep tail detection working")


if __name__ == "__main__":
    unittest.main()
