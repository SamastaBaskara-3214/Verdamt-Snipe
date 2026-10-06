"""Mode-gate POST: semua POST-body injection hanya boleh di mode 4 (poisoning).

Mode 3 (--assault) dan full = path discovery + GET param injection saja.
Yang diuji:
  1. default run_vuln_assault = allow_post False
  2. h2_smuggle_check (POST CL.TE) dilewati saat allow_post False
  3. OOB task xxe (POST XML) dibuang saat allow_post False
  4. stored_xss: allow_post False -> GET discovery, tanpa method POST
  5. stored_xss: default (True) -> flux POST lama dipertahankan
  6. VulnVerifier xxe_file: tanpa POST saat digate, POST saat diizinkan
  7. phase_verify_report: mode selain poisoning tidak mengirim POST verify
  8. poison.phase_vuln_assault = satu-satunya caller yang allow_post=True
"""
import inspect
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


class TestSignatureDefault(unittest.TestCase):
    def test_run_vuln_assault_default_dilarang_post(self):
        from runners.vuln_assault import run_vuln_assault
        sig = inspect.signature(run_vuln_assault)
        self.assertIn("allow_post", sig.parameters)
        self.assertIs(sig.parameters["allow_post"].default, False)


class _AssaultHarness(unittest.IsolatedAsyncioTestCase):
    """Patch modul berat supaya run_vuln_assault jalan tanpa jaringan."""

    def _patches(self):
        return [
            patch("runners.vuln_assault.run_nuclei", return_value=[]),
            patch("runners.vuln_assault.run_dalfox", return_value=[]),
            patch("modules.web.jwt_hunter.scan_jwt", new=AsyncMock(return_value=[])),
            patch("modules.web.host_header.scan_host_header", new=AsyncMock(return_value=[])),
            patch("modules.web.crlf.scan_crlf", new=AsyncMock(return_value=[])),
        ]

    async def _run(self, allow_post=None):
        from runners.vuln_assault import run_vuln_assault
        services = [{"url": "https://t.id/", "origin_ip": None, "waf": []}]
        kwargs = dict(module_flags=None, policy=None)
        if allow_post is not None:
            kwargs["allow_post"] = allow_post
        stack = [p for p in self._patches()]
        with stack[0], stack[1], stack[2], stack[3], stack[4]:
            return await run_vuln_assault(
                "t.id", services, [], {}, None, None, None,
                vuln_threads=5, **kwargs,
            )


class TestSmuggleGate(_AssaultHarness):
    async def test_default_tidak_panggil_h2_smuggle(self):
        with patch("modules.auth.bypass.WAFBypass.h2_smuggle_check",
                   return_value={}) as sm:
            await self._run()
        sm.assert_not_called()

    async def test_allow_post_true_panggil_h2_smuggle(self):
        with patch("modules.auth.bypass.WAFBypass.h2_smuggle_check",
                   return_value={}) as sm:
            await self._run(allow_post=True)
        self.assertEqual(sm.call_count, 1)


class TestOOBTaskBuild(unittest.TestCase):
    def _types(self, allow_post):
        from modules.extras.oob_detector import OOBDetector
        det = OOBDetector("t.id", [{"url": "https://t.id/"}],
                          {"/a": ["q1", "q2"]}, network_engine=None,
                          allow_post=allow_post)
        seen = []
        det._test_target = lambda task_type, url, param: seen.append(task_type) or task_type
        tasks = det._build_tasks()
        return tasks, seen

    def test_tanpa_post_tidak_ada_task_xxe(self):
        tasks, seen = self._types(False)
        self.assertNotIn("xxe", seen)
        # 1 path x 1 service x 2 param x 2 (ssrf+rce), tanpa xxe
        self.assertEqual(len(tasks), 4)

    def test_dengan_post_task_xxe_ada(self):
        _, seen = self._types(True)
        self.assertIn("xxe", seen)
        self.assertEqual(seen.count("xxe"), 1)


class TestStoredXSSGate(unittest.IsolatedAsyncioTestCase):
    def _hunter(self, allow_post):
        from modules.web.stored_xss import StoredXSSHunter
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(return_value={"status": 200, "body": "<form>"})
        kwargs = {} if allow_post is None else {"allow_post": allow_post}
        return StoredXSSHunter(["https://a.test/x"], engine, **kwargs), engine

    async def test_tanpa_post_get_discovery_saja(self):
        hunter, engine = self._hunter(allow_post=False)
        findings = await hunter.run()

        calls = engine.ahttp_send.call_args_list
        self.assertEqual(len(calls), len(hunter.FORMS))  # 1 GET per path, tanpa refetch
        for c in calls:
            self.assertNotEqual(c.kwargs.get("method"), "POST")

        self.assertEqual(len(findings), len(hunter.FORMS))
        for f in findings:
            self.assertEqual(f["type"], "form_endpoint")
            self.assertEqual(f["confidence"], "confirmed")

    async def test_tanpa_post_404_tidak_dilaporkan(self):
        from modules.web.stored_xss import StoredXSSHunter
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(return_value={"status": 404, "body": ""})
        hunter = StoredXSSHunter(["https://a.test/x"], engine, allow_post=False)
        findings = await hunter.run()
        self.assertEqual(findings, [])

    async def test_default_mode_masih_flux_post_lama(self):
        from modules.web.stored_xss import StoredXSSHunter
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(return_value={"status": 404, "body": ""})
        hunter = StoredXSSHunter(["https://a.test/x"], engine)  # default True
        await hunter.run()
        calls = engine.ahttp_send.call_args_list
        self.assertEqual(len(calls), len(hunter.FORMS))
        for c in calls:
            self.assertEqual(c.kwargs.get("method"), "POST")


class TestVulnVerifierGate(unittest.IsolatedAsyncioTestCase):
    def _finding(self, conf):
        return {"type": "xxe_file", "url": "https://t.id/xml",
                "confidence": conf, "title": "XXE"}

    async def test_tanpa_post_pakai_confidence(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(side_effect=AssertionError("POST terlarang"))
        from modules.scanners.scanner import VulnVerifier

        self.assertTrue(await VulnVerifier.verify(
            self._finding("confirmed"), engine, None, allow_post=False))
        self.assertFalse(await VulnVerifier.verify(
            self._finding("suspected"), engine, None, allow_post=False))
        engine.ahttp_send.assert_not_called()

    async def test_dengan_post_verifikasi_xxe_jalan(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "body": "root:x:0:0:"})
        from modules.scanners.scanner import VulnVerifier

        ok = await VulnVerifier.verify(self._finding("confirmed"), engine, None)
        self.assertTrue(ok)
        engine.ahttp_send.assert_awaited_once()
        self.assertEqual(engine.ahttp_send.call_args.kwargs.get("method"), "POST")


class TestPhaseVerifyReportMode(unittest.IsolatedAsyncioTestCase):
    async def _run(self, mode, engine):
        from verd import phase_verify_report
        findings = [{"type": "xxe_file", "title": "XXE",
                     "url": "https://t.id/xml", "confidence": "confirmed"}]
        await phase_verify_report("t.id", findings, [], [], [], [],
                                  time.time(), mode,
                                  async_engine=engine, session_manager=None)

    async def test_mode_assault_tidak_post_verify(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(side_effect=AssertionError("POST terlarang"))
        await self._run("assault", engine)
        engine.ahttp_send.assert_not_called()

    async def test_mode_poisoning_post_verify_dipakai(self):
        engine = MagicMock()
        engine.ahttp_send = AsyncMock(
            return_value={"status": 200, "body": "root:x:0:0:"})
        await self._run("poisoning", engine)
        self.assertEqual(engine.ahttp_send.call_count, 1)
        self.assertEqual(engine.ahttp_send.call_args.kwargs.get("method"), "POST")


class TestPoisonCallerOptIn(unittest.IsolatedAsyncioTestCase):
    async def test_phase_vuln_assault_allow_post_true(self):
        from runners import vuln_assault
        from runners.poison import phase_vuln_assault

        state = SimpleNamespace(
            target="t.id", origin_ip=None, services=[], scan_urls=set(), params={},
            scope_guard=None, session_manager=None, async_engine=None,
            current_concurrency=100, is_turbo=False, module_flags=None,
            policy=None, target_wafs=set(),
            track_latency=lambda t: None,
            extend_findings=lambda f: None,
        )
        mock = AsyncMock(return_value=([], set()))
        with patch.object(vuln_assault, "run_vuln_assault", new=mock):
            await phase_vuln_assault(state)
        self.assertIs(mock.call_args.kwargs.get("allow_post"), True)


if __name__ == "__main__":
    unittest.main()
