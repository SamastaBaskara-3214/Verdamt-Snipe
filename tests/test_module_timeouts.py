import asyncio
import time
import unittest
from unittest.mock import AsyncMock, patch


class TestModuleTimeouts(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_membatasi_modul_dan_log(self):
        from runners import vuln_assault

        async def slow_jwt(*args, **kwargs):
            await asyncio.sleep(60)

        with patch.dict(vuln_assault.MODULE_TIMEOUTS, {"jwt": 0.3}), \
             patch("runners.vuln_assault.w") as mock_w, \
             patch("modules.web.jwt_hunter.scan_jwt",
                   new=AsyncMock(side_effect=slow_jwt)), \
             patch("modules.web.host_header.scan_host_header",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.crlf.scan_crlf",
                   new=AsyncMock(return_value=[])), \
             patch("runners.vuln_assault.run_nuclei", return_value=[]), \
             patch("runners.vuln_assault.run_dalfox", return_value=[]):
            t0 = time.monotonic()
            findings, wafs = await vuln_assault.run_vuln_assault(
                "example.com", [], [], {}, None, None, None,
                vuln_threads=5, module_flags=None, policy=None,
            )
            elapsed = time.monotonic() - t0

        # modul tidur 60s tapi phase harus selesai jauh sebelum itu
        self.assertLess(elapsed, 15)
        self.assertEqual(findings, [])
        msgs = [c.args[0] for c in mock_w.call_args_list if c.args]
        self.assertTrue(
            any("jwt" in m and "timed out" in m for m in msgs), msgs)

    async def test_backstop_lebih_dari_timeout_internal(self):
        from runners import vuln_assault as va

        self.assertGreater(va.MODULE_TIMEOUTS["nuclei"], 300)
        self.assertGreater(va.MODULE_TIMEOUTS["dalfox"], 180)
        self.assertGreater(va.MODULE_TIMEOUTS["oob"], 60)

    def test_semua_modul_gather_punya_timeout(self):
        from runners import vuln_assault as va

        expected = {"nuclei", "dalfox", "internal_injection", "smuggling",
                    "oob", "jwt", "host_header", "crlf", "stored_xss", "idor"}
        self.assertEqual(set(va.MODULE_TIMEOUTS), expected)


if __name__ == "__main__":
    unittest.main()
