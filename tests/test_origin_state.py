import unittest
from unittest.mock import AsyncMock, patch


class TestOriginServicesNotMutated(unittest.IsolatedAsyncioTestCase):
    async def test_state_domain_utuh_modul_dalam_tetap_lihat_ip(self):
        from runners.vuln_assault import run_vuln_assault

        services = [{
            "url": "https://target.go.id/",
            "origin_ip": "203.0.113.5",
            "waf": [],
        }]
        jwt_mock = AsyncMock(return_value=[])

        with patch("modules.web.api_auth.jwt_hunter.scan_jwt", new=jwt_mock), \
             patch("modules.web.server_side.host_header.scan_host_header",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.server_side.crlf.scan_crlf",
                   new=AsyncMock(return_value=[])), \
             patch("modules.auth.bypass.WAFBypass.h2_smuggle_check",
                   return_value={}), \
             patch("runners.vuln_assault.run_nuclei",
                   return_value=[]) as nuclei_mock, \
             patch("runners.vuln_assault.run_dalfox", return_value=[]):
            findings, _ = await run_vuln_assault(
                "target.go.id", services, [], {}, None, None, None,
                vuln_threads=5, module_flags=None, policy=None,
            )

        # 1) list caller TIDAK berubah -> state file tetap domain
        self.assertEqual(services[0]["url"], "https://target.go.id/")
        self.assertEqual(services[0]["origin_ip"], "203.0.113.5")

        # 2) nuclei tetap dikasih target IP (perilaku lama dipertahankan)
        nuclei_targets = nuclei_mock.call_args.args[0]
        self.assertTrue(
            any("203.0.113.5" in t for t in nuclei_targets), nuclei_targets)

        # 3) modul web dalem tetap lihat primary_url versi IP
        self.assertEqual(jwt_mock.call_args.args[0], "https://203.0.113.5/")


if __name__ == "__main__":
    unittest.main()
