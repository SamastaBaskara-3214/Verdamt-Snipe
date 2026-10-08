import unittest
from unittest.mock import AsyncMock, patch


class TestFocusMode(unittest.IsolatedAsyncioTestCase):
    async def test_focus_mematikan_scanner_generik(self):
        from runners.vuln_assault import run_vuln_assault

        with patch("runners.vuln_assault.run_nuclei",
                   return_value=[]) as nuclei_mock, \
             patch("runners.vuln_assault.run_dalfox",
                   return_value=[]) as dalfox_mock, \
             patch("modules.web.api_auth.jwt_hunter.scan_jwt",
                   new=AsyncMock(return_value=[])) as jwt_mock, \
             patch("modules.web.server_side.host_header.scan_host_header",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.server_side.crlf.scan_crlf",
                   new=AsyncMock(return_value=[])):
            findings, _ = await run_vuln_assault(
                "example.com", [],
                ["https://example.com/a?x=1"], {"a": ["x"]},
                None, None, None,
                vuln_threads=5, module_flags={"jwt": True}, policy=None,
            )

        nuclei_mock.assert_not_called()
        dalfox_mock.assert_not_called()
        jwt_mock.assert_called()
        self.assertEqual(findings, [])

    async def test_tanpa_focus_scanner_generik_jalan(self):
        from runners.vuln_assault import run_vuln_assault

        with patch("runners.vuln_assault.run_nuclei",
                   return_value=[]) as nuclei_mock, \
             patch("runners.vuln_assault.run_dalfox",
                   return_value=[]) as dalfox_mock, \
             patch("modules.web.api_auth.jwt_hunter.scan_jwt",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.server_side.host_header.scan_host_header",
                   new=AsyncMock(return_value=[])), \
             patch("modules.web.server_side.crlf.scan_crlf",
                   new=AsyncMock(return_value=[])):
            await run_vuln_assault(
                "example.com", [],
                ["https://example.com/a?x=1"], {"a": ["x"]},
                None, None, None,
                vuln_threads=5, module_flags=None, policy=None,
            )

        nuclei_mock.assert_called_once()
        dalfox_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
