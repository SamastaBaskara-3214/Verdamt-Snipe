import asyncio
import unittest
from unittest.mock import MagicMock

from modules.web.client_side.csrf_verify import CSRFVerifier
from modules.web.client_side.postmessage_analyzer import PostMessageAnalyzer
from modules.web.client_side.clickjacking_verify import ClickjackingInspector
from modules.web.recon_crawlers.websocket_recon import WebSocketSniffer
from modules.web.client_side.proto_pollution_verify import ProtoPollutionVerifier
from modules.web.api_auth.oauth_auditor import OAuthAuditor
from modules.web.client_side.cors_verify import CORSVerifier
from modules.web.recon_crawlers.spa_crawler import SPACrawler


class TestPlaywrightSuiteModules(unittest.TestCase):
    def test_module_instantiations(self):
        target = "https://example.com"
        sm = MagicMock()
        sm.cookies = {"example.com": {"session": "test"}}

        csrf = CSRFVerifier(target, sm)
        self.assertEqual(csrf.target_url, target)

        pm = PostMessageAnalyzer(target)
        self.assertEqual(pm.target_url, target)

        cj = ClickjackingInspector(target)
        self.assertEqual(cj.target_url, target)

        ws = WebSocketSniffer(target)
        self.assertEqual(ws.target_url, target)

        pp = ProtoPollutionVerifier(target)
        self.assertEqual(pp.target_url, target)

        oa = OAuthAuditor(target)
        self.assertEqual(oa.target_url, target)

        cors = CORSVerifier(target)
        self.assertEqual(cors.target_url, target)

        spa = SPACrawler(target)
        self.assertEqual(spa.target_url, target)

    def test_module_execution_with_mock_pool(self):
        async def _test_async():
            target = "https://example.com"
            sm = MagicMock()
            sm.cookies = {"example.com": {"session": "test"}}

            from unittest.mock import AsyncMock, patch
            mock_context = AsyncMock()
            mock_page = AsyncMock()
            mock_page.on = MagicMock()
            mock_context.new_page.return_value = mock_page
            mock_page.evaluate.return_value = {}
            mock_page.query_selector_all.return_value = []

            with patch("core.browser_pool.SharedBrowserPool.new_context", return_value=mock_context):
                res_csrf = await CSRFVerifier(target, sm).run()
                self.assertIsInstance(res_csrf, list)

                res_pm = await PostMessageAnalyzer(target).run()
                self.assertIsInstance(res_pm, list)

                res_cj = await ClickjackingInspector(target).run()
                self.assertIsInstance(res_cj, list)

                res_ws = await WebSocketSniffer(target).run()
                self.assertIsInstance(res_ws, list)

                res_pp = await ProtoPollutionVerifier(target).run()
                self.assertIsInstance(res_pp, list)

                res_oa = await OAuthAuditor(target).run()
                self.assertIsInstance(res_oa, list)

                res_cors = await CORSVerifier(target).run()
                self.assertIsInstance(res_cors, list)

                res_spa = await SPACrawler(target).run()
                self.assertIsInstance(res_spa, dict)

        asyncio.run(_test_async())


if __name__ == "__main__":
    unittest.main()
