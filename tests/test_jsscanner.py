import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock
from modules.recon.jsscanner import JSScanner
from core.go_bridge import go_bridge

class TestJSScanner(unittest.TestCase):

    def test_analyze_content_python_fallback(self):
        scanner = JSScanner(urls=["http://example.com/app.js"])
        sample_js = '''
            var api_key = "AIzaSyD12345678901234567890123456789012";
            fetch("/api/v1/user/profile");
        '''
        findings, endpoints = scanner._analyze_content("http://example.com/app.js", sample_js, ["Cloudflare"], 0.05, 200)
        
        self.assertTrue(any(f["type"] == "js_secret_google_api" for f in findings))
        self.assertIn("/api/v1/user/profile", endpoints)

    def test_go_bridge_js_scan_batch(self):
        if not go_bridge.is_available():
            self.skipTest("Go Engine binary / socket not available")

        files = [{
            "url": "http://example.com/main.js",
            "content": 'var secret = "AKIAIOSFODNN7EXAMPLE"; fetch("/v2/internal/config");',
            "status": 200,
            "time": 0.02,
            "waf": "None"
        }]

        res = go_bridge.js_scan_batch(files)
        self.assertIsNotNone(res)
        self.assertTrue(any(f["type"] == "js_secret_aws_access_key" for f in res["findings"]))
        self.assertIn("/v2/internal/config", res["endpoints"])

    def test_scanner_run_with_mock_async_engine(self):
        mock_engine = MagicMock()
        mock_engine.ahttp_send = AsyncMock(return_value={
            "status": 200,
            "body": 'var slack = "xox' + 'b-1234567890-123456789012-abcdefghijklmnopqrstuvwx"; fetch("/api/v1/test");',
            "waf": [],
            "time": 0.01
        })

        scanner = JSScanner(urls=["http://example.com/bundle.js"], async_engine=mock_engine)
        loop = asyncio.new_event_loop()
        try:
            findings, endpoints = loop.run_until_complete(scanner.run())
            self.assertTrue(len(findings) > 0)
            self.assertTrue(len(endpoints) > 0)
        finally:
            loop.close()

if __name__ == '__main__':
    unittest.main()
