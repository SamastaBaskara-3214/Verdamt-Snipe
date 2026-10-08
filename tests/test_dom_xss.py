import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.web.client_side.dom_xss import DOMXSSScanner


class TestDOMXSSScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DOMXSSScanner(urls=["https://example.com/app.js"])

    def test_find_sources(self):
        js_code = """
        function getQuery() {
            var url = location.href;
            var hash = window.location.hash;
            return hash;
        }
        """
        sources = self.scanner._find_sources(js_code)
        self.assertGreaterEqual(len(sources), 2)

    def test_find_sinks(self):
        js_code = """
        function render(data) {
            document.write(data);
            element.innerHTML = data;
        }
        """
        sinks = self.scanner._find_sinks(js_code)
        self.assertGreaterEqual(len(sinks), 2)

    def test_taint_tracing(self):
        js_code = """
        function vulnerable() {
            var payload = location.hash;
            document.getElementById("output").innerHTML = payload;
        }
        """
        sources = self.scanner._find_sources(js_code)
        sinks = self.scanner._find_sinks(js_code)
        flows = self.scanner._trace_taint(js_code, sources, sinks)
        self.assertGreater(len(flows), 0)
        self.assertIn("innerHTML", flows[0]["sink"])

    def test_sanitizer_filter(self):
        js_code = """
        function safe() {
            var payload = location.hash;
            var clean = DOMPurify.sanitize(payload);
            document.getElementById("output").innerHTML = clean;
        }
        """
        sources = self.scanner._find_sources(js_code)
        sinks = self.scanner._find_sinks(js_code)
        flows = self.scanner._trace_taint(js_code, sources, sinks)
        # Should be filtered out due to DOMPurify sanitizer guard
        self.assertEqual(len(flows), 0)

    def test_dynamic_verification_method_exists(self):
        self.assertTrue(hasattr(self.scanner, "_verify_dynamic_pocs"))


if __name__ == "__main__":
    unittest.main()

