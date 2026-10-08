import unittest
from core.secret_scanner import SecretScanner, shannon_entropy
from modules.web.api_auth.graphql_profiler import GraphQLProfiler


class TestRoadmapEnhancements(unittest.TestCase):
    def test_shannon_entropy(self):
        low_ent = shannon_entropy("aaaaaaa")
        high_ent = shannon_entropy("4kL9Z2#mP!8xQ0wN")
        self.assertLess(low_ent, 1.0)
        self.assertGreater(high_ent, 3.5)

    def test_secret_scanner_detection(self):
        sample_body = """
        var aws_key = "AKIAIOSFODNN7EXAMPLE";
        var google_key = "AIzaSyD1234567890abcdefghijklmnopqrstuvWXYZ";
        """
        findings = SecretScanner.scan_response("https://example.com/js", sample_body)
        self.assertGreaterEqual(len(findings), 2)
        types = {f["title"] for f in findings}
        self.assertIn("Leaked Secret: AWS Access Key ID", types)
        self.assertIn("Leaked Secret: Google API Key", types)

    def test_graphql_profiler_instantiation(self):
        profiler = GraphQLProfiler("https://example.com", async_engine=None)
        self.assertEqual(profiler.seed_url, "https://example.com")


if __name__ == "__main__":
    unittest.main()
