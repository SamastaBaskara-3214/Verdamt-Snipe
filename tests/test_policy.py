import unittest
from unittest.mock import patch

from core.policy import ScanPolicy
from core.client import AsyncNetworkEngine, http_send
from verd import parse_scan_policy_options


class TestScanPolicy(unittest.TestCase):
    def test_scope_and_ports(self):
        policy = ScanPolicy(
            "https://example.com",
            allowed_hosts=("192.0.2.10",),
            allowed_ports=(443,),
        )

        self.assertTrue(policy.allows_url("https://example.com/login"))
        self.assertTrue(policy.allows_url("https://api.example.com/v1"))
        self.assertFalse(policy.allows_url("https://other.example.net/"))
        self.assertFalse(policy.allows_url("http://example.com/"))
        self.assertFalse(policy.allows_url("https://example.com:8443/"))
        self.assertTrue(policy.allows_url("https://192.0.2.10/"))

        self.assertEqual(
            policy.canonical_url("https://192.0.2.10/login#fragment"),
            "https://192.0.2.10/login",
        )
        self.assertEqual(
            policy.filter_urls(["https://192.0.2.10/a", "https://outside.example.net/b"]),
            ["https://192.0.2.10/a"],
        )

    def test_authorize_host_grants_discovered_origin_ip(self):
        policy = ScanPolicy("https://example.com")

        # Sebelum authorize: IP origin dibuang oleh scope filter
        self.assertFalse(policy.allows_url("https://192.0.2.50/"))
        self.assertEqual(policy.filter_urls(["https://192.0.2.50/a"]), [])

        policy.authorize_host("192.0.2.50")
        self.assertTrue(policy.allows_url("https://192.0.2.50/login"))
        self.assertEqual(
            policy.filter_urls(
                ["https://192.0.2.50/a", "https://outside.example.net/b"]
            ),
            ["https://192.0.2.50/a"],
        )

        # Host lain TETAP diblokir — authorize bersifat exact-host
        self.assertFalse(policy.allows_url("https://outside.example.net/"))
        # Domain utama tetap lolos
        self.assertTrue(policy.allows_url("https://example.com/"))
        # Idempoten + hostname dengan port tetap match (port gate terpisah)
        policy.authorize_host("192.0.2.50")
        self.assertTrue(policy.allows_host("192.0.2.50:8443"))
        self.assertEqual(policy.filter_urls(["https://192.0.2.50/"]), ["https://192.0.2.50"])

    def test_request_budget_is_atomic(self):
        policy = ScanPolicy("example.com", max_requests=2)

        self.assertTrue(policy.authorize_request("https://example.com/one").allowed)
        self.assertTrue(policy.authorize_request("https://example.com/two").allowed)
        denied = policy.authorize_request("https://example.com/three")

        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, "request_budget_exhausted")
        self.assertEqual(policy.requests_sent, 2)
        self.assertEqual(policy.requests_remaining, 0)

    def test_passive_policy_rejects_active_methods_and_tools(self):
        policy = ScanPolicy("example.com", mode="passive")

        self.assertTrue(policy.authorize_request("https://example.com/", "GET").allowed)
        post = policy.authorize_request("https://example.com/submit", "POST")
        self.assertFalse(post.allowed)
        self.assertEqual(post.reason, "method_not_allowed_in_passive_mode:POST")
        self.assertTrue(policy.check_tool("gau").allowed)
        self.assertFalse(policy.check_tool("nuclei").allowed)

    def test_timeout_is_clamped(self):
        policy = ScanPolicy("example.com", max_timeout=7)

        self.assertEqual(policy.clamp_timeout(None), 7)
        self.assertEqual(policy.clamp_timeout(30), 7)
        self.assertEqual(policy.clamp_timeout(2), 2)

    def test_sync_transport_denies_before_network(self):
        policy = ScanPolicy("example.com")

        response = http_send("https://outside.example.net/", policy=policy)

        self.assertEqual(response["status"], 0)
        self.assertEqual(response["error"], "policy_denied:out_of_scope_host")

    def test_cli_policy_options(self):
        options = parse_scan_policy_options([
            "--passive",
            "--max-requests=25",
            "--max-concurrency", "4",
            "--request-timeout", "5",
            "--allowed-hosts", "example.com,192.0.2.10",
            "--allowed-ports", "443,8443",
        ])

        self.assertEqual(options["mode"], "passive")
        self.assertEqual(options["max_requests"], 25)
        self.assertEqual(options["max_concurrency"], 4)
        self.assertEqual(options["max_timeout"], 5.0)
        self.assertEqual(options["allowed_hosts"], ("example.com", "192.0.2.10"))
        self.assertEqual(options["allowed_ports"], (443, 8443))


class TestPolicyAsyncTransport(unittest.IsolatedAsyncioTestCase):
    async def test_async_transport_denies_before_network(self):
        policy = ScanPolicy("example.com")
        with patch("core.curl_cffi_transport.CURL_CFFI_AVAILABLE", False):
            engine = AsyncNetworkEngine(policy=policy)
            try:
                response = await engine.ahttp_send("https://outside.example.net/")
            finally:
                await engine.close()

        self.assertEqual(response["status"], 0)
        self.assertEqual(response["error"], "policy_denied:out_of_scope_host")


if __name__ == "__main__":
    unittest.main()
