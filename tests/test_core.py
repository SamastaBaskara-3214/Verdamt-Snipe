import unittest
import sys
import os
from unittest.mock import AsyncMock, patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.scope import ScopeGuard
from core.state import SessionManager
from runners.shared import inject_query_payload, merge_params
from modules.auth.bypass import WAFBypass
from runners.poison import run_poison_assault
from core.ui import _MODES
from verd import parse_mode, parse_scan_args, seed_session_headers


class FakePoisonWordlistProvider:
    def __init__(self):
        self._local = {"dummy": ["dummy"]}

    def scan(self):
        return None

class TestVerdamtSnipeCore(unittest.TestCase):
    def test_scope_guard_host_in_scope(self):
        guard = ScopeGuard("example.com", include_subdomains=True)
        self.assertTrue(guard.host_in_scope("example.com"))
        self.assertTrue(guard.host_in_scope("sub.example.com"))
        self.assertTrue(guard.host_in_scope("deep.sub.example.com"))
        self.assertFalse(guard.host_in_scope("otherdomain.com"))
        self.assertFalse(guard.host_in_scope("example.com.attacker.com"))

    def test_scope_guard_canonical_url(self):
        guard = ScopeGuard("example.com", include_subdomains=True)
        self.assertEqual(
            guard.canonical_url("https://example.com/path/to/resource?q=1"),
            "https://example.com/path/to/resource?q=1"
        )
        self.assertEqual(
            guard.canonical_url("/path", base_url="https://sub.example.com/"),
            "https://sub.example.com/path"
        )
        self.assertEqual(
            guard.canonical_url("https://out-of-scope.com/"),
            ""
        )

    def test_inject_query_payload(self):
        url = "https://example.com/search?q=test&id=1"
        injected = inject_query_payload(url, "q", "injected_val")
        self.assertIn("q=injected_val", injected)
        self.assertIn("id=1", injected)

        # Non-existing param
        injected_new = inject_query_payload(url, "newparam", "val")
        self.assertIn("newparam=val", injected_new)

    def test_waf_detection(self):
        headers = {
            "Server": "cloudflare",
            "CF-RAY": "1234567abcd",
            "Content-Type": "text/html"
        }
        body = "Checking your browser..."
        detected = WAFBypass.detect_waf(headers, body)
        self.assertIn("cloudflare", detected)

    def test_merge_params(self):
        params = {"/": ["q", "id"]}
        merge_params(params, "/", ["id", "page", "limit"])
        self.assertEqual(sorted(params["/"]), sorted(["q", "id", "page", "limit"]))

    def test_parse_mode_uses_last_mode_flag(self):
        self.assertEqual(parse_mode(["--recon-light"]), "recon_light")
        self.assertEqual(parse_mode(["--recon"]), "recon")
        self.assertEqual(parse_mode(["--recon", "--full"]), "full")
        self.assertEqual(parse_mode(["--full", "--nuclei"]), "nuclei")

    def test_interactive_modes_have_cli_flags(self):
        mode_to_flag = {
            "recon_light": "--recon-light",
            "recon": "--recon",
            "app": "--app",
            "assault": "--assault",
            "poisoning": "--poisoning",
            "full": "--full",
            "nuclei": "--nuclei",
        }
        visible_modes = {mode_id for mode_id, _, _ in _MODES.values()}
        self.assertEqual(visible_modes, set(mode_to_flag))
        for mode_id, flag in mode_to_flag.items():
            self.assertEqual(parse_mode([flag]), mode_id)

    def test_parse_scan_args_supports_resume_without_target(self):
        target, flags, resume_path = parse_scan_args(["verd.py", "--resume", "outputs/example.com.state"])
        self.assertIsNone(target)
        self.assertEqual(flags, ["--resume", "outputs/example.com.state"])
        self.assertEqual(resume_path, "outputs/example.com.state")

    def test_parse_scan_args_supports_target_with_resume(self):
        target, flags, resume_path = parse_scan_args(["verd.py", "example.com", "--resume", "outputs/example.com.state"])
        self.assertEqual(target, "example.com")
        self.assertEqual(flags, ["--resume", "outputs/example.com.state"])
        self.assertEqual(resume_path, "outputs/example.com.state")

    def test_seed_session_headers_registers_auth_and_cookies(self):
        sm = SessionManager()
        seed_session_headers(
            sm,
            "https://example.com/app",
            {"Authorization": "Bearer abc123", "Cookie": "sid=one; theme=dark"},
        )
        self.assertEqual(sm.auth_tokens["example.com"], "Bearer abc123")
        self.assertEqual(sm.cookies["example.com"]["sid"], "one")
        self.assertEqual(sm.cookies["example.com"]["theme"], "dark")


class TestVerdamtSnipeCoreAsync(unittest.IsolatedAsyncioTestCase):
    async def test_run_poison_assault_returns_unpackable_result_when_duration_elapsed(self):
        with (
            patch("modules.wordlists.WordlistProvider", FakePoisonWordlistProvider),
            patch("modules.waf.bypass_engine.waf_bypass_pipeline", new=AsyncMock(return_value={})),
        ):
            result = await run_poison_assault(
                "example.com",
                "https://example.com/",
                [{"url": "https://example.com/", "waf": []}],
                [],
                ["https://example.com/"],
                None,
                None,
                None,
                max_duration=0,
            )

        findings, params, urls, wafs = result
        self.assertEqual(findings, [])
        self.assertEqual(params, {})
        self.assertEqual(urls, ["https://example.com/"])
        self.assertEqual(wafs, [])

if __name__ == "__main__":
    unittest.main()
