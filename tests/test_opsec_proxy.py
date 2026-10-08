"""OPSEC proxy semantics: env auto-load default, --no-proxy escape hatch."""
import os
import unittest

import core.proxy_manager as pm_mod
from core.proxy_manager import setup_proxy

ENV_KEYS = ("VERDAMT_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")
ENV_VALUE = "http://127.0.0.1:19099"


class TestProxyEnvAutoload(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in ENV_KEYS}
        self._saved_mgr = pm_mod.GLOBAL_PROXY_MGR
        self._saved_gate = pm_mod._ENV_FALLBACK_OK
        for k in ENV_KEYS:
            os.environ.pop(k, None)
        os.environ["VERDAMT_PROXY"] = ENV_VALUE

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        pm_mod.GLOBAL_PROXY_MGR = self._saved_mgr
        pm_mod._ENV_FALLBACK_OK = self._saved_gate

    def test_env_autoload_by_default(self):
        """VERDAMT_PROXY alone must activate the proxy (no flags needed)."""
        mgr = setup_proxy()
        self.assertEqual(mgr.current_proxy, ENV_VALUE)

    def test_use_env_false_keeps_direct(self):
        """--no-proxy: env configured but scan stays direct."""
        mgr = setup_proxy(use_env=False)
        self.assertFalse(mgr.current_proxy)
        from core.proxy_manager import resolve_proxy
        self.assertIsNone(resolve_proxy())  # raw-path fallback juga ke-gate

    def test_explicit_proxy_wins(self):
        mgr = setup_proxy(proxy="socks5://127.0.0.1:9050", use_env=False)
        self.assertEqual(mgr.current_proxy, "socks5://127.0.0.1:9050")

    def test_explicit_wins_over_env(self):
        mgr = setup_proxy(proxy="socks5://10.0.0.2:1080")
        self.assertEqual(mgr.current_proxy, "socks5://10.0.0.2:1080")


if __name__ == "__main__":
    unittest.main()
