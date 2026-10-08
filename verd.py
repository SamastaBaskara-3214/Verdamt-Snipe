#!/usr/bin/env python3
"""Entry point — parsing + orchestration live in core.cli_parser (Tahap 2).

Re-exports every name the test-suite imports via `from verd import ...`
and keeps the `verd:main` console entry (pyproject.toml) working.
"""
import asyncio
import sys

from core.cli_parser import (  # noqa: F401  (re-export for tests/legacy)
    VERSION, AUTHOR, VULN_THREADS,
    parse_target, parse_mode, parse_scan_args, parse_cli_headers,
    parse_scan_policy_options, _flag_value, _resolve_secret,
    _VALUE_FLAGS, _SHORT_ALIASES, interactive_mode_select,
    seed_session_headers, _active_proxy, phase_verify_report,
    async_main, main_cli, _execute_mode,
    _run_app_mode, _run_assault_mode, _run_poisoning_mode,
)
from core.ui import R, N  # noqa: F401


def main():
    try:
        asyncio.run(main_cli())
    except KeyboardInterrupt:
        print(f"\n{R}[!] Interrupted by user. Exiting.{N}")
        sys.exit(0)


if __name__ == "__main__":
    main()
