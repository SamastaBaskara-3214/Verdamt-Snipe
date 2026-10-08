"""orchestrator — verbatim split from poison.py (no logic changes)."""
import asyncio
import os
import re
import subprocess
import tempfile
import time
from collections import deque
from statistics import median
from urllib.parse import urlparse, urlencode
from typing import Dict, List, Optional, Set, Tuple
from core.external_tools import _find_tool
from core.ui import ph, i, w, s, p, G, C, B, N
from core.proxy_manager import get_global_proxy_manager
from modules.wordlists import WordlistProvider, PROVIDER
from runners.shared import inject_query_payload

from .flood import phase_bruteforce, phase_param_flood, phase_payload_flood
from .state import PHASE0_TIME_CAP, PoisonState, _budget_ok, _charge_external, _get_proxy_flag
from .wave import _hold_for_backoff



# Phase: Connection Exhaust

async def phase_connection_exhaust(state: PoisonState):
    """Connection Exhaust + adaptive monitoring."""
    from modules.web.connection_exhaust import ConnectionExhaust, EXHAUST_SOCKETS

    # Exhaust uses raw sockets (never billed by the policy), so it must stop
    # when the budget that governs every other generator is spent — and hold
    # while the host is already answering 429/403.
    if not _budget_ok(state):
        return
    if _hold_for_backoff(state, "connection exhaust"):
        return

    for sv in state.services[:2]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Exact debit: run() always attempts EXHAUST_SOCKETS connections.
        if not _charge_external(state, EXHAUST_SOCKETS, "connection-exhaust"):
            w(f"Budget cannot cover {EXHAUST_SOCKETS} exhaust sockets — skipping")
            break
        exhauster = ConnectionExhaust(
            sv["url"],
            timeout=min(30, int(state.time_left) // 2) if state.time_left > 5 else 10,
        )
        start = time.time()
        results = await exhauster.run()
        state.track_latency(start)

        if results.get("server_downgrade"):
            state.server_strained = True
        # Findings
        if results.get("total_time", 0) > 0:
            sl = results["slowloris"]
            pf = results["pool_flood"]
            cb = results["chunked_bomb"]
            total_refused = sl["refused"] + pf["refused"] + cb["refused"]
            total_open = sl["opened"] + cb["opened"]
            if total_refused > 50:
                state.add_finding({
                    "type": "conn_exhaust_pressure",
                    "title": "Connection Pool Under Pressure",
                    "url": sv["url"][:200],
                    "detail": f"{total_refused}/{total_open+total_refused} connections refused — pool exhaustion detected",
                    "confidence": "confirmed",
                })


# Phase: Cache Poisoning

async def phase_cache_poison(state: PoisonState):
    """Cache poisoning probe + delivery."""
    from modules.web.cache_poison import probe_unkeyed_headers, deliver_poisoned_payload

    if not _budget_ok(state):
        return

    base_urls = state.get_high_value_targets(5)
    for url in base_urls:
        if state.time_left < 5 or not _budget_ok(state):
            break
        start = time.time()
        findings = await probe_unkeyed_headers(url, state.async_engine, state.session_manager)
        state.track_latency(start)
        state.extend_findings(findings)

        # Extract poisoned headers from findings
        for f in findings:
            detail = f.get("detail", "")
            if "Header:" in detail:
                hdr = detail.split("Header: ", 1)[1].split(" — ", 1)[0].strip()
                if hdr and hdr not in state.poisoned_headers:
                    state.poisoned_headers.append(hdr)

        # Attempt cache delivery with poisoned headers
        if state.poisoned_headers:
            delivery = await deliver_poisoned_payload(
                url, state.async_engine, state.poisoned_headers,
                session_manager=state.session_manager,
            )
            state.extend_findings(delivery)


# Phase: Smuggling

async def phase_smuggling(state: PoisonState):
    """HTTP smuggling scan."""
    from modules.web.smuggling import scan_smuggling, SMUGGLE_REQUEST_BOUND

    if not _budget_ok(state):
        return
    if _hold_for_backoff(state, "smuggling probes"):
        return

    base_urls = [sv["url"] for sv in state.services[:3]]
    for url in base_urls:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Documented upper bound per host (see SMUGGLE_REQUEST_BOUND).
        if not _charge_external(state, SMUGGLE_REQUEST_BOUND, "smuggling"):
            w(f"Budget cannot cover {SMUGGLE_REQUEST_BOUND} smuggle probes — skipping")
            break
        start = time.time()
        findings = await scan_smuggling(url, state.async_engine, state.session_manager)
        state.track_latency(start)
        state.extend_findings(findings)
        if findings:
            state.smuggle_confirmed = True


# Phase: Vuln Assault

async def phase_vuln_assault(state: PoisonState):
    """Existing vuln modules — runs once per wave."""
    from runners.vuln_assault import run_vuln_assault

    # Pass origin IP discovered from previous waves
    if state.origin_ip:
        for sv in state.services:
            sv["origin_ip"] = state.origin_ip

    start = time.time()
    findings, wafs = await run_vuln_assault(
        state.target, state.services, list(state.scan_urls),
        state.params, state.scope_guard, state.session_manager,
        state.async_engine,
        vuln_threads=state.current_concurrency // 2,
        is_turbo=state.is_turbo,
        module_flags=state.module_flags,
        policy=state.policy,
        allow_post=True,
    )
    state.track_latency(start)
    state.extend_findings(findings)
    state.target_wafs.update(wafs)


# Phase: OOB Poll

async def phase_oob(state: PoisonState):
    """OOB/blind detection — runs once per wave."""
    from modules.extras.oob_detector import OOBDetector

    if not state.services or not state.params:
        return

    oob = OOBDetector(
        state.target, state.services, state.params,
        state.async_engine, session_manager=state.session_manager,
    )
    start = time.time()
    findings = await oob.run()
    state.track_latency(start)
    state.extend_findings(findings)

    # Inject blind XSS payloads
    if oob.interactsh.domain and state.time_left > 8:
        try:
            from modules.web.blind_xss import BlindXSSHunter
            hunter = BlindXSSHunter(
                state.async_engine,
                interactsh_domain=oob.interactsh.domain,
                session_manager=state.session_manager,
            )
            import uuid
            marker = "xss-" + uuid.uuid4().hex[:8]
            # phase_oob returns early without services, so services[0]
            # is the only base (10x identical injections were a bug).
            bases = [state.services[0]["url"]]
            for sv_url in bases:
                for path, plist in state.params.items():
                    for param in plist[:3]:
                        target = sv_url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
                        await hunter.inject_stored(target, param, marker)
        except Exception as e:
            w(f"blind XSS inject error: {str(e)[:60]}")

    # Auto-scan SSRF internal on blind_ssrf and ssrf findings
    for f in findings:
        if ("ssrf" in f.get("type", "")) and state.time_left > 10:
            param = None
            url = f.get("url", "")
            detail = f.get("detail", "")
            for part in detail.split("|"):
                part = part.strip()
                if part.startswith("Param:"):
                    param = part.split(":", 1)[1].strip()
                    break
            if param and url:
                try:
                    from modules.web.ssrf_scanner import SSRFScanner
                    scanner = SSRFScanner(state.async_engine, state.session_manager)
                    ssrf_findings = await scanner.scan(url, param)
                    if ssrf_findings:
                        state.extend_findings(ssrf_findings)
                except Exception as e:
                    w(f"SSRF auto-scan error: {str(e)[:60]}")


# Adaptive Wave Controller

async def _adaptive_wave_loop(state: PoisonState):
    """
    Core loop: phased execution with data dependencies respected.

    Block A: Discovery (param flood + bruteforce + cache + smuggle + exhaust)
    Block B: Detection (OOB + payload flood + auto-chain)
    Block C: Assault (vuln modules + plugins)
    Block D: Intelligence (session rotation + target reprioritization)
    """
    if state.time_left <= 0:
        return

    s(f"{G}========== POISON WAVE {state.wave} =========={N}")

    # Block A: Discovery
    # A1: Param discovery on high-value targets
    try:
        await phase_param_flood(state)
    except Exception as e:
        w(f"param_flood error: {str(e)[:80]}")

    # A2: Bruteforce + cache_poison + smuggling + connection_exhaust in parallel
    disc_tasks = [
        phase_bruteforce(state),
        phase_cache_poison(state),
        phase_smuggling(state),
        phase_connection_exhaust(state),
    ]
    disc_results = await asyncio.gather(*disc_tasks, return_exceptions=True)
    for idx, res in enumerate(disc_results):
        if isinstance(res, Exception):
            w(f"Discovery phase {idx} error: {str(res)[:80]}")

    # A3: Re-run param_flood on newly discovered URLs
    if state.time_left > 8:
        try:
            await phase_param_flood(state)
        except Exception as e:
            w(f"param_flood (re-run) error: {str(e)[:80]}")

    # Block B: Detection
    det_tasks = [
        phase_oob(state),
        phase_payload_flood(state),
    ]
    det_results = await asyncio.gather(*det_tasks, return_exceptions=True)
    for idx, res in enumerate(det_results):
        if isinstance(res, Exception):
            w(f"Detection phase {idx} error: {str(res)[:80]}")

    # Block C: Assault
    try:
        await phase_vuln_assault(state)
    except Exception as e:
        w(f"vuln_assault error: {str(e)[:80]}")

    # Block D: Custom Plugins
    try:
        from modules.plugin import run_plugins
        plugin_findings = await run_plugins(state)
        if plugin_findings:
            state.extend_findings(plugin_findings)
    except Exception as e:
        w(f"plugin error: {str(e)[:80]}")


# Main Entry Point

async def run_poison_assault(
    target: str,
    seed_url: str,
    services: List[Dict],
    subs: List[str],
    scan_urls: List[str],
    scope_guard,
    session_manager,
    async_engine,
    is_turbo: bool = False,
    module_flags: dict = None,
    auth_headers: dict = None,
    max_duration: int = 120,
    policy=None,
):
    """
    Event-driven poison orchestrator.

    3-block wave loop (discovery → detection → assault), each block under a
    hard deadline. Results self-feed into the next wave. Adaptive concurrency
    driven by real request latency.
    """
    if policy and policy.mode == "passive":
        return [], {}, list(scan_urls), []

    ph("POISON MODE: Event-Driven Orchestrator")

    # Auto-setup wordlists on first run (WordlistProvider already imported)
    wordlist_provider = WordlistProvider()
    wordlist_provider.scan()
    if not wordlist_provider._local:
        from modules.wordlists import auto_setup_wordlists
        await auto_setup_wordlists()
    i(PROVIDER.summary())

    # Create state
    existing_wafs = set()
    for sv in services:
        for waf_name in sv.get("waf", []):
            existing_wafs.add(waf_name)

    state = PoisonState(
        target, seed_url, services, subs, list(scan_urls),
        scope_guard, session_manager, async_engine, is_turbo,
        auth_headers=auth_headers,
        policy=policy,
    )
    state.target_wafs = existing_wafs
    state.max_duration = max_duration
    state.current_concurrency = 200 if is_turbo else 100
    state.module_flags = module_flags or {}

    # Adaptive controller input: every successful response reports its real
    # latency to the state (see PoisonState.track_request_latency). Cleared
    # again before returning so a later runner sharing this engine cannot
    # keep mutating a finished poison run.
    if hasattr(async_engine, "latency_observer"):
        async_engine.latency_observer = state.track_request_latency

    # Phase 0: WAF Bypass Engine — find origin IP + bypass techniques.
    #
    # Phase 0 gets its OWN time slice. It runs before the wave clock matters
    # but consumed it anyway (state.start_time is set at construction), and
    # through a proxy this stage alone takes 40-50s — so a 60s run ended with
    # a single wave. Cap the slice, then reset the wave clock below so
    # --max-time keeps meaning "time for the assault itself".
    from modules.waf.bypass_engine import waf_bypass_pipeline
    phase0_budget = min(max_duration, PHASE0_TIME_CAP)
    phase0_start = time.time()
    bypass_result = {}
    try:
        bypass_result = await asyncio.wait_for(
            waf_bypass_pipeline(target, subs, list(scan_urls),
                                proxy=_get_proxy_flag() or None),
            timeout=phase0_budget)
    except (asyncio.TimeoutError, TimeoutError):
        w(f"WAF bypass pipeline used its whole {phase0_budget}s slice — "
          "continuing without origin intel")
    phase0_elapsed = time.time() - phase0_start
    if isinstance(bypass_result, dict):
        if bypass_result.get("origin_ip"):
            state.origin_ip = bypass_result["origin_ip"]
            s(f"{G}Routing all phases through origin IP:{N} {B}{state.origin_ip}{N}")
            if state.policy:
                # Sekelas fix #1: tanpa authorize, policy.drop semua URL IP —
                # wave-wave awal (flood/brute/smuggle/OOB) jalan percuma.
                state.policy.authorize_host(state.origin_ip)
            for sv in services:
                sv["origin_ip"] = state.origin_ip
        if bypass_result.get("bypass_findings"):
            state.extend_findings(bypass_result["bypass_findings"])

    # Legacy origin hunt fallback — shares the rest of the Phase 0 slice
    if existing_wafs and not state.origin_ip:
        remaining_phase0 = phase0_budget - phase0_elapsed
        if remaining_phase0 >= 5:
            from modules.waf.origin_hunter import hunt_origin
            try:
                origin = await asyncio.wait_for(
                    hunt_origin(target, subs, proxy=_get_proxy_flag() or None),
                    timeout=remaining_phase0)
            except (asyncio.TimeoutError, TimeoutError):
                origin = None
                w("Origin hunt fallback hit the Phase 0 slice cap")
            if origin and origin.get("origin_ip"):
                state.origin_ip = origin["origin_ip"]
                s(f"{G}Origin IP (fallback):{N} {state.origin_ip}")
                if state.policy:
                    state.policy.authorize_host(state.origin_ip)
                for sv in services:
                    sv["origin_ip"] = state.origin_ip

    # Wave clock starts now: Phase 0 no longer eats into --max-time.
    state.start_time = time.time()
    i(f"Phase 0: {phase0_elapsed:.0f}s of {phase0_budget}s slice — "
      f"wave budget reset to {max_duration}s")

    # Main adaptive loop — waves until the duration budget is spent.
    # wait_for() is the hard deadline: inner phases (ffuf, exhaust, OOB,
    # vuln modules) can no longer run past max_duration, which the outer
    # while-condition alone could not enforce.
    try:
        while state.elapsed < state.max_duration:
            if not _budget_ok(state):
                w("Request budget exhausted — stopping poison waves")
                break
            try:
                await asyncio.wait_for(_adaptive_wave_loop(state),
                                       timeout=state.time_left)
            except (asyncio.TimeoutError, TimeoutError):
                w(f"Wave deadline reached ({max_duration}s) — stopping")
                break

            # Check if server fully degraded
            if state.server_strained:
                w("Server showing strain — continuing with adaptive aggression")

            # Start next wave with mutated params
            state.start_wave()
            s(f"{C}===== Next wave in 1s [{state.wave}] ======{N}")
            await asyncio.sleep(1)

    except asyncio.CancelledError:
        w("Poison mode interrupted")

    # Final summary
    elapsed = state.elapsed
    budget_note = ""
    if state.policy is not None:
        remaining = state.policy.requests_remaining
        if remaining is not None:
            budget_note = f" | budget left: {remaining}"
    ph(f"POISON COMPLETE — {elapsed:.0f}s | {state.wave} waves | {len(state.findings)} findings | {len(state.scan_urls)} urls{budget_note}")
    if hasattr(async_engine, "latency_observer"):
        async_engine.latency_observer = None
    return (
        state.findings,
        state.params,
        sorted(state.scan_urls),
        sorted(state.target_wafs),
    )
