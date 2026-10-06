from runners.recon_intel import run_recon_intel
from runners.app_analysis import run_app_analysis
from runners.vuln_assault import run_vuln_assault
from core.ui import w


async def run_full_assault(
    target,
    seed_url,
    services,
    subs,
    scan_urls,
    scope_guard,
    session_manager,
    auth_headers,
    auth_headers2,
    async_engine,
    vuln_threads,
    is_turbo=False,
    module_flags=None,
    policy=None,
):
    """Option 5: run recon, app analysis, and assault in order."""
    all_findings = []
    params = {}
    target_wafs = []
    # Work on a copy to avoid mutating caller's list
    current_urls = list(scan_urls)

    # Phase 1: Recon Intel
    try:
        findings, urls = await run_recon_intel(
            target, services, subs, current_urls, scope_guard,
            async_engine, is_turbo, session_manager=session_manager, policy=policy
        )
        all_findings.extend(findings)
        current_urls = list(urls)
    except Exception as e:
        w(f"Recon failed: {str(e)[:80]} — continuing with existing URLs")

    # Phase 2: App Analysis
    try:
        findings, discovered_params, urls = await run_app_analysis(
            target,
            seed_url,
            services,
            current_urls,
            scope_guard,
            session_manager,
            auth_headers,
            auth_headers2,
            async_engine,
            is_turbo,
            policy,
        )
        all_findings.extend(findings)
        params.update(discovered_params)
        current_urls = list(urls)
    except Exception as e:
        w(f"App analysis failed: {str(e)[:80]} — continuing with existing data")

    # Phase 3: Vuln Assault
    try:
        findings, wafs = await run_vuln_assault(
            target,
            services,
            current_urls,
            params,
            scope_guard,
            session_manager,
            async_engine,
            vuln_threads,
            is_turbo=is_turbo,
            module_flags=module_flags,
            policy=policy,
        )
        all_findings.extend(findings)
        target_wafs.extend(wafs)
    except Exception as e:
        w(f"Vuln assault failed: {str(e)[:80]}")

    return all_findings, params, current_urls, target_wafs
