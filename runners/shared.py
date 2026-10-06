import asyncio
import re
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit, parse_qsl, urlparse

from core.ui import G, N, Spinner, p, w


def normalize_takeover_findings(raw_findings):
    findings = []
    for item in raw_findings or []:
        sub = item.get("sub", "")
        service = item.get("service", "Unknown")
        cname = item.get("cname", "")
        findings.append({
            "type": "subdomain_takeover",
            "title": f"Potential Subdomain Takeover: {sub}",
            "url": f"https://{sub}" if sub else "",
            "detail": f"Dangling CNAME points to {cname} ({service})",
            "waf": "",
            "time": 0,
            "status": 0,
            "confidence": "suspected",
            "cvss_score": 3.1,
            "cvss_severity": "Low",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        })
    return findings


def normalize_urls(urls, scope_guard=None, keep_static=True):
    if scope_guard:
        return scope_guard.filter_urls(urls, keep_static=keep_static)

    normalized = set()
    for raw_url in urls or []:
        if not raw_url:
            continue
        url = str(raw_url).strip()
        if not url:
            continue
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            normalized.add(url.split("#")[0])
    return sorted(normalized)


def collect_js_assets(urls, services):
    js_urls = {u for u in urls if urlparse(u).path.lower().endswith(".js")}
    script_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)

    for sv in services or []:
        base_url = sv.get("url", "")
        body = sv.get("body", "") or ""
        for src in script_re.findall(body):
            js_urls.add(urljoin(base_url, src).split("#")[0])

    return sorted(js_urls)


def build_param_url(service_url, path, param):
    parsed = urlparse(path)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        base = path.split("#")[0]
    else:
        base = service_url.rstrip("/") + (path if str(path).startswith("/") else "/" + str(path))

    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode({param: 'FUZZ'})}"


async def validate_recon_urls(urls, scope_guard, async_engine, session_manager=None, max_urls=2000):
    candidates = normalize_urls(urls, scope_guard=scope_guard, keep_static=False)
    if not candidates:
        return []

    prioritized = sorted(
        candidates,
        key=lambda u: (
            0 if urlparse(u).query else 1,
            0 if any(x in urlparse(u).path.lower() for x in ["/api", "/graphql", "/auth", "/admin", "/upload"]) else 1,
            len(u),
        ),
    )[:max_urls]

    live = []
    spin = Spinner("Validating recon endpoints...")

    # Try high-speed Go Engine bridge first
    from core.go_bridge import go_bridge
    go_results = None
    if go_bridge.is_available():
        try:
            # Fetch adaptive delay if a global RateLimiter is available
            delay_ms, jitter_ms = 0, 0
            try:
                from core.ratelimit import RateLimiter as _RL
                # The global rate_limiter instance is typically set on async_engine
                _rl = getattr(async_engine, 'rate_limiter', None)
                if _rl:
                    delay_ms, jitter_ms = _rl.get_adaptive_delay_ms("default")
            except Exception:
                pass
            go_results = await asyncio.to_thread(
                go_bridge.probe_batch, prioritized, None, 100, 4, delay_ms, jitter_ms
            )
        except Exception:
            go_results = None

    if go_results is not None:
        for res in go_results:
            st = res.get("status_code", 0)
            if 200 <= st < 500:
                live.append(res["url"])
    else:
        # Fallback to Python Async Engine
        _sem = asyncio.Semaphore(100)
        async def probe(url):
            async with _sem:
                r = await async_engine.ahttp_send(url, timeout=4, state_context=session_manager)
                status = r.get("status", 0)
                spin.next()
                if 200 <= status < 500:
                    return url
                return None

        tasks = [probe(url) for url in prioritized]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for checked in results:
            if isinstance(checked, str):
                live.append(checked)

    spin.stop()
    p(f"Recon validation: {G}{len(live)}{N}/{len(prioritized)} endpoints responded with concrete HTTP status.")
    return sorted(set(live))


# Batas pasangan (url, param) per run. ~25 request/pair (xss: baseline+12
# payload, sqli: baseline+10) — tanpa batas, 11k pair = 275k request melelehkan
# budget max_requests (10000). Bukti: audit_example.com.jsonl —
# 10.000 allowed + 14.349 denied request_budget_exhausted.
PARAM_TARGET_CAP = 400


def build_param_scan_targets(scan_urls, params_by_path, max_params_per_url=25,
                             max_targets=PARAM_TARGET_CAP):
    """Build (url, param) pairs — query param observasi diprioritaskan,
    lalu path guess. Potong deterministik di max_targets (None = tanpa batas)."""
    query_side, path_side, seen = [], [], set()

    for url in scan_urls:
        parsed = urlparse(url)
        path_key = parsed.path or "/"

        query_params = list(dict.fromkeys(parse_qs(parsed.query).keys()))
        query_set = set(query_params)
        path_params = list(dict.fromkeys(params_by_path.get(path_key, [])))
        all_params = (query_params
                      + [q for q in path_params if q not in query_set])[:max_params_per_url]

        for param in all_params:
            key = (url, param)
            if key in seen:
                continue
            seen.add(key)
            if param in query_set:
                query_side.append(key)
            else:
                path_side.append(key)

    targets = query_side + path_side
    if max_targets is not None and len(targets) > max_targets:
        w(f"param target cap: {max_targets}/{len(targets)} pairs dipakai — "
          f"{len(targets) - max_targets} di-drop (prioritas query param)")
        targets = targets[:max_targets]
    return targets


def concrete_js_findings(findings, services, scan_urls, scope_guard):
    validated = []
    for finding in findings:
        if finding["type"].startswith("js_secret"):
            validated.append({**finding, "confidence": "confirmed"})
        elif finding["type"] == "js_endpoint":
            endpoint = finding.get("detail", "").replace("Endpoint matched: ", "").strip()
            if not endpoint:
                continue

            is_valid = False
            full_urls = []
            if endpoint.startswith("http"):
                full_urls = [endpoint]
            elif endpoint.startswith("/"):
                for service in services:
                    full_urls.append(urljoin(service["url"].rstrip("/") + "/", endpoint.lstrip("/")))

            for url in scope_guard.filter_urls(full_urls):
                if url in scan_urls:
                    validated.append({**finding, "url": url, "confidence": "confirmed"})
                    is_valid = True
                    break

            if not is_valid:
                validated.append({**finding, "confidence": "suspected"})
    return validated


def merge_params(params: Dict[str, List[str]], path: str, discovered: List[str]):
    if not discovered:
        return params
    params.setdefault(path or "/", [])
    params[path or "/"].extend([x for x in discovered if x not in params[path or "/"]])
    return params


def inject_query_payload(url: str, param: str, payload: str) -> str:
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    updated = []
    for key, value in query:
        if key == param and not replaced:
            updated.append((key, payload))
            replaced = True
        else:
            updated.append((key, value))
    if not replaced:
        updated.append((param, payload))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(updated), parts.fragment))
