import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests
from sentinel.config import SyntheticTarget

class SyntheticResult:
    def __init__(
        self,
        name: str,
        target_type: str,
        target: str,
        healthy: bool,
        latency_ms: float,
        status_code: Optional[int] = None,
        detail: str = "",
        ssl_days_left: Optional[int] = None
    ):
        self.name = name
        self.target_type = target_type
        self.target = target
        self.healthy = healthy
        self.latency_ms = round(latency_ms, 2)
        self.status_code = status_code
        self.detail = detail
        self.ssl_days_left = ssl_days_left

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "target_type": self.target_type,
            "target": self.target,
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "status_code": self.status_code,
            "detail": self.detail,
            "ssl_days_left": self.ssl_days_left
        }

def probe_http(target: SyntheticTarget) -> SyntheticResult:
    start = time.time()
    try:
        url = target.target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"http://{url}"
        resp = requests.get(url, timeout=target.timeout_sec, verify=False)
        lat = (time.time() - start) * 1000.0
        healthy = (resp.status_code == target.expected_status)
        detail = f"HTTP {resp.status_code} ({len(resp.content)} bytes)"
        return SyntheticResult(
            name=target.name,
            target_type="http",
            target=target.target,
            healthy=healthy,
            latency_ms=lat,
            status_code=resp.status_code,
            detail=detail
        )
    except Exception as e:
        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="http",
            target=target.target,
            healthy=False,
            latency_ms=lat,
            detail=f"Connection failed: {str(e)}"
        )

def probe_tcp(target: SyntheticTarget) -> SyntheticResult:
    start = time.time()
    try:
        parts = target.target.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 80

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(target.timeout_sec)
        s.connect((host, port))
        s.close()

        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="tcp",
            target=target.target,
            healthy=True,
            latency_ms=lat,
            detail=f"TCP port {port} open and accepting connections"
        )
    except Exception as e:
        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="tcp",
            target=target.target,
            healthy=False,
            latency_ms=lat,
            detail=f"TCP connection refused or timed out: {str(e)}"
        )

def probe_ssl(target: SyntheticTarget) -> SyntheticResult:
    start = time.time()
    try:
        parts = target.target.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 443

        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=target.timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                lat = (time.time() - start) * 1000.0

                # Calculate expiry
                not_after = cert['notAfter']
                # e.g., 'May 15 12:00:00 2026 GMT'
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp_date - datetime.now(timezone.utc)).days

                healthy = days_left > 14
                detail = f"TLS Certificate valid. Expires in {days_left} days ({exp_date.strftime('%Y-%m-%d')})"
                return SyntheticResult(
                    name=target.name,
                    target_type="ssl",
                    target=target.target,
                    healthy=healthy,
                    latency_ms=lat,
                    detail=detail,
                    ssl_days_left=days_left
                )
    except Exception as e:
        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="ssl",
            target=target.target,
            healthy=False,
            latency_ms=lat,
            detail=f"SSL handshake error: {str(e)}"
        )

def probe_dns(target: SyntheticTarget) -> SyntheticResult:
    start = time.time()
    try:
        ip = socket.gethostbyname(target.target)
        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="dns",
            target=target.target,
            healthy=True,
            latency_ms=lat,
            detail=f"Resolved to IP: {ip}"
        )
    except Exception as e:
        lat = (time.time() - start) * 1000.0
        return SyntheticResult(
            name=target.name,
            target_type="dns",
            target=target.target,
            healthy=False,
            latency_ms=lat,
            detail=f"DNS resolution failure: {str(e)}"
        )

def run_synthetic_probes(targets: List[SyntheticTarget]) -> List[SyntheticResult]:
    results = []
    for t in targets:
        t_type = t.type.lower()
        if t_type == "http":
            results.append(probe_http(t))
        elif t_type == "tcp":
            results.append(probe_tcp(t))
        elif t_type == "ssl":
            results.append(probe_ssl(t))
        elif t_type == "dns":
            results.append(probe_dns(t))
        else:
            results.append(probe_http(t))
    return results
