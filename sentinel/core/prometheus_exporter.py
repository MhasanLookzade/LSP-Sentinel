import time
from typing import Dict, Any, List, Optional
from sentinel import __version__
from sentinel.config import SentinelConfig
from sentinel.core.metrics import get_full_hard_health
from sentinel.core.synthetic import run_synthetic_probes
from sentinel.core.docker_monitor import DockerMonitor
from sentinel.core.services_monitor import ServicesMonitor

class PrometheusExporter:
    """Exports system and LSP-Sentinel health metrics into Prometheus exposition format."""

    def __init__(self, config: SentinelConfig):
        self.config = config

    def generate_metrics(self) -> str:
        lines: List[str] = []

        # Info metric
        lines.append("# HELP sentinel_info LSP-Sentinel agent build and host metadata")
        lines.append("# TYPE sentinel_info gauge")
        server_name = self.config.server_name.replace('"', '\\"')
        env = self.config.environment.replace('"', '\\"')
        lines.append(f'sentinel_info{{version="{__version__}",server_name="{server_name}",environment="{env}"}} 1')

        try:
            health = get_full_hard_health()
        except Exception:
            health = {}

        # CPU Metrics
        cpu = health.get("cpu", {})
        if "total_percent" in cpu:
            lines.append("\n# HELP node_cpu_utilization_percent Overall CPU utilization percent")
            lines.append("# TYPE node_cpu_utilization_percent gauge")
            lines.append(f"node_cpu_utilization_percent {cpu['total_percent']}")

        sys_info = health.get("system", {})
        if "cpu_count_logical" in sys_info:
            lines.append("# HELP node_cpu_cores_logical Total logical CPU cores")
            lines.append("# TYPE node_cpu_cores_logical gauge")
            lines.append(f"node_cpu_cores_logical {sys_info['cpu_count_logical']}")

        if "uptime_seconds" in sys_info:
            lines.append("# HELP node_uptime_seconds Total host uptime in seconds")
            lines.append("# TYPE node_uptime_seconds counter")
            lines.append(f"node_uptime_seconds {sys_info['uptime_seconds']}")

        # Memory Metrics
        mem = health.get("memory", {})
        ram = mem.get("ram", {})
        if ram:
            lines.append("\n# HELP node_memory_used_bytes Physical RAM used in bytes")
            lines.append("# TYPE node_memory_used_bytes gauge")
            lines.append(f"node_memory_used_bytes {ram.get('used_bytes', 0)}")

            lines.append("# HELP node_memory_total_bytes Total physical RAM in bytes")
            lines.append("# TYPE node_memory_total_bytes gauge")
            lines.append(f"node_memory_total_bytes {ram.get('total_bytes', 0)}")

            lines.append("# HELP node_memory_utilization_percent RAM utilization percentage")
            lines.append("# TYPE node_memory_utilization_percent gauge")
            lines.append(f"node_memory_utilization_percent {ram.get('percent', 0)}")

        swap = mem.get("swap", {})
        if swap:
            lines.append("\n# HELP node_swap_used_bytes Swap memory used in bytes")
            lines.append("# TYPE node_swap_used_bytes gauge")
            lines.append(f"node_swap_used_bytes {swap.get('used_bytes', 0)}")

            lines.append("# HELP node_swap_total_bytes Total swap memory in bytes")
            lines.append("# TYPE node_swap_total_bytes gauge")
            lines.append(f"node_swap_total_bytes {swap.get('total_bytes', 0)}")

            lines.append("# HELP node_swap_utilization_percent Swap utilization percentage")
            lines.append("# TYPE node_swap_utilization_percent gauge")
            lines.append(f"node_swap_utilization_percent {swap.get('percent', 0)}")

        # Disk Partitions
        partitions = health.get("disk", {}).get("partitions", [])
        if partitions:
            lines.append("\n# HELP node_disk_utilization_percent Mounted disk partition usage percentage")
            lines.append("# TYPE node_disk_utilization_percent gauge")
            for p in partitions:
                mount = p.get("mountpoint", "/").replace('"', '\\"')
                device = p.get("device", "").replace('"', '\\"')
                lines.append(f'node_disk_utilization_percent{{mountpoint="{mount}",device="{device}"}} {p.get("percent", 0)}')

            lines.append("# HELP node_disk_used_bytes Mounted disk partition used space in bytes")
            lines.append("# TYPE node_disk_used_bytes gauge")
            for p in partitions:
                mount = p.get("mountpoint", "/").replace('"', '\\"')
                lines.append(f'node_disk_used_bytes{{mountpoint="{mount}"}} {p.get("used_bytes", 0)}')

            lines.append("# HELP node_disk_total_bytes Mounted disk partition total space in bytes")
            lines.append("# TYPE node_disk_total_bytes gauge")
            for p in partitions:
                mount = p.get("mountpoint", "/").replace('"', '\\"')
                lines.append(f'node_disk_total_bytes{{mountpoint="{mount}"}} {p.get("total_bytes", 0)}')

        # Network Traffic
        net = health.get("network", {})
        if net:
            lines.append("\n# HELP node_network_receive_bytes_total Total bytes received across network interfaces")
            lines.append("# TYPE node_network_receive_bytes_total counter")
            lines.append(f"node_network_receive_bytes_total {net.get('bytes_recv', 0)}")

            lines.append("# HELP node_network_transmit_bytes_total Total bytes transmitted across network interfaces")
            lines.append("# TYPE node_network_transmit_bytes_total counter")
            lines.append(f"node_network_transmit_bytes_total {net.get('bytes_sent', 0)}")

        # Synthetic Probes
        try:
            probes = run_synthetic_probes(self.config.synthetic_targets)
            if probes:
                lines.append("\n# HELP sentinel_synthetic_probe_latency_ms Synthetic probe latency in milliseconds")
                lines.append("# TYPE sentinel_synthetic_probe_latency_ms gauge")
                for pr in probes:
                    t_name = pr.name.replace('"', '\\"')
                    t_type = pr.target_type.replace('"', '\\"')
                    lines.append(f'sentinel_synthetic_probe_latency_ms{{name="{t_name}",type="{t_type}"}} {pr.latency_ms}')

                lines.append("# HELP sentinel_synthetic_probe_status Synthetic probe status (1=healthy, 0=down)")
                lines.append("# TYPE sentinel_synthetic_probe_status gauge")
                for pr in probes:
                    t_name = pr.name.replace('"', '\\"')
                    t_type = pr.target_type.replace('"', '\\"')
                    status_val = 1 if pr.healthy else 0
                    lines.append(f'sentinel_synthetic_probe_status{{name="{t_name}",type="{t_type}"}} {status_val}')
        except Exception:
            pass

        # Services & Daemons
        try:
            sm = ServicesMonitor(services=self.config.services if hasattr(self.config, "services") else None)
            summary = sm.get_summary()

            lines.append("\n# HELP sentinel_service_status Monitored daemon status (1=active, 0=inactive/failed)")
            lines.append("# TYPE sentinel_service_status gauge")
            for s in summary.get("services", []):
                s_name = s.get("name", "").replace('"', '\\"')
                val = 1 if s.get("status") == "active" else 0
                lines.append(f'sentinel_service_status{{service="{s_name}"}} {val}')

            lines.append("# HELP sentinel_failed_services_count Count of failed services and units")
            lines.append("# TYPE sentinel_failed_services_count gauge")
            lines.append(f"sentinel_failed_services_count {summary.get('failed_count', 0)}")
        except Exception:
            pass

        # Docker Containers
        try:
            dm = DockerMonitor()
            if dm.available:
                containers = dm.get_containers_health()
                running = sum(1 for c in containers if c.get("status") == "running")
                crashed = sum(1 for c in containers if c.get("status") in ("exited", "dead") or c.get("restart_count", 0) > 3)

                lines.append("\n# HELP sentinel_docker_containers_total Count of Docker containers by state")
                lines.append("# TYPE sentinel_docker_containers_total gauge")
                lines.append(f'sentinel_docker_containers_total{{state="running"}} {running}')
                lines.append(f'sentinel_docker_containers_total{{state="unhealthy"}} {crashed}')
                lines.append(f'sentinel_docker_containers_total{{state="total"}} {len(containers)}')
        except Exception:
            pass

        return "\n".join(lines) + "\n"
