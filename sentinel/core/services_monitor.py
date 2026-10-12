import subprocess
import shutil
import sys
import psutil
from typing import List, Dict, Any, Optional

DEFAULT_CRITICAL_SERVICES = [
    "nginx",
    "docker",
    "postgresql",
    "mysql",
    "redis",
    "ssh",
    "sshd",
    "ufw",
    "cron",
    "crond",
    "systemd-journald",
    "caddy"
]

class ServiceStatus:
    def __init__(
        self,
        name: str,
        display_name: str,
        status: str,  # "active", "inactive", "failed", "unknown"
        sub_state: str = "unknown",
        pid: Optional[int] = None,
        memory_mb: Optional[float] = None,
        is_critical: bool = True,
        description: str = ""
    ):
        self.name = name
        self.display_name = display_name
        self.status = status
        self.sub_state = sub_state
        self.pid = pid
        self.memory_mb = memory_mb
        self.is_critical = is_critical
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "status": self.status,
            "sub_state": self.sub_state,
            "pid": self.pid,
            "memory_mb": round(self.memory_mb, 2) if self.memory_mb else None,
            "is_critical": self.is_critical,
            "description": self.description
        }

class ServicesMonitor:
    def __init__(self, services: Optional[List[str]] = None):
        self.services = services or DEFAULT_CRITICAL_SERVICES
        self.has_systemctl = bool(shutil.which("systemctl"))

    def get_failed_units(self) -> List[str]:
        """Returns list of failed systemd units on Linux servers."""
        if not self.has_systemctl:
            return []
        try:
            res = subprocess.run(
                ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain"],
                capture_output=True,
                text=True,
                timeout=4
            )
            failed = []
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if parts:
                    failed.append(parts[0])
            return failed
        except Exception:
            return []

    def _query_systemctl(self, service: str) -> ServiceStatus:
        """Queries systemctl for status and PID of a service."""
        try:
            # Check active state
            status_res = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True,
                text=True,
                timeout=3
            )
            raw_status = status_res.stdout.strip().lower()

            if raw_status == "active":
                status = "active"
            elif raw_status == "failed":
                status = "failed"
            elif raw_status in ("inactive", "deactivating"):
                status = "inactive"
            else:
                status = "unknown"

            # Query detailed properties
            show_res = subprocess.run(
                ["systemctl", "show", service, "--property=MainPID,SubState,Description,ActiveState"],
                capture_output=True,
                text=True,
                timeout=3
            )
            props = {}
            for line in show_res.stdout.strip().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k] = v

            pid = None
            raw_pid = props.get("MainPID", "0")
            if raw_pid.isdigit() and int(raw_pid) > 0:
                pid = int(raw_pid)

            sub_state = props.get("SubState", raw_status)
            desc = props.get("Description", service)

            memory_mb = None
            if pid:
                try:
                    p = psutil.Process(pid)
                    memory_mb = p.memory_info().rss / (1024 * 1024)
                except Exception:
                    pass

            return ServiceStatus(
                name=service,
                display_name=service.capitalize(),
                status=status,
                sub_state=sub_state,
                pid=pid,
                memory_mb=memory_mb,
                description=desc
            )
        except Exception:
            return ServiceStatus(
                name=service,
                display_name=service.capitalize(),
                status="unknown",
                sub_state="error"
            )

    def _query_process_fallback(self, service: str) -> ServiceStatus:
        """Process-based inspection fallback for non-systemd environments (Windows/macOS/containers)."""
        proc_names_to_match = [service.lower()]
        if service.lower() == "ssh":
            proc_names_to_match.extend(["sshd", "ssh.exe", "sshd.exe"])
        elif service.lower() == "postgresql":
            proc_names_to_match.extend(["postgres", "postgres.exe"])
        elif service.lower() == "mysql":
            proc_names_to_match.extend(["mysqld", "mysqld.exe"])
        elif service.lower() == "nginx":
            proc_names_to_match.extend(["nginx.exe"])
        elif service.lower() == "redis":
            proc_names_to_match.extend(["redis-server", "redis-server.exe"])
        elif service.lower() == "docker":
            proc_names_to_match.extend(["dockerd", "dockerd.exe", "docker.exe"])

        found_proc = None
        for p in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                name = (p.info['name'] or '').lower()
                for target in proc_names_to_match:
                    if target in name:
                        found_proc = p
                        break
                if found_proc:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if found_proc:
            try:
                mem_mb = found_proc.memory_info().rss / (1024 * 1024)
            except Exception:
                mem_mb = None
            return ServiceStatus(
                name=service,
                display_name=service.capitalize(),
                status="active",
                sub_state="running",
                pid=found_proc.pid,
                memory_mb=mem_mb,
                description=f"Process matched: {found_proc.info['name']}"
            )
        else:
            return ServiceStatus(
                name=service,
                display_name=service.capitalize(),
                status="inactive",
                sub_state="stopped",
                description="Process not running"
            )

    def check_services(self) -> List[ServiceStatus]:
        """Checks status of all configured services."""
        results = []
        for s in self.services:
            if self.has_systemctl:
                results.append(self._query_systemctl(s))
            else:
                results.append(self._query_process_fallback(s))
        return results

    def get_summary(self) -> Dict[str, Any]:
        """Returns high-level summary of service health."""
        statuses = self.check_services()
        failed_units = self.get_failed_units()

        active_count = sum(1 for s in statuses if s.status == "active")
        failed_count = sum(1 for s in statuses if s.status == "failed") + len(failed_units)
        inactive_count = sum(1 for s in statuses if s.status == "inactive")

        return {
            "total_monitored": len(statuses),
            "active_count": active_count,
            "failed_count": failed_count,
            "inactive_count": inactive_count,
            "failed_units": failed_units,
            "services": [s.to_dict() for s in statuses]
        }
