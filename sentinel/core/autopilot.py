import time
import logging
from typing import Dict, Any, List, Optional
from sentinel.config import SentinelConfig
from sentinel.core.metrics import get_full_hard_health
from sentinel.core.disk_analyzer import DiskAnalyzer, format_bytes
from sentinel.core.safety_rules import SafetyLevel
from sentinel.core.cleaner import DiskCleaner
from sentinel.core.services_monitor import ServicesMonitor
from sentinel.core.synthetic import run_synthetic_probes
from sentinel.core.alerts import AlertDispatcher

logger = logging.getLogger("sentinel.autopilot")

class AutopilotCycleResult:
    def __init__(
        self,
        timestamp: float,
        issues_detected: List[str],
        alerts_dispatched: List[str],
        auto_cleaned_mb: float = 0.0,
        cleaned_files_count: int = 0
    ):
        self.timestamp = timestamp
        self.issues_detected = issues_detected
        self.alerts_dispatched = alerts_dispatched
        self.auto_cleaned_mb = auto_cleaned_mb
        self.cleaned_files_count = cleaned_files_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "issues_count": len(self.issues_detected),
            "issues": self.issues_detected,
            "alerts": self.alerts_dispatched,
            "auto_cleaned_mb": round(self.auto_cleaned_mb, 2),
            "cleaned_files_count": self.cleaned_files_count
        }

class AutopilotEngine:
    """Autonomous DevOps watchdog that continuously inspects server health,

    sends debounced multi-channel alerts, and executes safe self-healing actions.
    """

    def __init__(self, config: SentinelConfig, cooldown_sec: int = 300):
        self.config = config
        self.cooldown_sec = cooldown_sec
        self.dispatcher = AlertDispatcher(config.alerts)
        self.last_alert_timestamps: Dict[str, float] = {}
        self.history: List[AutopilotCycleResult] = []
        self.total_cycles: int = 0
        self.is_running: bool = False

    def _can_alert(self, key: str, now: float) -> bool:
        last = self.last_alert_timestamps.get(key, 0.0)
        return (now - last) >= self.cooldown_sec

    def _mark_alerted(self, key: str, now: float):
        self.last_alert_timestamps[key] = now

    def run_check_cycle(self, auto_clean: bool = False) -> AutopilotCycleResult:
        """Executes a single autonomous evaluation cycle."""
        self.total_cycles += 1
        now = time.time()
        issues: List[str] = []
        dispatched_alerts: List[str] = []
        auto_cleaned_mb: float = 0.0
        cleaned_count: int = 0

        # 1. Inspect Hard Health Metrics
        try:
            health = get_full_hard_health()
        except Exception as e:
            health = {}
            issues.append(f"Metrics collection error: {str(e)}")

        cpu_pct = health.get("cpu", {}).get("total_percent", 0.0)
        ram_pct = health.get("memory", {}).get("ram", {}).get("percent", 0.0)
        partitions = health.get("disk", {}).get("partitions", [])

        # CPU Threshold Check
        if cpu_pct >= self.config.alerts.cpu_threshold_pct:
            issue_msg = f"CPU utilization critical: {cpu_pct}% >= threshold {self.config.alerts.cpu_threshold_pct}%"
            issues.append(issue_msg)
            if self._can_alert("cpu", now):
                self.dispatcher.send_alert(
                    title=f"CPU Spike Alert on {self.config.server_name}",
                    message=f"Current CPU load is {cpu_pct}%. Immediate triage recommended.",
                    severity="WARNING"
                )
                self._mark_alerted("cpu", now)
                dispatched_alerts.append("CPU Alert Dispatched")

        # RAM Threshold Check
        if ram_pct >= self.config.alerts.ram_threshold_pct:
            issue_msg = f"RAM saturation critical: {ram_pct}% >= threshold {self.config.alerts.ram_threshold_pct}%"
            issues.append(issue_msg)
            if self._can_alert("ram", now):
                self.dispatcher.send_alert(
                    title=f"Memory Exhaustion Alert on {self.config.server_name}",
                    message=f"RAM usage is {ram_pct}%. Risk of OOM process kills.",
                    severity="CRITICAL"
                )
                self._mark_alerted("ram", now)
                dispatched_alerts.append("RAM Alert Dispatched")

        # Disk Threshold Check & Self-Healing Auto-Relief
        disk_triggered = False
        critical_mount = "/"
        for p in partitions:
            pct = p.get("percent", 0.0)
            mount = p.get("mountpoint", "/")
            if pct >= self.config.alerts.disk_threshold_pct:
                disk_triggered = True
                critical_mount = mount
                issue_msg = f"Disk partition {mount} critical: {pct}% utilized"
                issues.append(issue_msg)

        if disk_triggered:
            if self._can_alert("disk", now):
                self.dispatcher.send_alert(
                    title=f"Disk Space Exhaustion on {self.config.server_name} ({critical_mount})",
                    message=f"Partition {critical_mount} has exceeded safe limits. Auto-cleaning initiated if enabled.",
                    severity="CRITICAL"
                )
                self._mark_alerted("disk", now)
                dispatched_alerts.append("Disk Alert Dispatched")

            # Autonomous Safe Disk Clean
            if auto_clean:
                try:
                    analyzer = DiskAnalyzer(
                        scan_paths=self.config.disk.scan_paths,
                        min_file_size_mb=self.config.disk.min_file_size_mb,
                        max_depth=self.config.disk.max_depth,
                        exclude_dirs=self.config.disk.exclude_dirs
                    )
                    scan_res = analyzer.scan(limit_top=50)

                    # Gather strictly SAFE files only
                    safe_files_to_clean = [
                        item.path for item in scan_res.top_files
                        if item.safety_level == SafetyLevel.SAFE
                    ]

                    if safe_files_to_clean:
                        cleaner = DiskCleaner(dry_run=False)
                        batch_res = cleaner.clean_batch(safe_files_to_clean, force_review=False)
                        auto_cleaned_mb = batch_res.total_bytes_reclaimed / (1024 * 1024)
                        cleaned_count = batch_res.success_count

                        if auto_cleaned_mb > 0:
                            relief_msg = (
                                f"Autonomous SRE Self-Healing: Reclaimed {auto_cleaned_mb:.2f} MB "
                                f"across {cleaned_count} safe files (rotated logs, package caches, tmp) on {critical_mount}."
                            )
                            issues.append(relief_msg)
                            self.dispatcher.send_alert(
                                title=f"Autonomous Disk Relief on {self.config.server_name}",
                                message=relief_msg,
                                severity="INFO"
                            )
                            dispatched_alerts.append("Autonomous Clean Dispatched")
                except Exception as e:
                    issues.append(f"Auto-clean execution error: {str(e)}")

        # 2. Inspect Services & Failed Units
        try:
            sm = ServicesMonitor(services=getattr(self.config, "services", None))
            summary = sm.get_summary()
            failed_units = summary.get("failed_units", [])
            if failed_units:
                f_msg = f"Failed systemd units detected: {', '.join(failed_units)}"
                issues.append(f_msg)
                if self._can_alert("services_failed", now):
                    self.dispatcher.send_alert(
                        title=f"Failed Services on {self.config.server_name}",
                        message=f_msg,
                        severity="WARNING"
                    )
                    self._mark_alerted("services_failed", now)
                    dispatched_alerts.append("Service Alert Dispatched")
        except Exception as e:
            issues.append(f"Services inspection error: {str(e)}")

        # 3. Inspect Synthetic Probes
        try:
            probes = run_synthetic_probes(self.config.synthetic_targets)
            for pr in probes:
                if not pr.healthy:
                    p_msg = f"Synthetic probe failure: {pr.name} ({pr.target_type}) -> {pr.detail}"
                    issues.append(p_msg)
                    probe_key = f"probe_{pr.name}"
                    if self._can_alert(probe_key, now):
                        self.dispatcher.send_alert(
                            title=f"Uptime Probe Down: {pr.name}",
                            message=f"Target: {pr.target}\nLatency: {pr.latency_ms}ms\nDetail: {pr.detail}",
                            severity="CRITICAL"
                        )
                        self._mark_alerted(probe_key, now)
                        dispatched_alerts.append(f"Probe Alert: {pr.name}")
        except Exception as e:
            issues.append(f"Synthetic probes error: {str(e)}")

        result = AutopilotCycleResult(
            timestamp=now,
            issues_detected=issues,
            alerts_dispatched=dispatched_alerts,
            auto_cleaned_mb=auto_cleaned_mb,
            cleaned_files_count=cleaned_count
        )

        self.history.append(result)
        if len(self.history) > 100:
            self.history.pop(0)

        return result

    def get_status(self) -> Dict[str, Any]:
        last_cycle = self.history[-1].to_dict() if self.history else None
        return {
            "is_running": self.is_running,
            "total_cycles": self.total_cycles,
            "cooldown_sec": self.cooldown_sec,
            "last_cycle": last_cycle,
            "recent_history": [c.to_dict() for c in self.history[-10:]]
        }
