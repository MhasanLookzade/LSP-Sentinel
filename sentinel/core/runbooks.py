from typing import Dict, Any, List, Optional
import time

class SREIncident:
    def __init__(
        self,
        title: str,
        severity: str,
        metric_value: str,
        root_causes: List[str],
        remediation_steps: List[str],
        commands: List[str],
        correlated_changes: Optional[List[Dict[str, Any]]] = None
    ):
        self.title = title
        self.severity = severity  # CRITICAL, WARNING, INFO
        self.metric_value = metric_value
        self.root_causes = root_causes
        self.remediation_steps = remediation_steps
        self.commands = commands
        self.correlated_changes = correlated_changes or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "metric_value": self.metric_value,
            "root_causes": self.root_causes,
            "remediation_steps": self.remediation_steps,
            "commands": self.commands,
            "correlated_changes": self.correlated_changes
        }

def generate_sre_runbooks(
    health_metrics: Dict[str, Any],
    disk_scan_summary: Optional[Dict[str, Any]] = None,
    synthetic_results: Optional[List[Dict[str, Any]]] = None,
    docker_containers: Optional[List[Dict[str, Any]]] = None,
    services_summary: Optional[Dict[str, Any]] = None,
    drift_changes: Optional[List[Dict[str, Any]]] = None
) -> List[SREIncident]:
    runbooks: List[SREIncident] = []

    # 1. Disk Space Crisis
    partitions = health_metrics.get("disk", {}).get("partitions", [])
    for p in partitions:
        pct = p.get("percent", 0)
        mount = p.get("mountpoint", "/")
        if pct >= 88.0:
            severity = "CRITICAL" if pct >= 95.0 else "WARNING"
            runbooks.append(SREIncident(
                title=f"High Disk Usage on {mount}",
                severity=severity,
                metric_value=f"{pct}% utilized",
                root_causes=[
                    "Unrotated application or system logs (/var/log growing indefinitely)",
                    "Dangling Docker layers, images, or build kits",
                    "Orphaned database dumps or old backups",
                    "Package manager cache not cleaned"
                ],
                remediation_steps=[
                    "Run 'lsp-sentinel disk' to identify the exact culprit files/folders",
                    "Execute safe log truncation or clean package caches",
                    "Prune Docker dangling assets"
                ],
                commands=[
                    "lsp-sentinel disk",
                    "lsp-sentinel clean --safe-only",
                    "journalctl --vacuum-time=3d",
                    "docker system prune -f",
                    "apt-get clean"
                ]
            ))

    # 2. RAM Pressure & OOM Risk
    ram = health_metrics.get("memory", {}).get("ram", {})
    ram_pct = ram.get("percent", 0)
    if ram_pct >= 88.0:
        severity = "CRITICAL" if ram_pct >= 95.0 else "WARNING"
        top_procs = health_metrics.get("processes", {}).get("top_memory", [])
        proc_names = [f"{p.get('name')} (PID {p.get('pid')}: {p.get('memory_percent')}%)" for p in top_procs[:3]]
        runbooks.append(SREIncident(
            title="Memory Saturation & Out-Of-Memory (OOM) Hazard",
            severity=severity,
            metric_value=f"{ram_pct}% RAM in use",
            root_causes=[
                f"Memory-hungry processes: {', '.join(proc_names) if proc_names else 'Heavy background workloads'}",
                "Memory leak in web application or background worker daemon",
                "Lack of swap partition or misconfigured swappiness"
            ],
            remediation_steps=[
                "Inspect memory consumption per PID",
                "Gracefully restart leaking service worker",
                "Verify swap status with 'free -h'"
            ],
            commands=[
                "top -o %MEM",
                "systemctl status <service_name>",
                "systemctl restart <service_name>"
            ]
        ))

    # 3. High CPU Load
    cpu = health_metrics.get("cpu", {})
    cpu_pct = cpu.get("total_percent", 0)
    if cpu_pct >= 85.0:
        runbooks.append(SREIncident(
            title="Sustained High CPU Utilization",
            severity="WARNING",
            metric_value=f"{cpu_pct}% CPU utilization",
            root_causes=[
                "Compute-intensive background jobs or infinite loop in script",
                "DDoS or sudden traffic surge hitting web server",
                "Crypto-miner or unauthorized rogue process"
            ],
            remediation_steps=[
                "Inspect top CPU threads",
                "Throttle background tasks with 'nice' or 'cpulimit'",
                "Check web server access logs for anomalous request rate"
            ],
            commands=[
                "top -o %CPU",
                "ps aux --sort=-%cpu | head -n 10"
            ]
        ))

    # 4. Synthetic Probe Failures
    if synthetic_results:
        for syn in synthetic_results:
            if not syn.get("healthy"):
                runbooks.append(SREIncident(
                    title=f"Synthetic Probe Down: {syn.get('name')}",
                    severity="CRITICAL",
                    metric_value=f"Target: {syn.get('target')} (Latency: {syn.get('latency_ms')}ms)",
                    root_causes=[
                        f"Target service returned failure: {syn.get('detail')}",
                        "Port closed or firewall / security group blocking ingress",
                        "Web daemon (Nginx, Caddy, Node.js, Gunicorn) is down or crashed"
                    ],
                    remediation_steps=[
                        "Check if local process is bound to port",
                        "Check web server / reverse proxy service status",
                        "Inspect recent systemd service logs"
                    ],
                    commands=[
                        "systemctl status nginx",
                        "journalctl -u nginx -n 50 --no-pager",
                        "curl -Iv " + syn.get('target')
                    ]
                ))

            # SSL expiring
            ssl_days = syn.get("ssl_days_left")
            if ssl_days is not None and ssl_days <= 14:
                runbooks.append(SREIncident(
                    title=f"SSL/TLS Certificate Expiring Soon: {syn.get('name')}",
                    severity="WARNING",
                    metric_value=f"{ssl_days} days remaining",
                    root_causes=[
                        "Let's Encrypt certbot timer or renewal cron has stalled",
                        "ACME HTTP-01 challenge failed due to webroot or DNS mismatch"
                    ],
                    remediation_steps=[
                        "Manually trigger certbot certificate renewal",
                        "Check certbot systemd timer status"
                    ],
                    commands=[
                        "certbot renew --dry-run",
                        "certbot renew",
                        "systemctl status certbot.timer"
                    ]
                ))

    # 5. Crash-Looping Docker Containers
    if docker_containers:
        for c in docker_containers:
            if c.get("is_crash_loop"):
                runbooks.append(SREIncident(
                    title=f"Docker Container Crash-Loop: {c.get('name')}",
                    severity="CRITICAL",
                    metric_value=f"Status: {c.get('status')}",
                    root_causes=[
                        "Application threw uncaught fatal exception on startup",
                        "Missing environment variable or database connection string",
                        "Host port conflict preventing container bind"
                    ],
                    remediation_steps=[
                        "Inspect container stdout/stderr logs",
                        "Verify environment and volumes",
                        "Restart container with updated configuration"
                    ],
                    commands=[
                        f"docker logs --tail 100 {c.get('id')}",
                        f"docker inspect {c.get('id')}",
                        f"docker restart {c.get('id')}"
                    ]
                ))

    # 6. Failed System Services & Units
    if services_summary:
        for unit in services_summary.get("failed_units", []):
            runbooks.append(SREIncident(
                title=f"Failed Systemd Unit: {unit}",
                severity="CRITICAL",
                metric_value="Unit status: failed",
                root_causes=[
                    f"Unit '{unit}' exited with error or failed start dependencies",
                    "Misconfigured unit file or missing credentials/files",
                    "Uncaught runtime exception in daemon process"
                ],
                remediation_steps=[
                    f"Inspect unit status and journalctl logs",
                    f"Fix configuration and reset failed state with 'systemctl reset-failed'"
                ],
                commands=[
                    f"systemctl status {unit}",
                    f"journalctl -u {unit} -n 50 --no-pager",
                    f"systemctl restart {unit}"
                ]
            ))

        for svc in services_summary.get("services", []):
            if svc.get("is_critical") and svc.get("status") in ("failed", "inactive"):
                s_name = svc.get("name")
                # Avoid duplicate if already reported in failed_units
                if s_name not in services_summary.get("failed_units", []):
                    runbooks.append(SREIncident(
                        title=f"Critical Service Inactive: {s_name}",
                        severity="CRITICAL" if svc.get("status") == "failed" else "WARNING",
                        metric_value=f"Status: {svc.get('status')} ({svc.get('sub_state', 'unknown')})",
                        root_causes=[
                            f"Service '{s_name}' is not currently running or crashed",
                            "Daemon was manually stopped or never enabled at boot",
                            "Port collision preventing daemon binding"
                        ],
                        remediation_steps=[
                            f"Inspect service journal logs",
                            f"Start and enable service using systemctl"
                        ],
                        commands=[
                            f"systemctl status {s_name}",
                            f"journalctl -u {s_name} -n 50 --no-pager",
                            f"systemctl start {s_name}"
                        ]
                    ))

    # 7. Correlate Pre-Incident System Drift
    if drift_changes and runbooks:
        for inc in runbooks:
            inc.correlated_changes = drift_changes
            for c in drift_changes[:2]:
                correl_note = f"⚡ Correlated Pre-Incident Change ({c['time_label']}): {c['target']} was {c['action'].lower()} ({c['category']})"
                if correl_note not in inc.root_causes:
                    inc.root_causes.insert(0, correl_note)

    return runbooks
