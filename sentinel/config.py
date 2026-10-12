from pathlib import Path
import os
import yaml
from pydantic import BaseModel, Field
from typing import List, Dict, Optional

DEFAULT_CONFIG_PATH = Path("sentinel.yaml")

class SyntheticTarget(BaseModel):
    name: str
    type: str = "http"  # http, tcp, dns, ssl
    target: str
    expected_status: int = 200
    timeout_sec: float = 3.0
    warn_latency_ms: float = 500.0
    check_ssl: bool = True

class AlertConfig(BaseModel):
    enabled: bool = False
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    cpu_threshold_pct: float = 85.0
    ram_threshold_pct: float = 90.0
    disk_threshold_pct: float = 88.0
    ssl_expiry_days_warn: int = 14

class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8443
    auth_token: Optional[str] = "sentinel-secure-key"
    cors_allowed_origins: List[str] = ["*"]

class DiskConfig(BaseModel):
    scan_paths: List[str] = ["/var/log", "/var/cache", "/tmp", "/var/lib/docker", "/root", "/home"]
    min_file_size_mb: float = 25.0
    max_scan_depth: int = 4
    exclude_dirs: List[str] = [
        "/proc", "/sys", "/dev", "/run", "/snap",
        "C:\\Windows", "C:\\$Recycle.Bin", "C:\\System Volume Information"
    ]

class ChaosLimits(BaseModel):
    max_duration_sec: int = 60
    max_cpu_percent: int = 90
    max_ram_mb: int = 1024
    allow_network_simulation: bool = True

class AutopilotConfig(BaseModel):
    enabled: bool = False
    check_interval_sec: int = 60
    auto_clean_enabled: bool = False
    cooldown_sec: int = 300

class DriftConfig(BaseModel):
    enabled: bool = True
    watch_paths: List[str] = Field(default_factory=lambda: [
        "/etc/nginx",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/fstab",
        "/etc/sysctl.conf",
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/etc/ssh/sshd_config",
        "/etc/environment",
        ".env",
        "sentinel.yaml"
    ])
    state_file: str = ".sentinel_drift_ledger.json"
    max_history: int = 500

class SentinelConfig(BaseModel):
    server_name: str = "VPS-Production-01"
    environment: str = "production"
    disk: DiskConfig = Field(default_factory=DiskConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    web: ServerConfig = Field(default_factory=ServerConfig)
    chaos: ChaosLimits = Field(default_factory=ChaosLimits)
    autopilot: AutopilotConfig = Field(default_factory=AutopilotConfig)
    drift: DriftConfig = Field(default_factory=DriftConfig)
    services: List[str] = Field(default_factory=lambda: [
        "nginx", "docker", "postgresql", "mysql", "redis", "ssh", "sshd", "ufw", "cron"
    ])
    synthetic_targets: List[SyntheticTarget] = Field(default_factory=lambda: [
        SyntheticTarget(name="Google DNS", type="dns", target="8.8.8.8"),
        SyntheticTarget(name="Cloudflare DNS", type="dns", target="1.1.1.1"),
        SyntheticTarget(name="Local Web / Nginx", type="http", target="http://127.0.0.1:80", timeout_sec=2.0),
        SyntheticTarget(name="GitHub API SSL", type="ssl", target="api.github.com:443")
    ])

def load_config(config_path: Optional[Path] = None) -> SentinelConfig:
    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return SentinelConfig(**data)
        except Exception:
            return SentinelConfig()
    return SentinelConfig()
