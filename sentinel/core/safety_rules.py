from enum import Enum
from pathlib import Path
import os
import re
from typing import Dict, Any, Optional

class SafetyLevel(str, Enum):
    SAFE = "SAFE"           # Safe to prune automatically or with 1-click
    REVIEW = "REVIEW"       # Large file/folder that can be purged or rotated after inspection
    CRITICAL = "CRITICAL"   # NEVER delete; system integrity or data will be destroyed

class ReclaimAction(str, Enum):
    DELETE = "DELETE"               # Direct unlinking/removal
    TRUNCATE = "TRUNCATE"           # Truncate to 0 bytes (vital for open log files on Linux!)
    DOCKER_PRUNE = "DOCKER_PRUNE"   # Use Docker daemon prune commands
    PACKAGE_PRUNE = "PACKAGE_PRUNE" # apt clean / dnf clean all
    MANUAL = "MANUAL"               # Review required, manual decision
    PROTECTED = "PROTECTED"         # System forbidden

class SafetyVerdict:
    def __init__(
        self,
        level: SafetyLevel,
        action: ReclaimAction,
        reason: str,
        recommendation: str,
        command_hint: Optional[str] = None
    ):
        self.level = level
        self.action = action
        self.reason = reason
        self.recommendation = recommendation
        self.command_hint = command_hint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "action": self.action.value,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "command_hint": self.command_hint
        }

# Regex patterns for fast rule matching
SAFE_ROTATED_LOG_PATTERNS = [
    r".*\.log\.[0-9]+(\.gz|\.xz|\.bz2)?$",
    r".*\.log(\.gz|\.xz|\.bz2)$",
    r".*(syslog|messages|auth|daemon|kern|mail|dpkg)\.[0-9]+(\.gz|\.xz|\.bz2)?$",
    r".*\.[0-9]+(\.gz|\.xz|\.bz2)$",
    r".*\.old$",
    r".*\.bak$",
    r".*journal.*\.[0-9]+$",
]

SAFE_CACHE_DIRS = [
    "/var/cache/apt",
    "/var/cache/yum",
    "/var/cache/dnf",
    "/var/cache/apk",
    "/tmp",
    "/var/tmp",
    "/.cache",
    "/AppData/Local/Temp",
    "/npm-cache",
    "/.npm",
    "/.pip/cache",
    "/.cache/pip",
]

CRITICAL_PATHS = [
    "/etc",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/dev",
    "/proc",
    "/sys",
    "/var/lib/mysql",
    "/var/lib/postgresql",
    "/var/lib/redis",
    "/var/lib/mongodb",
    "/.ssh",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
]

def evaluate_file_safety(file_path: str, size_bytes: int) -> SafetyVerdict:
    """Evaluates whether an individual file is safe to delete, truncate, or protected."""
    p_str = file_path.replace("\\", "/")
    p_lower = p_str.lower()
    filename = Path(p_str).name.lower()

    # 1. Critical security files & keys
    if any(k in p_lower for k in ["/id_rsa", "/id_ed25519", "authorized_keys", "known_hosts", "/.ssh/"]):
        return SafetyVerdict(
            SafetyLevel.CRITICAL,
            ReclaimAction.PROTECTED,
            "SSH Key or Security Credential",
            "NEVER delete: This will lock you out of SSH or compromise server identity.",
            None
        )

    # 2. Critical system binaries & configs
    for crit in CRITICAL_PATHS:
        c_norm = crit.replace("\\", "/").lower()
        if p_lower.startswith(c_norm):
            return SafetyVerdict(
                SafetyLevel.CRITICAL,
                ReclaimAction.PROTECTED,
                f"Essential OS system path ({crit})",
                "DO NOT DELETE: Essential for operating system boot, core libraries, or database storage.",
                None
            )

    # 3. Direct Docker overlay2 files (must not be manually deleted via rm!)
    if "/var/lib/docker/overlay2" in p_lower or "/docker/overlay2" in p_lower:
        return SafetyVerdict(
            SafetyLevel.CRITICAL,
            ReclaimAction.DOCKER_PRUNE,
            "Raw Docker container filesystem layer",
            "DO NOT manually rm! Deleting overlay2 files corrupts Docker daemon. Use 'docker system prune' instead.",
            "docker system prune -af --volumes"
        )

    # 4. Safe rotated log files
    for pat in SAFE_ROTATED_LOG_PATTERNS:
        if re.match(pat, filename):
            return SafetyVerdict(
                SafetyLevel.SAFE,
                ReclaimAction.DELETE,
                "Rotated historical log file",
                "Safe to delete: This is an archived log from past days/weeks. Active services do not write to it.",
                f"rm -f '{file_path}'"
            )

    # 5. Core dumps and crash files
    if filename.startswith("core.") or "/var/crash/" in p_lower:
        return SafetyVerdict(
            SafetyLevel.SAFE,
            ReclaimAction.DELETE,
            "Application crash core dump",
            "Safe to delete: Diagnostic memory dump from past process crashes.",
            f"rm -f '{file_path}'"
        )

    # 6. Package manager archives
    if ("/var/cache/apt/archives/" in p_lower and filename.endswith(".deb")) or \
       ("/var/cache/yum/" in p_lower and filename.endswith(".rpm")):
        return SafetyVerdict(
            SafetyLevel.SAFE,
            ReclaimAction.PACKAGE_PRUNE,
            "Downloaded OS package archive",
            "Safe to purge: Cached installer files no longer needed after software was installed.",
            "apt-get clean" if "apt" in p_lower else "yum clean all"
        )

    # 7. Ephemeral Temp files
    if "/tmp/" in p_lower or "/var/tmp/" in p_lower or "appdata/local/temp" in p_lower:
        return SafetyVerdict(
            SafetyLevel.SAFE,
            ReclaimAction.DELETE,
            "Temporary runtime file",
            "Safe to delete: Ephemeral file stored in temporary directory.",
            f"rm -f '{file_path}'"
        )

    # 8. Active Log files (e.g., syslog, access.log, app.log)
    if filename.endswith(".log"):
        if size_bytes > 50 * 1024 * 1024:  # > 50MB
            return SafetyVerdict(
                SafetyLevel.REVIEW,
                ReclaimAction.TRUNCATE,
                "Active uncompressed log file exceeding 50MB",
                "DO NOT 'rm'! Truncate to 0 bytes instead. Linux holds open file handles; 'truncate -s 0' frees space immediately without stopping the service.",
                f"truncate -s 0 '{file_path}'"
            )
        else:
            return SafetyVerdict(
                SafetyLevel.REVIEW,
                ReclaimAction.MANUAL,
                "Standard active log file",
                "Review log contents. Consider setting up logrotate or truncating if no longer needed.",
                f"truncate -s 0 '{file_path}'"
            )

    # 9. Backup archives and database dumps (*.tar.gz, *.sql, *.bak)
    if any(filename.endswith(ext) for ext in [".tar.gz", ".tgz", ".zip", ".sql", ".dump", ".sql.gz"]):
        return SafetyVerdict(
            SafetyLevel.REVIEW,
            ReclaimAction.MANUAL,
            "Archive or Database Dump",
            "Review: Could be an automated or manual backup. Verify if a more recent backup exists before deleting.",
            None
        )

    # Default fallback
    return SafetyVerdict(
        SafetyLevel.REVIEW,
        ReclaimAction.MANUAL,
        "General large file",
        "Inspect file owner and usage before removing.",
        None
    )

def evaluate_folder_safety(folder_path: str, size_bytes: int) -> SafetyVerdict:
    """Evaluates whether an entire directory is safe to purge or protected."""
    p_str = folder_path.replace("\\", "/")
    p_lower = p_str.lower()

    # 1. Critical directories
    for crit in CRITICAL_PATHS:
        c_norm = crit.replace("\\", "/").lower()
        if p_lower == c_norm or (p_lower.startswith(c_norm) and len(p_lower) <= len(c_norm) + 1):
            return SafetyVerdict(
                SafetyLevel.CRITICAL,
                ReclaimAction.PROTECTED,
                f"Core Operating System folder ({crit})",
                "NEVER delete this folder! Will corrupt system boot, kernel, or database storage.",
                None
            )

    # 2. Docker overlay storage
    if "/var/lib/docker" in p_lower:
        return SafetyVerdict(
            SafetyLevel.CRITICAL,
            ReclaimAction.DOCKER_PRUNE,
            "Docker daemon data store",
            "DO NOT rm -rf! Use 'docker system prune' or 'docker volume prune' to clean safely.",
            "docker system prune -af --volumes"
        )

    # 3. Safe cache folders
    for safe_cache in SAFE_CACHE_DIRS:
        if safe_cache.lower() in p_lower:
            return SafetyVerdict(
                SafetyLevel.SAFE,
                ReclaimAction.DELETE,
                "Temporary or package build cache directory",
                "Safe to purge cache contents. Application will rebuild cache on demand.",
                f"rm -rf '{folder_path}'/*"
            )

    # 4. Git / Node / Python caches
    if p_lower.endswith(".cache") or p_lower.endswith("node_modules/.cache") or p_lower.endswith("__pycache__"):
        return SafetyVerdict(
            SafetyLevel.SAFE,
            ReclaimAction.DELETE,
            "Build or bytecode cache",
            "Safe to delete. Purely cache artifacts.",
            f"rm -rf '{folder_path}'"
        )

    return SafetyVerdict(
        SafetyLevel.REVIEW,
        ReclaimAction.MANUAL,
        "Application or User directory",
        "Inspect contents. Delete subcomponents individually rather than entire folder.",
        None
    )
