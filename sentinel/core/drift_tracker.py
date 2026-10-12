import os
import sys
import time
import json
import hashlib
import difflib
from pathlib import Path
from typing import List, Dict, Any, Optional

DEFAULT_WATCH_PATHS = [
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
]

class ChangeEvent:
    def __init__(
        self,
        target: str,
        category: str,  # "CONFIG", "PACKAGE", "CRONTAB", "ENVIRONMENT"
        action: str,    # "MODIFIED", "CREATED", "DELETED", "UPGRADED"
        details: str,
        timestamp: Optional[float] = None,
        diff_preview: Optional[str] = None
    ):
        self.target = target
        self.category = category
        self.action = action
        self.details = details
        self.timestamp = timestamp or time.time()
        self.diff_preview = diff_preview

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "category": self.category,
            "action": self.action,
            "details": self.details,
            "timestamp": self.timestamp,
            "diff_preview": self.diff_preview
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangeEvent":
        return cls(
            target=data.get("target", ""),
            category=data.get("category", "CONFIG"),
            action=data.get("action", "MODIFIED"),
            details=data.get("details", ""),
            timestamp=data.get("timestamp"),
            diff_preview=data.get("diff_preview")
        )

class DriftTracker:
    """Time-Machine System Drift & Change Ledger.

    Continuously tracks configuration drifts, crontab edits, and package updates,
    and correlates them against production anomalies.
    """

    def __init__(
        self,
        watch_paths: Optional[List[str]] = None,
        state_file: str = ".sentinel_drift_ledger.json",
        max_history: int = 500
    ):
        self.watch_paths = watch_paths or DEFAULT_WATCH_PATHS
        self.state_file = Path(state_file)
        self.max_history = max_history
        self.file_snapshots: Dict[str, Dict[str, Any]] = {}
        self.events: List[ChangeEvent] = []
        self._load_state()

    def _load_state(self):
        if not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.file_snapshots = data.get("snapshots", {})
                self.events = [ChangeEvent.from_dict(e) for e in data.get("events", [])]
        except Exception:
            self.file_snapshots = {}
            self.events = []

    def _save_state(self):
        try:
            # Ensure parent directory exists
            if self.state_file.parent:
                self.state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "updated_at": time.time(),
                "snapshots": self.file_snapshots,
                "events": [e.to_dict() for e in self.events[-self.max_history:]]
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _hash_file(self, path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def _read_content_snippet(self, path: Path, max_bytes: int = 100000) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read(max_bytes)
        except Exception:
            return None

    def _collect_files(self) -> List[Path]:
        files: List[Path] = []
        for p_str in self.watch_paths:
            p = Path(p_str)
            if not p.exists():
                continue
            if p.is_file():
                files.append(p.resolve())
            elif p.is_dir():
                try:
                    for root, _, filenames in os.walk(p):
                        for fname in filenames:
                            f_path = Path(root) / fname
                            # Avoid deep cache/git files
                            if any(x in f_path.parts for x in (".git", "node_modules", "__pycache__")):
                                continue
                            files.append(f_path.resolve())
                except Exception:
                    pass
        return files

    def _check_package_manager_logs(self) -> List[ChangeEvent]:
        """Parses recent package installations or upgrades on Linux servers."""
        pkg_events: List[ChangeEvent] = []
        dpkg_log = Path("/var/log/dpkg.log")
        if dpkg_log.exists():
            try:
                # Read last 30 lines of dpkg.log
                with open(dpkg_log, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[-30:]
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[2] in ("install", "upgrade", "remove"):
                        action_type = "UPGRADED" if parts[2] == "upgrade" else ("CREATED" if parts[2] == "install" else "DELETED")
                        pkg_name = parts[3]
                        # Check if this package event already recorded in recent events
                        if not any(e.target == pkg_name and e.category == "PACKAGE" for e in self.events[-20:]):
                            pkg_events.append(ChangeEvent(
                                target=pkg_name,
                                category="PACKAGE",
                                action=action_type,
                                details=f"Dpkg {parts[2]}: {line.strip()}"
                            ))
            except Exception:
                pass
        return pkg_events

    def snapshot_and_audit(self) -> List[ChangeEvent]:
        """Performs a change-detection audit against watch paths and package logs.

        Returns list of newly detected change events in this pass.
        """
        now = time.time()
        new_events: List[ChangeEvent] = []
        current_files = self._collect_files()
        seen_paths = set()

        # Is this the initial calibration run?
        is_first_run = len(self.file_snapshots) == 0

        for f_path in current_files:
            p_str = str(f_path)
            seen_paths.add(p_str)
            try:
                stat = f_path.stat()
                file_hash = self._hash_file(f_path)
                if not file_hash:
                    continue

                if is_first_run:
                    # Baseline recording
                    content = self._read_content_snippet(f_path)
                    self.file_snapshots[p_str] = {
                        "hash": file_hash,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "content": content
                    }
                    continue

                prev = self.file_snapshots.get(p_str)
                if not prev:
                    # File was newly created!
                    content = self._read_content_snippet(f_path)
                    category = "CRONTAB" if "cron" in p_str else ("ENVIRONMENT" if ".env" in p_str else "CONFIG")
                    evt = ChangeEvent(
                        target=p_str,
                        category=category,
                        action="CREATED",
                        details=f"New configuration file created ({stat.st_size} bytes)",
                        timestamp=now
                    )
                    new_events.append(evt)
                    self.events.append(evt)
                    self.file_snapshots[p_str] = {
                        "hash": file_hash,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "content": content
                    }
                elif prev["hash"] != file_hash:
                    # File was modified!
                    content = self._read_content_snippet(f_path)
                    prev_content = prev.get("content", "")

                    # Compute unified diff snippet if content available
                    diff_str = None
                    if prev_content and content:
                        diff_lines = list(difflib.unified_diff(
                            prev_content.splitlines(keepends=True),
                            content.splitlines(keepends=True),
                            fromfile=f"a/{f_path.name}",
                            tofile=f"b/{f_path.name}",
                            n=2
                        ))
                        if diff_lines:
                            diff_str = "".join(diff_lines[:25])  # Cap at 25 lines

                    category = "CRONTAB" if "cron" in p_str else ("ENVIRONMENT" if ".env" in p_str else "CONFIG")
                    evt = ChangeEvent(
                        target=p_str,
                        category=category,
                        action="MODIFIED",
                        details=f"File changed (hash: {prev['hash'][:8]} -> {file_hash[:8]}, size: {prev['size']} -> {stat.st_size} B)",
                        timestamp=now,
                        diff_preview=diff_str
                    )
                    new_events.append(evt)
                    self.events.append(evt)
                    self.file_snapshots[p_str] = {
                        "hash": file_hash,
                        "mtime": stat.st_mtime,
                        "size": stat.st_size,
                        "content": content
                    }

            except Exception:
                continue

        # Check for deleted files
        if not is_first_run:
            deleted_paths = [p for p in self.file_snapshots.keys() if p not in seen_paths]
            for d_path in deleted_paths:
                category = "CRONTAB" if "cron" in d_path else "CONFIG"
                evt = ChangeEvent(
                    target=d_path,
                    category=category,
                    action="DELETED",
                    details="Tracked configuration file was removed",
                    timestamp=now
                )
                new_events.append(evt)
                self.events.append(evt)
                del self.file_snapshots[d_path]

        # Audit package logs
        pkg_events = self._check_package_manager_logs()
        for pe in pkg_events:
            new_events.append(pe)
            self.events.append(pe)

        self._save_state()
        return new_events

    def get_recent_changes(self, since_seconds: int = 7200) -> List[ChangeEvent]:
        """Returns all change events recorded in the last `since_seconds` (default 2 hours)."""
        cutoff = time.time() - since_seconds
        return [e for e in self.events if e.timestamp >= cutoff]

    def correlate_with_incident(self, window_seconds: int = 3600) -> List[Dict[str, Any]]:
        """Correlates recent changes with an active incident.

        Answers: "What configuration or package changed in the 60 minutes before now?"
        """
        now = time.time()
        recent = self.get_recent_changes(since_seconds=window_seconds)
        results = []
        for e in sorted(recent, key=lambda x: x.timestamp, reverse=True):
            mins_ago = max(0, int((now - e.timestamp) / 60))
            time_label = f"{mins_ago}m ago" if mins_ago > 0 else "just now"
            results.append({
                "target": e.target,
                "category": e.category,
                "action": e.action,
                "time_label": time_label,
                "details": e.details,
                "diff_preview": e.diff_preview,
                "timestamp": e.timestamp
            })
        return results

    def get_summary(self) -> Dict[str, Any]:
        """High-level summary of watched files and recent drifts."""
        recent_2h = self.get_recent_changes(since_seconds=7200)
        recent_24h = self.get_recent_changes(since_seconds=86400)
        return {
            "total_tracked_files": len(self.file_snapshots),
            "changes_last_2h": len(recent_2h),
            "changes_last_24h": len(recent_24h),
            "recent_events": [e.to_dict() for e in self.events[-30:]]
        }
