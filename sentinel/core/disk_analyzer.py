from pathlib import Path
import os
import time
from typing import List, Dict, Any, Optional
from sentinel.core.safety_rules import evaluate_file_safety, evaluate_folder_safety, SafetyLevel

def format_bytes(size_bytes: int) -> str:
    """Format bytes to human-readable string (KB, MB, GB, TB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    elif size_bytes < 1024 * 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024 * 1024):.2f} TB"

class FileInfo:
    def __init__(self, path: str, size: int, modified_time: float):
        self.path = path
        self.size = size
        self.modified_time = modified_time
        self.verdict = evaluate_file_safety(path, size)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size,
            "size_formatted": format_bytes(self.size),
            "modified_time": self.modified_time,
            "safety": self.verdict.to_dict()
        }

class FolderInfo:
    def __init__(self, path: str, total_size: int, file_count: int):
        self.path = path
        self.total_size = total_size
        self.file_count = file_count
        self.verdict = evaluate_folder_safety(path, total_size)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.total_size,
            "size_formatted": format_bytes(self.total_size),
            "file_count": self.file_count,
            "safety": self.verdict.to_dict()
        }

class DiskScanResult:
    def __init__(self):
        self.scan_duration_sec: float = 0.0
        self.total_files_scanned: int = 0
        self.total_folders_scanned: int = 0
        self.total_size_scanned: int = 0
        self.safe_reclaimable_bytes: int = 0
        self.reviewable_bytes: int = 0
        self.protected_bytes: int = 0
        self.top_files: List[FileInfo] = []
        self.top_folders: List[FolderInfo] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_duration_sec": round(self.scan_duration_sec, 2),
            "total_files_scanned": self.total_files_scanned,
            "total_folders_scanned": self.total_folders_scanned,
            "total_size_scanned_formatted": format_bytes(self.total_size_scanned),
            "safe_reclaimable_formatted": format_bytes(self.safe_reclaimable_bytes),
            "safe_reclaimable_bytes": self.safe_reclaimable_bytes,
            "reviewable_formatted": format_bytes(self.reviewable_bytes),
            "reviewable_bytes": self.reviewable_bytes,
            "protected_formatted": format_bytes(self.protected_bytes),
            "top_files": [f.to_dict() for f in self.top_files],
            "top_folders": [f.to_dict() for f in self.top_folders],
        }

class DiskAnalyzer:
    def __init__(
        self,
        scan_paths: Optional[List[str]] = None,
        min_file_size_mb: float = 20.0,
        max_depth: int = 4,
        exclude_dirs: Optional[List[str]] = None
    ):
        self.scan_paths = scan_paths or []
        self.min_file_size_bytes = int(min_file_size_mb * 1024 * 1024)
        self.max_depth = max_depth
        self.exclude_dirs = [e.replace("\\", "/").lower() for e in (exclude_dirs or [])]

    def _is_excluded(self, path_str: str) -> bool:
        norm = path_str.replace("\\", "/").lower()
        for excl in self.exclude_dirs:
            if norm == excl or norm.startswith(excl + "/"):
                return True
        return False

    def scan(self, target_paths: Optional[List[str]] = None, limit_top: int = 15) -> DiskScanResult:
        start_time = time.time()
        result = DiskScanResult()
        paths_to_scan = target_paths or self.scan_paths

        # If no valid path is passed, default to system temp & user home or cwd
        if not paths_to_scan:
            paths_to_scan = [str(Path.home()), str(Path.cwd())]

        large_files: List[FileInfo] = []
        folder_size_map: Dict[str, Dict[str, Any]] = {}

        for root_target in paths_to_scan:
            target = Path(root_target)
            if not target.exists():
                continue

            # If scanning a single file
            if target.is_file():
                try:
                    st = target.stat()
                    fi = FileInfo(str(target), st.st_size, st.st_mtime)
                    result.total_files_scanned += 1
                    result.total_size_scanned += st.st_size
                    if fi.verdict.level == SafetyLevel.SAFE:
                        result.safe_reclaimable_bytes += st.st_size
                    elif fi.verdict.level == SafetyLevel.REVIEW:
                        result.reviewable_bytes += st.st_size
                    else:
                        result.protected_bytes += st.st_size
                    large_files.append(fi)
                except (PermissionError, OSError):
                    pass
                continue

            base_depth = len(target.resolve().parts)

            for root, dirs, files in os.walk(str(target), topdown=True):
                # Check exclusion and depth limits
                root_norm = root.replace("\\", "/")
                if self._is_excluded(root_norm):
                    dirs[:] = []
                    continue

                curr_depth = len(Path(root).parts) - base_depth
                if curr_depth >= self.max_depth:
                    dirs[:] = []  # Don't descend further

                folder_size = 0
                folder_file_count = 0

                for f in files:
                    file_path = os.path.join(root, f)
                    try:
                        st = os.stat(file_path)
                        size = st.st_size
                        result.total_files_scanned += 1
                        result.total_size_scanned += size
                        folder_size += size
                        folder_file_count += 1

                        fi = FileInfo(file_path, size, st.st_mtime)
                        if fi.verdict.level == SafetyLevel.SAFE:
                            result.safe_reclaimable_bytes += size
                        elif fi.verdict.level == SafetyLevel.REVIEW:
                            result.reviewable_bytes += size
                        else:
                            result.protected_bytes += size

                        if size >= self.min_file_size_bytes:
                            large_files.append(fi)
                    except (PermissionError, OSError):
                        continue

                result.total_folders_scanned += 1
                if folder_size > 0:
                    folder_size_map[root] = {
                        "size": folder_size,
                        "count": folder_file_count
                    }

        # Sort top files
        large_files.sort(key=lambda x: x.size, reverse=True)
        result.top_files = large_files[:limit_top]

        # Aggregate and sort top folders
        sorted_folders = sorted(folder_size_map.items(), key=lambda item: item[1]["size"], reverse=True)
        top_folders: List[FolderInfo] = []
        for folder_path, meta in sorted_folders[:limit_top]:
            top_folders.append(FolderInfo(folder_path, meta["size"], meta["count"]))
        result.top_folders = top_folders

        result.scan_duration_sec = time.time() - start_time
        return result
