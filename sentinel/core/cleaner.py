from pathlib import Path
import os
import subprocess
import shutil
from typing import List, Dict, Any, Optional
from sentinel.core.safety_rules import evaluate_file_safety, SafetyLevel, ReclaimAction

class CleanItemResult:
    def __init__(self, path: str, action: str, bytes_freed: int, status: str, message: str):
        self.path = path
        self.action = action
        self.bytes_freed = bytes_freed
        self.status = status  # SUCCESS, SKIPPED, ERROR
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "action": self.action,
            "bytes_freed": self.bytes_freed,
            "status": self.status,
            "message": self.message
        }

class CleanBatchResult:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.total_bytes_freed: int = 0
        self.items: List[CleanItemResult] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "total_bytes_freed": self.total_bytes_freed,
            "items": [it.to_dict() for it in self.items]
        }

class DiskCleaner:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def clean_file(self, file_path: str, force_review: bool = False) -> CleanItemResult:
        # 1. STRICT SAFETY SHIELD: Evaluate rules first (even before file check)
        pre_verdict = evaluate_file_safety(file_path, 0)
        if pre_verdict.level == SafetyLevel.CRITICAL or pre_verdict.action == ReclaimAction.PROTECTED:
            return CleanItemResult(
                file_path,
                "BLOCKED",
                0,
                "SKIPPED",
                f"SAFETY SHIELD ACTIVATED: {pre_verdict.reason}. This file is essential to system stability."
            )

        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return CleanItemResult(file_path, "NONE", 0, "SKIPPED", "File does not exist or is not a regular file")

        try:
            size = p.stat().st_size
        except OSError as e:
            return CleanItemResult(file_path, "NONE", 0, "ERROR", f"Cannot stat file: {e}")

        verdict = evaluate_file_safety(file_path, size)

        # STRICT SAFETY GUARD: Never touch CRITICAL or PROTECTED
        if verdict.level == SafetyLevel.CRITICAL or verdict.action == ReclaimAction.PROTECTED:
            return CleanItemResult(
                file_path,
                "BLOCKED",
                0,
                "SKIPPED",
                f"SAFETY SHIELD ACTIVATED: {verdict.reason}. This file is essential to system stability."
            )

        # If it's REVIEW, require explicit confirmation
        if verdict.level == SafetyLevel.REVIEW and not force_review:
            return CleanItemResult(
                file_path,
                "REQUIRES_CONFIRMATION",
                0,
                "SKIPPED",
                f"File flagged for REVIEW ({verdict.reason}). Set force_review=True to proceed."
            )

        # Perform Action
        if self.dry_run:
            act_name = f"WOULD_{verdict.action.value}"
            return CleanItemResult(file_path, act_name, size, "SUCCESS", f"[DRY-RUN] Would execute: {verdict.recommendation}")

        # Real Execution
        try:
            if verdict.action == ReclaimAction.DELETE:
                p.unlink()
                return CleanItemResult(file_path, "DELETED", size, "SUCCESS", "File successfully removed.")

            elif verdict.action == ReclaimAction.TRUNCATE:
                # Open with 'w' or truncate to 0 to preserve inode and handle for active daemons
                with open(p, "w", encoding="utf-8") as f:
                    f.truncate(0)
                return CleanItemResult(file_path, "TRUNCATED", size, "SUCCESS", "File truncated to 0 bytes without disrupting running daemon.")

            elif verdict.action == ReclaimAction.PACKAGE_PRUNE:
                if verdict.command_hint:
                    res = subprocess.run(verdict.command_hint, shell=True, capture_output=True, text=True, timeout=30)
                    return CleanItemResult(file_path, "PACKAGE_PRUNED", size, "SUCCESS", f"Ran {verdict.command_hint}: {res.stdout.strip()}")
                else:
                    p.unlink()
                    return CleanItemResult(file_path, "DELETED", size, "SUCCESS", "Package cache file deleted.")

            else:
                return CleanItemResult(file_path, "SKIPPED", 0, "SKIPPED", f"Action {verdict.action} requires manual intervention.")

        except Exception as e:
            return CleanItemResult(file_path, "ERROR", 0, "ERROR", f"Failed to execute cleanup: {str(e)}")

    def clean_batch(self, file_paths: List[str], force_review: bool = False) -> CleanBatchResult:
        result = CleanBatchResult(dry_run=self.dry_run)
        for fp in file_paths:
            item_res = self.clean_file(fp, force_review=force_review)
            result.items.append(item_res)
            if item_res.status == "SUCCESS":
                result.total_bytes_freed += item_res.bytes_freed
        return result

    def prune_docker(self) -> Dict[str, Any]:
        """Runs safe docker prune if docker is available."""
        if self.dry_run:
            return {
                "dry_run": True,
                "command": "docker system prune -f",
                "message": "[DRY-RUN] Would run 'docker system prune -f' to clean dangling images, stopped containers and build cache."
            }
        try:
            res = subprocess.run(["docker", "system", "prune", "-f"], capture_output=True, text=True, timeout=60)
            return {
                "dry_run": False,
                "success": res.returncode == 0,
                "output": res.stdout or res.stderr
            }
        except Exception as e:
            return {
                "dry_run": False,
                "success": False,
                "error": str(e)
            }
