import subprocess
import json
from typing import Dict, Any, List

class DockerMonitor:
    def __init__(self):
        self.available = self._check_docker_cli()

    def _check_docker_cli(self) -> bool:
        try:
            res = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=3)
            return res.returncode == 0
        except Exception:
            return False

    def get_containers_health(self) -> List[Dict[str, Any]]:
        """Lists containers with status, health, and restart metrics."""
        if not self.available:
            return []

        try:
            cmd = ["docker", "ps", "-a", "--format", "{{json .}}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return []

            containers = []
            for line in res.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    c = json.loads(line)
                    status_str = c.get("Status", "")
                    state_str = c.get("State", "")
                    # Detect crash-looping
                    is_crash_loop = "Restarting" in status_str or "unhealthy" in status_str.lower()

                    containers.append({
                        "id": c.get("ID"),
                        "name": c.get("Names"),
                        "image": c.get("Image"),
                        "state": state_str,
                        "status": status_str,
                        "is_crash_loop": is_crash_loop,
                        "ports": c.get("Ports")
                    })
                except json.JSONDecodeError:
                    continue
            return containers
        except Exception:
            return []

    def get_disk_waste_summary(self) -> Dict[str, Any]:
        """Calculates Docker reclaimable space (dangling images, build cache, stopped containers)."""
        if not self.available:
            return {"available": False, "reclaimable": "Docker daemon not running/detected"}

        try:
            cmd = ["docker", "system", "df", "--format", "{{json .}}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
            if res.returncode != 0:
                return {"available": True, "error": "Unable to query docker system df"}

            items = []
            for line in res.stdout.strip().split("\n"):
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

            return {
                "available": True,
                "summary": items,
                "recommended_command": "docker system prune -f"
            }
        except Exception as e:
            return {"available": False, "error": str(e)}
