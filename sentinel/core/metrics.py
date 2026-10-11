import os
import platform
import time
from typing import Dict, Any, List, Optional
import psutil

def get_system_overview() -> Dict[str, Any]:
    """Retrieves high-level host system metadata and uptime."""
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    hours, rem = divmod(int(uptime_seconds), 3600)
    minutes, seconds = divmod(rem, 60)
    days, hours = divmod(hours, 24)

    uptime_str = f"{days}d {hours}h {minutes}m" if days > 0 else f"{hours}h {minutes}m {seconds}s"

    # Load average (Linux natively provides this, on Windows fallback gracefully)
    load_avg = [0.0, 0.0, 0.0]
    if hasattr(os, "getloadavg"):
        try:
            load_avg = list(os.getloadavg())
        except OSError:
            pass

    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "cpu_count_logical": psutil.cpu_count(logical=True) or 1,
        "cpu_count_physical": psutil.cpu_count(logical=False) or 1,
        "uptime_seconds": uptime_seconds,
        "uptime_formatted": uptime_str,
        "load_average": [round(x, 2) for x in load_avg]
    }

def get_cpu_metrics() -> Dict[str, Any]:
    """Retrieves CPU utilization, frequency, and core distribution."""
    per_core = psutil.cpu_percent(interval=0.1, percpu=True)
    total = sum(per_core) / max(len(per_core), 1)

    freq = psutil.cpu_freq()
    freq_data = {
        "current_mhz": round(freq.current, 1) if freq else 0.0,
        "min_mhz": round(freq.min, 1) if freq and freq.min else 0.0,
        "max_mhz": round(freq.max, 1) if freq and freq.max else 0.0,
    }

    return {
        "total_percent": round(total, 1),
        "per_core_percent": [round(c, 1) for c in per_core],
        "frequency": freq_data
    }

def get_memory_metrics() -> Dict[str, Any]:
    """Retrieves RAM and Swap memory utilization."""
    vm = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "ram": {
            "total_bytes": vm.total,
            "used_bytes": vm.used,
            "available_bytes": vm.available,
            "free_bytes": vm.free,
            "percent": vm.percent,
            "cached_bytes": getattr(vm, "cached", 0),
            "buffers_bytes": getattr(vm, "buffers", 0),
        },
        "swap": {
            "total_bytes": swap.total,
            "used_bytes": swap.used,
            "free_bytes": swap.free,
            "percent": swap.percent
        }
    }

def get_disk_health_metrics() -> Dict[str, Any]:
    """Retrieves mounted partitions, usage, inodes (if Linux), and I/O rates."""
    partitions = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            part_info = {
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent": usage.percent
            }
            # Check inode stats on Linux
            if hasattr(os, "statvfs"):
                try:
                    vfs = os.statvfs(part.mountpoint)
                    if vfs.f_files > 0:
                        used_inodes = vfs.f_files - vfs.f_ffree
                        part_info["inodes_total"] = vfs.f_files
                        part_info["inodes_used"] = used_inodes
                        part_info["inodes_percent"] = round((used_inodes / vfs.f_files) * 100.0, 1)
                except Exception:
                    pass

            partitions.append(part_info)
        except (PermissionError, OSError):
            continue

    # Disk I/O counters
    io_data = {}
    try:
        io = psutil.disk_io_counters()
        if io:
            io_data = {
                "read_bytes": io.read_bytes,
                "write_bytes": io.write_bytes,
                "read_count": io.read_count,
                "write_count": io.write_count
            }
    except Exception:
        pass

    return {
        "partitions": partitions,
        "io": io_data
    }

def get_network_metrics() -> Dict[str, Any]:
    """Retrieves network interfaces, byte counters, and open listening ports."""
    net_io = psutil.net_io_counters()
    net_data = {
        "bytes_sent": net_io.bytes_sent if net_io else 0,
        "bytes_recv": net_io.bytes_recv if net_io else 0,
        "packets_sent": net_io.packets_sent if net_io else 0,
        "packets_recv": net_io.packets_recv if net_io else 0,
        "errin": net_io.errin if net_io else 0,
        "errout": net_io.errout if net_io else 0,
    }

    # Listening ports detection
    listening_ports = []
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.status == "LISTEN" and c.laddr:
                listening_ports.append({
                    "port": c.laddr.port,
                    "ip": c.laddr.ip,
                    "pid": c.pid
                })
    except (psutil.AccessDenied, PermissionError, OSError):
        pass

    # Sort ports
    listening_ports.sort(key=lambda x: x["port"])

    return {
        "traffic": net_data,
        "listening_ports": listening_ports[:20]
    }

def get_top_processes(limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
    """Gets top processes consuming CPU and RAM."""
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
        try:
            info = p.info
            # Round values
            info['cpu_percent'] = round(info.get('cpu_percent') or 0.0, 1)
            info['memory_percent'] = round(info.get('memory_percent') or 0.0, 1)
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    top_cpu = sorted(procs, key=lambda x: x['cpu_percent'], reverse=True)[:limit]
    top_mem = sorted(procs, key=lambda x: x['memory_percent'], reverse=True)[:limit]

    return {
        "top_cpu": top_cpu,
        "top_memory": top_mem
    }

def get_full_hard_health() -> Dict[str, Any]:
    """Aggregates complete hard health report."""
    return {
        "timestamp": time.time(),
        "system": get_system_overview(),
        "cpu": get_cpu_metrics(),
        "memory": get_memory_metrics(),
        "disk": get_disk_health_metrics(),
        "network": get_network_metrics(),
        "processes": get_top_processes(limit=8)
    }
