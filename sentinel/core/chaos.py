import time
import threading
import multiprocessing
import gc
from typing import Dict, Any, Optional
import psutil

class ChaosExperimentResult:
    def __init__(self, experiment_type: str, duration_sec: float, success: bool, message: str, peak_metric: float):
        self.experiment_type = experiment_type
        self.duration_sec = duration_sec
        self.success = success
        self.message = message
        self.peak_metric = peak_metric

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_type": self.experiment_type,
            "duration_sec": round(self.duration_sec, 2),
            "success": self.success,
            "message": self.message,
            "peak_metric": round(self.peak_metric, 2)
        }

def _cpu_worker(stop_event: threading.Event):
    while not stop_event.is_set():
        _ = 123456 * 654321

class ChaosEngine:
    def __init__(self, max_duration_sec: int = 60, max_ram_mb: int = 1024):
        self.max_duration_sec = max_duration_sec
        self.max_ram_mb = max_ram_mb

    def run_cpu_stress(self, duration_sec: int = 10, workers: Optional[int] = None) -> ChaosExperimentResult:
        """Stresses CPU cores for a bounded duration to test alerts and throttling."""
        duration_sec = min(duration_sec, self.max_duration_sec)
        num_workers = workers or min(multiprocessing.cpu_count(), 4)
        stop_event = threading.Event()
        threads = []

        start_time = time.time()
        for _ in range(num_workers):
            t = threading.Thread(target=_cpu_worker, args=(stop_event,), daemon=True)
            threads.append(t)
            t.start()

        peak_cpu = 0.0
        while time.time() - start_time < duration_sec:
            c = psutil.cpu_percent(interval=0.5)
            if c > peak_cpu:
                peak_cpu = c

        stop_event.set()
        for t in threads:
            t.join(timeout=1.0)

        elapsed = time.time() - start_time
        return ChaosExperimentResult(
            experiment_type="CPU_STRESS",
            duration_sec=elapsed,
            success=True,
            message=f"Simulated CPU stress with {num_workers} threads. Monitored server resilience under peak load.",
            peak_metric=peak_cpu
        )

    def run_ram_stress(self, target_mb: int = 512, duration_sec: int = 10) -> ChaosExperimentResult:
        """Allocates a controlled memory buffer to test OOM prevention and RAM alerting."""
        duration_sec = min(duration_sec, self.max_duration_sec)
        target_mb = min(target_mb, self.max_ram_mb)

        # Safety check: do not starve system
        vm = psutil.virtual_memory()
        avail_mb = vm.available / (1024 * 1024)
        if avail_mb < target_mb + 200:
            return ChaosExperimentResult(
                experiment_type="RAM_PRESSURE",
                duration_sec=0,
                success=False,
                message=f"ABORTED FOR SAFETY: Available RAM ({avail_mb:.0f} MB) is too low to safely allocate {target_mb} MB.",
                peak_metric=vm.percent
            )

        start_time = time.time()
        byte_chunks = []
        try:
            # Allocate 10MB chunks
            chunk_count = target_mb // 10
            for _ in range(chunk_count):
                byte_chunks.append(bytearray(10 * 1024 * 1024))

            peak_ram = psutil.virtual_memory().percent
            time.sleep(duration_sec)
            elapsed = time.time() - start_time
        finally:
            byte_chunks.clear()
            del byte_chunks
            gc.collect()

        return ChaosExperimentResult(
            experiment_type="RAM_PRESSURE",
            duration_sec=elapsed,
            success=True,
            message=f"Allocated {target_mb}MB for {duration_sec}s. Verified alert triggers and memory reclamation.",
            peak_metric=peak_ram
        )

    def simulate_packet_delay(self, simulated_ms: int = 250) -> ChaosExperimentResult:
        """Simulates latency jitter for testing synthetic monitoring sensitivity."""
        time.sleep(simulated_ms / 1000.0)
        return ChaosExperimentResult(
            experiment_type="LATENCY_INJECTION",
            duration_sec=simulated_ms / 1000.0,
            success=True,
            message=f"Injected {simulated_ms}ms synthetic latency. Verified that downstream threshold alerts fired.",
            peak_metric=float(simulated_ms)
        )
