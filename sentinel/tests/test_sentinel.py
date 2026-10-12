import unittest
from pathlib import Path
import tempfile
import os

from sentinel.core.safety_rules import evaluate_file_safety, evaluate_folder_safety, SafetyLevel, ReclaimAction
from sentinel.core.metrics import get_system_overview, get_cpu_metrics, get_memory_metrics, get_disk_health_metrics
from sentinel.core.cleaner import DiskCleaner
from sentinel.core.synthetic import SyntheticTarget, probe_dns, probe_tcp
from sentinel.core.runbooks import generate_sre_runbooks
from sentinel.core.services_monitor import ServicesMonitor, ServiceStatus
from sentinel.core.prometheus_exporter import PrometheusExporter
from sentinel.core.autopilot import AutopilotEngine
from sentinel.config import SentinelConfig, AlertConfig

class TestSafetyRules(unittest.TestCase):
    def test_critical_paths_protected(self):
        # /etc, /boot, database paths must be CRITICAL
        v1 = evaluate_file_safety("/etc/nginx/nginx.conf", 1024)
        self.assertEqual(v1.level, SafetyLevel.CRITICAL)
        self.assertEqual(v1.action, ReclaimAction.PROTECTED)

        v2 = evaluate_file_safety("/var/lib/mysql/ibdata1", 1024 * 1024 * 100)
        self.assertEqual(v2.level, SafetyLevel.CRITICAL)

        v3 = evaluate_file_safety("/home/user/.ssh/id_rsa", 2048)
        self.assertEqual(v3.level, SafetyLevel.CRITICAL)

    def test_safe_rotated_logs(self):
        # Rotated logs should be SAFE to delete
        v1 = evaluate_file_safety("/var/log/nginx/access.log.1", 10 * 1024 * 1024)
        self.assertEqual(v1.level, SafetyLevel.SAFE)
        self.assertEqual(v1.action, ReclaimAction.DELETE)

        v2 = evaluate_file_safety("/var/log/syslog.2.gz", 50 * 1024 * 1024)
        self.assertEqual(v2.level, SafetyLevel.SAFE)
        self.assertEqual(v2.action, ReclaimAction.DELETE)

    def test_active_large_logs_require_truncate(self):
        # Active large log files (> 50MB) should be REVIEW with TRUNCATE, not DELETE
        v = evaluate_file_safety("/var/log/app.log", 80 * 1024 * 1024)
        self.assertEqual(v.level, SafetyLevel.REVIEW)
        self.assertEqual(v.action, ReclaimAction.TRUNCATE)

    def test_folder_safety(self):
        vf_crit = evaluate_folder_safety("/etc", 1024)
        self.assertEqual(vf_crit.level, SafetyLevel.CRITICAL)

        vf_cache = evaluate_folder_safety("/var/cache/apt", 500 * 1024 * 1024)
        self.assertEqual(vf_cache.level, SafetyLevel.SAFE)

class TestCleanerShield(unittest.TestCase):
    def test_dry_run_protects_files(self):
        with tempfile.NamedTemporaryFile(suffix=".log.1", delete=False) as tf:
            tf.write(b"rotated log data")
            t_path = tf.name

        try:
            cleaner = DiskCleaner(dry_run=True)
            res = cleaner.clean_file(t_path)
            self.assertEqual(res.status, "SUCCESS")
            self.assertTrue("WOULD_" in res.action)
            # File must still exist because dry-run
            self.assertTrue(os.path.exists(t_path))
        finally:
            if os.path.exists(t_path):
                os.remove(t_path)

    def test_cleaner_blocks_critical(self):
        cleaner = DiskCleaner(dry_run=False)
        # Attempting to clean /etc/hosts or simulated critical
        res = cleaner.clean_file("/etc/hosts")
        self.assertEqual(res.action, "BLOCKED")
        self.assertEqual(res.status, "SKIPPED")

class TestMetrics(unittest.TestCase):
    def test_overview_metrics(self):
        ov = get_system_overview()
        self.assertIn("hostname", ov)
        self.assertIn("uptime_formatted", ov)

    def test_cpu_and_mem_metrics(self):
        cpu = get_cpu_metrics()
        self.assertIn("total_percent", cpu)
        mem = get_memory_metrics()
        self.assertIn("ram", mem)
        self.assertIn("swap", mem)

class TestSyntheticAndRunbooks(unittest.TestCase):
    def test_dns_probe(self):
        t = SyntheticTarget(name="DNS Test", type="dns", target="8.8.8.8")
        res = probe_dns(t)
        self.assertTrue(res.healthy)

    def test_runbooks_generation(self):
        fake_health = {
            "disk": {"partitions": [{"mountpoint": "/", "percent": 96.0}]},
            "memory": {"ram": {"percent": 92.0}},
            "cpu": {"total_percent": 90.0},
            "processes": {"top_memory": [{"name": "node", "pid": 1234, "memory_percent": 45.0}]}
        }
        runbooks = generate_sre_runbooks(fake_health)
        self.assertGreaterEqual(len(runbooks), 2)
        # Verify runbook has copy-paste commands
        self.assertTrue(any("docker" in cmd or "lsp-sentinel" in cmd for rb in runbooks for cmd in rb.commands))

    def test_runbooks_with_failed_services(self):
        fake_health = {"disk": {}, "memory": {}, "cpu": {}, "processes": {}}
        fake_services = {
            "failed_units": ["nginx.service"],
            "services": [
                {"name": "postgresql", "status": "failed", "is_critical": True, "sub_state": "failed"}
            ]
        }
        runbooks = generate_sre_runbooks(fake_health, services_summary=fake_services)
        self.assertGreaterEqual(len(runbooks), 2)
        titles = [r.title for r in runbooks]
        self.assertTrue(any("nginx.service" in t for t in titles))
        self.assertTrue(any("postgresql" in t for t in titles))

class TestDevOpsModules(unittest.TestCase):
    def test_services_monitor_summary(self):
        sm = ServicesMonitor(services=["nginx", "docker"])
        summary = sm.get_summary()
        self.assertIn("total_monitored", summary)
        self.assertIn("services", summary)
        self.assertEqual(summary["total_monitored"], 2)
        self.assertIsInstance(summary["services"], list)

    def test_prometheus_exporter(self):
        cfg = SentinelConfig()
        exporter = PrometheusExporter(cfg)
        output = exporter.generate_metrics()
        self.assertIn("sentinel_info", output)
        self.assertIn("node_cpu_utilization_percent", output)
        self.assertIn("node_memory_used_bytes", output)

    def test_autopilot_engine_cycle(self):
        cfg = SentinelConfig(alerts=AlertConfig(enabled=False, cpu_threshold_pct=1.0))
        engine = AutopilotEngine(config=cfg, cooldown_sec=300)
        res = engine.run_check_cycle(auto_clean=False)
        self.assertIsNotNone(res.timestamp)
        # Since CPU threshold is 1.0%, an anomaly should be detected
        self.assertGreaterEqual(len(res.issues_detected), 1)
        status = engine.get_status()
        self.assertEqual(status["total_cycles"], 1)

if __name__ == "__main__":
    unittest.main()

