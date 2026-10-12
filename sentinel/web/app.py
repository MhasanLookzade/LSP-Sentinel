from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from sentinel import __version__
from sentinel.config import load_config
from sentinel.core.metrics import get_full_hard_health
from sentinel.core.disk_analyzer import DiskAnalyzer
from sentinel.core.cleaner import DiskCleaner
from sentinel.core.synthetic import run_synthetic_probes
from sentinel.core.chaos import ChaosEngine
from sentinel.core.runbooks import generate_sre_runbooks
from sentinel.core.alerts import AlertDispatcher
from sentinel.core.docker_monitor import DockerMonitor
from sentinel.core.services_monitor import ServicesMonitor
from sentinel.core.prometheus_exporter import PrometheusExporter
from sentinel.core.autopilot import AutopilotEngine
from sentinel.core.drift_tracker import DriftTracker

app = FastAPI(
    title="LSP-Sentinel SRE Dashboard",
    version=__version__,
    description="Autonomous LSP-Sentinel Health, Resilience & Disk Intelligence"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

cfg = load_config()
autopilot_engine = AutopilotEngine(config=cfg, cooldown_sec=cfg.autopilot.cooldown_sec)
drift_tracker = DriftTracker(
    watch_paths=cfg.drift.watch_paths,
    state_file=cfg.drift.state_file,
    max_history=cfg.drift.max_history
)

class CleanRequest(BaseModel):
    files: List[str]
    dry_run: bool = True
    force_review: bool = False

class ChaosRequest(BaseModel):
    type: str = "cpu"  # cpu, ram, delay
    duration_sec: int = 5
    size_mb: int = 256

class AlertTestRequest(BaseModel):
    channel: str = "all"  # telegram, discord, slack, all

@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "version": __version__,
            "server_name": cfg.server_name,
            "environment": cfg.environment
        }
    )

@app.get("/api/health")
async def api_health():
    health_data = get_full_hard_health()
    dm = DockerMonitor()
    docker_data = {
        "available": dm.available,
        "containers": dm.get_containers_health() if dm.available else []
    }
    return {
        "status": "success",
        "data": health_data,
        "docker": docker_data
    }

@app.get("/api/disk/scan")
async def api_disk_scan(path: Optional[str] = None, min_mb: float = 10.0, depth: int = 4):
    scan_paths = [path] if path else cfg.disk.scan_paths
    analyzer = DiskAnalyzer(
        scan_paths=scan_paths,
        min_file_size_mb=min_mb,
        max_depth=depth,
        exclude_dirs=cfg.disk.exclude_dirs
    )
    result = analyzer.scan(limit_top=25)
    return {
        "status": "success",
        "result": result.to_dict()
    }

@app.post("/api/disk/clean")
async def api_disk_clean(req: CleanRequest):
    cleaner = DiskCleaner(dry_run=req.dry_run)
    res = cleaner.clean_batch(req.files, force_review=req.force_review)
    return {
        "status": "success",
        "result": res.to_dict()
    }

@app.get("/api/synthetic")
async def api_synthetic():
    results = run_synthetic_probes(cfg.synthetic_targets)
    return {
        "status": "success",
        "probes": [r.to_dict() for r in results]
    }

@app.post("/api/chaos")
async def api_chaos(req: ChaosRequest):
    engine = ChaosEngine(max_duration_sec=cfg.chaos.max_duration_sec, max_ram_mb=cfg.chaos.max_ram_mb)
    if req.type == "cpu":
        res = engine.run_cpu_stress(duration_sec=req.duration_sec)
    elif req.type == "ram":
        res = engine.run_ram_stress(target_mb=req.size_mb, duration_sec=req.duration_sec)
    elif req.type == "delay":
        res = engine.simulate_packet_delay(simulated_ms=req.duration_sec * 50)
    else:
        raise HTTPException(status_code=400, detail="Invalid experiment type. Must be cpu, ram, or delay.")

    return {
        "status": "success",
        "experiment": res.to_dict()
    }

@app.get("/metrics")
async def prometheus_metrics():
    """Exposes Prometheus / OpenMetrics scraping format."""
    exporter = PrometheusExporter(cfg)
    metrics_output = exporter.generate_metrics()
    return Response(
        content=metrics_output,
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )

@app.get("/api/services")
async def api_services():
    """Inspect status of critical DevOps services and failed systemd units."""
    sm = ServicesMonitor(services=getattr(cfg, "services", None))
    return {
        "status": "success",
        "summary": sm.get_summary()
    }

@app.get("/api/autopilot/status")
async def api_autopilot_status():
    """Retrieve autonomous autopilot status, last cycles, and alert debouncing state."""
    return {
        "status": "success",
        "autopilot": autopilot_engine.get_status()
    }

@app.post("/api/autopilot/run-cycle")
async def api_autopilot_cycle(auto_clean: bool = False):
    """Trigger an on-demand autonomous audit cycle with optional safe self-healing relief."""
    res = autopilot_engine.run_check_cycle(auto_clean=auto_clean)
    return {
        "status": "success",
        "cycle": res.to_dict()
    }

@app.get("/api/drift")
async def api_drift(since_minutes: int = 120):
    """Retrieve recent configuration and system changes tracked by the Time-Machine."""
    changes = drift_tracker.get_recent_changes(since_seconds=since_minutes * 60)
    summary = drift_tracker.get_summary()
    correlated = drift_tracker.correlate_with_incident(window_seconds=since_minutes * 60)
    return {
        "status": "success",
        "since_minutes": since_minutes,
        "summary": summary,
        "changes_count": len(changes),
        "changes": [c.to_dict() for c in changes],
        "correlated": correlated
    }

@app.post("/api/drift/snapshot")
async def api_drift_snapshot():
    """Trigger an immediate Time-Machine state snapshot and delta audit."""
    new_events = drift_tracker.snapshot_and_audit()
    return {
        "status": "success",
        "newly_detected": len(new_events),
        "events": [e.to_dict() for e in new_events]
    }

@app.get("/api/runbooks")
async def api_runbooks():
    h = get_full_hard_health()
    syn = [s.to_dict() for s in run_synthetic_probes(cfg.synthetic_targets)]
    dm = DockerMonitor()
    dock = dm.get_containers_health() if dm.available else []
    sm = ServicesMonitor(services=getattr(cfg, "services", None))
    svc_summary = sm.get_summary()
    correlated_drift = drift_tracker.correlate_with_incident(window_seconds=3600)
    runbooks = generate_sre_runbooks(
        h,
        synthetic_results=syn,
        docker_containers=dock,
        services_summary=svc_summary,
        drift_changes=correlated_drift
    )
    return {
        "status": "success",
        "count": len(runbooks),
        "runbooks": [r.to_dict() for r in runbooks]
    }

@app.post("/api/alerts/test")
async def api_test_alert(req: AlertTestRequest):
    dispatcher = AlertDispatcher(cfg.alerts)
    res = dispatcher.send_alert(
        title="Manual Test Ping from LSP-Sentinel Dashboard",
        message="System resilience check test notification. All alert channels operational.",
        severity="INFO"
    )
    return {
        "status": "success",
        "delivery": res
    }

