import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from pathlib import Path
from typing import Optional, List
import sys

from sentinel import __version__
from sentinel.config import load_config
from sentinel.core.metrics import get_full_hard_health
from sentinel.core.disk_analyzer import DiskAnalyzer, format_bytes
from sentinel.core.safety_rules import SafetyLevel
from sentinel.core.cleaner import DiskCleaner
from sentinel.core.synthetic import run_synthetic_probes
from sentinel.core.chaos import ChaosEngine
from sentinel.core.runbooks import generate_sre_runbooks
from sentinel.core.docker_monitor import DockerMonitor
from sentinel.core.services_monitor import ServicesMonitor
from sentinel.core.autopilot import AutopilotEngine
from sentinel.core.drift_tracker import DriftTracker

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

app = typer.Typer(
    name="lsp-sentinel",
    help="Autonomous LSP-Sentinel SRE Health, Resilience & Disk Intelligence Suite",
    add_completion=False
)
console = Console(highlight=False)

def render_banner():
    banner = f"""[bold cyan]
  _     ____  ____        ____             _   _            _ 
 | |   / ___||  _ \\      / ___|  ___ _ __ | |_(_)_ __   ___| |
 | |   \\___ \\| |_) |_____\\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |
 | |___ ___) |  __/ |_____|___) |  __/ | | | |_| | | | |  __/ |
 |_____|____/|_|         |____/ \\___|_| |_|\\__|_|_| |_|\\___|_| v{__version__}
    [/bold cyan][dim]Autonomous LSP-Sentinel SRE Health, Resilience & Disk Intelligence[/dim]
"""
    console.print(banner)

@app.command()
def health(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Inspect full hard health metrics: CPU, RAM, Disks, Ports, and Processes."""
    render_banner()
    with Progress(SpinnerColumn(), TextColumn("[bold green]Collecting hard health metrics..."), transient=True) as progress:
        progress.add_task("metrics", total=None)
        h = get_full_hard_health()

    sys_info = h["system"]
    cpu = h["cpu"]
    mem = h["memory"]
    disk = h["disk"]
    net = h["network"]

    # 1. System Overview Panel
    overview_text = (
        f"[bold white]Host:[/bold white] {sys_info['hostname']}   "
        f"[bold white]OS:[/bold white] {sys_info['os']} {sys_info['release']} ({sys_info['architecture']})   "
        f"[bold white]Uptime:[/bold white] [green]{sys_info['uptime_formatted']}[/green]   "
        f"[bold white]Load Avg:[/bold white] {sys_info['load_average']}"
    )
    console.print(Panel(overview_text, title="[bold cyan]System Overview[/bold cyan]", border_style="cyan"))

    # 2. CPU & Memory Panels
    cpu_color = "red" if cpu['total_percent'] > 85 else ("yellow" if cpu['total_percent'] > 60 else "green")
    ram_pct = mem['ram']['percent']
    ram_color = "red" if ram_pct > 88 else ("yellow" if ram_pct > 70 else "green")

    ram_used_fmt = format_bytes(mem['ram']['used_bytes'])
    ram_total_fmt = format_bytes(mem['ram']['total_bytes'])

    cpu_panel = (
        f"[bold]Total CPU:[/bold] [{cpu_color}]{cpu['total_percent']}%[/{cpu_color}]\n"
        f"[bold]Cores:[/bold] {sys_info['cpu_count_logical']} logical ({sys_info['cpu_count_physical']} physical)\n"
        f"[bold]Per-Core:[/bold] {', '.join(f'{c}%' for c in cpu['per_core_percent'][:8])}"
    )
    mem_panel = (
        f"[bold]RAM Used:[/bold] [{ram_color}]{ram_pct}%[/{ram_color}] ({ram_used_fmt} / {ram_total_fmt})\n"
        f"[bold]Cached / Buffers:[/bold] {format_bytes(mem['ram']['cached_bytes'])} / {format_bytes(mem['ram']['buffers_bytes'])}\n"
        f"[bold]Swap:[/bold] {mem['swap']['percent']}% ({format_bytes(mem['swap']['used_bytes'])} / {format_bytes(mem['swap']['total_bytes'])})"
    )

    t_resources = Table(show_header=True, header_style="bold magenta", expand=True)
    t_resources.add_column("CPU Metrics", ratio=1)
    t_resources.add_column("Memory & Swap Metrics", ratio=1)
    t_resources.add_row(cpu_panel, mem_panel)
    console.print(t_resources)

    # 3. Disk Partitions Table
    t_disk = Table(title="Mounted Storage Partitions", show_header=True, header_style="bold cyan", expand=True)
    t_disk.add_column("Mountpoint", style="bold white")
    t_disk.add_column("Filesystem")
    t_disk.add_column("Used / Total")
    t_disk.add_column("Usage %", justify="right")
    t_disk.add_column("Inodes %", justify="right")

    for p in disk["partitions"]:
        pct = p["percent"]
        col = "red" if pct > 88 else ("yellow" if pct > 70 else "green")
        inodes = f"{p['inodes_percent']}%" if "inodes_percent" in p else "N/A"
        t_disk.add_row(
            p["mountpoint"],
            p["fstype"],
            f"{format_bytes(p['used_bytes'])} / {format_bytes(p['total_bytes'])}",
            f"[{col}]{pct}%[/{col}]",
            inodes
        )
    console.print(t_disk)

    # 4. Top Resource Processes
    t_proc = Table(title="Top Resource Consuming Processes", show_header=True, header_style="bold blue", expand=True)
    t_proc.add_column("PID", justify="right")
    t_proc.add_column("Process Name", style="bold white")
    t_proc.add_column("CPU %", justify="right")
    t_proc.add_column("RAM %", justify="right")
    t_proc.add_column("User")

    for pr in h["processes"]["top_cpu"][:6]:
        t_proc.add_row(
            str(pr.get("pid")),
            str(pr.get("name")),
            f"[yellow]{pr.get('cpu_percent')}%[/yellow]",
            f"{pr.get('memory_percent')}%",
            str(pr.get("username") or "system")
        )
    console.print(t_proc)

    # Docker status
    dm = DockerMonitor()
    if dm.available:
        containers = dm.get_containers_health()
        running_cnt = sum(1 for c in containers if "Up" in c["status"])
        console.print(f"[bold green]✔ Docker Daemon Active:[/bold green] {running_cnt} running container(s)")

@app.command()
def disk(
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Custom folder path to scan"),
    min_size: float = typer.Option(20.0, "--min-mb", help="Minimum file size in MB to display"),
    depth: int = typer.Option(4, "--depth", "-d", help="Folder scan depth"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Scan large files & folders with intelligent safety classifications (SAFE / REVIEW / CRITICAL)."""
    render_banner()
    cfg = load_config(config_file)
    scan_targets = [path] if path else cfg.disk.scan_paths

    analyzer = DiskAnalyzer(
        scan_paths=scan_targets,
        min_file_size_mb=min_size,
        max_depth=depth,
        exclude_dirs=cfg.disk.exclude_dirs
    )

    with Progress(SpinnerColumn(), TextColumn("[bold yellow]Deep scanning filesystems & classifying safety rules..."), transient=True) as progress:
        progress.add_task("scan", total=None)
        res = analyzer.scan(limit_top=12)

    # Summary Panel
    summary_text = (
        f"[bold white]Scanned:[/bold white] {res.total_files_scanned} files across {res.total_folders_scanned} folders ({res.to_dict()['total_size_scanned_formatted']}) in {res.scan_duration_sec:.2f}s\n"
        f"[bold green]🟢 SAFE RECLAIMABLE SPACE:[/bold green] [bold white]{res.to_dict()['safe_reclaimable_formatted']}[/bold white] (Safe to purge immediately)\n"
        f"[bold yellow]🟡 REVIEWABLE STORAGE:[/bold yellow] [bold white]{res.to_dict()['reviewable_formatted']}[/bold white] (Active logs / dumps - review before cleaning)\n"
        f"[bold red]🔴 PROTECTED SYSTEM ASSETS:[/bold red] [bold white]{res.to_dict()['protected_formatted']}[/bold white] (Shielded by Sentinel)"
    )
    console.print(Panel(summary_text, title="[bold green]Disk Space Intelligence Summary[/bold green]", border_style="green"))

    # Top Folders Table
    t_folders = Table(title="Top Largest Directories", show_header=True, header_style="bold magenta", expand=True)
    t_folders.add_column("Directory Path", style="bold white")
    t_folders.add_column("Size", justify="right")
    t_folders.add_column("Safety Verdict")
    t_folders.add_column("Action / Guidance")

    for f in res.top_folders[:8]:
        sec = f.verdict
        badge = "[green]🟢 SAFE TO PURGE[/green]" if sec.level == SafetyLevel.SAFE else (
            "[yellow]🟡 REVIEW[/yellow]" if sec.level == SafetyLevel.REVIEW else "[red]🔴 CRITICAL PROTECTED[/red]"
        )
        t_folders.add_row(
            f.path,
            f.to_dict()["size_formatted"],
            badge,
            f"[dim]{sec.recommendation}[/dim]"
        )
    console.print(t_folders)

    # Top Files Table
    t_files = Table(title=f"Top Largest Files (>= {min_size} MB)", show_header=True, header_style="bold cyan", expand=True)
    t_files.add_column("File Path", style="bold white")
    t_files.add_column("Size", justify="right")
    t_files.add_column("Safety Level")
    t_files.add_column("Recommended Action")

    for fi in res.top_files[:10]:
        sec = fi.verdict
        badge = "[green]🟢 SAFE[/green]" if sec.level == SafetyLevel.SAFE else (
            "[yellow]🟡 REVIEW[/yellow]" if sec.level == SafetyLevel.REVIEW else "[red]🔴 PROTECTED[/red]"
        )
        action_note = f"[cyan]{sec.action.value}[/cyan]: {sec.recommendation}"
        if sec.command_hint:
            action_note += f"\n[dim yellow]Hint: {sec.command_hint}[/dim yellow]"
        t_files.add_row(
            fi.path,
            fi.to_dict()["size_formatted"],
            badge,
            action_note
        )
    console.print(t_files)

    console.print("\n[dim]To safely free space, run: [bold green]lsp-sentinel clean --safe-only[/bold green][/dim]")

@app.command()
def clean(
    safe_only: bool = typer.Option(True, "--safe-only", help="Only delete files classified strictly as SAFE"),
    include_review: bool = typer.Option(False, "--include-review", help="Also process REVIEW files with safe truncation"),
    dry_run: bool = typer.Option(True, "--dry-run/--execute", help="Dry run mode previews actions without modifying disk"),
    path: Optional[str] = typer.Option(None, "--path", "-p", help="Target folder or file to clean"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Safely reclaim disk space using the intelligent safety shield."""
    render_banner()
    cfg = load_config(config_file)
    scan_targets = [path] if path else cfg.disk.scan_paths

    analyzer = DiskAnalyzer(scan_paths=scan_targets, min_file_size_mb=1.0)
    with Progress(SpinnerColumn(), TextColumn("[bold yellow]Scanning for reclaimable files..."), transient=True) as progress:
        progress.add_task("scan", total=None)
        res = analyzer.scan(limit_top=100)

    # Filter files to clean
    targets_to_clean = []
    for f in res.top_files:
        if f.verdict.level == SafetyLevel.SAFE:
            targets_to_clean.append(f.path)
        elif f.verdict.level == SafetyLevel.REVIEW and include_review:
            targets_to_clean.append(f.path)

    cleaner = DiskCleaner(dry_run=dry_run)
    batch_res = cleaner.clean_batch(targets_to_clean, force_review=include_review)

    t_clean = Table(title=f"Cleanup Results ({'[yellow]DRY-RUN[/yellow]' if dry_run else '[green]EXECUTED[/green]'})", expand=True)
    t_clean.add_column("File", style="bold white")
    t_clean.add_column("Action")
    t_clean.add_column("Space Freed", justify="right")
    t_clean.add_column("Status")
    t_clean.add_column("Details")

    for item in batch_res.items:
        stat_color = "green" if item.status == "SUCCESS" else ("yellow" if item.status == "SKIPPED" else "red")
        t_clean.add_row(
            item.path,
            item.action,
            format_bytes(item.bytes_freed),
            f"[{stat_color}]{item.status}[/{stat_color}]",
            item.message
        )
    console.print(t_clean)

    freed_str = format_bytes(batch_res.total_bytes_freed)
    if dry_run:
        console.print(f"\n[bold yellow]Preview Complete:[/bold yellow] Would safely reclaim [bold green]{freed_str}[/bold green].")
        console.print("[dim]To execute this cleanup for real, run:[/dim] [bold green]lsp-sentinel clean --safe-only --execute[/bold green]\n")
    else:
        console.print(f"\n[bold green]Cleanup Complete![/bold green] Successfully reclaimed [bold green]{freed_str}[/bold green] of disk space!\n")

@app.command()
def synthetic(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Run synthetic health & uptime probes (HTTP, SSL, TCP, DNS)."""
    render_banner()
    cfg = load_config(config_file)
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Probing synthetic targets & SSL certificates..."), transient=True) as progress:
        progress.add_task("probe", total=None)
        results = run_synthetic_probes(cfg.synthetic_targets)

    t_syn = Table(title="Synthetic Service Resilience Probes", show_header=True, header_style="bold green", expand=True)
    t_syn.add_column("Probe Name", style="bold white")
    t_syn.add_column("Type")
    t_syn.add_column("Target")
    t_syn.add_column("Health Status")
    t_syn.add_column("Latency", justify="right")
    t_syn.add_column("Diagnostic Details")

    for r in results:
        status_badge = "[bold green]✔ HEALTHY[/bold green]" if r.healthy else "[bold red]✖ FAILING[/bold red]"
        lat_color = "green" if r.latency_ms < 200 else ("yellow" if r.latency_ms < 500 else "red")
        t_syn.add_row(
            r.name,
            r.target_type.upper(),
            r.target,
            status_badge,
            f"[{lat_color}]{r.latency_ms} ms[/{lat_color}]",
            r.detail
        )
    console.print(t_syn)

@app.command()
def chaos(
    test_type: str = typer.Option("cpu", "--type", "-t", help="Experiment type: 'cpu', 'ram', or 'delay'"),
    duration: int = typer.Option(10, "--duration", "-d", help="Duration in seconds (max 60s)"),
    size_mb: int = typer.Option(256, "--size-mb", help="RAM buffer size in MB for ram stress"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Run resilience & chaos experiments to verify system alerting and throttling."""
    render_banner()
    cfg = load_config(config_file)
    engine = ChaosEngine(max_duration_sec=cfg.chaos.max_duration_sec, max_ram_mb=cfg.chaos.max_ram_mb)

    console.print(f"[bold yellow]⚡ Initiating Chaos Experiment:[/bold yellow] {test_type.upper()} for {duration} seconds...")
    if test_type.lower() == "cpu":
        res = engine.run_cpu_stress(duration_sec=duration)
    elif test_type.lower() == "ram":
        res = engine.run_ram_stress(target_mb=size_mb, duration_sec=duration)
    elif test_type.lower() == "delay":
        res = engine.simulate_packet_delay(simulated_ms=duration * 50)
    else:
        console.print("[red]Unknown experiment type. Choose 'cpu', 'ram', or 'delay'.[/red]")
        raise typer.Exit(1)

    panel_body = (
        f"[bold white]Experiment:[/bold white] {res.experiment_type}\n"
        f"[bold white]Duration:[/bold white] {res.duration_sec}s\n"
        f"[bold white]Peak Observed:[/bold white] [bold cyan]{res.peak_metric}[/bold cyan]\n"
        f"[bold white]Status:[/bold white] {'[green]SUCCESS[/green]' if res.success else '[red]FAILED[/red]'}\n"
        f"[bold white]Result:[/bold white] {res.message}"
    )
    console.print(Panel(panel_body, title="[bold red]Resilience Chaos Result[/bold red]", border_style="red"))

@app.command()
def runbook(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Generate dynamic SRE incident triage runbooks for active issues."""
    render_banner()
    cfg = load_config(config_file)
    with Progress(SpinnerColumn(), TextColumn("[bold magenta]Diagnosing system issues & compiling runbooks..."), transient=True) as progress:
        progress.add_task("runbook", total=None)
        h = get_full_hard_health()
        syn = [s.to_dict() for s in run_synthetic_probes(cfg.synthetic_targets)]
        dm = DockerMonitor()
        dock = dm.get_containers_health() if dm.available else []
        sm = ServicesMonitor(services=getattr(cfg, "services", None))
        svc_summary = sm.get_summary()

        drift_tracker = DriftTracker(
            watch_paths=cfg.drift.watch_paths,
            state_file=cfg.drift.state_file,
            max_history=cfg.drift.max_history
        )
        drift_tracker.snapshot_and_audit()
        correlated_drift = drift_tracker.correlate_with_incident(window_seconds=3600)

        runbooks = generate_sre_runbooks(
            h,
            synthetic_results=syn,
            docker_containers=dock,
            services_summary=svc_summary,
            drift_changes=correlated_drift
        )

    if not runbooks:
        console.print(Panel("[bold green]✔ All systems nominal! No active incidents or remediation required.[/bold green]", border_style="green"))
        return

    for inc in runbooks:
        col = "red" if inc.severity == "CRITICAL" else "yellow"
        drift_section = ""
        if inc.correlated_changes:
            drift_lines = "\n".join(f"  [bold yellow]⚡ {c['time_label']}:[/bold yellow] {c['target']} [magenta]({c['action']})[/magenta]" for c in inc.correlated_changes[:3])
            drift_section = f"\n[bold red underline]⚡ Pre-Incident System Drift Detected:[/bold red underline]\n{drift_lines}\n"

        body = (
            f"[bold]Severity:[/bold] [{col}]{inc.severity}[/{col}]   [bold]Observation:[/bold] {inc.metric_value}\n\n"
            f"{drift_section}"
            f"[bold underline]Likely Root Causes:[/bold underline]\n" + "\n".join(f"• {c}" for c in inc.root_causes) + "\n\n"
            f"[bold underline]Actionable Remediation Commands:[/bold underline]\n" + "\n".join(f"[bold cyan]$ {cmd}[/bold cyan]" for cmd in inc.commands)
        )
        console.print(Panel(body, title=f"[{col}]Incident Triage: {inc.title}[/{col}]", border_style=col))

@app.command()
def drift(
    since: str = typer.Option("2h", "--since", "-s", help="Time window to inspect (e.g. 30m, 2h, 24h)"),
    show_diff: bool = typer.Option(False, "--diff", "-d", help="Display unified diff previews for modified files"),
    snapshot: bool = typer.Option(True, "--snapshot/--no-snapshot", help="Take a fresh snapshot and audit changes now"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Time-Machine: Track configuration drifts, crontab edits, and package updates."""
    render_banner()
    cfg = load_config(config_file)
    tracker = DriftTracker(
        watch_paths=cfg.drift.watch_paths,
        state_file=cfg.drift.state_file,
        max_history=cfg.drift.max_history
    )

    # Parse time string
    multiplier = 3600
    val_str = since.lower().strip()
    if val_str.endswith("m"):
        multiplier = 60
        num = float(val_str[:-1])
    elif val_str.endswith("h"):
        multiplier = 3600
        num = float(val_str[:-1])
    elif val_str.endswith("d"):
        multiplier = 86400
        num = float(val_str[:-1])
    else:
        try:
            num = float(val_str)
        except ValueError:
            num = 2.0

    seconds_window = int(num * multiplier)

    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Scanning system for configuration drifts & updates..."), transient=True) as progress:
        progress.add_task("drift", total=None)
        if snapshot:
            newly_found = tracker.snapshot_and_audit()
        else:
            newly_found = []

    changes = tracker.get_recent_changes(since_seconds=seconds_window)
    summary = tracker.get_summary()

    console.print(Panel(
        f"[bold white]Monitored Targets:[/bold white] {summary['total_tracked_files']} files & packages\n"
        f"[bold white]Changes in last {since}:[/bold white] [bold {'yellow' if changes else 'green'}]{len(changes)} change event(s)[/bold {'yellow' if changes else 'green'}]\n"
        f"[bold white]Ledger State:[/bold white] {cfg.drift.state_file}",
        title="[bold cyan]⏳ Time-Machine System Drift Ledger[/bold cyan]",
        border_style="cyan"
    ))

    if not changes:
        console.print("[bold green]✔ No configuration drift or package modifications detected in the requested time window.[/bold green]\n")
        return

    t = Table(title=f"Changes Detected in the Last {since}", show_header=True, header_style="bold magenta", expand=True)
    t.add_column("Time", style="bold white", width=14)
    t.add_column("Category", justify="center", width=12)
    t.add_column("Action", justify="center", width=12)
    t.add_column("Target Path / Package", style="bold cyan")
    t.add_column("Details", style="dim")

    now = time.time()
    for e in reversed(changes):
        mins_ago = max(0, int((now - e.timestamp) / 60))
        time_str = f"{mins_ago}m ago" if mins_ago > 0 else "just now"

        if e.action == "MODIFIED":
            act_badge = "[bold yellow]MODIFIED[/bold yellow]"
        elif e.action in ("CREATED", "UPGRADED"):
            act_badge = "[bold green]" + e.action + "[/bold green]"
        else:
            act_badge = "[bold red]" + e.action + "[/bold red]"

        cat_badge = f"[cyan]{e.category}[/cyan]"
        t.add_row(
            time_str,
            cat_badge,
            act_badge,
            e.target,
            e.details[:60]
        )

    console.print(t)

    if show_diff:
        diff_count = 0
        for e in reversed(changes):
            if e.diff_preview:
                diff_count += 1
                console.print(Panel(
                    f"[dim]{e.diff_preview}[/dim]",
                    title=f"[yellow]Unified Diff: {e.target}[/yellow]",
                    border_style="yellow"
                ))
        if diff_count == 0:
            console.print("[dim]No textual diffs available for these changes.[/dim]")


@app.command()
def services(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Inspect status of critical DevOps services and failed systemd units."""
    render_banner()
    cfg = load_config(config_file)
    with Progress(SpinnerColumn(), TextColumn("[bold cyan]Auditing system services and daemons..."), transient=True) as progress:
        progress.add_task("services", total=None)
        sm = ServicesMonitor(services=getattr(cfg, "services", None))
        summary = sm.get_summary()

    t = Table(title="DevOps Services & Daemon Status", show_header=True, header_style="bold magenta", expand=True)
    t.add_column("Service", style="bold white")
    t.add_column("Status", justify="center")
    t.add_column("Sub-State")
    t.add_column("PID", justify="right")
    t.add_column("Memory", justify="right")
    t.add_column("Details", style="dim")

    for s in summary["services"]:
        st = s["status"]
        if st == "active":
            status_badge = "[bold green]🟢 ACTIVE[/bold green]"
        elif st == "failed":
            status_badge = "[bold red]🔴 FAILED[/bold red]"
        else:
            status_badge = "[dim]⚪ INACTIVE[/dim]"

        pid_str = str(s["pid"]) if s["pid"] else "--"
        mem_str = f"{s['memory_mb']:.1f} MB" if s["memory_mb"] else "--"
        t.add_row(
            s["name"],
            status_badge,
            s["sub_state"],
            pid_str,
            mem_str,
            s["description"][:45]
        )
    console.print(t)

    failed_units = summary.get("failed_units", [])
    if failed_units:
        failed_text = "\n".join(f"[bold red]✖ {u}[/bold red]" for u in failed_units)
        console.print(Panel(failed_text, title="[bold red]⚠️ Failed Systemd Units[/bold red]", border_style="red"))
    else:
        console.print(Panel("[bold green]✔ Zero failed systemd units detected on host.[/bold green]", border_style="green"))

@app.command()
def autopilot(
    interval: Optional[int] = typer.Option(None, "--interval", "-i", help="Check interval in seconds"),
    auto_clean: bool = typer.Option(False, "--auto-clean", help="Enable autonomous emergency purge of SAFE-only logs/cache"),
    cycles: int = typer.Option(0, "--cycles", "-n", help="Number of check cycles to run (0 = run continuously)"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Launch Autonomous DevOps Watchdog with live threshold alerts and safe self-healing."""
    render_banner()
    cfg = load_config(config_file)
    check_interval = interval or cfg.autopilot.check_interval_sec
    engine = AutopilotEngine(config=cfg, cooldown_sec=cfg.autopilot.cooldown_sec)

    clean_mode_str = "[bold green]ENABLED (SAFE-only)[/bold green]" if auto_clean else "[dim]DISABLED[/dim]"
    console.print(Panel(
        f"[bold white]Target Server:[/bold white] {cfg.server_name} ({cfg.environment})\n"
        f"[bold white]Poll Interval:[/bold white] {check_interval} seconds\n"
        f"[bold white]Auto-Clean Mode:[/bold white] {clean_mode_str}\n"
        f"[bold white]Alert Cooldown:[/bold white] {cfg.autopilot.cooldown_sec}s\n"
        f"[dim]Press Ctrl+C to stop autopilot watchdog.[/dim]",
        title="[bold cyan]🤖 LSP-Sentinel DevOps Autopilot Watchdog[/bold cyan]",
        border_style="cyan"
    ))

    import time
    cycle_count = 0
    try:
        while True:
            cycle_count += 1
            timestamp_str = time.strftime("%H:%M:%S")
            res = engine.run_check_cycle(auto_clean=auto_clean)

            if res.issues_detected:
                console.print(f"[bold yellow][{timestamp_str} | Cycle #{cycle_count}][/bold yellow] Detected [bold red]{len(res.issues_detected)} anomaly(s)[/bold red]:")
                for issue in res.issues_detected:
                    console.print(f"  [red]• {issue}[/red]")
                if res.alerts_dispatched:
                    console.print(f"  [green]📢 Dispatched alerts: {', '.join(res.alerts_dispatched)}[/green]")
                if res.auto_cleaned_mb > 0:
                    console.print(f"  [bold green]🧹 Autonomous Relief: Reclaimed {res.auto_cleaned_mb:.2f} MB across {res.cleaned_files_count} files[/bold green]")
            else:
                console.print(f"[dim][{timestamp_str} | Cycle #{cycle_count}][/dim] [green]✔ All server health metrics nominal.[/green]")

            if cycles > 0 and cycle_count >= cycles:
                console.print(f"\n[bold green]Autopilot completed requested {cycles} cycle(s).[/bold green]")
                break

            time.sleep(check_interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Autopilot watchdog stopped by user.[/yellow]")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8443, "--port", "-p", help="Bind port"),
    config_file: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to sentinel.yaml")
):
    """Launch embedded modern Web Dashboard."""
    render_banner()
    import uvicorn
    console.print(f"[bold green]🚀 Launching LSP-Sentinel Web Dashboard on http://{host}:{port}[/bold green]")
    uvicorn.run("sentinel.web.app:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    app()
