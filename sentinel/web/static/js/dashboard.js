// LSP-Sentinel Interactive Dashboard JavaScript

let currentDiskResult = null;
let liveInterval = null;

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  fetchHealth();
  fetchSynthetic();
  fetchRunbooks();
  triggerDiskScan();

  // Auto-refresh metrics every 4 seconds
  liveInterval = setInterval(fetchHealth, 4000);
});

// Tab Switcher
function initTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });
}

// 1. Fetch Hard Health
async function fetchHealth() {
  try {
    const res = await fetch("/api/health");
    const json = await res.json();
    if (json.status !== "success") return;

    const data = json.data;
    const cpu = data.cpu;
    const mem = data.memory;
    const sys = data.system;

    // Header host
    document.getElementById("server-host").innerText = sys.hostname;
    document.getElementById("server-uptime").innerText = sys.uptime_formatted;
    document.getElementById("server-os").innerText = `${sys.os} ${sys.release}`;

    // CPU Card
    document.getElementById("cpu-val").innerText = `${cpu.total_percent}%`;
    const cpuBar = document.getElementById("cpu-bar");
    cpuBar.style.width = `${Math.min(cpu.total_percent, 100)}%`;
    cpuBar.className = `bar-fill ${cpu.total_percent > 85 ? 'red' : (cpu.total_percent > 65 ? 'amber' : 'cyan')}`;
    document.getElementById("cpu-sub").innerText = `${sys.cpu_count_logical} Cores | Load: ${sys.load_average.join(", ")}`;

    // RAM Card
    const ramPct = mem.ram.percent;
    document.getElementById("ram-val").innerText = `${ramPct}%`;
    const ramBar = document.getElementById("ram-bar");
    ramBar.style.width = `${ramPct}%`;
    ramBar.className = `bar-fill ${ramPct > 85 ? 'red' : (ramPct > 70 ? 'amber' : 'green')}`;
    document.getElementById("ram-sub").innerText = `${formatBytes(mem.ram.used_bytes)} / ${formatBytes(mem.ram.total_bytes)}`;

    // Swap Card
    const swapPct = mem.swap.percent;
    document.getElementById("swap-val").innerText = `${swapPct}%`;
    const swapBar = document.getElementById("swap-bar");
    swapBar.style.width = `${swapPct}%`;
    document.getElementById("swap-sub").innerText = `${formatBytes(mem.swap.used_bytes)} / ${formatBytes(mem.swap.total_bytes)}`;

    // Partitions
    renderPartitions(data.disk.partitions);

    // Processes
    renderProcesses(data.processes.top_cpu);

    // Docker
    renderDocker(json.docker);

  } catch (err) {
    console.error("Health fetch error:", err);
  }
}

function renderPartitions(partitions) {
  const tbody = document.getElementById("partitions-tbody");
  if (!tbody || !partitions) return;
  tbody.innerHTML = partitions.map(p => {
    const col = p.percent > 85 ? "text-red" : (p.percent > 70 ? "text-amber" : "text-green");
    return `
      <tr>
        <td><strong>${p.mountpoint}</strong></td>
        <td>${p.device}</td>
        <td>${p.fstype}</td>
        <td>${formatBytes(p.used_bytes)} / ${formatBytes(p.total_bytes)}</td>
        <td><span class="${col}"><strong>${p.percent}%</strong></span></td>
        <td>${p.inodes_percent ? p.inodes_percent + '%' : 'N/A'}</td>
      </tr>
    `;
  }).join("");
}

function renderProcesses(procs) {
  const tbody = document.getElementById("procs-tbody");
  if (!tbody || !procs) return;
  tbody.innerHTML = procs.slice(0, 6).map(p => `
    <tr>
      <td><code>${p.pid}</code></td>
      <td><strong>${escapeHtml(p.name)}</strong></td>
      <td><span class="text-amber">${p.cpu_percent}%</span></td>
      <td>${p.memory_percent}%</td>
      <td>${escapeHtml(p.username || 'sys')}</td>
    </tr>
  `).join("");
}

function renderDocker(docker) {
  const container = document.getElementById("docker-status-box");
  if (!container) return;
  if (!docker || !docker.available) {
    container.innerHTML = `<span class="text-muted">Docker daemon not running or not detected on host.</span>`;
    return;
  }
  const running = docker.containers.filter(c => c.status.includes("Up")).length;
  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <span><strong>Docker Active:</strong> ${running} running / ${docker.containers.length} total</span>
      <span class="badge badge-safe">ONLINE</span>
    </div>
  `;
}

// 2. Disk Intelligence & Safety Analyzer
async function triggerDiskScan() {
  const btn = document.getElementById("btn-rescan-disk");
  if (btn) btn.innerText = "⏳ Scanning...";

  try {
    const res = await fetch("/api/disk/scan");
    const json = await res.json();
    if (json.status === "success") {
      currentDiskResult = json.result;
      renderDiskIntelligence(json.result);
    }
  } catch (err) {
    console.error("Scan error:", err);
  } finally {
    if (btn) btn.innerText = "🔄 Re-scan Disks";
  }
}

function renderDiskIntelligence(result) {
  // Hero stats
  document.getElementById("disk-safe-space").innerText = result.safe_reclaimable_formatted;
  document.getElementById("disk-review-space").innerText = result.reviewable_formatted;
  document.getElementById("disk-protected-space").innerText = result.protected_formatted;
  document.getElementById("disk-scan-time").innerText = `${result.scan_duration_sec}s (${result.total_files_scanned} files inspected)`;

  // Render Folders
  const folderTbody = document.getElementById("folders-tbody");
  if (folderTbody && result.top_folders) {
    folderTbody.innerHTML = result.top_folders.map(f => {
      const badgeClass = f.safety.level === "SAFE" ? "badge-safe" : (f.safety.level === "REVIEW" ? "badge-review" : "badge-critical");
      return `
        <tr>
          <td><code style="word-break: break-all;">${escapeHtml(f.path)}</code></td>
          <td><strong>${f.size_formatted}</strong></td>
          <td><span class="badge ${badgeClass}">${f.safety.level}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(f.safety.recommendation)}</td>
        </tr>
      `;
    }).join("");
  }

  // Render Files
  renderFilesTable(result.top_files);
}

function renderFilesTable(files, filter = "ALL") {
  const fileTbody = document.getElementById("files-tbody");
  if (!fileTbody || !files) return;

  const filtered = files.filter(f => {
    if (filter === "ALL") return true;
    return f.safety.level === filter;
  });

  if (filtered.length === 0) {
    fileTbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted);">No files match filter '${filter}'</td></tr>`;
    return;
  }

  fileTbody.innerHTML = filtered.map(f => {
    const badgeClass = f.safety.level === "SAFE" ? "badge-safe" : (f.safety.level === "REVIEW" ? "badge-review" : "badge-critical");
    const isSafe = f.safety.level === "SAFE";
    return `
      <tr>
        <td><input type="checkbox" class="file-chk" value="${escapeHtml(f.path)}" ${isSafe ? 'checked' : ''} data-level="${f.safety.level}"></td>
        <td><code style="word-break: break-all;">${escapeHtml(f.path)}</code></td>
        <td><strong>${f.size_formatted}</strong></td>
        <td><span class="badge ${badgeClass}">${f.safety.level}</span></td>
        <td style="font-size: 0.8rem; color: var(--text-secondary);">
          <div>${escapeHtml(f.safety.action)}: ${escapeHtml(f.safety.recommendation)}</div>
          ${f.safety.command_hint ? `<div class="cmd-block" style="margin-top:4px;">$ ${escapeHtml(f.safety.command_hint)}</div>` : ''}
        </td>
      </tr>
    `;
  }).join("");
}

function filterFiles(level) {
  if (!currentDiskResult) return;
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  event.target.classList.add("active");
  renderFilesTable(currentDiskResult.top_files, level);
}

// 3. Safe Cleanup Execution
async function executeCleanup(dryRun = true) {
  const checkboxes = document.querySelectorAll(".file-chk:checked");
  const selectedFiles = Array.from(checkboxes).map(c => c.value);

  if (selectedFiles.length === 0) {
    alert("Please select at least one file to clean.");
    return;
  }

  if (!dryRun) {
    const confirm = window.confirm(`WARNING: You are about to permanently execute cleanup on ${selectedFiles.length} file(s). Proceed?`);
    if (!confirm) return;
  }

  try {
    const res = await fetch("/api/disk/clean", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        files: selectedFiles,
        dry_run: dryRun,
        force_review: false
      })
    });
    const json = await res.json();
    openModal(json.result);
    if (!dryRun) {
      triggerDiskScan();
    }
  } catch (err) {
    alert("Cleanup failed: " + err);
  }
}

function openModal(batchResult) {
  const modal = document.getElementById("cleanup-modal");
  const content = document.getElementById("modal-content-body");
  const title = document.getElementById("modal-title");

  title.innerText = batchResult.dry_run ? "🛡️ Dry-Run Cleanup Preview" : "✅ Cleanup Execution Completed";

  content.innerHTML = `
    <div style="margin-bottom: 1rem;">
      <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">
        Total Space Reclaimable: <strong class="text-green">${formatBytes(batchResult.total_bytes_freed)}</strong>
      </p>
      <p style="color: var(--text-muted); font-size: 0.85rem;">
        ${batchResult.dry_run ? 'No files were deleted. The table below shows what will happen.' : 'The actions below have been successfully executed.'}
      </p>
    </div>
    <div class="table-wrapper" style="max-height: 320px; overflow-y: auto;">
      <table class="data-table">
        <thead>
          <tr>
            <th>Target Path</th>
            <th>Action</th>
            <th>Freed</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${batchResult.items.map(it => `
            <tr>
              <td><code style="font-size:0.75rem;">${escapeHtml(it.path)}</code></td>
              <td>${it.action}</td>
              <td>${formatBytes(it.bytes_freed)}</td>
              <td><span class="${it.status === 'SUCCESS' ? 'text-green' : 'text-amber'}">${it.status}</span></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;

  modal.classList.add("active");
}

function closeModal() {
  document.getElementById("cleanup-modal").classList.remove("active");
}

// 4. Synthetic Probes
async function fetchSynthetic() {
  try {
    const res = await fetch("/api/synthetic");
    const json = await res.json();
    const tbody = document.getElementById("synthetic-tbody");
    if (!tbody || !json.probes) return;

    tbody.innerHTML = json.probes.map(p => {
      const latCol = p.latency_ms < 200 ? "text-green" : (p.latency_ms < 500 ? "text-amber" : "text-red");
      const statBadge = p.healthy ? '<span class="badge badge-safe">HEALTHY</span>' : '<span class="badge badge-critical">FAILING</span>';
      return `
        <tr>
          <td><strong>${escapeHtml(p.name)}</strong></td>
          <td><code>${p.target_type.toUpperCase()}</code></td>
          <td>${escapeHtml(p.target)}</td>
          <td>${statBadge}</td>
          <td><span class="${latCol}">${p.latency_ms} ms</span></td>
          <td style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(p.detail)}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Synthetic error:", err);
  }
}

// 5. Chaos Launcher
async function launchChaos(type) {
  const resultBox = document.getElementById("chaos-output-box");
  resultBox.innerHTML = `<span style="color:var(--accent-amber);">⚡ Running ${type.toUpperCase()} resilience stress experiment... please wait...</span>`;

  try {
    const res = await fetch("/api/chaos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: type,
        duration_sec: 6,
        size_mb: 256
      })
    });
    const json = await res.json();
    if (json.status === "success") {
      const exp = json.experiment;
      resultBox.innerHTML = `
        <div style="padding: 1rem; background: rgba(0,0,0,0.4); border-radius: 8px; border: 1px solid var(--border-subtle);">
          <div style="color:var(--accent-green); font-weight:700; margin-bottom:4px;">✔ Experiment Completed: ${exp.experiment_type}</div>
          <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:6px;">${exp.message}</div>
          <div style="font-size:0.8rem;">Peak Metric: <strong>${exp.peak_metric}</strong> | Elapsed: <strong>${exp.duration_sec}s</strong></div>
        </div>
      `;
    }
  } catch (err) {
    resultBox.innerHTML = `<span style="color:var(--accent-red);">✖ Chaos execution error: ${err}</span>`;
  }
}

// 6. Runbooks
async function fetchRunbooks() {
  try {
    const res = await fetch("/api/runbooks");
    const json = await res.json();
    const container = document.getElementById("runbooks-container");
    if (!container) return;

    if (json.count === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 3rem; background: var(--bg-card); border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
          <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🎉</div>
          <h3 style="color: var(--accent-green); margin-bottom: 0.5rem;">All Systems Operating Nominally</h3>
          <p style="color: var(--text-muted); font-size: 0.9rem;">No active incidents detected. VPS health, disk limits, and synthetic probes are within healthy thresholds.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = json.runbooks.map(rb => {
      const isCrit = rb.severity === "CRITICAL";
      const borderCol = isCrit ? "var(--accent-red)" : "var(--accent-amber)";
      return `
        <div class="glass-card" style="border-left: 4px solid ${borderCol}; margin-bottom: 1.5rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <h3 style="font-size:1.15rem; color:#fff;">🚨 ${escapeHtml(rb.title)}</h3>
            <span class="badge ${isCrit ? 'badge-critical' : 'badge-review'}">${rb.severity}</span>
          </div>
          <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:1rem;">
            <strong>Observation:</strong> ${escapeHtml(rb.metric_value)}
          </p>

          <div style="margin-bottom:1rem;">
            <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Likely Root Causes:</div>
            <ul style="padding-left:1.25rem; font-size:0.85rem; color:var(--text-secondary);">
              ${rb.root_causes.map(c => `<li>${escapeHtml(c)}</li>`).join("")}
            </ul>
          </div>

          <div>
            <div style="font-size:0.8rem; font-weight:700; text-transform:uppercase; color:var(--text-muted); margin-bottom:4px;">Actionable Remediation Commands:</div>
            ${rb.commands.map(cmd => `<div class="cmd-block">$ ${escapeHtml(cmd)}</div>`).join("")}
          </div>
        </div>
      `;
    }).join("");

  } catch (err) {
    console.error("Runbook error:", err);
  }
}

// 7. Test Alerts
async function triggerTestAlert() {
  const btn = document.getElementById("btn-test-alert");
  if (btn) btn.innerText = "Sending...";
  try {
    const res = await fetch("/api/alerts/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channel: "all" })
    });
    const json = await res.json();
    alert("Test alert dispatched! Results:\n" + JSON.stringify(json.delivery.details, null, 2));
  } catch (e) {
    alert("Alert dispatch failed: " + e);
  } finally {
    if (btn) btn.innerText = "📢 Dispatch Test Alert";
  }
}

// Helpers
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
