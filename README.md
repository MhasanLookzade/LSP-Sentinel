# 🛡️ LSP-Sentinel

> **Autonomous SRE Health, Resilience & Disk Intelligence Suite for Production Servers**

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ed.svg)](https://docker.com)
[![Architecture](https://img.shields.io/badge/architecture-CLI%20%2B%20Web%20Dashboard-cyan.svg)](#)

---

## 📌 Overview

**LSP-Sentinel** is an all-in-one SRE (Site Reliability Engineering) agent built for production Linux & cloud servers. It combines **hard system health monitoring**, an **intelligent disk safety auditor** (that distinguishes what is safe to delete from what is critical), **synthetic service & SSL uptime probes**, **controlled chaos resilience testing**, and **automated incident triage runbook generation**.

It provides two interfaces:
1. **Interactive Rich CLI / TUI**: High-speed, colorful terminal reporting directly over SSH.
2. **Modern Glassmorphic Web Dashboard**: Embedded responsive dark-mode interface with live metric telemetry, interactive file tables, and one-click actions.

---

## ✨ Core Superpowers

### 1. 💾 Disk Intelligence & Safety Shield
Unlike naive `du` or `find` commands that list files without context, LSP-Sentinel analyzes file paths and metadata against sysadmin safety rules:
* 🟢 **SAFE TO PURGE**: Rotated logs (`*.log.1`, `*.log.gz`), systemd journals older than 3 days, package manager archives (`/var/cache/apt/archives`), temporary files (`/tmp/*`), core dumps, and dangling Docker layers.
* 🟡 **REVIEW CAREFULLY**: Large active uncompressed application logs (`>50MB`, e.g. `nginx/access.log`, `syslog`). *Crucially recommends **safe truncation (`truncate -s 0`)** instead of `rm` so active processes don't leak inodes and space is freed immediately.*
* 🔴 **PROTECTED / SYSTEM CRITICAL**: System boot files (`/boot`), core configurations (`/etc`), active database files (`/var/lib/mysql`, `/var/lib/postgresql`), and SSH keys (`~/.ssh`). **Shielded by Sentinel—any attempt to clean these is strictly blocked.**

### 2. 📊 Hard Health Monitoring
* **CPU**: Overall utilization, per-core metrics, 1m/5m/15m load averages, and clock frequency.
* **Memory & Swap**: Physical RAM utilization, free, cached, buffer memory, and swap saturation.
* **Disks & Inodes**: Partition usage percentages, filesystem types, inode exhaustion tracking, and I/O rates.
* **Network & Open Ports**: Real-time traffic throughput and listening port audit (e.g. 22/SSH, 80/HTTP, 443/HTTPS, 3306/MySQL).
* **Processes & Docker**: Top CPU & Memory consuming processes and container crash-loop detection.

### 3. 🌐 Synthetic Service & TLS/SSL Probes
* **HTTP/HTTPS Probes**: Monitors external URLs and internal services for status codes and response latency.
* **TLS/SSL Expiration Watchdog**: Alerts when SSL certificates have fewer than 14 days remaining before expiration.
* **TCP Port Ping**: Verifies connectivity to database, cache, or reverse-proxy ports.
* **DNS Resolution**: Tracks domain query latency and resolver availability.

### 4. ⚡ Chaos & Resilience Testing Lab
Run bounded, safe experiments on your server to verify alerting pipelines and daemon auto-restarts:
* **CPU Stress Simulation**: Multithreaded computation spike for a configurable duration.
* **RAM Pressure Allocation**: Controlled memory buffer allocation with strict OOM-safety abort limits.
* **Synthetic Latency Injection**: Simulates network jitter to verify synthetic probe sensitivity.

### 5. 🛠️ Automated SRE Triage Runbooks
When disk usage reaches critical thresholds (>88%), memory is exhausted, or a synthetic probe fails, LSP-Sentinel automatically diagnoses root causes and drafts **copy-paste shell remediation commands**.

### 6. 📢 Multi-Channel Alerting
Dispatches instant incident alerts to **Telegram Bots**, **Discord Webhooks**, and **Slack Channels**.

---

## 🚀 Quickstart & Installation

### Option 1: 1-Line Installer on Linux (Ubuntu / Debian / CentOS / Rocky)

Run the automated installer as root:

```bash
sudo bash install.sh
```

This will:
1. Install Python3 and virtual environment dependencies.
2. Set up `/opt/lsp-sentinel` and symlink the CLI to `/usr/local/bin/lsp-sentinel` (and `lsp-sential`).
3. Configure and start a `systemd` service (`lsp-sentinel.service`) running the web dashboard on port `8443`.

### Option 2: Docker / Docker Compose

Deploy with zero host pollution:

```bash
docker compose up -d
```

The Web Dashboard will be available at `http://<YOUR-SERVER-IP>:8443`.

### Option 3: Local Python Virtual Environment

```bash
# Clone and enter directory
cd lsp-sentinel

# Create venv and install
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

---

## 💻 CLI Command Reference

| Command | Description |
| :--- | :--- |
| `lsp-sentinel health` | Executive colored dashboard of CPU, RAM, Disks, Ports, and Processes |
| `lsp-sentinel disk` | Deep scan large files/folders with safety verdicts (🟢 SAFE, 🟡 REVIEW, 🔴 PROTECTED) |
| `lsp-sentinel clean --dry-run` | Preview reclaimable space without modifying any file |
| `lsp-sentinel clean --safe-only --execute` | Safely delete only files classified strictly as SAFE |
| `lsp-sentinel synthetic` | Probe all configured HTTP endpoints, TCP ports, and SSL certificates |
| `lsp-sentinel chaos --type cpu --duration 5` | Run a 5-second CPU resilience experiment |
| `lsp-sentinel runbook` | Generate dynamic incident triage runbooks for active anomalies |
| `lsp-sentinel serve --port 8443` | Launch the embedded modern web dashboard |

*(Note: `lsp-sential` is also registered as a valid CLI alias)*

---

## ⚙️ Configuration (`sentinel.yaml`)

```yaml
server_name: "LSP-Production-01"
environment: "production"

disk:
  scan_paths:
    - "/var/log"
    - "/var/cache"
    - "/tmp"
    - "/root"
    - "/home"
  min_file_size_mb: 25.0
  max_scan_depth: 4

alerts:
  enabled: true
  telegram_bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
  telegram_chat_id: "YOUR_CHAT_ID"
  discord_webhook_url: "https://discord.com/api/webhooks/..."
  cpu_threshold_pct: 85.0
  ram_threshold_pct: 90.0
  disk_threshold_pct: 88.0

synthetic_targets:
  - name: "Public Internet"
    type: "http"
    target: "https://1.1.1.1"
  - name: "API SSL Check"
    type: "ssl"
    target: "api.github.com:443"
```

---

## 🧪 Testing

Run the full automated test suite:

```bash
python -m unittest sentinel/tests/test_sentinel.py
```

---

## 📄 License

MIT License. Crafted for DevOps and SRE professionals managing modern production infrastructure.
