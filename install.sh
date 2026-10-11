#!/usr/bin/env bash
set -e

# ==============================================================================
# LSP-Sentinel Automated Installer for Ubuntu, Debian, CentOS, AlmaLinux, Rocky
# ==============================================================================

echo -e "\033[1;36m"
echo "  _     ____  ____        ____             _   _            _ "
echo " | |   / ___||  _ \      / ___|  ___ _ __ | |_(_)_ __   ___| |"
echo " | |   \___ \| |_) |_____\___ \ / _ \ '_ \| __| | '_ \ / _ \ |"
echo " | |___ ___) |  __/ |_____|___) |  __/ | | | |_| | | | |  __/ |"
echo " |_____|____/|_|         |____/ \___|_| |_|\__|_|_| |_|\___|_|"
echo "  Autonomous LSP-Sentinel SRE Health & Disk Intelligence Suite"
echo -e "\033[0m"

INSTALL_DIR="/opt/lsp-sentinel"
BIN_LINK="/usr/local/bin/lsp-sentinel"
BIN_ALIAS="/usr/local/bin/lsp-sential"
SERVICE_FILE="/etc/systemd/system/lsp-sentinel.service"

if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;31mError: Please run as root (e.g. sudo bash install.sh)\033[0m"
  exit 1
fi

echo -e "\033[1;32m[1/5] Detecting package manager & installing dependencies...\033[0m"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip curl
elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip curl
else
    echo "Warning: Unknown package manager. Please ensure python3 and venv are installed."
fi

echo -e "\033[1;32m[2/5] Setting up installation in $INSTALL_DIR...\033[0m"
mkdir -p "$INSTALL_DIR"
cp -r sentinel "$INSTALL_DIR/"
cp sentinel.yaml "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp pyproject.toml "$INSTALL_DIR/"

echo -e "\033[1;32m[3/5] Creating Python virtual environment & installing wheels...\033[0m"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip -q
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
"$INSTALL_DIR/.venv/bin/pip" install -e "$INSTALL_DIR" -q

echo -e "\033[1;32m[4/5] Creating CLI symlinks in $BIN_LINK...\033[0m"
cat << 'EOF' > "$BIN_LINK"
#!/usr/bin/env bash
exec /opt/lsp-sentinel/.venv/bin/python -m sentinel.cli "$@"
EOF
chmod +x "$BIN_LINK"
ln -sf "$BIN_LINK" "$BIN_ALIAS"

echo -e "\033[1;32m[5/5] Configuring systemd background service...\033[0m"
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=LSP-Sentinel SRE Health & Disk Intelligence Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python -m uvicorn sentinel.web.app:app --host 0.0.0.0 --port 8443
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lsp-sentinel.service
systemctl restart lsp-sentinel.service

echo ""
echo -e "\033[1;32m===============================================================\033[0m"
echo -e "\033[1;32m✔ LSP-Sentinel successfully installed and started!\033[0m"
echo -e "\033[1;36m"
echo "  • CLI Commands:"
echo "      lsp-sentinel health      # View live CPU, RAM, and storage metrics"
echo "      lsp-sentinel disk        # View large files/folders and safety verdicts"
echo "      lsp-sentinel clean       # Safely purge safe logs & package caches"
echo "      lsp-sentinel synthetic   # Probe websites, ports, and SSL certs"
echo "      lsp-sentinel chaos       # Run resilience and chaos load tests"
echo "      lsp-sentinel runbook     # Generate automated triage runbooks"
echo ""
echo "  • Web Dashboard:"
echo "      http://<YOUR-SERVER-IP>:8443"
echo ""
echo "  • Systemd service status:"
echo "      systemctl status lsp-sentinel"
echo -e "\033[1;32m===============================================================\033[0m"
