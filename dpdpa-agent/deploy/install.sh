#!/usr/bin/env bash
# Veritas — One-shot install-from-source script for Debian/Ubuntu-based Linux (development; customers use the .deb)
#
# Run once from the repository root:
#   sudo bash deploy/install.sh
#
# Re-running is safe: it updates the installed files and restarts the service.
# The evidence store (evidence.db) and agent store (agents.db) are preserved
# across updates — they are never overwritten by rsync.

set -euo pipefail

INSTALL_DIR="/opt/veritas"
VENV_DIR="$INSTALL_DIR/venv"
PROJECT_SRC="$(cd "$(dirname "$0")/.." && pwd)"   # dpdpa-agent/ directory
SERVICE_SRC="$PROJECT_SRC/deploy/veritas.service"
SERVICE_DEST="/etc/systemd/system/veritas.service"

# ---- Preflight ----

if [[ $EUID -ne 0 ]]; then
  echo "Error: run this script as root." >&2
  echo "       sudo bash deploy/install.sh" >&2
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "Error: python3 not found. Install it first:" >&2
  echo "       sudo apt install python3 python3-venv python3-pip" >&2
  exit 1
fi

if ! command -v rsync &>/dev/null; then
  echo "==> Installing rsync..."
  apt-get install -y rsync --quiet
fi

# ---- System user ----

echo "==> Creating system user 'veritas'..."
if id -u veritas &>/dev/null; then
  echo "    (user already exists — skipping)"
else
  useradd --system --no-create-home --shell /bin/false veritas
fi

# ---- Copy project files ----

echo "==> Copying project to $INSTALL_DIR/dpdpa-agent/ ..."
mkdir -p "$INSTALL_DIR"
rsync -a --delete "$PROJECT_SRC/" "$INSTALL_DIR/dpdpa-agent/" \
  --exclude '__pycache__'         \
  --exclude '*.pyc'               \
  --exclude '.git'                \
  --exclude '.env'                \
  --exclude 'evidence_store/evidence.db'  \
  --exclude 'agent_store/agents.db'       \
  --exclude 'deploy/install.sh'           \
  --exclude '*.log'

# ---- Virtual environment ----

if [[ ! -d "$VENV_DIR" ]]; then
  echo "==> Creating Python virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

echo "==> Upgrading pip..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet

echo "==> Installing Python dependencies (this may take several minutes on Pi)..."
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/dpdpa-agent/requirements.txt" --quiet

# ---- spaCy model ----

if ! "$VENV_DIR/bin/python" -c "import spacy; spacy.load('en_core_web_lg')" &>/dev/null; then
  echo "==> Downloading spaCy language model (en_core_web_lg, ~750 MB)..."
  "$VENV_DIR/bin/python" -m spacy download en_core_web_lg --quiet
else
  echo "==> spaCy model already installed — skipping download."
fi

# ---- Permissions ----

echo "==> Setting file permissions..."
chown -R veritas:veritas "$INSTALL_DIR"

# ---- systemd service ----

echo "==> Installing systemd service..."
cp "$SERVICE_SRC" "$SERVICE_DEST"
systemctl daemon-reload
systemctl enable veritas

# Start or restart
if systemctl is-active --quiet veritas; then
  echo "==> Restarting Veritas service..."
  systemctl restart veritas
else
  echo "==> Starting Veritas service..."
  systemctl start veritas
fi

# Wait briefly and check status
sleep 3
if systemctl is-active --quiet veritas; then
  STATUS="active (running)"
else
  STATUS="FAILED — check: journalctl -u veritas -n 50"
fi

# ---- Done ----

echo ""
echo "============================================"
echo "  Veritas installation complete"
echo "============================================"
echo ""
echo "  Service status : $STATUS"

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
echo "  Dashboard URL  : http://${LOCAL_IP}:8000"
echo ""
echo "  Useful commands:"
echo "    systemctl status veritas        # check service health"
echo "    journalctl -u veritas -f        # follow live logs"
echo "    systemctl restart veritas       # restart after config changes"
echo ""
echo "  Optional — LLM investigation (OpenAI API key):"
echo "    nano /opt/veritas/dpdpa-agent/.env"
echo "    # Add: OPENAI_API_KEY=sk-..."
echo "    systemctl restart veritas"
echo ""
