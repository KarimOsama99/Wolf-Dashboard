#!/usr/bin/env bash
# ──────────────────────────────────────────────────
#  Wolf Eye Dashboard — Quick Start
# ──────────────────────────────────────────────────
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "═══════════════════════════════════════════════"
echo "  🐺  Wolf Eye Dashboard"
echo "═══════════════════════════════════════════════"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "  ✗  python3 not found — please install Python 3.8+"
    exit 1
fi

# Install deps if needed
python3 -c "import fastapi, uvicorn" 2>/dev/null || {
    echo "  → Installing dependencies..."
    pip install -r requirements.txt --quiet
}

echo "  → Starting server at http://localhost:8080"
echo "  → Press Ctrl+C to stop"
echo ""

# Ensure index.html is in static/ where server.py expects it
if [ -f "$SCRIPT_DIR/index.html" ] && [ ! -f "$SCRIPT_DIR/static/index.html" ]; then
    mkdir -p "$SCRIPT_DIR/static"
    cp "$SCRIPT_DIR/index.html" "$SCRIPT_DIR/static/index.html"
    echo "  → Copied index.html → static/index.html"
fi

python3 server.py
