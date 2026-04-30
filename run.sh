#!/usr/bin/env bash
# Quick-start for the ECC web interface.
# Run from the repo root (where KeyGeneration.py lives).

set -e

if [ ! -f KeyGeneration.py ]; then
    echo "Error: run this from the repo root (KeyGeneration.py not found here)."
    exit 1
fi

if ! command -v sage >/dev/null 2>&1; then
    echo "Warning: 'sage' not found on PATH. The UI will load but every request will fail."
    echo "Set SAGE_BIN if Sage is installed elsewhere."
fi

echo ""
echo "Starting at http://localhost:8000"
echo "Ctrl-C to stop."
echo ""
exec uvicorn server:app --reload --port 8000
