#!/usr/bin/env bash
# One-time setup on macOS / Linux (Python 3.11-3.13; 3.12 recommended)
set -euo pipefail
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
[ -d .venv312 ] || "$PY" -m venv .venv312
source .venv312/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts/generate_data.py
python scripts/train_ml.py
echo "Setup complete. Start the dashboard with ./run_app.sh"
