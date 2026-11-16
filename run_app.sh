#!/usr/bin/env bash
# Starts the dashboard on http://127.0.0.1:7860
set -euo pipefail
cd "$(dirname "$0")"
source .venv312/bin/activate
python app.py
