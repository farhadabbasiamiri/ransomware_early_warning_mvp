@echo off
REM Starts the dashboard on http://127.0.0.1:7860 - keep this window open while you use it.
cd /d "%~dp0"
if not exist .venv312\Scripts\activate.bat (
  echo Run setup_windows.bat first.
  exit /b 1
)
call .venv312\Scripts\activate.bat
python app.py
