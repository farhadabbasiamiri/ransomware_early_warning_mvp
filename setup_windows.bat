@echo off
REM One-time setup on Windows: creates a Python 3.12 environment, installs packages, prepares data and the ML model.
cd /d "%~dp0"
py -3.12 --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.12 was not found. Install the 64-bit Python 3.12 from https://www.python.org/downloads/windows/ and run this again.
  exit /b 1
)
if not exist .venv312\Scripts\activate.bat py -3.12 -m venv .venv312
call .venv312\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Package installation failed. Copy the red error lines and ask for help.
  exit /b 1
)
python scripts\generate_data.py
python scripts\train_ml.py
echo.
echo Setup complete. Start the dashboard with run_app.bat
