@echo off
setlocal
cd /d "%~dp0"

where pyw.exe >nul 2>nul
if %errorlevel%==0 (
  start "" pyw.exe -m security_lab_assistant.gui
  exit /b 0
)

where pythonw.exe >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw.exe -m security_lab_assistant.gui
  exit /b 0
)

where py.exe >nul 2>nul
if %errorlevel%==0 (
  start "" py.exe -m security_lab_assistant.gui
  exit /b 0
)

where python.exe >nul 2>nul
if %errorlevel%==0 (
  start "" python.exe -m security_lab_assistant.gui
  exit /b 0
)

echo Python was not found. Install Python 3.11+ or run from a terminal with Python on PATH.
pause
