@echo off
setlocal enabledelayedexpansion

title CYBERGUARD — Digital Threat Intelligence
cd /d "%~dp0"

echo =================================================================
echo          CYBERGUARD — DIGITAL THREAT INTELLIGENCE
echo =================================================================
echo Working Directory: %CD%
echo.

:: Detect Python from .venv or PATH
if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
    echo [OK] Using virtual environment (.venv)
) else (
    set "PYTHON_EXE=python"
    echo [INFO] Using system Python
)

:: Test if Python is accessible
%PYTHON_EXE% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python was not found!
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo and ensure "Add Python to PATH" is checked during installation.
    pause
    exit /b 1
)

:: Default port 8000
set PORT=8000

:: Check if port 8000 is occupied
netstat -ano | findstr /R /C:":8000 " >nul 2>&1
if not errorlevel 1 (
    echo [NOTICE] Port 8000 is in use. Falling back to port 8001...
    set PORT=8001
)

echo [OK] Starting CyberGuard on http://127.0.0.1:%PORT%/
echo Press Ctrl+C to terminate the server.
echo.

:: Open browser after 2 seconds in background
start "" /b cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:%PORT%/"

:: Run Uvicorn server
%PYTHON_EXE% -m uvicorn cyberguard.api:app --host 127.0.0.1 --port %PORT%

pause
