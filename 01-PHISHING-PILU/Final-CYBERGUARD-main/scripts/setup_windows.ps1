# ==============================================================================
# CYBERGUARD — WINDOWS AUTOMATED ENVIRONMENT SETUP SCRIPT
# Sets up Python virtual environment and installs all dependencies.
# ==============================================================================

$ErrorActionPreference = "Stop"

# Detect Project Root (Directory containing this script / ..)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $ProjectRoot

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "         CYBERGUARD — AUTOMATED ENVIRONMENT SETUP               " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Project Root: $ProjectRoot`n" -ForegroundColor Gray

# 1. Check Python Installation
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[✓] Detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[✕] Error: Python was not found in PATH." -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/ and check 'Add to PATH'." -ForegroundColor Yellow
    exit 1
}

# 2. Create Virtual Environment
$VenvPath = Join-Path $ProjectRoot ".venv"
if (-not (Test-Path $VenvPath)) {
    Write-Host "[*] Creating Python virtual environment in .venv..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "[✓] Virtual environment created successfully." -ForegroundColor Green
} else {
    Write-Host "[i] Existing virtual environment found in .venv." -ForegroundColor Cyan
}

# 3. Activate Virtual Environment
$ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
if (Test-Path $ActivateScript) {
    Write-Host "[*] Activating virtual environment..." -ForegroundColor Yellow
    & $ActivateScript
}

# 4. Upgrade pip & Install Dependencies
$ReqFile = Join-Path $ProjectRoot "requirements.txt"
if (Test-Path $ReqFile) {
    Write-Host "[*] Upgrading pip..." -ForegroundColor Yellow
    python -m pip install --upgrade pip --quiet
    
    Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
    Write-Host "    (This may take a few moments for PyTorch, OpenCV, and FastAPI)..." -ForegroundColor Gray
    python -m pip install -r $ReqFile
    Write-Host "[✓] All dependencies installed successfully." -ForegroundColor Green
} else {
    Write-Host "[✕] Warning: requirements.txt not found!" -ForegroundColor Red
}

Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                     SETUP COMPLETE!                            " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "To start CyberGuard, run:" -ForegroundColor White
Write-Host "   .\scripts\run_windows.ps1" -ForegroundColor Yellow
Write-Host "Or double-click: run_cyberguard.bat`n" -ForegroundColor Yellow
