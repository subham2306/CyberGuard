# ==============================================================================
# CYBERGUARD — WINDOWS RUN SCRIPT
# Starts the CyberGuard FastAPI Server & Serves the Interactive AI Frontend.
# ==============================================================================

# Detect Project Root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
Set-Location $ProjectRoot

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "         CYBERGUARD — DIGITAL THREAT INTELLIGENCE               " -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Starting CyberGuard Server from: $ProjectRoot`n" -ForegroundColor Gray

# 1. Activate Virtual Environment if available
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    Write-Host "[✓] Using project virtual environment (.venv)" -ForegroundColor Green
    $PyCmd = $VenvPython
} else {
    Write-Host "[i] Virtual environment not found; using system Python." -ForegroundColor Cyan
    $PyCmd = "python"
}

# 2. Check Port 8000 availability; fallback to 8001 if occupied
$Port = 8000
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("127.0.0.1", $Port)
    $tcp.Close()
    Write-Host "[!] Port 8000 is currently occupied (e.g. by system services)." -ForegroundColor Yellow
    Write-Host "[*] Automatically falling back to Port 8001..." -ForegroundColor Yellow
    $Port = 8001
} catch {
    # Port 8000 is free!
    $Port = 8000
}

Write-Host "`n[✓] Launching CyberGuard on: http://127.0.0.1:$Port/" -ForegroundColor Green
Write-Host "    Press CTRL+C in this console to stop the server.`n" -ForegroundColor Gray

# Launch browser after a brief delay
Start-Job -ScriptBlock {
    param($TargetUrl)
    Start-Sleep -Seconds 2
    Start-Process $TargetUrl
} -ArgumentList "http://127.0.0.1:$Port/" | Out-Null

# 3. Start Uvicorn Server
& $PyCmd -m uvicorn cyberguard.api:app --host 127.0.0.1 --port $Port
