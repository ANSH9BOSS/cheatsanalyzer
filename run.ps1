$ErrorActionPreference = "Stop"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ANSH9BOSS CHEAT ANALYZER v2.0 - FORENSIC SUITE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Python installation
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[*] Python is not installed. Attempting auto-install via winget..." -ForegroundColor Yellow
    try {
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } catch {
        Write-Host "[-] Please install Python from https://www.python.org/downloads/ (Check 'Add Python to PATH')" -ForegroundColor Red
        Start-Process "https://www.python.org/downloads/"
        Pause
        exit 1
    }
}

# 2. Install dependencies
Write-Host "[*] Installing required forensic and Glassmorphism GUI packages..." -ForegroundColor Cyan
python -m pip install customtkinter psutil rich pyfiglet requests -q

# 3. Ensure full suite is present (download and extract if running standalone)
if (-not (Test-Path "core") -or -not (Test-Path "ui")) {
    Write-Host "[*] Fetching complete ANSH9BOSS suite from GitHub..." -ForegroundColor Cyan
    $zipPath = "$env:TEMP\cheatsanalyzer.zip"
    $extractPath = "$env:TEMP\cheatsanalyzer_run"
    Invoke-WebRequest -Uri "https://github.com/ANSH9BOSS/cheatsanalyzer/archive/refs/heads/main.zip" -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Remove-Item -Path $zipPath -Force
    Set-Location "$extractPath\cheatsanalyzer-main"
}

# 4. Launch the Glassmorphism GUI
Write-Host "[+] Launching Glassmorphism Forensic Interface..." -ForegroundColor Green
python ansh9boss.py $args
