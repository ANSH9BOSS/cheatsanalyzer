$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ANSH9BOSS CHEAT ANALYZER v2.0 - FORENSIC SUITE" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Quick Python Check
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[+] Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[*] Python not found. Installing via winget..." -ForegroundColor Yellow
    try {
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    } catch {
        Write-Host "[-] Please install Python from https://www.python.org/downloads/ and check 'Add to PATH'" -ForegroundColor Red
        Start-Process "https://www.python.org/downloads/"
        Pause
        exit 1
    }
}

# 2. Fast Dependency Check (Only installs if missing)
$needInstall = $false
try {
    python -c "import customtkinter, psutil, rich, pyfiglet, requests" 2>$null
    if ($LASTEXITCODE -ne 0) { $needInstall = $true }
} catch {
    $needInstall = $true
}

if ($needInstall) {
    Write-Host "[*] Installing required UI and forensic packages (one-time setup)..." -ForegroundColor Cyan
    python -m pip install customtkinter psutil rich pyfiglet requests --quiet --no-warn-script-location
}

# 3. Ensure full suite is present
if (-not (Test-Path "core") -or -not (Test-Path "ui")) {
    Write-Host "[*] Fetching ANSH9BOSS suite from GitHub..." -ForegroundColor Cyan
    $zipPath = "$env:TEMP\cheatsanalyzer.zip"
    $extractPath = "$env:TEMP\cheatsanalyzer_run"
    
    if (Test-Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    
    Invoke-WebRequest -Uri "https://github.com/ANSH9BOSS/cheatsanalyzer/archive/refs/heads/main.zip" -OutFile $zipPath -UseBasicParsing
    
    # Fast Native .NET Decompression (Avoids PowerShell Expand-Archive bugs)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
    } catch {
        tar.exe -xf "$zipPath" -C "$extractPath" 2>$null
    }
    
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Set-Location "$extractPath\cheatsanalyzer-main"
}

# 4. Launch GUI
Write-Host "[+] Launching Glassmorphism Forensic Interface..." -ForegroundColor Green
python ansh9boss.py $args
