#!/bin/bash
set -e

echo "=========================================================="
echo "   ANSH9BOSS CHEAT ANALYZER v2.0 - FORENSIC SUITE         "
echo "=========================================================="

# 1. Environment and Python Check
if [ -d "/data/data/com.termux" ]; then
    echo "[*] Android Termux environment detected."
    if ! command -v python &> /dev/null; then
        echo "[+] Installing Python..."
        pkg update -y && pkg install python -y
    fi
else
    echo "[*] Linux/macOS environment detected."
    if ! command -v python3 &> /dev/null; then
        echo "[-] Error: Python3 is not installed. Please install Python3 manually."
        exit 1
    fi
fi

# 2. Dependencies
echo "[*] Installing Python dependencies (rich, pyfiglet, psutil, requests)..."
python3 -m pip install --break-system-packages rich pyfiglet psutil requests customtkinter 2>/dev/null || python3 -m pip install rich pyfiglet psutil requests customtkinter || pip install rich pyfiglet psutil requests

# 3. Check for core and ui modules
if [ ! -d "core" ] || [ ! -d "ui" ]; then
    echo "[*] Fetching complete ANSH9BOSS suite from GitHub..."
    TMP_DIR=$(mktemp -d)
    curl -sSL -o "$TMP_DIR/cheatsanalyzer.zip" https://github.com/ANSH9BOSS/cheatsanalyzer/archive/refs/heads/main.zip
    unzip -q "$TMP_DIR/cheatsanalyzer.zip" -d "$TMP_DIR"
    cd "$TMP_DIR/cheatsanalyzer-main"
fi

# 4. Launch Suite
python3 ansh9boss.py "$@"
