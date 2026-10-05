# Build netbypass into a single Windows .exe using PyInstaller.
# Run from the netbypass/ folder in PowerShell:  .\build.ps1

$ErrorActionPreference = "Stop"

Write-Host "==> Creating virtual environment" -ForegroundColor Cyan
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

Write-Host "==> Installing dependencies" -ForegroundColor Cyan
python -m pip install --upgrade pip
pip install -r requirements.txt pyinstaller

Write-Host "==> Building bypass.exe" -ForegroundColor Cyan
# --onefile     : single .exe
# --name        : output name
# --collect-all : make sure rich/certifi data files are bundled
pyinstaller --onefile --name bypass `
    --collect-all rich `
    --collect-all certifi `
    bypass.py

Write-Host ""
Write-Host "Done. Output: dist\bypass.exe" -ForegroundColor Green
Write-Host "Run it like:  .\dist\bypass.exe --profile config.yaml --mode proxy"
Write-Host "Note: sing-box.exe is a SEPARATE binary; keep it where config.yaml points."
