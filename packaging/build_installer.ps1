# PhishGuard installer build (Phase 2d)
#
# Usage (from project root):  powershell -ExecutionPolicy Bypass -File packaging/build_installer.ps1
#
# Steps: validate prerequisites -> ensure React production build -> ensure PyInstaller
# backend bundle -> package with electron-builder NSIS -> verify output exists.
# Never copies secrets; never touches user data.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Write-Host "== PhishGuard installer build ==" -ForegroundColor Cyan

# 1. Prerequisites
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw "node is required on PATH to build the installer" }
if (-not (Test-Path "$Root/desktop/node_modules/electron-builder")) {
    throw "desktop/node_modules/electron-builder missing - run: cd desktop && npm install"
}
if (-not (Test-Path "$Root/desktop/icon.ico")) { throw "desktop/icon.ico missing" }

# 2. React production build (rebuild if dist is absent)
if (-not (Test-Path "$Root/frontend/dist/index.html")) {
    Write-Host "frontend/dist missing - running npm run build..."
    Push-Location "$Root/frontend"
    npm run build
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "frontend build failed" }
    Pop-Location
} else {
    Write-Host "frontend/dist present - reusing"
}

# 3. PyInstaller backend bundle (rebuild if absent)
if (-not (Test-Path "$Root/packaging/dist/phishguard-backend/phishguard-backend.exe")) {
    Write-Host "backend bundle missing - running build_backend.ps1..."
    powershell -ExecutionPolicy Bypass -File "$PSScriptRoot/build_backend.ps1"
    if ($LASTEXITCODE -ne 0) { throw "backend packaging failed" }
} else {
    Write-Host "backend bundle present - reusing"
}

# 4. Electron-builder NSIS package
Write-Host "Packaging installer with electron-builder..."
Push-Location "$Root/desktop"
npx electron-builder --win nsis --x64
$Code = $LASTEXITCODE
Pop-Location
if ($Code -ne 0) { throw "electron-builder failed with exit code $Code" }

# 5. Verify artifact
$Installer = Get-ChildItem "$Root/desktop/dist" -Filter "MailBuddy-Setup-*.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Installer) { throw "installer artifact not found in desktop/dist" }
Write-Host "== Installer built: $($Installer.FullName) ($([math]::Round($Installer.Length/1MB,1)) MB) ==" -ForegroundColor Green
