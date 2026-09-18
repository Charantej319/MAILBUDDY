# PhishGuard backend packaging build script (Phase 2c).
#
# Produces: packaging/dist/phishguard-backend/phishguard-backend.exe
#
# - Uses the current Python (PyInstaller 6.22.3 supports 3.14).
# - Requires frontend/dist to exist (built by `npm run build`); does not run
#   npm itself so the frontend build stays an explicit, verified step.
# - NEVER copies backend/.env or any secret into the bundle.
# - NEVER deletes %APPDATA%\PhishGuard or any user data.
#
# Usage:  powershell -ExecutionPolicy Bypass -File packaging/build_backend.ps1

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

Write-Host "=== PhishGuard backend packaging ===" -ForegroundColor Cyan

# ── 1. Prerequisites ─────────────────────────────────────────────────
$pyVersion = (& python --version) 2>$null
if ($LASTEXITCODE -ne 0) { Write-Error "Python not found on PATH." }
Write-Host "Python: $pyVersion"

$pyInstallerVersion = (& python -m PyInstaller --version) 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller missing - installing (build machine only)..."
    & python -m pip install pyinstaller==6.22.3
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to install PyInstaller." }
} else {
    Write-Host "PyInstaller: $pyInstallerVersion"
}

$frontendDist = Join-Path $projectRoot "frontend/dist/index.html"
if (-not (Test-Path $frontendDist)) {
    Write-Error @"
frontend/dist/index.html not found.
Run 'npm run build' in frontend/ first (kept as an explicit, verified step).
"@
}
Write-Host "frontend/dist: OK"

# ── 2. Clean previous build outputs (build artifacts only, never user data) ──
$distDir = Join-Path $projectRoot "packaging/dist"
$buildDir = Join-Path $projectRoot "packaging/build"
foreach ($dir in @($distDir, $buildDir)) {
    if (Test-Path $dir) {
        Remove-Item -Recurse -Force $dir
        Write-Host "cleaned $dir"
    }
}

# ── 3. PyInstaller ───────────────────────────────────────────────────
Push-Location $projectRoot
try {
    & python -m PyInstaller packaging/phishguard_backend.spec `
        --distpath packaging/dist `
        --workpath packaging/build `
        --noconfirm
    if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller build failed." }
} finally {
    Pop-Location
}

# ── 4. Output verification ───────────────────────────────────────────
$exe = Join-Path $distDir "phishguard-backend/phishguard-backend.exe"
if (-not (Test-Path $exe)) { Write-Error "Expected executable not found: $exe" }

$size = (Get-ChildItem (Join-Path $distDir "phishguard-backend") -Recurse | Measure-Object -Property Length -Sum).Sum
Write-Host ("bundle size: {0:N1} MB" -f ($size / 1MB)) -ForegroundColor Green

# Secret scan on text-representable bundle files (source + config artifacts).
Write-Host "scanning bundle for secret material..."
$leakPattern = "gsk_[A-Za-z0-9]{20,}|GOOGLE_CLIENT_SECRET=[A-Za-z0-9]|AIza[A-Za-z0-9_\-]{30,}"
$bundleDir = Join-Path $distDir "phishguard-backend"
$hits = Get-ChildItem $bundleDir -Recurse -File -Include *.py, *.txt, *.json, *.toml, *.cfg, *.html, *.js |
    Select-String -Pattern $leakPattern -List
if ($hits) {
    Write-Error "SECRET MATERIAL FOUND IN BUNDLE: $($hits.Path -join ', ')"
}
Write-Host "secret scan: CLEAN" -ForegroundColor Green

Write-Host "=== BUILD OK: $exe ===" -ForegroundColor Green
