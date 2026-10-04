# Builds dist\SecureVault.exe - a single file that runs without Python installed.
# Usage (from the project folder):  powershell -ExecutionPolicy Bypass -File .\build.ps1
# Native tools write notices to stderr, so check $LASTEXITCODE rather than using -ErrorAction Stop.
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python -m pip install -q --disable-pip-version-check -r requirements.txt -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency install failed." }

Write-Host "Running tests..."
.\.venv\Scripts\python -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed - not building." }

Write-Host "Building SecureVault.exe..."
.\.venv\Scripts\pyinstaller --noconfirm --clean --onefile --windowed `
    --name SecureVault `
    --exclude-module PIL --exclude-module pytest `
    app.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }

$exe = Get-Item dist\SecureVault.exe
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
"$hash  SecureVault.exe" | Out-File -Encoding ascii dist\SecureVault.exe.sha256
Write-Host ""
Write-Host "Built $($exe.FullName) ($([math]::Round($exe.Length / 1MB, 1)) MB)"
Write-Host "SHA-256: $hash"
