# GrantScope one-shot verification for Windows / PowerShell.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
# Requires Python 3.8+ on PATH. No third-party modules, no network access.

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

Write-Host "==> unit tests" -ForegroundColor Cyan
& $py -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw "unit tests failed" }

Write-Host "==> build zipapp" -ForegroundColor Cyan
& $py build.py
if ($LASTEXITCODE -ne 0) { throw "build failed" }

Write-Host "==> zipapp version" -ForegroundColor Cyan
& $py dist/grantscope.pyz version
if ($LASTEXITCODE -ne 0) { throw "zipapp smoke test failed" }

Write-Host "==> clean bundle gate (expect exit 0)" -ForegroundColor Cyan
& $py dist/grantscope.pyz audit examples/good --no-color --fail-on high
if ($LASTEXITCODE -ne 0) { throw "good bundle unexpectedly failed the gate" }

Write-Host "==> broken bundle gate (expect exit 1)" -ForegroundColor Cyan
& $py dist/grantscope.pyz audit examples/bad --no-color --quiet --fail-on critical
if ($LASTEXITCODE -eq 0) { throw "bad bundle unexpectedly passed the gate" }

Write-Host "==> SARIF output" -ForegroundColor Cyan
& $py dist/grantscope.pyz audit examples/bad --format sarif --output dist/bad.sarif --fail-on never
if ($LASTEXITCODE -ne 0) { throw "SARIF generation failed" }

Write-Host "verify OK" -ForegroundColor Green
