# Builds dist\NOMAD-<version>.exe (e.g. dist\NOMAD-1.2.3.exe): a single file with no console window.
# Install the build tools first with:  pip install -r requirements-dev.txt
# If PowerShell says running scripts is disabled, run it as:  powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Use the project's virtual environment when there is one, so it works without activating it first (another
# Python on the PATH may not have NOMAD's packages, and the tests would fail)
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) { $python = 'python' }
Write-Host "Using $python"

& $python -c "import pytest, PyInstaller, PyQt5, paramiko, openpyxl, win32service"
if ($LASTEXITCODE -ne 0) {
    throw "$python is missing packages NOMAD needs to build. Install them with: $python -m pip install -r requirements-dev.txt"
}

& $python -m pytest
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building. The failures are listed above." }

& $python -m nomad.ui.icon build\nomad.ico
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the icon." }

# The splash the exe shows from the moment it's opened, while it unpacks (NOMAD then shows the same picture itself)
& $python -m nomad.ui.splash build\splash.png
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the splash picture." }

& $python -m nomad.version resource build\version.txt
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the version resource." }

$exeName = & $python -m nomad.version exe-name
if ($LASTEXITCODE -ne 0) { throw "Couldn't read the version." }

# nomad\data holds the MAC vendor list, bundled so vendor lookups work offline. win32timezone and servicemanager
# are loaded by pywin32 when the exe runs as the IPAM server service, where PyInstaller can't see them
& $python -m PyInstaller --noconfirm --clean --onefile --noconsole --name $exeName --icon build\nomad.ico --splash build\splash.png --version-file build\version.txt --add-data "nomad\data;nomad\data" --hidden-import win32timezone --hidden-import servicemanager Main.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
Write-Host "Built dist\$exeName.exe"
