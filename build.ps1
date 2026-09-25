# Builds dist\NOMAD.exe: a single file with no console window.
# Install the build tools first with:  pip install -r requirements-dev.txt
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

python -m pytest
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }

python -m nomad.ui.icon build\nomad.ico
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the icon." }

python -m nomad.version resource build\version.txt
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the version resource." }

python -m PyInstaller --noconfirm --clean --onefile --noconsole --name "NOMAD" --icon build\nomad.ico --version-file build\version.txt Main.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
Write-Host "Built dist\NOMAD.exe version $(python -m nomad.version)"
