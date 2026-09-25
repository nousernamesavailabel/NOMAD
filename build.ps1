# Builds dist\NOMAD-<version>.exe (e.g. dist\NOMAD-1.2.3.exe): a single file with no console window.
# Install the build tools first with:  pip install -r requirements-dev.txt
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

python -m pytest
if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building." }

python -m nomad.ui.icon build\nomad.ico
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the icon." }

python -m nomad.version resource build\version.txt
if ($LASTEXITCODE -ne 0) { throw "Couldn't create the version resource." }

$exeName = python -m nomad.version exe-name
if ($LASTEXITCODE -ne 0) { throw "Couldn't read the version." }

# nomad\data holds the MAC vendor list, bundled so vendor lookups work offline
python -m PyInstaller --noconfirm --clean --onefile --noconsole --name $exeName --icon build\nomad.ico --version-file build\version.txt --add-data "nomad\data;nomad\data" Main.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
Write-Host "Built dist\$exeName.exe"
