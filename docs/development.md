# Development

## Run from source

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pythonw main.py
```

## Run the tests

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

## Build the exe

```powershell
.\build.ps1
```

This runs the tests, then builds `dist\NOMAD-<version>.exe`, a single file with no console window.

- `build.ps1` uses `.venv` when it exists.
- If PowerShell says running scripts is disabled, run `powershell -ExecutionPolicy Bypass -File .\build.ps1`.
- The exe's startup splash is drawn by PyInstaller with Python's Tcl/Tk, so the Python that builds needs tkinter. That's the python.org installer's "tcl/tk and IDLE" option, on by default.

## Release

The version lives in `nomad\__init__.py`.

As you work, note changes under Unreleased in `CHANGELOG.md`, and add a line or two for users in `nomad\data\whats_new.md`. That file is shown under **Help** > **What's New...**, and the tests check every version has an entry.

Then:

```powershell
python -m nomad.version bump patch    # or minor / major
git add -A
git commit -m "Release X.Y.Z"
git tag vX.Y.Z
.\build.ps1
```

Upload `dist\NOMAD-<version>.exe` to a new GitHub release, so the README's quick start finds it.

## Update the MAC vendor list

1. Download <https://standards-oui.ieee.org/oui/oui.csv>.
2. Run `python -m nomad.oui build oui.csv`.

## Services in a console

To try out or troubleshoot a service, stop it and run it in a console:

```powershell
NOMAD.exe --ipam-server
NOMAD.exe --map-watcher
```

From source, use `python main.py --ipam-server` or `python main.py --map-watcher`.
