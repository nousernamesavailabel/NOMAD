"""NOMAD's version number (semantic versioning: MAJOR.MINOR.PATCH), set in nomad/__init__.py.

Run as a script:
    python -m nomad.version                           print the current version
    python -m nomad.version bump patch|minor|major    raise the version and date its CHANGELOG entry
    python -m nomad.version resource build\\version.txt  write the Windows version resource for the packaged exe
    python -m nomad.version exe-name                  print the packaged exe's name without .exe (e.g. NOMAD-1.2.3)
"""
import datetime
import re
import sys
from pathlib import Path

from . import __version__
from .system import APP_FULL_NAME, APP_NAME

PACKAGE_INIT = Path(__file__).with_name("__init__.py")
CHANGELOG = Path(__file__).parent.parent / "CHANGELOG.md"
VERSION_PATTERN = re.compile(r'^__version__ = "(\d+)\.(\d+)\.(\d+)"', re.MULTILINE)
UNRELEASED_HEADING = "## [Unreleased]"


def parse_version(text):
    """Split "1.2.3" into (1, 2, 3)."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", text.strip())
    if not match:
        raise ValueError(f"Not a MAJOR.MINOR.PATCH version: {text!r}")
    return tuple(int(part) for part in match.groups())


def bumped(version, part):
    """The version after raising one part; the parts after it go back to 0."""
    major, minor, patch = parse_version(version)
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Can only bump major, minor or patch, not {part!r}")


def set_version(new_version, init_path=PACKAGE_INIT):
    """Rewrite the version in the package's __init__.py."""
    parse_version(new_version)
    text = init_path.read_text(encoding="utf-8")
    if not VERSION_PATTERN.search(text):
        raise ValueError(f"No __version__ line in {init_path}")
    init_path.write_text(VERSION_PATTERN.sub(f'__version__ = "{new_version}"', text, count=1), encoding="utf-8")


def release_changelog(new_version, changelog_path=CHANGELOG, today=None):
    """Turn the Unreleased section into this version's entry and start a fresh, empty Unreleased section."""
    today = today or datetime.date.today()
    text = changelog_path.read_text(encoding="utf-8")
    if UNRELEASED_HEADING not in text:
        raise ValueError(f"No '{UNRELEASED_HEADING}' section in {changelog_path}")
    heading = f"{UNRELEASED_HEADING}\n\n## [{new_version}] - {today.isoformat()}"
    changelog_path.write_text(text.replace(UNRELEASED_HEADING, heading, 1), encoding="utf-8")


def exe_name(version=__version__):
    """The packaged exe's name without the .exe, so each build says which version it is."""
    return f"{APP_NAME}-{version}"


def version_resource(version=__version__):
    """PyInstaller's --version-file contents, which fill in the exe's Properties > Details tab."""
    numbers = parse_version(version) + (0,)
    return f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('ProductName', '{APP_NAME}'),
      StringStruct('FileDescription', '{APP_NAME} - {APP_FULL_NAME}'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('ProductVersion', '{version}'),
      StringStruct('InternalName', '{APP_NAME}'),
      StringStruct('OriginalFilename', '{exe_name(version)}.exe')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def main(args):
    if not args:
        print(__version__)
    elif args[0] == "bump" and len(args) == 2:
        new_version = bumped(__version__, args[1])
        set_version(new_version)
        release_changelog(new_version)
        print(f"{__version__} -> {new_version}\n"
              f"Next:\n  git commit -am \"Release {new_version}\"\n  git tag v{new_version}\n  .\\build.ps1")
    elif args[0] == "exe-name" and len(args) == 1:
        print(exe_name())
    elif args[0] == "resource" and len(args) == 2:
        output = Path(args[1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(version_resource(), encoding="utf-8")
        print(f"Wrote {output} for version {__version__}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
