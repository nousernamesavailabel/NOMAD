"""Which NOMAD each service on this computer runs, so NOMAD can say when one wants updating.

Each service notes, as it starts, the NOMAD version it runs and a stamp of its code (when its copy of NOMAD last
changed): <its argument>.json in %ProgramData%\\NOMAD\\services, which every user may read (there's nothing secret in
it) and only the services and administrators may change (made when a service is installed or updated).

NOMAD compares the running services' notes with itself (behind()): a service runs an older NOMAD, or was started
before its copy of NOMAD changed (so it runs the code from before: likely when running from source, where the version
doesn't change), or says nothing (from before NOMAD noted it). The banner across NOMAD's window says so
(ui/service_banner.py), and Tools > Services & Firewall shows each one's version.
"""
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import __version__

log = logging.getLogger(__name__)

CODE_SUFFIXES = {".py", ".js", ".css", ".html"}  # What a service from source runs (and serves)


def versions_dir():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "services"


def code_path():
    """What this process runs: the exe (packaged), or the nomad package's folder (from source)."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve().parent


def code_stamp(path):
    """When the code at path last changed: an exe's modified time, or the newest of a source folder's files (0.0 if
    it can't be read)."""
    path = Path(path)
    try:
        if path.is_file():
            return path.stat().st_mtime
        newest = 0.0
        for folder, folders, files in os.walk(path):
            folders[:] = [name for name in folders if name != "__pycache__"]
            for name in files:
                if os.path.splitext(name)[1] in CODE_SUFFIXES:
                    newest = max(newest, os.stat(os.path.join(folder, name)).st_mtime)
        return newest
    except OSError:
        return 0.0


def note_path(argument, directory=None):
    """The note of the service started with this argument ("--map-watcher-service")."""
    return Path(directory or versions_dir()) / f"{argument.strip('-')}.json"


def note_started(argument, directory=None):
    """Note which NOMAD this service runs (called as it starts). Never fails the service."""
    try:
        path = code_path()
        note = {"version": __version__, "started": time.time(), "pid": os.getpid(), "code": str(path),
                "stamp": code_stamp(path)}
        target = note_path(argument, directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(note), encoding="utf-8")
        from .system import replace_file
        replace_file(temporary, target)
    except OSError as error:  # Installed before the folder was made: noted once it's updated
        log.info("Couldn't note this service's version: %s", error)


def read_note(argument, directory=None):
    try:
        note = json.loads(note_path(argument, directory).read_text(encoding="utf-8"))
        return note if isinstance(note, dict) else None
    except (OSError, ValueError):
        return None


def version_key(version):
    """(2, 7, 1) from "2.7.1" (what can't be read counts as 0)."""
    parts = []
    for part in str(version or "").split("."):
        digits = "".join(character for character in part if character.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


@dataclass(frozen=True)
class Behind:
    title: str  # "Map Watcher"
    reason: str  # "runs NOMAD 2.7.1"


def why_behind(note, version=__version__, stamp_of=code_stamp):
    """Why a running service with this note (None: it noted nothing) wants updating, or "" if it doesn't."""
    if note is None:
        return "runs an older NOMAD"
    if version_key(note.get("version")) < version_key(version):
        return f"runs NOMAD {note.get('version') or 'older'}"
    started_with = float(note.get("stamp") or 0)
    if started_with and note.get("code") and stamp_of(note["code"]) > started_with + 1:
        return "was started before its copy of NOMAD changed"
    return ""


def behind(entries, status_of, read=read_note, version=__version__, stamp_of=code_stamp):
    """[Behind] of the running services (services_catalog entries) that want updating. status_of(entry): its state
    (ipam.service's RUNNING...)."""
    from .ipam.service import RUNNING
    found = []
    stamps = {}

    def stamp_cached(path):  # The services share their code: look at it once
        if path not in stamps:
            stamps[path] = stamp_of(path)
        return stamps[path]
    for entry in entries:
        try:
            if status_of(entry) != RUNNING:
                continue
            reason = why_behind(read(entry.spec().argument), version, stamp_cached)
        except Exception as error:  # pywin32 missing, or its module can't be read: nothing to say
            log.info("Couldn't check the %s service's version: %s", entry.title, error)
            continue
        if reason:
            found.append(Behind(entry.title, reason))
    return found


def version_text(entry, state, read=read_note):
    """For the Services window's Version column: "2.7.1", "2.8.0 (restart: its copy changed)", or ""."""
    from .ipam.service import RUNNING
    if state != RUNNING:
        return ""
    note = read(entry.spec().argument)
    if note is None:
        return "older (doesn't say)"
    text = str(note.get("version") or "?")
    reason = why_behind(note)
    if reason == "was started before its copy of NOMAD changed":
        text += " (started before its copy changed)"
    return text
