"""Files are put in place with system.replace_file, which waits out Windows refusing while the virus scanner has one
open for a moment, never with a bare os.replace."""
import re
from pathlib import Path

import pytest

from nomad import system

PACKAGE = Path(__file__).resolve().parent.parent / "nomad"
BARE = re.compile(r"\bos\.replace\(|(?<!self\.fs)\.replace\((temporary|part|path)\b")  # Not SFTP renames


def test_only_the_helper_replaces_files():
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in BARE.finditer(source):
            found.append(f"{path.relative_to(PACKAGE)}:{source.count(chr(10), 0, match.start()) + 1}")
    assert [place for place in found if not place.startswith("system.py:")] == []
    assert BARE.search("os.replace(temporary, path)") and BARE.search("temporary.replace(path)")
    assert not BARE.search("self.fs.replace(part, transfer.remote)")


def test_a_file_held_open_for_good_still_fails(tmp_path, monkeypatch):
    tries = []

    def refused(source, target):
        tries.append(target)
        raise PermissionError(13, "Access is denied")
    monkeypatch.setattr(system.os, "replace", refused)
    monkeypatch.setattr(system.time, "sleep", lambda seconds: None)
    with pytest.raises(PermissionError):
        system.replace_file(tmp_path / "a.tmp", tmp_path / "a")
    assert len(tries) == system.REPLACE_TRIES


def test_other_errors_are_not_retried(tmp_path):
    with pytest.raises(FileNotFoundError):
        system.replace_file(tmp_path / "missing.tmp", tmp_path / "a")
