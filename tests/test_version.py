import datetime

import pytest

from nomad import __version__
from nomad.version import bumped, parse_version, release_changelog, set_version, version_resource


def test_current_version_is_valid():
    assert len(parse_version(__version__)) == 3


def test_bumped():
    assert bumped("1.2.3", "patch") == "1.2.4"
    assert bumped("1.2.3", "minor") == "1.3.0"
    assert bumped("1.2.3", "major") == "2.0.0"
    with pytest.raises(ValueError):
        bumped("1.2.3", "build")
    with pytest.raises(ValueError):
        bumped("1.2", "patch")


def test_set_version(tmp_path):
    init = tmp_path / "__init__.py"
    init.write_text('__version__ = "1.0.0"  # comment kept\n')
    set_version("1.1.0", init)
    assert init.read_text() == '__version__ = "1.1.0"  # comment kept\n'


def test_release_changelog(tmp_path):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [Unreleased]\n\n- Fixed a thing\n\n## [1.0.0] - 2026-01-01\n")
    release_changelog("1.0.1", changelog, datetime.date(2026, 2, 3))
    assert changelog.read_text() == ("# Changelog\n\n## [Unreleased]\n\n## [1.0.1] - 2026-02-03\n\n- Fixed a thing\n\n"
                                     "## [1.0.0] - 2026-01-01\n")


def test_version_resource():
    resource = version_resource("2.3.4")
    assert "filevers=(2, 3, 4, 0)" in resource
    assert "StringStruct('FileVersion', '2.3.4')" in resource
