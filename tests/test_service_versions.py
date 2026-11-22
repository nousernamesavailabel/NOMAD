"""Which NOMAD each service on this computer runs, and the banner that says when one wants updating."""
import time
from types import SimpleNamespace

import pytest
from PyQt5.QtWidgets import QApplication

from nomad import __version__, service_versions
from nomad.netmap import monitor_record
from nomad.service_versions import Behind, behind, note_started, read_note, version_key, why_behind
from nomad.ui.service_banner import ServiceUpdateBanner, banner_text


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_a_service_notes_which_nomad_it_runs(tmp_path):
    note_started("--map-watcher-service", tmp_path)
    note = read_note("--map-watcher-service", tmp_path)
    assert note["version"] == __version__ and note["stamp"] > 0 and abs(note["started"] - time.time()) < 60
    assert read_note("--dashboard-service", tmp_path) is None
    assert why_behind(note) == ""  # This NOMAD, and its code hasn't changed since it started


def test_why_a_service_wants_updating():
    assert version_key("2.10.0") > version_key("2.9.3") and version_key("2.8") < version_key("2.8.1")
    assert why_behind(None) == "runs an older NOMAD"  # From before services noted it
    assert why_behind({"version": "2.7.1"}, version="2.8.0") == "runs NOMAD 2.7.1"
    assert why_behind({"version": "2.9.0"}, version="2.8.0") == ""  # Newer is fine
    note = {"version": "2.8.0", "code": "C:/NOMAD", "stamp": 1000.0}
    assert why_behind(note, "2.8.0", stamp_of=lambda path: 1000.5) == ""
    assert why_behind(note, "2.8.0", stamp_of=lambda path: 2000.0) == "was started before its copy of NOMAD changed"


def test_only_running_services_are_checked():
    entries = [SimpleNamespace(title=title, spec=lambda argument=argument: SimpleNamespace(argument=argument))
               for title, argument in (("Map Watcher", "--map-watcher-service"),
                                       ("NOMAD Dashboard", "--dashboard-service"),
                                       ("Flow Collector", "--flow-collector-service"))]
    states = {"Map Watcher": "Running", "NOMAD Dashboard": "Running", "Flow Collector": "Stopped"}
    notes = {"--map-watcher-service": {"version": "1.0.0"}, "--dashboard-service": {"version": __version__}}
    found = behind(entries, lambda entry: states[entry.title], read=notes.get)
    assert found == [Behind("Map Watcher", "runs NOMAD 1.0.0")]


def test_the_banner_names_them_and_stays_dismissed_until_something_else_wants_updating(app):
    banner = ServiceUpdateBanner(admin=True, finder=lambda: [])
    one = [Behind("Map Watcher", "runs NOMAD 2.7.1")]
    banner.set_found(one)
    assert not banner.isHidden()
    assert banner.label.text().startswith("A NOMAD service on this computer needs updating: The Map Watcher runs "
                                          "NOMAD 2.7.1. Tick it in Tools > Services & Firewall")
    banner.dismiss()
    assert banner.isHidden()
    banner.set_found(one)  # Still the same: still dismissed
    assert banner.isHidden()
    two = one + [Behind("NOMAD Dashboard", "was started before its copy of NOMAD changed")]
    banner.set_found(two)
    assert not banner.isHidden() and "and the NOMAD Dashboard was started before" in banner.label.text()
    banner.set_found([])  # Updated
    assert banner.isHidden()
    assert "Ask an administrator" in banner_text(one, admin=False)
    banner.deleteLater()


def test_the_watcher_drops_the_summaries_of_maps_it_no_longer_monitors(tmp_path):
    monitor_record.write_shared("map-a", {"version": 1}, tmp_path)
    monitor_record.write_shared("map-b", {"version": 1}, tmp_path)
    monitor_record.remove_shared_except({"map-a"}, tmp_path)
    assert monitor_record.read_shared("map-a", tmp_path) and monitor_record.read_shared("map-b", tmp_path) is None


def test_the_services_folder_is_under_program_data(tmp_path, monkeypatch):
    monkeypatch.setenv("ProgramData", str(tmp_path))
    assert service_versions.versions_dir() == tmp_path / "NOMAD" / "services"
