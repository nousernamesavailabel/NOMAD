"""Which NOMAD each service on this computer runs, and the banner that says when one wants updating."""
import os
import time
from types import SimpleNamespace

import pytest
from PyQt5.QtWidgets import QApplication

from nomad import __version__, service_versions
from nomad.netmap import monitor_record
from nomad.service_versions import CHANGED, Behind, behind, keep_noting, loaded_files, note_started, read_note, \
    version_key, why_behind
from nomad.ui.service_banner import ServiceUpdateBanner, banner_text


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_a_service_notes_which_nomad_it_runs(tmp_path):
    note_started("--map-watcher-service", tmp_path, keep=False)
    note = read_note("--map-watcher-service", tmp_path)
    assert note["version"] == __version__ and abs(note["started"] - time.time()) < 60
    # From source: the files it has loaded (this one among them), not the whole of NOMAD
    assert os.path.normcase(service_versions.__file__) in note["files"]
    assert read_note("--dashboard-service", tmp_path) is None
    assert why_behind(note) == ""  # This NOMAD, and its code hasn't changed since it started


def test_only_a_change_to_a_file_the_service_loaded_makes_it_want_updating(tmp_path):
    root = tmp_path / "nomad"
    (root / "flows").mkdir(parents=True)
    used, unused = root / "flows" / "service.py", root / "editor.py"
    for path in (used, unused):
        path.write_text("x = 1\n", encoding="utf-8")
    modules = {"nomad.flows.service": type("Module", (), {"__file__": str(used)}),
               "nomad.ui.editor": type("Module", (), {"__file__": str(unused)}), "builtin": object(),
               "elsewhere": type("Module", (), {"__file__": str(tmp_path / "other.py")})}
    files = loaded_files(root=root, modules={"nomad.flows.service": modules["nomad.flows.service"],
                                             "elsewhere": modules["elsewhere"], "builtin": object()})
    assert list(files) == [os.path.normcase(str(used))]
    note = {"version": __version__, "code": str(root), "files": files}
    later = time.time() + 100
    os.utime(unused, (later, later))  # A file it doesn't use
    assert why_behind(note) == ""
    # Loaded later: noted with when it changed as it was loaded, and those noted before are kept as they were
    assert set(loaded_files(files, root, modules)) == {os.path.normcase(str(used)), os.path.normcase(str(unused))}
    os.utime(used, (later, later))
    assert why_behind(note) == CHANGED
    assert why_behind({**note, "files": {str(tmp_path / "gone.py"): 1.0}}) == CHANGED


def test_a_service_from_source_notes_the_files_it_loads_later(tmp_path, monkeypatch):
    note = {"version": __version__, "code": str(tmp_path), "files": {}}
    later = tmp_path / "later.py"
    later.write_text("", encoding="utf-8")
    monkeypatch.setitem(__import__("sys").modules, "nomad_later_test", type("Module", (), {"__file__": str(later)}))
    keep_noting(note, "--flow-collector-service", tmp_path, seconds=0, rounds=1)
    assert list(read_note("--flow-collector-service", tmp_path)["files"]) == [os.path.normcase(str(later))]


def test_why_a_service_wants_updating():
    assert version_key("2.10.0") > version_key("2.9.3") and version_key("2.8") < version_key("2.8.1")
    assert why_behind(None) == "runs an older NOMAD"  # From before services noted it
    assert why_behind({"version": "2.7.1"}, version="2.8.0") == "runs NOMAD 2.7.1"
    assert why_behind({"version": "2.9.0"}, version="2.8.0") == ""  # Newer is fine
    note = {"version": "2.8.0", "code": "C:/NOMAD", "stamp": 1000.0}
    assert why_behind(note, "2.8.0", stamp_of=lambda path: 1000.5) == ""
    assert why_behind(note, "2.8.0", stamp_of=lambda path: 2000.0) == CHANGED  # Packaged: NOMAD.exe changed


def test_only_running_services_are_checked():
    entries = [SimpleNamespace(title=title, key=key,
                               spec=lambda argument=argument: SimpleNamespace(argument=argument))
               for title, key, argument in (("Map Watcher", "watcher", "--map-watcher-service"),
                                            ("NOMAD Dashboard", "dashboard", "--dashboard-service"),
                                            ("Flow Collector", "flows", "--flow-collector-service"))]
    states = {"Map Watcher": "Running", "NOMAD Dashboard": "Running", "Flow Collector": "Stopped"}
    notes = {"--map-watcher-service": {"version": "1.0.0"}, "--dashboard-service": {"version": __version__}}
    found = behind(entries, lambda entry: states[entry.title], read=notes.get)
    assert found == [Behind("Map Watcher", "runs NOMAD 1.0.0", "watcher")]


def test_the_banner_names_them_and_stays_dismissed_until_something_else_wants_updating(app):
    banner = ServiceUpdateBanner(admin=True, finder=lambda: [])
    one = [Behind("Map Watcher", "runs NOMAD 2.7.1", "watcher")]
    banner.set_found(one)
    assert not banner.isHidden()
    assert banner.label.text() == ("A NOMAD service on this computer needs updating: The Map Watcher runs NOMAD "
                                   "2.7.1. Update Now updates it, keeping its settings.")
    banner.dismiss()
    assert banner.isHidden()
    banner.set_found(one)  # Still the same: still dismissed
    assert banner.isHidden()
    two = one + [Behind("NOMAD Dashboard", CHANGED, "dashboard")]
    banner.set_found(two)
    assert not banner.isHidden() and "and the NOMAD Dashboard was started before" in banner.label.text()
    banner.set_found([])  # Updated
    assert banner.isHidden()
    assert "Ask an administrator" in banner_text(one, admin=False)
    banner.deleteLater()


def test_update_now_updates_them_without_their_windows(app):
    banner = ServiceUpdateBanner(admin=True, finder=lambda: [])
    wanted = []
    banner.update_wanted.connect(wanted.append)
    banner.set_found([Behind("Map Watcher", "runs NOMAD 2.7.1", "watcher"), Behind("Flow Collector", CHANGED,
                                                                                   "flows")])
    assert banner.update_button.isVisibleTo(banner)
    banner.update_button.click()
    assert wanted == [["watcher", "flows"]]
    banner.set_updating(True)
    assert banner.label.text().startswith("Updating the Map Watcher and Flow Collector")
    assert not banner.update_button.isEnabled()
    banner.set_updating(False, ["The Map Watcher wasn't updated: access denied"])
    assert banner.update_button.isEnabled() and banner.label.text().startswith("The Map Watcher wasn't updated")
    assert not ServiceUpdateBanner(admin=False).update_button.isVisibleTo(banner)  # Only administrators can
    banner.deleteLater()


def test_the_updater_updates_in_order_and_frees_the_syslog_port(app, monkeypatch):
    from nomad import services_catalog
    from nomad.ui import service_updates, syslog_service_dialog
    calls = []
    entries = [SimpleNamespace(key=key, title=key, update=lambda key=key: calls.append(f"update {key}"))
               for key in ("tribe", "syslog", "watcher")]
    monkeypatch.setattr(services_catalog, "SERVICES", entries)
    monkeypatch.setattr(syslog_service_dialog, "free_syslog_port", lambda window: calls.append("free 514"))
    monkeypatch.setattr(syslog_service_dialog, "give_syslog_port_back", lambda window, released: calls.append("back"))
    monkeypatch.setattr(service_updates, "run_in_background", lambda job, done, failed: done(job()))
    updater = service_updates.ServiceUpdater(SimpleNamespace())
    finished = []
    updater.finished.connect(finished.append)
    assert updater.update([entries[2], entries[1]])
    assert calls == ["free 514", "update syslog", "update watcher", "back"] and finished == [[]]


def test_the_services_button_shows_its_ampersand(app):
    banner = ServiceUpdateBanner(admin=True, finder=lambda: [])
    assert banner.services_button.text().replace("&&", "&") == "Services & Firewall..."
    assert "&&" in banner.services_button.text()  # A lone & would be taken as a shortcut key and not shown
    banner.deleteLater()


def test_update_now_shows_each_service_in_a_progress_window(app, monkeypatch):
    from nomad import services_catalog
    from nomad.ui import service_updates
    from nomad.ui.service_update_dialog import ServiceUpdateDialog
    from nomad.ui.tribe_steps import DONE, FAILED

    def refused():
        raise OSError("access denied")

    entries = [SimpleNamespace(key="watcher", title="Map Watcher", update=lambda: None),
               SimpleNamespace(key="dashboard", title="NOMAD Dashboard", update=refused)]
    monkeypatch.setattr(services_catalog, "SERVICES", entries)
    later = []
    monkeypatch.setattr(service_updates, "run_in_background", lambda job, done, failed: later.append((job, done)))
    updater = service_updates.ServiceUpdater(SimpleNamespace())
    dialog = ServiceUpdateDialog(None, entries, updater)
    assert dialog.headline.text() == "Updating the Map Watcher and NOMAD Dashboard"
    assert dialog.close_button.text() == "Hide"
    assert updater.update(entries)
    job, done = later[0]
    done(job())
    assert dialog.states == {"watcher": DONE, "dashboard": FAILED}
    assert dialog.notes["dashboard"].text() == "access denied"
    assert dialog.headline.text() == "Some services weren't updated"
    assert dialog.close_button.text() == "Close"
    dialog.deleteLater()


def test_the_progress_window_says_when_all_are_up_to_date(app, monkeypatch):
    from nomad import services_catalog
    from nomad.ui import service_updates
    from nomad.ui.service_update_dialog import ServiceUpdateDialog
    entries = [SimpleNamespace(key="watcher", title="Map Watcher", update=lambda: None)]
    monkeypatch.setattr(services_catalog, "SERVICES", entries)
    monkeypatch.setattr(service_updates, "run_in_background", lambda job, done, failed: done(job()))
    updater = service_updates.ServiceUpdater(SimpleNamespace())
    dialog = ServiceUpdateDialog(None, entries, updater)
    assert updater.update(entries)
    assert dialog.headline.text() == "The Map Watcher is up to date"
    dialog.deleteLater()


def test_the_watcher_drops_the_summaries_of_maps_it_no_longer_monitors(tmp_path):
    monitor_record.write_shared("map-a", {"version": 1}, tmp_path)
    monitor_record.write_shared("map-b", {"version": 1}, tmp_path)
    monitor_record.remove_shared_except({"map-a"}, tmp_path)
    assert monitor_record.read_shared("map-a", tmp_path) and monitor_record.read_shared("map-b", tmp_path) is None


def test_the_services_folder_is_under_program_data(tmp_path, monkeypatch):
    monkeypatch.setenv("ProgramData", str(tmp_path))
    assert service_versions.versions_dir() == tmp_path / "NOMAD" / "services"


def test_each_service_updates_with_the_settings_it_has(monkeypatch):
    from nomad import services_catalog
    from nomad.dashboard import service as dashboard_service
    from nomad.ipam import service as ipam_service
    from nomad.netmap import watch_service
    calls = []
    monkeypatch.setattr(watch_service, "load_config", lambda: {"maps": ["a"]})
    monkeypatch.setattr(watch_service, "install", lambda config, copies=(): calls.append(("watcher", config)))
    monkeypatch.setattr(dashboard_service, "load_config", lambda: {"port": 8444})
    monkeypatch.setattr(dashboard_service, "install", lambda config: calls.append(("dashboard", config)))
    monkeypatch.setattr(ipam_service, "install", lambda port=None: calls.append(("tribe", port)))
    for key in ("watcher", "dashboard", "tribe"):
        services_catalog.entry(key).update()
    assert calls == [("watcher", {"maps": ["a"]}), ("dashboard", {"port": 8444}), ("tribe", None)]
    assert all(entry.update_quietly or entry.install_quietly for entry in services_catalog.SERVICES)
