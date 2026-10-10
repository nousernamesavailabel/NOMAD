"""Disconnect from the Tribe: asked first, then each step shown as it happens, against a real tribe server."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402
from test_ipam_server import ADMIN, key_for, plan, small_map, team_store  # noqa: E402

from nomad.ipam.client import TeamClient, TeamKey, TeamStore  # noqa: E402
from nomad.ipam.server import IpamServer  # noqa: E402
from nomad.ipam.store import USED  # noqa: E402
from nomad.netmap.tribe import TribeMaps  # noqa: E402
from nomad.ui import tribe_leave_dialog  # noqa: E402
from nomad.ui.common import run_in_background  # noqa: E402
from nomad.ui.netmap_tribe import TribeSync  # noqa: E402
from nomad.ui.tribe_leave_dialog import FORGET, MAPS, NETWORKS, OWN, SEND, STOP, LeaveTribeDialog  # noqa: E402
from nomad.ui.tribe_steps import DONE, SKIPPED, WAITING, WARNING  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def server(tmp_path):
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def wait_for(app, condition, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    return False


class FakeIpamPage(QObject):
    """The IP Addresses page as far as leaving needs, with a real copy of the tribe's IPAM data."""
    tribe_synced = pyqtSignal()
    tribe_sync_failed = pyqtSignal(str)

    def __init__(self, team):
        super().__init__()
        self.team, self.local_store, self.calls = team, object(), []

    def open_store(self):
        self.calls.append("open_store")

    def unsent_tribe_changes(self):
        return self.team.pending_count() + len(self.team.refused()) if self.team is not None else 0

    def sync_now(self):
        team, outgoing = self.team, self.team.outgoing()  # The copy is read here, on the UI thread
        run_in_background(lambda: team.send_pending(outgoing), self.sent, self.failed)

    def sent(self, results):
        self.team.apply_sent(results)
        if self.team.pending_count():
            self.team.last_error = "Can't reach the IPAM server (127.0.0.1: refused)."
            self.tribe_sync_failed.emit(self.team.last_error)
        else:
            self.tribe_synced.emit()

    def failed(self, error):
        self.tribe_sync_failed.emit(str(error))

    def stop_watching(self):
        self.calls.append("stop_watching")

    def forget_team_copy(self):
        self.team.reset_copy()
        self.team.close()
        self.team = None

    def connect_team(self):
        self.calls.append("connect_team")

    def fill_networks(self):
        self.calls.append("fill_networks")


class FakeMapPage:
    def __init__(self, tribe):
        self.tribe, self.tribe_map_id = tribe, None

    def unsent_tribe_changes(self):
        return self.tribe.maps.pending_count() if self.tribe.maps is not None else 0

    def tribe_key_changed(self, forget=False):
        self.tribe.reset(forget=forget)
        self.tribe.ensure()


class FakeWindow:
    def __init__(self, ipam, netmap):
        self.ipam_tab, self.netmap_tab, self.changed = ipam, netmap, 0

    def tribe_key_changed(self, origin=None):
        self.changed += 1


@pytest.fixture
def leaving(app, server, tmp_path, monkeypatch):
    """open(key) -> (dialog, window, maps file): Carol, in the tribe with that key (the server's by default)."""
    made = []

    def open_dialog(key=None):
        key = key or key_for(server)
        saved = [key]
        monkeypatch.setattr(tribe_leave_dialog, "forget_key", saved.clear)
        team = TeamStore(key, tmp_path / "carol.db", TeamClient(key, user="carol", computer="LAPTOP"))
        maps_file = tmp_path / "carol-maps.db"
        tribe = TribeSync(key_loader=lambda: saved[-1] if saved else None, maps_factory=lambda key: TribeMaps(
            key.server_id, TeamClient(key, user="carol", computer="LAPTOP"), maps_file))
        window = FakeWindow(FakeIpamPage(team), FakeMapPage(tribe))
        dialog = LeaveTribeDialog(None, window)
        made.append((dialog, window))
        return dialog, window, maps_file

    yield open_dialog
    for dialog, window in made:
        dialog.leaving = False
        dialog.reject()
        window.netmap_tab.tribe.shutdown()
        if window.ipam_tab.team is not None:
            window.ipam_tab.team.close()
        dialog.deleteLater()


def test_asked_first_then_each_step_is_shown(app, server, leaving):
    admin = team_store(server, server.directory.parent, "admin", ADMIN)
    admin.import_networks([plan()])
    key = key_for(server)
    maps = TribeMaps(key.server_id, TeamClient(key, user="carol"), server.directory.parent / "carol-maps.db")
    maps.create("HQ", small_map(), {}, {})
    maps.close()
    dialog, window, maps_file = leaving()
    window.ipam_tab.team.sync()
    assert dialog.headline.text() == "Disconnect from the tribe?" and "your own networks and maps are kept" in \
        dialog.message.text()
    assert all(dialog.states[step] == WAITING for step in dialog.steps)  # Nothing done until Disconnect
    assert dialog.disconnect_button.isVisibleTo(dialog) and dialog.close_button.text() == "Cancel"
    dialog.disconnect_button.click()
    assert dialog.states[SEND] == SKIPPED and dialog.notes[SEND].text() == "Nothing waiting to be sent"
    assert not dialog.close_button.isEnabled()  # Can't be stopped part of the way through
    assert wait_for(app, lambda: dialog.left)
    assert [dialog.states[step] for step in (STOP, FORGET, NETWORKS, MAPS, OWN)] == [DONE] * 5
    assert dialog.notes[NETWORKS].text() == "Removed 1 network" and dialog.notes[MAPS].text() == "Removed 1 map"
    assert window.ipam_tab.team is None and window.netmap_tab.tribe.maps is None
    assert TribeMaps(key.server_id, None, maps_file).maps() == []  # The maps' copy was emptied
    assert {"stop_watching", "connect_team", "fill_networks"} <= set(window.ipam_tab.calls)
    assert dialog.headline.text() == "Disconnected from the tribe" and dialog.close_button.isEnabled()
    assert dialog.close_button.text() == "Close"


def test_changes_waiting_are_sent_first(app, server, leaving, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    maps = TribeMaps(key_for(server).server_id, TeamClient(key_for(server), user="carol"), tmp_path / "carol-maps.db")
    map_id = maps.create("HQ", small_map(), {}, {})
    maps.close()
    dialog, window, _ = leaving()
    team = window.ipam_tab.team
    team.sync()
    team.online = False  # Made offline, so it waits
    team.set_address(network.id, "10.0.0.20", USED, "printer")
    tribe = window.netmap_tab.tribe
    tribe.shutdown()  # So the page's own sync doesn't send it first
    changed = small_map()
    changed.positions["acc1"] = (50.0, 100.0)
    tribe.maps.save(map_id, changed)
    assert dialog.count_unsent() == 2
    dialog.unsent = dialog.count_unsent()
    dialog.disconnect_button.click()
    assert wait_for(app, lambda: dialog.left)
    assert dialog.states[SEND] == DONE and dialog.notes[SEND].text() == "Sent 2 changes"
    admin.sync()
    assert admin.address(network.id, "10.0.0.20").name == "printer"


def test_changes_that_cant_be_sent_can_be_given_up(app, server, leaving, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    team_store(server, tmp_path, "carol").close()  # Carol's copy is up to date, then she goes offline
    key = key_for(server)
    dialog, window, _ = leaving(TeamKey(key.server_id, ["127.0.0.1"], 1, key.fingerprint, key.secret))
    window.ipam_tab.team.set_address(network.id, "10.0.0.21", USED, "scanner")
    dialog.unsent = dialog.count_unsent()
    dialog.disconnect_button.click()
    assert wait_for(app, lambda: dialog.states[SEND] == WARNING)
    assert "1 change still hasn't reached the tribe server" in dialog.notes[SEND].text()
    assert "couldn't be sent: Can't reach" in dialog.notes[SEND].text()
    assert dialog.anyway_button.isVisibleTo(dialog) and dialog.states[FORGET] == WAITING
    assert dialog.close_button.isEnabled()  # Cancel still leaves everything as it was
    dialog.anyway_button.click()
    assert wait_for(app, lambda: dialog.left) and window.ipam_tab.team is None


def test_cancel_changes_nothing(app, server, leaving):
    dialog, window, _ = leaving()
    dialog.reject()
    assert not dialog.left and window.ipam_tab.team is not None and window.netmap_tab.tribe.maps is not None
