"""Connect to the Tribe: the steps of joining shown as they happen, against a real tribe server."""
import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QObject, QTimer, pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402
from test_ipam_server import key_for  # noqa: E402

from nomad.ipam.client import TeamClient, TeamKey  # noqa: E402
from nomad.ipam.server import IpamServer  # noqa: E402
from nomad.netmap.tribe import TribeMaps  # noqa: E402
from nomad.ui import tribe_join_dialog  # noqa: E402
from nomad.ui.netmap_tribe import TribeSync  # noqa: E402
from nomad.ui.tribe_join_dialog import CHECK, DONE, FAILED, KEY, MAPS, NETWORKS, REACH, SAVE, SKIPPED, WARNING, \
    JoinTribeDialog  # noqa: E402


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
    """The IP Addresses page as far as joining needs: its tribe copy syncs a moment after it's (re)connected."""
    tribe_synced = pyqtSignal()
    tribe_sync_failed = pyqtSignal(str)

    def __init__(self, networks=("11AB SIPR", "11AB NIPR"), fails=None):
        super().__init__()
        self.team, self.networks, self.fails, self.opened = None, list(networks), fails, 0

    def connect_team(self):
        self.team = SimpleNamespace(networks=lambda: self.networks)
        QTimer.singleShot(200, self.finish_sync)

    def finish_sync(self):
        if self.fails:
            self.tribe_sync_failed.emit(self.fails)
        else:
            self.tribe_synced.emit()

    def open_store(self):
        self.opened += 1
        if self.team is None:
            self.connect_team()


class FakeWindow:
    def __init__(self, server, tmp_path, ipam):
        self.saved = []
        self.ipam_tab = ipam
        self.netmap_tab = SimpleNamespace(tribe=TribeSync(
            key_loader=lambda: self.saved[-1] if self.saved else None,
            maps_factory=lambda key: TribeMaps(key.server_id, TeamClient(key, user="carol", computer="LAPTOP"),
                                               tmp_path / "carol-maps.db")))
        self.changed = 0

    def tribe_key_changed(self, origin=None):
        self.changed += 1
        self.netmap_tab.tribe.reset()
        self.netmap_tab.tribe.ensure()
        if self.ipam_tab.team is not None:
            self.ipam_tab.connect_team()

    def shutdown(self):
        self.netmap_tab.tribe.shutdown()


@pytest.fixture
def joining(app, server, tmp_path, monkeypatch):
    """open(key) -> the dialog, connecting with that key (the server's own by default) as Carol."""
    made = []

    def open_dialog(key=None, ipam=None):
        window = FakeWindow(server, tmp_path, ipam or FakeIpamPage())
        monkeypatch.setattr(tribe_join_dialog, "read_key_file", lambda path: key or key_for(server))
        monkeypatch.setattr(tribe_join_dialog, "save_key", window.saved.append)
        dialog = JoinTribeDialog(None, window, "tribe.nomadkey")
        made.append((dialog, window))
        return dialog, window

    yield open_dialog
    for dialog, window in made:
        dialog.reject()
        window.shutdown()
        dialog.deleteLater()


def settled(dialog):
    return not dialog.working() and dialog.thread is None


def test_each_step_is_shown_then_the_downloads_are_followed(app, server, joining):
    dialog, window = joining()
    assert dialog.states[KEY] == DONE and dialog.states[REACH] == "working"
    assert dialog.bar.maximum() == 0  # Moving while it works
    assert "Tribe server at 127.0.0.1" in dialog.notes[KEY].text()
    assert dialog.close_button.text() == "Cancel"
    assert wait_for(app, lambda: dialog.states[SAVE] == DONE)
    assert window.saved and dialog.saved and window.changed == 1
    assert "Reached 127.0.0.1; its certificate matches" in dialog.notes[REACH].text()
    assert dialog.notes[CHECK].text().startswith("Accepted by")
    assert window.ipam_tab.opened == 1  # The IP Addresses page connected, though it hadn't been shown
    assert wait_for(app, lambda: settled(dialog))
    assert [dialog.states[step] for step in (NETWORKS, MAPS)] == [DONE, DONE]
    assert dialog.notes[NETWORKS].text() == "2 networks from the tribe"
    assert dialog.notes[MAPS].text() == "0 maps yet: the tribe hasn't shared any"
    assert dialog.headline.text() == "Connected to the tribe"
    assert dialog.close_button.text() == "Close" and dialog.bar.value() == dialog.bar.maximum()


def test_closing_during_the_download_leaves_it_running(app, server, joining):
    dialog, window = joining()
    assert wait_for(app, lambda: dialog.states[SAVE] == DONE)
    assert dialog.close_button.text() == "Continue in Background"
    dialog.reject()  # Stops following: a late answer doesn't touch the closed window
    assert wait_for(app, lambda: window.netmap_tab.tribe.last_sync)
    assert dialog.states[MAPS] == "working"


def test_a_server_that_cant_be_reached_can_be_saved_anyway(app, server, joining):
    key = key_for(server)
    dialog, window = joining(TeamKey(key.server_id, ["127.0.0.1"], 1, key.fingerprint, key.secret))
    assert wait_for(app, lambda: settled(dialog))
    assert dialog.states[REACH] == FAILED and "Can't reach" in dialog.notes[REACH].text()
    assert dialog.states[CHECK] == SKIPPED and not window.saved
    assert dialog.anyway_button.isVisibleTo(dialog) and dialog.headline.text().endswith("can't be reached right now")
    dialog.anyway_button.click()
    assert window.saved and dialog.saved and window.changed == 1
    assert wait_for(app, lambda: dialog.states[NETWORKS] == SKIPPED and dialog.states[MAPS] == SKIPPED)
    assert dialog.headline.text() == "Tribe key saved" and not dialog.anyway_button.isVisibleTo(dialog)


@pytest.mark.parametrize("wrong, step, message", [
    ("secret", CHECK, "isn't accepted"),
    ("fingerprint", REACH, "isn't the one in the tribe key file"),
])
def test_a_key_the_server_refuses_isnt_saved(app, server, joining, wrong, step, message):
    key = key_for(server)
    setattr(key, wrong, "0" * 64)
    dialog, window = joining(key)
    assert wait_for(app, lambda: settled(dialog))
    assert dialog.states[step] == FAILED and message in dialog.notes[step].text()
    assert not window.saved and not dialog.saved and window.changed == 0
    assert dialog.headline.text() == "Couldn't connect to the tribe" and not dialog.anyway_button.isVisibleTo(dialog)
    assert dialog.states[SAVE] == SKIPPED and dialog.close_button.text() == "Close"


def test_a_file_that_isnt_a_key_stops_at_the_first_step(app, tmp_path, monkeypatch):
    path = tmp_path / "notes.nomadkey"
    path.write_text("not a key", encoding="utf-8")
    window = SimpleNamespace(tribe_key_changed=lambda origin=None: pytest.fail("Nothing should be saved"))
    dialog = JoinTribeDialog(None, window, str(path))
    try:
        assert dialog.states[KEY] == FAILED and "Couldn't read notes.nomadkey" in dialog.notes[KEY].text()
        assert dialog.thread is None and not dialog.saved
    finally:
        dialog.reject()
        dialog.deleteLater()


def test_a_download_that_fails_says_so_and_recovers(app, server, joining):
    ipam = FakeIpamPage(fails="Can't reach the IPAM server (timed out).")
    dialog, window = joining(ipam=ipam)
    assert wait_for(app, lambda: settled(dialog))
    assert dialog.states[NETWORKS] == WARNING and "NOMAD keeps trying" in dialog.notes[NETWORKS].text()
    assert dialog.headline.text() == "Connected to the tribe, but not everything has arrived yet"
    ipam.tribe_synced.emit()  # The next try worked
    assert dialog.states[NETWORKS] == DONE and dialog.headline.text() == "Connected to the tribe"


def test_cancelling_while_the_server_is_asked(app, server, joining, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(tribe_join_dialog.TeamClient, "status", lambda self: release.wait(10) and {})
    dialog, window = joining()
    thread = dialog.thread
    dialog.reject()
    assert dialog.thread is None and not window.saved
    release.set()
    assert thread.wait(5000)
