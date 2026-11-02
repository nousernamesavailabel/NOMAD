"""Telling a tribe server older than this NOMAD from one that's fine, and recommending the update, against a real
server made to report an older API level."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402
from test_ipam_server import key_for  # noqa: E402

from nomad import __version__  # noqa: E402
from nomad.ipam import server as server_module  # noqa: E402
from nomad.ipam.client import LOCK_API, NETWORK_API, SERVER_FEATURES, TeamKey, server_update  # noqa: E402
from nomad.ipam.server import ADMIN, API_LEVEL, IpamServer  # noqa: E402
from nomad.ui import tribe_version  # noqa: E402
from nomad.ui.tribe_version import TribeUpdateBanner  # noqa: E402


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


def status(api, version="1.36.0", name="CORE1"):
    return {"server_id": "s", "name": name, "version": version, "api": api}


def test_only_a_server_below_this_nomads_api_level_needs_updating():
    assert server_update(status(API_LEVEL)) is None
    assert server_update(status(API_LEVEL + 5, version="9.0.0")) is None  # Newer than NOMAD needs: fine
    update = server_update(status(API_LEVEL - 1))
    assert (update.name, update.version, update.api) == ("CORE1", "1.36.0", API_LEVEL - 1)


def test_the_recommendation_names_the_server_and_the_version_to_update_to():
    summary = server_update(status(NETWORK_API - 1)).summary
    assert summary.startswith("The tribe server CORE1 is running NOMAD 1.36.0 (Tribe API 14)")
    assert f"Update the server to NOMAD {__version__} or newer" in summary


def test_what_the_update_brings_is_only_what_the_server_lacks():
    assert server_update(status(LOCK_API)).missing == ["sharing a whole network with a map"]
    assert "locked map icons" in server_update(status(LOCK_API - 1)).missing


def test_steps_differ_on_the_server_itself():
    update = server_update(status(LOCK_API))
    assert f"Copy NOMAD {__version__} or newer to the tribe server" in update.steps()
    assert "Copy NOMAD" not in update.steps(on_server=True)
    assert "Update Service" in update.steps(on_server=True)


def test_a_server_too_old_to_give_its_level_or_version_still_needs_updating():
    update = server_update({"server_id": "s"})
    assert update.api == 1 and "(Tribe API 1)" in update.summary and "an older NOMAD" in update.summary
    assert update.summary.startswith("The tribe server is running")


def test_every_api_level_says_what_it_brought():
    """A new API_LEVEL needs its line in SERVER_FEATURES, or the recommendation leaves it out."""
    assert [level for level, _ in SERVER_FEATURES] == list(range(2, API_LEVEL + 1))


@pytest.fixture
def banners(app):
    made = []

    def make(key_loader):
        banner = TribeUpdateBanner(key_loader)
        made.append(banner)
        return banner

    yield make
    for banner in made:
        banner.stop()
        banner.deleteLater()
    app.processEvents()


def needs_update(banner):
    return banner.update_needed is not None


def test_the_banner_recommends_updating_an_older_server(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    banner = banners(lambda: key_for(server))
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    assert banner.isVisibleTo(None) and f"NOMAD {__version__} or newer" in banner.label.text()
    assert not banner.on_server


def test_no_banner_for_a_server_as_new_or_newer(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL + 3)
    banner = banners(lambda: key_for(server))
    banner.check()
    thread = banner.checker.thread
    thread.join(10)  # It's done, rather than asking again
    assert not thread.is_alive()
    app.processEvents()
    assert not needs_update(banner) and not banner.isVisibleTo(None)


def test_no_tribe_key_means_nothing_to_check(app, banners):
    banner = banners(lambda: None)
    banner.check()
    thread = banner.checker.thread
    thread.join(10)
    assert not thread.is_alive() and not banner.isVisibleTo(None)


def test_a_server_out_of_reach_is_asked_again_until_it_answers(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    monkeypatch.setattr(tribe_version, "RETRY_SECONDS", 0.05)
    real = key_for(server)
    key = TeamKey(real.server_id, ["127.0.0.1"], 1, real.fingerprint, real.secret)
    banner = banners(lambda: key)
    banner.check()
    time.sleep(0.2)
    app.processEvents()
    assert not needs_update(banner)
    key.port = real.port
    assert wait_for(app, lambda: needs_update(banner))


def test_the_banner_goes_once_the_server_is_updated(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    monkeypatch.setattr(tribe_version, "RECHECK_SECONDS", 0.05)
    banner = banners(lambda: key_for(server))
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL)
    assert wait_for(app, lambda: not banner.isVisibleTo(None))
    assert not needs_update(banner)


def test_dismissed_it_stays_away_until_the_server_changes(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 2)
    monkeypatch.setattr(tribe_version, "RECHECK_SECONDS", 0.05)
    banner = banners(lambda: key_for(server))
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    banner.dismiss_button.click()
    assert not banner.isVisibleTo(None)
    time.sleep(0.2)
    app.processEvents()
    assert not banner.isVisibleTo(None)  # Asked again: the same news
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    assert wait_for(app, lambda: banner.isVisibleTo(None))  # Updated, but not far enough


def test_focus_mode_hides_it_and_brings_it_back(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    banner = banners(lambda: key_for(server))
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    banner.set_focused(True)
    assert not banner.isVisibleTo(None)
    banner.set_focused(False)
    assert banner.isVisibleTo(None)


def test_checking_again_forgets_the_old_tribes_answer(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    keys = [key_for(server)]
    banner = banners(lambda: keys[0])
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    keys[0] = None  # Left the tribe
    banner.check()
    assert not needs_update(banner) and not banner.isVisibleTo(None)


def test_on_the_server_itself_the_steps_say_so(app, server, banners, monkeypatch):
    monkeypatch.setattr(server_module, "API_LEVEL", API_LEVEL - 1)
    key = key_for(server)
    key.role = ADMIN
    banner = banners(lambda: key)
    banner.check()
    assert wait_for(app, lambda: needs_update(banner))
    assert banner.on_server
