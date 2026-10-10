"""Watching for new devices and tribe maps on the Network Map page."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from netmap_fakes import build_network  # noqa: E402
from PyQt5.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402
from test_netmap_tab import Window  # noqa: E402
from test_netmap_watch import NEW_PC, plug_in_switch, renumber_acc1, renumbered_network, rtr1_answers  # noqa: E402

from nomad.netmap import export, store, watch  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, Crawler  # noqa: E402
from nomad.snmpv3 import V3User  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.netmap_tribe import TribeSync  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait_for(app, condition, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    return False


def make_tab(network, tmp_path, monkeypatch, tribe=None):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    page.resize(1200, 800)
    page.overrides = [("10.0.0.12/32", "secret")]
    page.watcher.client_factory = network.client
    page.watcher.crawl = lambda network_map, options, seeds, should_stop: watch.crawl_from(
        network_map, options, seeds, network.client, network.ping, network.echo, should_stop)
    page.watcher.listen_check.setChecked(False)  # Not port 514 in tests
    if tribe is not None:
        page.tribe.shutdown()
        page.tribe = tribe
        tribe.synced.connect(page.on_tribe_synced)
        tribe.status_changed.connect(page.update_tribe_label)
    return page


def crawl(network):
    return Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")], trace=False),
                   client_factory=network.client, pinger=network.ping, echo=network.echo).run()


def idle(page):
    watcher = page.watcher
    return watcher.signature_thread is None and watcher.refresh_thread is None and \
        watcher.recheck_thread is None and not watcher.to_refresh


def test_watching_adds_a_new_switch_tagged_new(app, tmp_path, monkeypatch):
    network = build_network()
    page = make_tab(network, tmp_path, monkeypatch)
    try:
        page.on_crawled(crawl(network))
        page.watch_check.setChecked(True)
        assert page.watcher.running
        assert wait_for(app, lambda: idle(page) and page.watcher.last_neighbors)
        assert page.network_map.news == {}  # Nothing new on a fresh map
        plug_in_switch(network)
        page.watcher.poll_neighbors()
        assert wait_for(app, lambda: "acc3" in page.network_map.devices and idle(page))
        assert "device:acc3" in page.network_map.news and f"host:{NEW_PC}" in page.network_map.news
        assert page.view.items_by_key["acc3"].news_text == "NEW"
        assert page.view.items_by_key["acc3"].news_text and page.view.new_hosts == {NEW_PC}
        column = export.DEVICE_COLUMNS.index("New")
        new_rows = [page.devices_table.item(row, 0).text() for row in range(page.devices_table.rowCount())
                    if page.devices_table.item(row, column).text()]
        assert new_rows == ["acc3.corp.example"]
        assert "1 new" not in page.watch_label.text() and "new" in page.watch_label.text()
        assert any("New device: acc3" in line for line in page.watcher.lines)
        saved = store.load(page.map_path)
        assert "device:acc3" in saved.news  # Saved with the map
        page.mark_seen(page.news_of_devices(["acc3"]))
        assert page.network_map.news == {} and page.view.items_by_key["acc3"].news_text == ""
    finally:
        page.shutdown()


def test_watching_follows_a_switch_to_its_new_address(app, tmp_path, monkeypatch):
    network = renumbered_network()
    page = make_tab(network, tmp_path, monkeypatch)
    try:
        page.on_crawled(crawl(network))
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: idle(page) and page.watcher.last_neighbors)
        renumber_acc1(network)
        page.watcher.poll_neighbors()
        assert wait_for(app, lambda: page.network_map.devices["acc1"].mgmt_ip == "10.18.0.11" and idle(page))
        assert any("doesn't answer at 10.0.0.11 any more but does at 10.18.0.11" in line
                   for line in page.watcher.lines)
        assert store.load(page.map_path).devices["acc1"].mgmt_ip == "10.18.0.11"  # Saved
    finally:
        page.shutdown()


def test_triggered_switch_is_read_after_the_delay(app, tmp_path, monkeypatch):
    network = build_network()
    page = make_tab(network, tmp_path, monkeypatch)
    try:
        page.on_crawled(crawl(network))
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: idle(page) and page.watcher.last_neighbors)
        plug_in_switch(network)
        page.watcher.queue.delay = 0
        from nomad.syslog import parse_message
        page.watcher.on_syslog(parse_message("<189>53: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed "
                                             "state to up", "10.0.0.11"))
        page.watcher.on_syslog(parse_message("<189>53: hello", "10.9.9.9"))
        page.watcher.tick()
        assert wait_for(app, lambda: "acc3" in page.network_map.devices and idle(page))
        assert any("port GigabitEthernet1/0/7 up: reading it" in line for line in page.watcher.lines)
    finally:
        page.shutdown()


# --------------------------------------------------------------------- Tribe maps through a real server

@pytest.fixture
def server(tmp_path):
    from nomad.ipam.server import IpamServer
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def tribe_for(server, tmp_path, user):
    from nomad.ipam.client import TeamClient
    from nomad.netmap.tribe import TribeMaps
    from test_ipam_server import key_for
    key = key_for(server)
    return TribeSync(key_loader=lambda: key, maps_factory=lambda key: TribeMaps(
        key.server_id, TeamClient(key, user=user, computer=user.upper()), tmp_path / f"{user}-maps.db"))


def test_tribe_map_shared_between_two_pages(app, server, tmp_path, monkeypatch):
    network = build_network()
    alice = make_tab(network, tmp_path / "a", monkeypatch, tribe_for(server, tmp_path, "alice"))
    bob = make_tab(network, tmp_path / "b", monkeypatch, tribe_for(server, tmp_path, "bob"))
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    try:
        alice.communities = ["public", "s3cret"]
        alice.v3_users = [V3User("nomad", "sha", "authpass1", "aes128", "privpass1")]
        alice.on_crawled(crawl(network))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        alice.share_with_tribe()
        assert alice.tribe_map_id is not None and alice.map_path is None
        assert "Tribe map HQ" in alice.tribe_label.text()

        maps = bob.tribe.ensure()
        assert wait_for(app, lambda: [item["name"] for item in maps.maps()] == ["HQ"])
        bob.open_tribe_map(maps.maps()[0]["id"])
        assert set(bob.network_map.devices) == set(alice.network_map.devices)
        assert bob.communities == ["public", "s3cret"]  # The map's community strings came with it
        assert bob.v3_users == alice.v3_users  # And its SNMPv3 users

        # Alice changes the credentials: Bob's page uses them without opening the map again
        alice.communities = ["n3w"]
        alice.credentials_changed()
        assert "Shared the SNMP credentials" in alice.status_label.text()
        assert wait_for(app, lambda: bob.communities == ["n3w"], 15)
        assert "changed this map's SNMP credentials" in bob.status_label.text()

        # Bob moves a device; Alice sees it
        bob.view.items_by_key["core"].setPos(1234, 567)
        bob.save_positions()
        assert wait_for(app, lambda: tuple(alice.network_map.positions.get("core", ())) == (1234.0, 567.0), 15)
        assert alice.view.items_by_key["core"].pos().x() == 1234

        # Watching on Alice's computer found something: Bob sees it tagged NEW
        alice.network_map.news["device:acc1"] = {"when": "2026-10-02T10:00:00", "where": "", "by": "x"}
        alice.write_map(alice.network_map, None)
        assert wait_for(app, lambda: "device:acc1" in bob.network_map.news, 15)
        assert bob.view.items_by_key["acc1"].news_text == "NEW"

        # Deleted by Alice: Bob keeps a copy as a file
        monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
        alice.delete_tribe_map()
        assert alice.tribe_map_id is None and alice.map_path is not None
        assert wait_for(app, lambda: bob.tribe_map_id is None, 15)
        assert bob.map_path is not None and "deleted" in bob.status_label.text()
    finally:
        alice.shutdown()
        bob.shutdown()



def test_tribe_map_groups_collapsed_on_each_page_alone(app, server, tmp_path, monkeypatch):
    network = build_network()
    alice = make_tab(network, tmp_path / "a", monkeypatch, tribe_for(server, tmp_path, "alice"))
    bob = make_tab(network, tmp_path / "b", monkeypatch, tribe_for(server, tmp_path, "bob"))
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    try:
        crawled = crawl(network)
        site = crawled.new_group("HQ")
        crawled.set_group(["core", "acc1"], site.key)
        alice.on_crawled(crawled)
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        alice.share_with_tribe()
        maps = bob.tribe.ensure()
        assert wait_for(app, lambda: [item["name"] for item in maps.maps()] == ["HQ"])
        bob.open_tribe_map(maps.maps()[0]["id"])

        # Alice collapses the site: nothing to send, so Bob's stays open
        alice.view.set_collapsed(alice.view.group_items[site.key], True)
        assert alice.tribe.maps.pending_count() == 0 and not alice.save_timer.isActive()

        # Bob moves a device: Alice sees it, with her site still collapsed
        bob.view.items_by_key["core"].setPos(1234, 567)
        bob.save_positions()
        assert wait_for(app, lambda: tuple(alice.network_map.positions.get("core", ())) == (1234.0, 567.0), 15)
        assert alice.view.group_items[site.key].group.collapsed
        assert not bob.view.group_items[site.key].group.collapsed
    finally:
        alice.shutdown()
        bob.shutdown()



def test_tribe_map_save_waiting_doesnt_undo_anothers_move(app, server, tmp_path, monkeypatch):
    network = build_network()
    alice = make_tab(network, tmp_path / "a", monkeypatch, tribe_for(server, tmp_path, "alice"))
    bob = make_tab(network, tmp_path / "b", monkeypatch, tribe_for(server, tmp_path, "bob"))
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    try:
        alice.on_crawled(crawl(network))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        alice.share_with_tribe()
        maps = bob.tribe.ensure()
        assert wait_for(app, lambda: [item["name"] for item in maps.maps()] == ["HQ"])
        bob.open_tribe_map(maps.maps()[0]["id"])

        # Alice drags a device; before her save is due, Bob's move of another arrives
        alice.view.items_by_key["acc1"].setPos(-300, 800)
        alice.save_timer.setInterval(60000)
        alice.save_timer.start()
        bob.view.items_by_key["core"].setPos(1234, 567)
        bob.save_positions()
        assert wait_for(app, lambda: tuple(alice.network_map.positions.get("core", ())) == (1234.0, 567.0), 15)
        assert alice.network_map.positions["acc1"] == (-300.0, 800.0)  # Hers saved on the way, not lost
        assert wait_for(app, lambda: tuple(bob.network_map.positions.get("acc1", ())) == (-300.0, 800.0), 15)
        assert bob.network_map.positions["core"] == (1234.0, 567.0)  # And his not undone
    finally:
        alice.shutdown()
        bob.shutdown()

def test_watching_stands_by_while_another_computer_watches(app, server, tmp_path, monkeypatch):
    network = build_network()
    page = make_tab(network, tmp_path, monkeypatch, tribe_for(server, tmp_path, "alice"))
    try:
        page.on_crawled(crawl(network))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        page.share_with_tribe()
        bobs_sync = tribe_for(server, tmp_path, "bob")
        other = bobs_sync.ensure()
        assert other.lease(page.tribe_map_id, "bob-service", kind="service")["yours"]
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: page.watcher.standing_by)
        assert "BOB" in page.watcher.standing_by and "service" in page.watcher.standing_by
        assert "watched by" in page.watch_label.text()
        other.lease(page.tribe_map_id, "bob-service", release=True)
        page.watcher.lease_checked = 0
        page.watcher.tick()
        assert wait_for(app, lambda: not page.watcher.standing_by)
        bobs_sync.shutdown()
    finally:
        page.shutdown()


def test_tribe_server_uses_its_own_key_for_maps(app, server, tmp_path, monkeypatch):
    """NOMAD on the tribe server (as administrator) uses the server's admin key, as the IP Addresses page does."""
    from nomad.ipam import client
    from nomad.ipam.client import admin_key
    key = admin_key(server.directory)
    key.port = server.port
    monkeypatch.setattr(client, "admin_key", lambda: key)
    monkeypatch.setattr(client, "load_saved_key", lambda: None)
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    window = Window()
    window.admin = True
    page = netmap_tab.NetworkMapTab(window)
    page.tribe.maps_factory = lambda key: __import__("nomad.netmap.tribe", fromlist=["TribeMaps"]).TribeMaps(
        key.server_id, client.TeamClient(key, user="admin", computer="SRV"), tmp_path / "server-maps.db")
    try:
        assert page.tribe_key() is key
        page.fill_tribe_menu()
        texts = [action.text() for action in page.tribe_menu.actions()]
        assert "This computer is the tribe server" in texts and "Connect to the Tribe with Another Key File..." not in texts
        page.on_crawled(crawl(build_network()))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("Server's map", True))
        page.share_with_tribe()
        assert page.tribe_map_id is not None
        window.admin = False  # Not as administrator: no key, and the menu says why and offers to join
        monkeypatch.setattr(netmap_tab, "is_tribe_server", lambda: True)
        page.tribe_key_changed()
        assert page.tribe_map_id is None and page.map_path is not None  # Kept as a file
        page.fill_tribe_menu()
        texts = [action.text() for action in page.tribe_menu.actions()]
        assert texts[0].startswith("This is the tribe server: restart NOMAD as administrator")
        assert "Connect to the Tribe with a Key File..." in texts
    finally:
        page.shutdown()


def test_joining_the_tribe_from_the_map_page(app, server, tmp_path, monkeypatch):
    from nomad.ipam import client
    from nomad.ui import tribe_join_dialog
    from nomad.ui.tribe_join_dialog import MAPS, QFileDialog, JoinTribeDialog
    from test_ipam_server import key_for
    saved = []
    monkeypatch.setattr(client, "load_saved_key", lambda: saved[-1] if saved else None)
    monkeypatch.setattr(tribe_join_dialog, "save_key", saved.append)
    monkeypatch.setattr(tribe_join_dialog, "read_key_file", lambda path: key_for(server))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args, **kwargs: ("tribe.nomadkey", ""))
    monkeypatch.setattr(netmap_tab, "is_tribe_server", lambda: False)  # This PC may have the IPAM service
    shown = []
    monkeypatch.setattr(JoinTribeDialog, "exec_", lambda dialog: shown.append(dialog) or wait_for(
        app, lambda: dialog.saved and not dialog.working()))
    page = make_tab(build_network(), tmp_path, monkeypatch)
    page.tribe.maps_factory = lambda key: __import__("nomad.netmap.tribe", fromlist=["TribeMaps"]).TribeMaps(
        key.server_id, client.TeamClient(key, user="carol"), tmp_path / "carol-maps.db")
    notified = []
    page.window.ipam_tab = None
    page.window.netmap_tab = page
    page.window.tribe_key_changed = lambda origin=None: (notified.append(origin), page.tribe_key_changed())
    try:
        page.fill_tribe_menu()
        assert [action.text() for action in page.tribe_menu.actions()] == ["Connect to the Tribe with a Key File..."]
        page.join_tribe()
        assert saved and notified == [None] and "Connected to the tribe" in page.status_label.text()
        assert shown[0].states[MAPS] == "done"  # The dialog followed the map page's first sync
        assert page.tribe.maps is not None
        page.fill_tribe_menu()
        texts = [action.text() for action in page.tribe_menu.actions()]
        assert "Connect to the Tribe with Another Key File..." in texts
        assert not any("Leave" in text or "Disconnect" in text for text in texts)  # Only in Tools > Tribe Management
    finally:
        page.shutdown()


def test_new_credentials_have_devices_that_dont_answer_asked_again(app, tmp_path, monkeypatch):
    from nomad.snmpv3 import V3User
    user = V3User("nomad", "sha", "authpass1", "aes128", "privpass1")
    network = build_network()
    page = make_tab(network, tmp_path, monkeypatch)
    try:
        page.on_crawled(crawl(network))
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: idle(page) and page.watcher.last_neighbors)
        assert any("Asked the device that doesn't answer SNMP again: none do yet" in line
                   for line in page.watcher.lines)
        rtr1_answers(network, communities=(), v3_users=(user,))  # Set up with an SNMPv3 user
        assert page.add_credential(user)  # The map gets the user: rtr1 is asked at once
        assert wait_for(app, lambda: page.network_map.devices["rtr1"].source == "snmp" and idle(page))
        assert any("rtr1.corp.example answers SNMP now (v3 user nomad (SHA-1, AES-128)): reading it" in line
                   for line in page.watcher.lines)
        assert store.load(page.map_path).devices["rtr1"].source == "snmp"
    finally:
        page.shutdown()


def test_the_watch_timers_can_be_set(app, tmp_path, monkeypatch):
    from PyQt5.QtCore import QSettings
    network = build_network()
    page = make_tab(network, tmp_path, monkeypatch)
    try:
        page.on_crawled(crawl(network))
        page.watcher.timers.set_values({"neighbor_interval": 120, "host_interval": 1800, "recheck_interval": 900,
                                        "trigger_delay": 10})
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: idle(page) and page.watcher.last_neighbors)
        watcher = page.watcher
        assert (watcher.neighbor_timer.interval(), watcher.host_timer.interval(), watcher.recheck_timer.interval(),
                watcher.queue.delay) == (120000, 1800000, 900000, 10)
        assert "asked again every 15 min" in watcher.summary_label.text()
        settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
        page.save_settings(settings)
        other = make_tab(network, tmp_path, monkeypatch)
        other.restore_settings(settings)
        assert other.watcher.timers.values() == watcher.timers.values()
        other.shutdown()
    finally:
        page.shutdown()


class IdleCrawl:
    """Stands in for the crawl thread: notes what map it was to add to, and does nothing."""

    def __init__(self, started, known):
        started.append(known)
        self.event = self.crawled = self.failed = self.finished = self

    def connect(self, *args):
        pass

    def start(self):
        pass


def answer_with(monkeypatch, label):
    """Have the next question box answered by clicking the button labeled label."""
    def click(box):
        next(button for button in box.buttons() if button.text().replace("&", "") == label).click()
        return 0
    monkeypatch.setattr(QMessageBox, "exec_", click)


def test_start_on_a_tribe_map_can_make_a_new_map_instead(app, server, tmp_path, monkeypatch):
    network = build_network()
    (tmp_path / "a").mkdir()
    page = make_tab(network, tmp_path / "a", monkeypatch, tribe_for(server, tmp_path, "alice"))
    try:
        page.on_crawled(crawl(network))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        page.share_with_tribe()
        map_id = page.tribe_map_id
        before = page.tribe.maps.items(map_id)
        page.seeds_input.setText("10.0.0.1")

        answer_with(monkeypatch, "Cancel")
        page.start()
        assert page.worker is None and page.tribe_map_id == map_id  # Nothing started, still the tribe map

        answer_with(monkeypatch, "New Map")
        started = []
        monkeypatch.setattr(netmap_tab, "CrawlThread", lambda settings, known, parent: IdleCrawl(started, known))
        page.start()
        assert started == [None]  # A crawl started, from scratch
        assert page.tribe_map_id is None and page.network_map is None
        page.worker = None
        page.on_crawled(crawl(network))  # What it found: a map file of its own
        assert page.map_path is not None and page.tribe_map_id is None
        assert page.tribe.maps.items(map_id) == before  # The tribe map as it was
    finally:
        page.shutdown()


def test_monitor_and_watch_are_remembered_as_soon_as_they_are_ticked(app, tmp_path, monkeypatch):
    from PyQt5.QtCore import QSettings
    network = build_network()
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    pages = []

    def page_with_settings():
        page = make_tab(network, tmp_path, monkeypatch)
        page.window.settings = settings
        page.monitor.pinger = lambda address: True
        pages.append(page)
        return page

    try:
        page = page_with_settings()
        page.on_crawled(crawl(network))
        page.monitor_check.setChecked(True)
        page.watch_check.setChecked(True)
        # Noted straight away: NOMAD closed by Windows restarting has them on again when it starts
        assert settings.value("netmap/monitor", False, bool) and settings.value("netmap/watch", False, bool)
        page.shutdown()
        again = page_with_settings()
        again.restore_settings(settings)
        assert again.monitor_check.isChecked() and again.watch_check.isChecked()
        assert again.monitor.running and again.watcher.running
        assert settings.value("netmap/watch", False, bool)  # Turning them back on didn't forget either
        again.watch_check.setChecked(False)
        assert not settings.value("netmap/watch", True, bool) and settings.value("netmap/monitor", False, bool)
        again.watch_check.setChecked(True)
        again.shutdown()

        # The map open last time isn't there this time: they stay off, but are still on for when it is
        settings.setValue("netmap/last_map", str(tmp_path / "away.nomadmap"))
        missing = page_with_settings()
        missing.restore_settings(settings)
        assert not missing.monitor_check.isChecked() and not missing.watch_check.isChecked()
        missing.save_settings(settings)
        assert settings.value("netmap/monitor", False, bool) and settings.value("netmap/watch", False, bool)
    finally:
        for page in pages:
            page.shutdown()


def test_a_page_freed_after_watching_a_tribe_map_leaves_nothing_to_crash_qt(app, server, tmp_path, monkeypatch):
    # Watching a tribe map claims the watching, and stopping gives it up, each on a thread. Their finished signals,
    # still waiting to be delivered when the page (and so the threads) was freed, used to crash Qt once delivered:
    # they went to lambdas
    import gc
    network = build_network()
    gc.disable()  # So the page and everything in it are freed together, by the collection below
    try:
        page = make_tab(network, tmp_path, monkeypatch, tribe_for(server, tmp_path, "alice"))
        page.on_crawled(crawl(network))
        monkeypatch.setattr(QInputDialog, "getText", lambda *args, **kwargs: ("HQ", True))
        page.share_with_tribe()
        page.watch_check.setChecked(True)
        assert wait_for(app, lambda: page.watcher.active and page.watcher.lease_thread is None)
        page.watcher.lease_checked = 0
        page.watcher.tick()  # Claimed again, as every so often
        page.watch_check.setChecked(False)  # And given up
        assert page.watcher.lease_thread is not None and page.watcher.releasing
        page.shutdown()
        del page
        gc.collect()
        app.processEvents()  # What the threads said as they finished: dropped with the page, not delivered
    finally:
        gc.enable()
