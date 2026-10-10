"""The Network Map page: showing a crawled map, finding things on it, the tables, exports and settings."""
import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from netmap_fakes import LAB_MACS, PC1_MAC, build_network  # noqa: E402
from PyQt5.QtCore import QRectF, QSettings, Qt, pyqtSignal  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMenu, QWidget  # noqa: E402

from nomad.netmap import export, store  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, Crawler  # noqa: E402
from nomad.netmap.layout import NODE_WIDTH  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.netmap_view import DeviceItem, HostPortItem, LinkItem  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    """Stands in for the main window."""
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)

    def current_adapter(self):
        return None

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


@pytest.fixture
def crawled():
    network = build_network()
    return Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                   client_factory=network.client, pinger=network.ping,
                   echo=network.echo).run()


@pytest.fixture
def tab(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    page.resize(1200, 800)
    yield page
    page.shutdown()


def test_showing_a_map(tab, crawled, tmp_path):
    tab.on_crawled(crawled)
    items = tab.view.scene().items()
    assert sum(isinstance(item, DeviceItem) for item in items) == 5
    assert sum(isinstance(item, LinkItem) for item in items) == 4
    assert tab.devices_table.rowCount() == 5
    assert tab.links_table.rowCount() == 4
    assert tab.hosts_table.rowCount() == len(crawled.hosts)
    assert tab.map_path is not None and tab.map_path.parent == tmp_path  # Saved automatically
    assert "Done: 5 devices" in tab.status_label.text()
    device_items = {item.device.key: item for item in items if isinstance(item, DeviceItem)}
    for key in device_items:  # No two devices on top of each other
        for other in device_items:
            if key < other:
                a, b = device_items[key].pos(), device_items[other].pos()
                assert (a - b).manhattanLength() > 50


@pytest.mark.parametrize("focus_widget", ["view", "find_input", "devices_table"])
def test_escape_clears_vlan_highlight(tab, crawled, focus_widget):
    tab.setParent(None)
    tab.on_crawled(crawled)
    tab.highlight_vlan(10)
    tab.show()
    if focus_widget == "devices_table":
        tab.tabs.setCurrentWidget(tab.devices_table)
    widget = getattr(tab, focus_widget)
    widget.setFocus()
    QApplication.processEvents()
    assert tab.view.vlan_focus is not None
    assert tab.vlan_bar.isVisible()

    QTest.keyClick(widget, Qt.Key_Escape)

    assert tab.vlan_shown is None
    assert tab.view.vlan_focus is None
    assert not tab.vlan_bar.isVisible()
    tab.hide()


def test_escape_cancels_link_drawing_before_clearing_vlan(tab, crawled):
    tab.setParent(None)
    tab.on_crawled(crawled)
    tab.highlight_vlan(10)
    tab.show()
    assert tab.view.start_drawing("acc1")
    QApplication.processEvents()

    QTest.keyClick(tab.view, Qt.Key_Escape)

    assert tab.view.drawing is None
    assert tab.vlan_shown == (10, None)
    QTest.keyClick(tab.view, Qt.Key_Escape)
    assert tab.vlan_shown is None
    assert tab.view.vlan_focus is None
    tab.hide()


def test_finding_a_host_opens_its_switch(tab, crawled):
    tab.on_crawled(crawled)
    assert tab.view.find(PC1_MAC.replace("-", ":").lower())
    selected = tab.view.scene().selectedItems()
    assert len(selected) == 1 and isinstance(selected[0], HostPortItem) and selected[0].port == "Gi1/0/5"
    assert "Gi1/0/5" in tab.details.toPlainText()
    assert tab.view.find("pa-fw")
    assert "Firewall" in tab.details.toPlainText()
    assert not tab.view.find("no-such-thing")


def test_find_steps_through_every_match(tab, crawled):
    tab.on_crawled(crawled)
    matches = tab.view.find_matches("10.")
    devices = [key for kind, key, _ in matches if kind == "device"]
    assert len(devices) > 1 and len(matches) > len(devices)  # Devices first, then hosts
    tab.find_input.setText("10.")
    shown = []
    for _ in matches:
        tab.find()
        shown.append(tab.view.last_found[1])
        assert f"{len(shown)} of {len(matches)}" in tab.status_label.text()
    assert shown == matches  # Each once, in order
    tab.find()
    assert tab.view.last_found[1] == matches[0]  # Round to the first again
    tab.find(backward=True)
    assert tab.view.last_found[1] == matches[-1]  # And back round to the last
    tab.find_input.setText("10.10")  # Different text starts again from the first
    tab.find()
    assert tab.view.last_found[1] == tab.view.find_matches("10.10")[0]
    tab.find_input.setText("10.")
    tab.find(select_all=True)
    selected = [item for item in tab.view.scene().selectedItems() if isinstance(item, DeviceItem)]
    assert len(selected) == len(devices) and f"Selected {len(devices)} devices" in tab.status_label.text()


def test_expanding_hosts_and_shared_ports(tab, crawled):
    tab.on_crawled(crawled)
    acc2 = tab.view.items_by_key["acc2"]
    assert acc2.host_count == len(LAB_MACS)
    tab.view.toggle_hosts(acc2)
    assert [item.port for item in acc2.port_items] == ["Eth1/10"]
    tab.view.toggle_hosts(acc2)
    assert acc2.port_items == []


def test_port_labels_clear_the_hosts_badge(tab, crawled):
    tab.on_crawled(crawled)
    acc2, core = tab.view.items_by_key["acc2"], tab.view.items_by_key["core"]
    link = next(link for link in acc2.links if core in (link.a_item, link.b_item))
    for dx in (0, 60, -120):  # Straight below, then off to each side
        acc2.setPos(0, 0)
        core.setPos(dx, 400)
        badge = acc2.mapRectToScene(acc2.badge)
        point = link.label_point(link.a_item is acc2)
        label = QRectF(0, 0, 60, 16)
        label.moveCenter(point)
        assert not label.intersects(badge)
    acc2.setPos(0, 0)
    core.setPos(400, 0)  # Off to the side the badge doesn't matter: the label stays just past the box
    assert link.label_point(link.a_item is acc2).x() == pytest.approx(NODE_WIDTH / 2 + 26)


def test_dragged_positions_are_saved_and_kept_after_recrawl(tab, crawled):
    tab.on_crawled(crawled)
    tab.view.items_by_key["core"].setPos(5000, 5000)
    tab.save_positions()
    reloaded = store.load(tab.map_path)
    assert reloaded.positions["core"] == (5000, 5000)
    network = build_network()
    again = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                    client_factory=network.client, pinger=network.ping,
                   echo=network.echo).run()
    tab.on_crawled(again)
    assert tab.view.items_by_key["core"].pos().x() == 5000


def test_exports(tab, crawled, tmp_path):
    tab.on_crawled(crawled)
    image = tab.view.render_image(scale=1)
    assert image.width() > 300 and image.height() > 100
    svg = tmp_path / "map.svg"
    tab.view.render_svg(svg)
    assert "<svg" in svg.read_text(encoding="utf-8")


def test_settings_round_trip(tab, tmp_path, app):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.seeds_input.setText("10.0.0.1")
    tab.communities, tab.overrides = ["public", "backup"], [("10.20.0.0/16", "secret")]
    tab.scope, tab.max_hops = ["10.0.0.0/8"], 3
    tab.save_settings(settings)
    settings.sync()
    assert "secret" not in (tmp_path / "settings.ini").read_text(encoding="utf-8", errors="replace")
    other = netmap_tab.NetworkMapTab(Window())
    other.restore_settings(settings)
    assert other.seeds_input.text() == "10.0.0.1"
    assert other.communities == ["public", "backup"] and other.overrides == [("10.20.0.0/16", "secret")]
    assert other.scope == ["10.0.0.0/8"] and other.max_hops == 3


def test_v3_users_saved_encrypted_and_tried_in_order(tab, tmp_path, app):
    from nomad.snmpv3 import V3User
    user = V3User("nomad", "sha256", "authpass1", "aes256", "privpass1")
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.communities, tab.v3_users, tab.v3_first = ["public"], [user], False
    tab.overrides = [("10.20.0.0/16", user)]
    tab.save_settings(settings)
    settings.sync()
    assert "privpass1" not in (tmp_path / "settings.ini").read_text(encoding="utf-8", errors="replace")
    other = netmap_tab.NetworkMapTab(Window())
    other.restore_settings(settings)
    assert other.v3_users == [user] and other.overrides == [("10.20.0.0/16", user)] and not other.v3_first
    assert other.credentials() == ["public", user]
    assert other.crawl_settings(["10.0.0.1"]).communities == ["public", user]
    assert other.snmp_access("10.20.1.1")[0] == user
    other.v3_first = True
    assert other.watch_options().communities == [user, "public"]
    assert other.add_credential("fresh") and other.communities[0] == "fresh"
    renamed = V3User("nomad", "sha", "authpass2", "aes128", "privpass2")
    assert other.add_credential(renamed) and other.v3_users == [renamed]
    assert other.overrides == [("10.20.0.0/16", renamed)]  # The subnet's user is the new one
    assert not other.add_credential(renamed)


def test_device_details_list_links_and_hosts(crawled):
    text = netmap_tab.device_html(crawled, "acc1")
    assert "Te1/1/1" in text and "core.corp.example" in text
    assert "SEP00AABBCCDDEE" in text


def test_logical_view(tab, crawled):
    tab.on_crawled(crawled)
    keys = set(tab.l3_view.items_by_key)
    assert {"core", "pa-fw1", "rtr1", "net:10.0.0.0/24", "net:10.10.0.0/24", "hop:10.0.0.253", "self"} <= keys
    tab.tabs.setCurrentWidget(tab.l3_view)
    tab.find_input.setText("10.10.0.0")
    tab.find()
    text = tab.details.toPlainText()
    assert "Hosts on the map (3)" in text and "core.corp.example" in text
    assert tab.l3_view.find("10.99.0.1")
    assert "10.50.0.1" in tab.details.toPlainText()  # The trace that found it
    assert "Routes" in netmap_tab.device_html(crawled, "core")


def test_logical_drawio_export(tab, crawled, tmp_path, monkeypatch):
    tab.on_crawled(crawled)
    tab.tabs.setCurrentWidget(tab.l3_view)
    target = tmp_path / "logical.drawio"
    monkeypatch.setattr(tab, "export_path", lambda *args: target)
    tab.export_drawio()
    text = target.read_text(encoding="utf-8")
    assert "10.10.0.0/24" in text and "dashed=1" in text


def test_compare_with_an_older_map(tab, crawled, tmp_path):
    import copy
    older = copy.deepcopy(crawled)
    del older.devices["acc2"]
    older.links = [link for link in older.links if "acc2" not in (link.a, link.b)]
    older.hosts = [host for host in older.hosts if host.device != "acc2"]
    older_path = store.save(older, tmp_path / "older.nomadmap")
    tab.on_crawled(crawled)
    tab.compare_with(older_path)
    dialog = tab.compare_dialog
    assert dialog is not None and dialog.table.rowCount() >= 2  # The device and its link (hosts hidden)
    assert tab.view.items_by_key["acc2"].highlight is not None
    assert tab.view.items_by_key["core"].highlight is None
    dialog.churn_check.setChecked(True)
    assert dialog.table.rowCount() == 2 + len(LAB_MACS)
    dialog.close()
    assert tab.view.items_by_key["acc2"].highlight is None


def test_scope_dialog_values(app):
    from nomad.ui.netmap_dialogs import ScopeDialog
    dialog = ScopeDialog(["10.0.0.0/8"], 4, 100, True, False, 24)
    assert dialog.values() == (["10.0.0.0/8"], 4, 100, True, False, 24)


def test_host_dialog_checks_what_is_entered(tab, crawled):
    from nomad.ui.netmap_dialogs import HostDialog
    dialog = HostDialog(crawled, device="acc1", port="GigabitEthernet1/0/20")
    dialog.name_input.setText("label-printer")
    dialog.mac_input.setText("00:11:22:33:44:55")
    dialog.vlan_input.setValue(10)
    host = dialog.values()
    assert (host.device, host.port, host.mac, host.vlan, host.manual) == \
        ("acc1", "Gi1/0/20", "00-11-22-33-44-55", 10, True)
    dialog.mac_input.setText("not a mac")
    with pytest.raises(ValueError, match="isn't a MAC"):
        dialog.values()
    dialog.mac_input.setText(PC1_MAC)
    with pytest.raises(ValueError, match="already on the map"):
        dialog.values()
    dialog.mac_input.setText("")
    dialog.ip_input.setText("10.10.0.300")
    with pytest.raises(ValueError, match="isn't an IP"):
        dialog.values()
    dialog.ip_input.setText("")
    dialog.name_input.setText("")
    with pytest.raises(ValueError, match="at least"):
        dialog.values()
    assert "Gi1/0/5" in [dialog.port_combo.itemText(index) for index in range(dialog.port_combo.count())]


def test_adding_and_deleting_hosts(tab, crawled, monkeypatch):
    from nomad.netmap.model import Host
    from PyQt5.QtWidgets import QMessageBox
    tab.on_crawled(crawled)
    before = len(crawled.hosts)
    printer = Host(mac="", device="acc1", port="Gi1/0/20", ip="10.10.0.50", name="old-printer", manual=True)
    crawled.hosts.append(printer)
    tab.map_changed(printer)
    assert tab.hosts_table.rowCount() == before + 1
    assert "Gi1/0/20" in [item.port for item in tab.view.items_by_key["acc1"].port_items]  # Opened to show it
    assert any(host.name == "old-printer" and host.manual for host in store.load(tab.map_path).hosts)

    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    lab = [host for host in crawled.hosts if host.mac in LAB_MACS]
    tab.delete_hosts(lab)
    assert tab.hosts_table.rowCount() == before + 1 - len(LAB_MACS)
    assert tab.view.items_by_key["acc2"].host_count == 0
    assert not any(host.mac in LAB_MACS for host in store.load(tab.map_path).hosts)


def test_hand_added_hosts_survive_mapping_again(tab, crawled):
    from nomad.netmap.model import Host
    tab.on_crawled(crawled)
    crawled.hosts.append(Host(mac="", device="acc1", port="Gi1/0/20", ip="10.10.0.50", name="old-printer",
                              manual=True))
    crawled.hosts.append(Host(mac=PC1_MAC, device="acc1", port="Gi1/0/9", name="reception-pc", manual=True,
                              note="Moved?"))
    crawled.hosts.append(Host(mac="", device="gone-switch", port="Gi0/1", name="orphan", manual=True))
    network = build_network()
    again = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                    client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    tab.on_crawled(again)
    hosts = tab.network_map.hosts
    assert [host.name for host in hosts if host.manual] == ["old-printer"]
    found = next(host for host in hosts if host.mac == PC1_MAC)
    assert (found.port, found.name, found.note, found.manual) == ("Gi1/0/5", "reception-pc", "Moved?", False)
    assert "1 host added by hand wasn't kept" in tab.status_label.text()


def test_live_map_and_progress_while_crawling(tab):
    network = build_network()
    events = []
    final = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                    client_factory=network.client, pinger=network.ping, echo=network.echo,
                    events=lambda kind, *details: events.append((kind, details))).run()
    tab.crawl_progress.start()
    tab.worker = object()  # As if crawling
    started = next(index for index, (kind, _) in enumerate(events) if kind == "started")
    tab.on_crawl_event(*events[started])
    tab.crawl_progress.refresh()
    assert tab.crawl_progress.reading_table.rowCount() == 1
    assert tab.crawl_progress.reading_table.item(0, 0).text() == "10.0.0.1"
    first_map = next(index for index, (kind, _) in enumerate(events) if kind == "map")
    for kind, details in events[started + 1:first_map + 1]:
        tab.on_crawl_event(kind, details)
    assert "core" in tab.view.items_by_key  # Drawn before the crawl is done
    assert tab.network_map is None and tab.displayed_map() is tab.live_map
    tab.view.items_by_key["core"].setPos(4000, 4000)  # Dragged while it crawls
    for kind, details in events[first_map + 1:]:
        tab.on_crawl_event(kind, details)
    tab.crawl_progress.refresh()
    assert tab.crawl_progress.reading_table.rowCount() == 0
    assert tab.crawl_progress.counts_label.text().startswith("Traceroute to 3 addresses")  # The last phase
    tab.on_crawled(final)
    tab.worker = None
    tab.on_thread_finished()
    assert tab.network_map is final and tab.view.items_by_key["core"].pos().x() == 4000
    log_text = "\n".join(tab.crawl_progress.lines)
    assert "Found acc1.corp.example (10.0.0.11) through CDP" in log_text and "Finished in" in log_text
    assert not tab.crawl_progress.row.isVisible()
    assert all(item.highlight is None for item in tab.view.items_by_key.values())


def test_progress_text():
    from nomad.ui.netmap_progress import counts_text, duration, estimate
    counts = {"read": 10, "reading": 8, "queued": 22, "found": 60, "no_snmp": 2, "unreachable": 0}
    assert estimate(counts, 60) == "about 3 min left so far"  # 30 left at 12 a minute
    assert estimate(dict(counts, read=2), 60) == ""  # Too soon to tell
    text = counts_text(counts, 75)
    assert text.startswith("Read 10  ·  reading 8  ·  queued 22  ·  60 found  ·  2 ping but no SNMP  ·  1:15")
    assert duration(3725) == "1:02:05"


def test_hosts_hidden_until_asked_for_with_vlans(tab, crawled):
    from nomad.ui.netmap_view import host_line
    tab.on_crawled(crawled)
    assert not tab.hosts_check.isChecked()
    assert all(not item.port_items for item in tab.view.items_by_key.values())  # Hidden by default
    tab.hosts_check.setChecked(True)
    shown = {key for key, item in tab.view.items_by_key.items() if item.port_items}
    assert shown == {"acc1", "acc2"}
    gi5 = next(item for item in tab.view.items_by_key["acc1"].port_items if item.port == "Gi1/0/5")
    assert sorted(host_line(host) for host in gi5.hosts) == [("10.10.0.21", "VLAN 10"),
                                                             ("SEP00AABBCCDDEE  10.10.0.22", "VLAN 10")]
    tab.hosts_check.setChecked(False)
    assert all(not item.port_items for item in tab.view.items_by_key.values())


def test_selecting_several_devices(tab, crawled, app):
    from PyQt5.QtCore import Qt
    from PyQt5.QtTest import QTest
    tab.on_crawled(crawled)
    QTest.keyClick(tab.view, Qt.Key_A, Qt.ControlModifier)
    assert len(tab.view.scene().selectedItems()) == 5
    assert "5 selected" in tab.details.toPlainText()
    # Moving one of a selection moves them all (Qt's own behavior for selected movable items)
    assert all(item.flags() & item.ItemIsMovable for item in tab.view.items_by_key.values())


def show_in_labels(tab, key):
    from PyQt5.QtWidgets import QMenu
    menu, actions = QMenu(), {}
    tab.add_show_in(menu, actions, key)
    return {action.text(): run for action, run in actions.items()}


def test_show_in_other_tabs(tab, crawled):
    tab.on_crawled(crawled)
    tab.tabs.setCurrentWidget(tab.view)
    choices = show_in_labels(tab, "core")
    assert list(choices) == ["Logical (L3)", "Devices", "Links"]  # Show In: not the tab showing

    choices["Links"]()
    assert tab.tabs.currentWidget() is tab.links_table
    rows = sorted({index.row() for index in tab.links_table.selectionModel().selectedRows()})
    assert len(rows) == 4  # Every link of the core
    assert "Links" not in show_in_labels(tab, "core")

    show_in_labels(tab, "acc2")["Devices"]()
    assert tab.tabs.currentWidget() is tab.devices_table
    selected = tab.devices_table.selectionModel().selectedRows()
    assert len(selected) == 1 and tab.devices_table.item(selected[0].row(), 0).text() == "acc2"

    show_in_labels(tab, "core")["Logical (L3)"]()
    assert tab.tabs.currentWidget() is tab.l3_view
    assert [item.key for item in tab.l3_view.scene().selectedItems()] == ["core"]
    assert "Logical (L3)" not in show_in_labels(tab, "acc2")  # No IP interfaces: not on the L3 view

    show_in_labels(tab, "rtr1")["Physical (L2)"]()
    assert tab.tabs.currentWidget() is tab.view
    assert [item.key for item in tab.view.scene().selectedItems()] == ["rtr1"]


def test_device_menu_groups_like_items(tab, crawled, monkeypatch):
    for name in ("terminal_tab", "scp_tab"):
        page = Mock()
        page.saved_matches.return_value = []
        setattr(tab.window, name, page)
    tab.on_crawled(crawled)
    keys = sorted(crawled.devices)
    for key in keys[:2]:
        tab.view.items_by_key[key].setSelected(True)
    shown = []
    monkeypatch.setattr(QMenu, "exec_", lambda menu, *args: shown.append(
        {action.text(): action.menu() for action in menu.actions() if not action.isSeparator()}))
    tab.show_device_menu(keys[0], None)
    entries = shown[-1]
    assert len(entries) <= 16  # Fits on the screen (it was over 40 entries)
    assert {"Connect", "Tools", "Show In", "Group", "Layout", "Edit", "Copy Name", "Copy Address"} <= set(entries)
    assert "Copy IP Address" not in entries and "Show on Map" not in entries  # Copy Address, Show In
    assert "Delete 2 Devices..." in [action.text() for action in entries["Edit"].actions()]


def test_links_table_shows_both_ends(tab, crawled):
    tab.on_crawled(crawled)
    row = next(row for row in range(tab.links_table.rowCount()) if tab.links_table.item(row, 2).text() == "acc2")
    assert set(tab.links_table.item(row, 0).data_object) == {"core", "acc2"}
    tab.show_in(tab.view, list(tab.links_table.item(row, 0).data_object))
    assert {item.key for item in tab.view.scene().selectedItems()} == {"core", "acc2"}


def test_filtering_the_hosts_table(tab, crawled, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox
    tab.on_crawled(crawled)
    vlan_column = 6
    hosts_filter = tab.table_filters[tab.hosts_table]
    hosts_filter.set_filter(vlan_column, {"30"})
    visible = [row for row in range(tab.hosts_table.rowCount()) if not tab.hosts_table.isRowHidden(row)]
    assert len(visible) == 5
    assert tab.tabs.tabText(tab.tabs.indexOf(tab.hosts_table)) == f"Hosts (5 of {len(crawled.hosts)})"

    tab.hosts_table.selectAll()  # Ctrl+A also selects rows a filter hides: they mustn't be deleted
    assert len(tab.selected_table_hosts()) == 5
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    tab.delete_hosts(tab.selected_table_hosts())
    assert len(tab.network_map.hosts) == len(crawled.hosts) and len(crawled.hosts) > 0
    assert not any(host.vlan == 30 for host in tab.network_map.hosts)
    assert tab.tabs.tabText(tab.tabs.indexOf(tab.hosts_table)).startswith("Hosts (0 of")  # Kept after refilling

    hosts_filter.clear()
    assert tab.tabs.tabText(tab.tabs.indexOf(tab.hosts_table)) == "Hosts"


def test_show_in_clears_a_filter_hiding_the_row(tab, crawled):
    tab.on_crawled(crawled)
    tab.table_filters[tab.devices_table].set_filter(export.DEVICE_COLUMNS.index("Kind"), {"Firewall"})
    tab.show_in(tab.devices_table, ["core"])
    assert not tab.table_filters[tab.devices_table].active
    selected = tab.devices_table.selectionModel().selectedRows()
    assert tab.devices_table.item(selected[0].row(), 0).text() == "core.corp.example"


def test_tables_start_a_to_z(tab, crawled):
    tab.on_crawled(crawled)
    names = [tab.devices_table.item(row, 0).text() for row in range(tab.devices_table.rowCount())]
    assert names == sorted(names, key=str.lower)


def drag(view, start, end, modifiers=None):
    """Press, move and release the left button on the view, as a real drag does (QTest.mouseMove can't hold a
    button down in Qt 5)."""
    from PyQt5.QtCore import QEvent, QPointF, Qt
    from PyQt5.QtGui import QMouseEvent
    from PyQt5.QtWidgets import QApplication
    modifiers = modifiers if modifiers is not None else Qt.NoModifier
    viewport = view.viewport()
    for kind, point, buttons in ((QEvent.MouseButtonPress, start, Qt.LeftButton),
                                 (QEvent.MouseMove, (start + end) / 2, Qt.LeftButton),
                                 (QEvent.MouseMove, end, Qt.LeftButton),
                                 (QEvent.MouseButtonRelease, end, Qt.NoButton)):
        QApplication.sendEvent(viewport, QMouseEvent(kind, QPointF(point), Qt.LeftButton, buttons, modifiers))


def test_shift_drag_selects_and_plain_drag_moves_the_view(tab, crawled, app):
    from PyQt5.QtCore import QPoint, Qt
    tab.on_crawled(crawled)
    tab.show()
    tab.tabs.setCurrentWidget(tab.view)
    view = tab.view
    view.resetTransform()
    for _ in range(3):
        app.processEvents()
    view.centerOn(view.items_by_key["core"])
    core = view.mapFromScene(view.items_by_key["core"].pos())
    start, end = QPoint(core.x() - 120, core.y() - 60), QPoint(core.x() + 120, core.y() + 60)

    before = (view.horizontalScrollBar().value(), view.verticalScrollBar().value())
    drag(view, start, end)
    assert view.scene().selectedItems() == []  # A plain drag moves the view, it doesn't select
    assert (view.horizontalScrollBar().value(), view.verticalScrollBar().value()) != before

    view.centerOn(view.items_by_key["core"])
    core = view.mapFromScene(view.items_by_key["core"].pos())
    start, end = QPoint(core.x() - 120, core.y() - 60), QPoint(core.x() + 120, core.y() + 60)
    drag(view, start, end, Qt.ShiftModifier)
    assert "core" in {item.key for item in view.scene().selectedItems() if hasattr(item, "key")}
    assert view.dragMode() == view.ScrollHandDrag  # Back to moving the view afterwards
    tab.hide()


def test_find_box_is_local_to_each_sub_tab(tab, crawled):
    tab.on_crawled(crawled)
    tab.tabs.setCurrentWidget(tab.hosts_table)
    assert "Filter the hosts" in tab.find_input.placeholderText()
    tab.find_input.setText("52-54-00-00-00-0")
    visible = [row for row in range(tab.hosts_table.rowCount()) if not tab.hosts_table.isRowHidden(row)]
    assert len(visible) == len(LAB_MACS)
    tab.tabs.setCurrentWidget(tab.devices_table)
    assert tab.find_input.text() == ""  # Its own box
    tab.find_input.setText("pa-fw")
    assert sum(not tab.devices_table.isRowHidden(row) for row in range(tab.devices_table.rowCount())) == 1
    tab.tabs.setCurrentWidget(tab.hosts_table)
    assert tab.find_input.text() == "52-54-00-00-00-0"  # Back as it was
    assert tab.tabs.tabText(tab.tabs.indexOf(tab.hosts_table)).startswith(f"Hosts ({len(LAB_MACS)} of")
    tab.tabs.setCurrentWidget(tab.view)
    assert "Find a device" in tab.find_input.placeholderText() and tab.find_input.text() == ""


def test_find_in_the_crawl_log(tab):
    tab.crawl_progress.add_log("Found acc1 through CDP")
    tab.crawl_progress.add_log("Found acc2 through CDP")
    tab.tabs.setCurrentWidget(tab.crawl_progress.tab)
    assert tab.find_input.isEnabled()
    tab.find_input.setText("acc2")
    tab.find()
    assert tab.crawl_progress.log_view.textCursor().selectedText() == "acc2"
    assert tab.crawl_progress.find("acc2")  # Goes round to the top again


def test_ctrl_f_goes_to_the_page_showing():
    from nomad.ui.main_window import MainWindow

    class Page:
        found = False

        def focus_find(self):
            self.found = True

    class Navigator:
        def __init__(self, page):
            self.page = page

        def currentWidget(self):
            return self.page

    class Window:
        statuses = []

        def show_status(self, *args):
            self.statuses.append(args[0])

    window, page = Window(), Page()
    window.navigator = Navigator(page)
    MainWindow.focus_find(window)
    assert page.found
    window.navigator = Navigator(object())
    MainWindow.focus_find(window)
    assert window.statuses == ["This page has nothing to search."]


def test_monitoring_the_map(tab, crawled):
    from nomad.netmap.monitor import DOWN, UP
    answers = {"10.0.0.1": 3, "10.0.0.11": 5, "10.0.0.12": 2, "10.0.0.5": 1, "10.0.0.254": None}
    tab.monitor.pinger = answers.get
    tab.on_crawled(crawled)
    status_column = export.DEVICE_COLUMNS.index("Status")
    assert tab.devices_table.item(0, status_column).text() == ""  # Not monitored yet
    tab.monitor_check.setChecked(True)
    assert tab.monitor.running
    def poll():  # As a poll returns them: by device
        tab.monitor.on_results({key: answers[address] for key, address in tab.monitor.targets.items()})
    for _ in range(2):  # rtr1 must miss twice before it counts as down
        poll()
    assert tab.monitor.status("core").status == UP and tab.monitor.status("rtr1").status == DOWN
    assert tab.view.items_by_key["core"].monitor_state.rtt == 3
    assert tab.view.items_by_key["rtr1"].monitor_state.status == DOWN
    assert tab.l3_view.items_by_key["rtr1"].monitor_state.status == DOWN  # Both views
    statuses = {tab.devices_table.item(row, 0).text(): tab.devices_table.item(row, status_column).text()
                for row in range(tab.devices_table.rowCount())}
    assert statuses["rtr1.corp.example"] == "Down" and statuses["core.corp.example"] == "Up"
    assert tab.monitor_label.text() == "4 up · 1 down"
    assert "rtr1.corp.example (10.0.0.254) is down" in "\n".join(tab.monitor.lines)
    assert not any("is up" in line for line in tab.monitor.lines)  # First answers aren't news
    assert tab.network_map.status_log[-1][1:4] == ["rtr1", "rtr1.corp.example", DOWN]

    answers["10.0.0.254"] = 9
    poll()
    assert "is up again, after being down" in tab.monitor.lines[-1]
    assert "Up, 9 ms" in netmap_tab.device_html(crawled, "rtr1", tab.monitor.status("rtr1"))

    tab.monitor_check.setChecked(False)
    assert tab.view.items_by_key["core"].monitor_state is None and tab.monitor_label.text() == ""
    tab.save_positions()
    assert len(store.load(tab.map_path).status_log) == 2  # Down and up again, kept with the map


def test_monitoring_resumes_at_startup(tab, crawled, tmp_path):
    tab.on_crawled(crawled)
    tab.monitor.pinger = lambda address: 1
    tab.monitor_check.setChecked(True)
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.save_settings(settings)
    other = netmap_tab.NetworkMapTab(Window())
    other.monitor.pinger = lambda address: 1
    other.restore_settings(settings)
    assert other.monitor_check.isChecked() and other.monitor.running
    other.shutdown()


def test_crawl_from_here_updates_the_map_open(tab, tmp_path):
    network = build_network()
    first = Crawler(CrawlSettings(seeds=["10.0.0.1"], scope=["10.0.0.0/30"], trace=False),
                    client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    tab.on_crawled(first)
    path, maps = tab.map_path, sorted(tmp_path.glob("*.nomadmap"))
    tab.view.items_by_key["core"].setPos(3000, 3000)
    tab.save_positions()

    tab.extending = True  # As crawl_from sets it
    network = build_network()
    newer = Crawler(CrawlSettings(seeds=["10.0.0.11"], trace=False), client_factory=network.client,
                    pinger=network.ping, echo=network.echo, known=tab.network_map).run()
    tab.on_crawled(newer)
    assert tab.network_map is first and tab.map_path == path  # The same map, in the same file
    assert sorted(tmp_path.glob("*.nomadmap")) == maps  # No new map saved
    assert tab.network_map.devices["acc1"].source == "snmp"
    assert tab.view.items_by_key["core"].pos().x() == 3000  # Left where it was
    assert store.load(path).devices["acc1"].source == "snmp"
    assert "added 0 devices to this map (1 read over SNMP for the first time)" in tab.status_label.text()


def test_session_hints_for_a_device(tab, crawled):
    tab.on_crawled(crawled)
    network_map = tab.network_map
    device = next(device for device in network_map.devices.values() if device.name and device.interfaces_l3)
    site = network_map.new_group("HQ")
    building = network_map.new_group("Main / North", netmap_tab.BUILDING, site.key)
    network_map.set_group([device.key], building.key)
    hints = tab.session_hints(network_map, device)
    assert hints["folder"] == "HQ/Main - North"
    assert hints["name"] and hints["name"] in hints["aliases"]
    assert device.interfaces_l3[0][0] in hints["aliases"]


def test_new_map_leaves_the_one_open_as_it_was(tab, crawled):
    tab.on_crawled(crawled)
    first = tab.map_path
    tab.view.items_by_key["core"].setPos(4321, 0)
    tab.save_timer.start()  # A move waiting to be saved
    tab.new_map()
    assert tab.network_map is None and tab.map_path is None and tab.view.items_by_key == {}
    assert tab.devices_table.rowCount() == 0 and not tab.new_button.isEnabled()
    assert "New map" in tab.status_label.text()
    assert store.load(first).positions["core"] == (4321, 0)  # Saved as it was left
    tab.on_crawled(crawled)  # Mapped again (the same minute): a file of its own
    assert tab.map_path != first and first.exists()
    assert store.load(first).positions["core"] == (4321, 0)


def test_the_map_open_is_remembered_straight_away(tab, crawled, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.window.settings = settings
    tab.on_crawled(crawled)
    assert settings.value("netmap/last_map") == str(tab.map_path)  # Before NOMAD closes
    other = netmap_tab.NetworkMapTab(Window())
    other.restore_settings(settings)
    assert other.map_path == tab.map_path and set(other.network_map.devices) == set(crawled.devices)
    tab.new_map()
    assert settings.value("netmap/last_map") == ""


def test_a_map_that_could_not_be_reopened_is_still_the_one_to_reopen(tab, crawled, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    missing = tmp_path / "gone.nomadmap"
    settings.setValue("netmap/last_map", str(missing))
    tab.restore_settings(settings)
    assert tab.network_map is None and "wasn't opened" in tab.status_label.text()
    tab.save_settings(settings)
    assert settings.value("netmap/last_map") == str(missing)  # Not forgotten for not being there this once
    tab.on_crawled(crawled)
    tab.save_settings(settings)
    assert settings.value("netmap/last_map") == str(tab.map_path)  # Until another map is opened


def test_spacing_is_remembered(tab, crawled, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.on_crawled(crawled)
    tab.set_spacing("roomy")
    tab.save_settings(settings)
    other = netmap_tab.NetworkMapTab(Window())
    try:
        other.restore_settings(settings)
        assert other.arrange_spacing == "roomy"
        settings.setValue("netmap/arrange_spacing", "sideways")
        other.restore_settings(settings)
        assert other.arrange_spacing == "normal"
    finally:
        other.shutdown()


def top(widget):
    """How far down the page a widget is."""
    return widget.mapTo(widget.window(), widget.rect().topLeft()).y()


@pytest.mark.parametrize("compact", [True, False])
def test_monitor_and_watch_news_dont_squeeze_the_find_box(tab, crawled, compact):
    tab.set_compact_top(compact)
    tab.on_crawled(crawled)
    tab.resize(1600, 800)
    tab.window.show()  # The page shows inside it
    try:
        tab.show_summary(tab.monitor_label, "5 up")
        tab.show_summary(tab.watch_label, "nothing new")
        QApplication.processEvents()
        width = tab.find_input.width()
        for monitoring, watching in (("120 up · 14 down · 3 checking", "watched by ALICE-PC (the Map Watcher service)"),
                                     ("5 up", "watched by ALICE-PC (the Map Watcher service)"),
                                     ("120 up · 14 down · 3 checking", "nothing new")):
            tab.show_summary(tab.monitor_label, monitoring)
            tab.show_summary(tab.watch_label, watching)
            QApplication.processEvents()
            assert tab.find_input.width() == width  # The same room whatever they say
        assert tab.watch_label.toolTip() == tab.watch_label.text() or not compact  # The whole of it, cut short
    finally:
        tab.window.hide()


def test_compact_top_bar(tab, crawled):
    tab.window.show()  # The page shows inside it
    try:
        assert tab.compact_top  # The default
        QApplication.processEvents()
        assert tab.crawl_row.isVisible() and not tab.crawl_button.isEnabled()  # No map: where to start is showing
        tab.on_crawled(crawled)
        QApplication.processEvents()
        assert not tab.crawl_row.isVisible() and tab.crawl_button.isEnabled()
        assert tab.map_button.isVisible() and not tab.new_button.isVisible() and not tab.tribe_button.isVisible()
        middles = [top(widget) + widget.height() / 2 for widget in (tab.map_button, tab.monitor_check,
                                                                     tab.find_input, tab.arrange_button)]
        assert max(middles) - min(middles) < 4  # One row
        tab.crawl_button.setChecked(True)  # To map again, or from another switch
        assert tab.crawl_row.isVisible()
        tab.crawl_button.setChecked(False)
        assert not tab.crawl_row.isVisible()
        message = "A long message. " * 60
        netmap_tab.set_hint(tab.status_label, message, "info")
        QApplication.processEvents()
        assert tab.status_label.text() == message and tab.status_label.toolTip() == message
        assert tab.status_label.height() < 2 * tab.status_label.fontMetrics().height()  # One line
        compact_height = top(tab.tabs)

        tab.set_compact_top(False)  # The classic bar, as it was
        QApplication.processEvents()
        assert tab.crawl_row.isVisible() and tab.new_button.isVisible() and not tab.map_button.isVisible()
        assert top(tab.crawl_row) < top(tab.new_button) < top(tab.find_input)
        assert tab.status_label.height() > 2 * tab.status_label.fontMetrics().height()  # Wrapped
        assert top(tab.tabs) > compact_height + 60
        tab.set_compact_top(True)
        QApplication.processEvents()
        assert tab.map_button.isVisible() and not tab.new_button.isVisible() and top(tab.tabs) == compact_height
    finally:
        tab.window.hide()


def test_map_menu_does_what_the_map_buttons_do(tab, crawled, monkeypatch):
    tab.on_crawled(crawled)
    tab.update_map_menu()
    entries = {action.text(): action for action in tab.map_menu.actions() if not action.isSeparator()}
    assert list(entries) == ["Crawl: Start From, Gateway, Start, Stop", "New Map", "Open...", "Recent", "Save As...", "Export", "Compare", "IPAM Network...",
                             "Record in IPAM...", "SNMP Credentials...", "Scope...", "Tribe", "Key"]
    assert all(action.isEnabled() for action in entries.values())
    from PyQt5 import sip
    kept = [tab.crawl_action] + [entry for entry, _ in tab.map_entries]
    assert all(sip.ispycreated(item) for item in kept)  # Ones Qt made would outlive the menu as stale wrappers
    recent = entries["Recent"].menu()
    recent.aboutToShow.emit()
    assert recent.actions() and [action.text() for action in recent.actions()] == \
        [action.text() for action in tab.recent_menu.actions()]
    export = entries["Export"].menu()
    export.aboutToShow.emit()
    assert "Picture (PNG)..." in [action.text() for action in export.actions()]
    called = []
    monkeypatch.setattr(tab, "new_map", lambda quiet=False: called.append("new"))
    entries["New Map"].trigger()
    assert called == ["new"]
    monkeypatch.setattr(netmap_tab.CommunitiesDialog, "exec_", lambda dialog: called.append("credentials"))
    monkeypatch.setattr(netmap_tab.ScopeDialog, "exec_", lambda dialog: called.append("scope"))
    assert not tab.crawl_row.isVisibleTo(tab)  # Compact, with a map: the crawl row is put away...
    entries["SNMP Credentials..."].trigger()
    entries["Scope..."].trigger()  # ...but its settings are still in the Map menu
    assert called == ["new", "credentials", "scope"]
    crawl = entries["Crawl: Start From, Gateway, Start, Stop"]
    assert not crawl.isChecked()
    crawl.trigger()  # The crawl row, without finding the Crawl button
    assert tab.crawl_row.isVisibleTo(tab) and tab.crawl_button.isChecked()
    tab.update_map_menu()
    assert crawl.isChecked()
    crawl.trigger()
    assert not tab.crawl_row.isVisibleTo(tab)
    monkeypatch.undo()
    tab.new_map()
    tab.update_map_menu()
    assert not entries["Save As..."].isEnabled() and not entries["Export"].isEnabled()
    assert entries["Open..."].isEnabled()


def test_top_bar_choice_is_remembered(tab, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    tab.set_compact_top(False)
    tab.save_settings(settings)
    other = netmap_tab.NetworkMapTab(Window())
    try:
        assert other.compact_top
        other.restore_settings(settings)
        assert not other.compact_top and other.new_button.parent() is not other.spare
    finally:
        other.shutdown()


def test_watch_news_use_the_room_monitor_news_leave(tab, crawled):
    tab.on_crawled(crawled)
    long_news = "watched by ALICE-PC (the Map Watcher service)"
    tab.show_summary(tab.watch_label, long_news)
    alone = tab.watch_label.width()  # Its own share: cut short
    assert tab.watch_label.fontMetrics().horizontalAdvance(long_news) > alone
    tab.show_summary(tab.monitor_label, "5 up")
    assert tab.monitor_label.width() < tab.monitor_label.fontMetrics().horizontalAdvance("999 up · 99 down")
    assert tab.watch_label.width() > alone  # And what Monitor's short news leave
    assert tab.status_slack.width() == 0
    tab.show_summary(tab.watch_label, "")  # Only monitoring: what its news don't use is kept, not given away
    assert tab.status_slack.width() > 0
    tab.set_compact_top(False)
    assert tab.status_slack.parent() is tab.spare and tab.monitor_label.maximumWidth() > 10000
