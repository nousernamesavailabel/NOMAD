"""Right-click > Tools > Find switch port: the host's MAC (or its address) searched for on the MAC Finder page."""
import ipaddress
import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMenu, QVBoxLayout, QWidget  # noqa: E402

from nomad.ipam.store import USED, IpamStore  # noqa: E402
from nomad.netmap import store as map_store  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, Crawler  # noqa: E402
from nomad.netmap.model import ROUTER, SWITCH  # noqa: E402
from nomad.snapshot import NetworkSnapshot  # noqa: E402
from nomad.sweep import SweepHit  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.host_menu import FIND_PORT, TOOLS, HostActions  # noqa: E402
from nomad.ui.ipam_tab import LOCAL, IpamTab, SweepResults  # noqa: E402
from nomad.ui.sweep_tab import SweepTab  # noqa: E402

from netmap_fakes import build_network  # noqa: E402

MAC = "aabb.ccdd.eeff"
FORMATTED = "AA-BB-CC-DD-EE-FF"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    """Stands in for the main window: the pages only call it for other pages."""
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        for name in ("terminal_tab", "scp_tab"):
            page = Mock()
            page.saved_matches.return_value = []
            setattr(self, name, page)

    def current_adapter(self):
        return None

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def entries(menu):
    """{label: action} for menu and its submenus."""
    found = {}
    for action in menu.actions():
        found[action.text()] = action
        if action.menu() is not None:
            found.update(entries(action.menu()))
    return found


def menu_window():
    window = Mock()
    for name in ("terminal_tab", "scp_tab", "rdp_tab"):
        getattr(window, name).saved_matches.return_value = []
    return window


def tools_of(menu):
    return next(action.menu() for action in menu.actions() if action.text() == TOOLS)


def choose_find(window, host, **kwargs):
    menu = QMenu()
    actions = HostActions(window, None).add_to(menu, host, **kwargs)
    action = next(action for action in actions if action.text() == FIND_PORT)
    assert action in tools_of(menu).actions()
    actions[action]()
    menu.deleteLater()


# ----------------------------------------------------------------- The menu entry

def test_in_tools_after_capture_traffic(app):
    menu = QMenu()
    HostActions(menu_window(), None).add_to(menu, "10.0.0.5", mac=MAC)
    labels = [action.text() for action in tools_of(menu).actions()]
    assert labels[labels.index("Capture Traffic...") + 1] == FIND_PORT
    menu.deleteLater()


def test_searches_by_the_mac_when_the_page_knows_it(app):
    window = menu_window()
    choose_find(window, "10.0.0.5", mac=MAC)
    window.navigator.setCurrentWidget.assert_called_once_with(window.mac_finder_tab)
    window.mac_finder_tab.find_switch_port.assert_called_once_with(FORMATTED)


@pytest.mark.parametrize("mac", ["", "not a mac", "aa:bb:cc"])
def test_searches_by_the_address_without_a_mac(app, mac):
    window = menu_window()
    choose_find(window, "10.0.0.5", mac=mac)
    window.mac_finder_tab.find_switch_port.assert_called_once_with("10.0.0.5")


def test_an_ipv6_scope_is_dropped(app):
    window = menu_window()
    choose_find(window, "fe80::1%12")
    window.mac_finder_tab.find_switch_port.assert_called_once_with("fe80::1")


def test_left_out_when_asked_or_without_mac_finder(app):
    menu = QMenu()
    HostActions(menu_window(), None).add_to(menu, "10.0.0.5", mac=MAC, leave_out=(FIND_PORT,))
    assert FIND_PORT not in entries(menu)
    window = menu_window()
    window.mac_finder_tab = None
    other = QMenu()
    HostActions(window, None).add_to(other, "10.0.0.5", mac=MAC)
    assert FIND_PORT not in entries(other) and "Ping" in entries(other)
    menu.deleteLater()
    other.deleteLater()


# ----------------------------------------------------------------- The pages that know a host's MAC

@pytest.fixture
def chosen(monkeypatch):
    """Picks Find switch port from whatever menu opens; the (host, mac) it was asked for."""
    calls = []
    monkeypatch.setattr(HostActions, "find_switch_port", lambda self, host, mac="": calls.append((host, mac)))
    monkeypatch.setattr(QMenu, "exec_", lambda menu, *args: entries(menu).get(FIND_PORT))
    return calls


def test_sweep_results_pass_the_mac(app, chosen):
    window = Window()
    window.snapshot = NetworkSnapshot()
    page = SweepTab(window)
    page.add_host("10.0.0.5", SweepHit(3, FORMATTED))
    page.add_host("10.0.0.6", SweepHit(None))
    page.resize(900, 500)
    page.show()
    app.processEvents()
    for row in (page.row_for("10.0.0.5"), page.row_for("10.0.0.6")):
        page.show_context_menu(page.table.visualItemRect(page.table.item(row, 0)).center())
    assert chosen == [("10.0.0.5", FORMATTED), ("10.0.0.6", "")]
    page.close()
    page.deleteLater()


@pytest.fixture
def ipam(app, tmp_path):
    store = IpamStore(str(tmp_path / "find.db"), user="tester")
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.0/24", "LAN")
    store.set_address(network.id, "10.0.0.5", USED, "blank", "")
    store.set_address(network.id, "10.0.0.6", USED, "kept", "AA-AA-AA-AA-AA-AA")
    window = Window()
    layout = QVBoxLayout(window)
    tab = IpamTab(window)
    layout.addWidget(tab)
    tab.local_store, tab.source, tab.network_id = store, LOCAL, network.id
    tab.fill_tree()
    tab.tree.setCurrentItem(tab.tree.topLevelItem(0))
    tab.show_subnet()
    window.resize(1400, 700)
    window.show()
    app.processEvents()
    yield tab
    window.close()
    window.deleteLater()
    store.close()


def right_click_address(tab, address):
    row = next(row for row in range(tab.model.rowCount()) if tab.model.data(tab.model.index(row, 0)) == address)
    tab.address_menu(tab.table.visualRect(tab.model.index(row, 0)).center())


def test_ipam_passes_the_recorded_mac_else_the_swept_one(ipam, chosen):
    right_click_address(ipam, "10.0.0.5")
    right_click_address(ipam, "10.0.0.6")
    assert chosen == [("10.0.0.5", ""), ("10.0.0.6", "AA-AA-AA-AA-AA-AA")]
    results = SweepResults()
    results.found("10.0.0.5", 3, "BB-BB-BB-BB-BB-BB")
    results.found("10.0.0.6", 3, "CC-CC-CC-CC-CC-CC")
    ipam.model.sweep = results
    chosen.clear()
    right_click_address(ipam, "10.0.0.5")
    right_click_address(ipam, "10.0.0.6")
    assert chosen == [("10.0.0.5", "BB-BB-BB-BB-BB-BB"), ("10.0.0.6", "AA-AA-AA-AA-AA-AA")]  # IPAM's own wins
    assert ipaddress.ip_address("10.0.0.5") in results.hosts


@pytest.fixture
def map_tab(app, tmp_path, monkeypatch):
    monkeypatch.setattr(map_store, "maps_dir", lambda: tmp_path)
    network = build_network()
    crawled = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                      client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    page = netmap_tab.NetworkMapTab(Window())
    page.resize(1200, 800)
    page.on_crawled(crawled)
    yield page
    page.shutdown()


def test_map_hosts_pass_their_mac(map_tab, chosen):
    index, host = next((index, host) for index, host in enumerate(map_tab.network_map.hosts) if host.ip and host.mac)
    row = next(row for row in range(map_tab.hosts_table.rowCount())
               if map_tab.hosts_table.item(row, 0).data_object == index)
    map_tab.show_hosts_table_menu(map_tab.hosts_table.visualItemRect(map_tab.hosts_table.item(row, 0)).center())
    assert chosen == [(host.ip, host.mac)]
    chosen.clear()
    on_port = [item for item in map_tab.network_map.hosts_by_port(host.device).get(host.port, [])]
    map_tab.show_port_menu(host.device, host.port, None)
    assert chosen == ([(host.ip, host.mac)] if len(on_port) == 1 and on_port[0].ip else [])


def test_not_on_the_map_menus_of_switches_and_routers(map_tab, chosen, monkeypatch):
    shown = []
    monkeypatch.setattr(QMenu, "exec_", lambda menu, *args: shown.append(set(entries(menu))))
    for key, device in map_tab.network_map.devices.items():
        if device.mgmt_ip and device.kind in (SWITCH, ROUTER):
            map_tab.show_device_menu(key, None)
    assert shown and all("Ping" in labels and FIND_PORT not in labels for labels in shown)
