"""The IP Addresses page: selecting each kind of subnet shows it without errors, and SSH/SCP to an address."""
import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import Qt, QTimer  # noqa: E402
from PyQt5.QtGui import QContextMenuEvent  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMenu, QTreeWidgetItemIterator, QVBoxLayout, QWidget  # noqa: E402

from nomad.ipam.store import USED, IpamStore  # noqa: E402
from nomad.terminal.sessions import Session  # noqa: E402
from nomad.ui.ipam_tab import LOCAL, IpamTab  # noqa: E402
from nomad.ui.host_menu import HostActions  # noqa: E402
from nomad.ui.ip_menu import IpContextMenus  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    """Stands in for the main window: the page only calls it for other pages and the busy indicator."""

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def test_selecting_each_subnet(app, tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.0/24", "LAN", gateway="10.0.0.1")
    store.add_subnet(network.id, "10.0.1.0/29", "68900 MAIN TCN Loopback", loopbacks=True)
    store.add_subnet(network.id, "fd00::/64", "IPv6")
    store.set_address(network.id, "10.0.1.0", USED, "rtr1")
    tab = IpamTab(Window())
    tab.local_store, tab.source, tab.network_id = store, LOCAL, network.id
    tab.fill_tree()
    shown = {}
    items = QTreeWidgetItemIterator(tab.tree)
    while items.value():
        tab.tree.setCurrentItem(items.value())
        tab.show_subnet()
        shown[items.value().text(0)] = tab.subnet_label.text()
        items += 1
    assert "loopbacks, each /32" in shown["10.0.1.0/29"] and "1 of 8 recorded" in shown["10.0.1.0/29"]
    assert "netmask 255.255.255.0" in shown["10.0.0.0/24"]
    assert "fd00::/64" in shown
    store.close()


def test_search_by_network_and_kind(app, tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    first, second = store.add_network("First"), store.add_network("Second")
    for network in (first, second):
        store.add_subnet(network.id, "10.0.0.0/24", "68890 LAN")
        store.set_address(network.id, "10.0.0.7", USED, "68890-sw1")
    tab = IpamTab(Window())
    tab.local_store = store
    tab.fill_networks()
    assert [tab.search_network_combo.itemText(index) for index in range(tab.search_network_combo.count())] ==         ["All networks", "First", "Second"]

    def results():
        return [tuple(tab.results_table.item(row, column).text() for column in (0, 1, 3))
                for row in range(tab.results_table.rowCount())]

    tab.search_input.setText("68890")
    tab.search()
    assert len(results()) == 4 and "in any network" in tab.results_label.text()
    tab.search_network_combo.setCurrentIndex(tab.search_network_combo.findText("Second"))  # Searches again
    assert sorted(results()) == [("Second", "10.0.0.0/24", ""), ("Second", "10.0.0.0/24", "10.0.0.7")]
    tab.search_kind_combo.setCurrentIndex(tab.search_kind_combo.findText("Addresses"))
    assert results() == [("Second", "10.0.0.0/24", "10.0.0.7")]
    assert tab.results_label.text() == "1 result for '68890' (addresses) in Second"

    # Matching one detail only, which shows in the results
    store.add_subnet(first.id, "10.0.1.0/24", "Voice", fields={"Telephony Rng": "68890"})
    tab.fill_networks()
    assert tab.search_match_combo.findText("Telephony Rng") >= 0
    tab.search_kind_combo.setCurrentIndex(0)
    tab.search_network_combo.setCurrentIndex(0)
    tab.search_match_combo.setCurrentIndex(tab.search_match_combo.findText("Telephony Rng"))
    assert results() == [("First", "10.0.1.0/24", "")]
    assert tab.results_table.item(0, 6).text() == "Telephony Rng: 68890"
    assert tab.results_label.text() == "1 result for Telephony Rng '68890' in any network"
    tab.search_network_combo.setCurrentIndex(tab.search_network_combo.findText("Second"))

    # The chosen network stays chosen when the list of networks is refreshed, and falls back to All if it's gone
    tab.fill_networks()
    assert tab.search_network_combo.currentText() == "Second"
    store.delete_network(second.id)
    tab.fill_networks()
    assert tab.search_network_combo.currentText() == "All networks"
    store.close()


class SessionPage:
    def __init__(self, matches):
        self.matches, self.opened = matches, []

    def saved_matches(self, host, aliases=(), protocol="SSH"):
        self.asked = (host, list(aliases))
        return self.matches

    def open_address(self, host, protocol="SSH", aliases=(), name="", folder="", use_saved=True):
        self.opened.append((host, list(aliases), name, folder, use_saved))


@pytest.fixture
def address_page(app, tmp_path):
    store = IpamStore(str(tmp_path / "menus.db"), user="tester")
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.0/24", "LAN")
    store.set_address(network.id, "10.0.0.5", USED, "core-sw1")
    window = Window()
    window.terminal_tab = SessionPage([])
    window.scp_tab = SessionPage([])
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
    yield window, tab
    window.close()
    window.deleteLater()
    store.close()


def entries(menu):
    """{label: action} for menu and its submenus (Connect, Tools)."""
    found = {}
    for action in menu.actions():
        found[action.text()] = action
        if action.menu() is not None:
            found.update(entries(action.menu()))
    return found


def assert_address_actions(menu):
    top = [action.text() for action in menu.actions()]
    assert {"Edit...", "Mark Used", "Copy", "Connect", "Tools", "History...", "Show on Map",
            "Copy IP Address"}.issubset(top)
    labels = set(entries(menu))
    assert {"Open SSH Session", "Open SCP Session", "Open Telnet Session", "Create Terminal Session...",
            "SSH with PuTTY", "Open http://10.0.0.5", "Open https://10.0.0.5", "Ping", "Traceroute", "Scan Ports",
            "SNMP Details", "Monitor Latency", "Capture Traffic..."}.issubset(labels)
    assert "Show in IPAM" not in labels  # On the IPAM page already
    tools = next(action.menu() for action in menu.actions() if action.text() == "Tools")
    assert [action.text() for action in tools.actions()].count("Ping") == 1
    assert not any(label.startswith("IP:") for label in top)


@pytest.mark.parametrize("column", [0, 3])
@pytest.mark.parametrize("choice,method", [("SSH with PuTTY", "open_ssh"),
                                          ("Open http://10.0.0.5", "open_web"),
                                          ("Show on Map", "show_map"), ("Edit...", "edit_address")])
def test_native_address_menu_has_all_actions_and_targets_clicked_row(address_page, monkeypatch, column,
                                                                    choice, method):
    window, tab = address_page
    callback = Mock()
    if method == "edit_address":
        monkeypatch.setattr(tab, method, lambda: callback())
    else:
        monkeypatch.setattr(HostActions, method, callback)
    tab.table.selectRow(6)  # Previously selected address must not be used for a right-click on another row.
    point = tab.table.visualRect(tab.model.index(5, column)).center()
    def choose(menu, position):
        assert_address_actions(menu)
        action = entries(menu)[choice]
        if method == "edit_address":
            action.trigger()  # exec_() normally emits triggered for the existing directly wired actions.
        return action
    monkeypatch.setattr(QMenu, "exec_", choose)
    tab.address_menu(point)
    assert list(map(str, tab.selected_addresses())) == ["10.0.0.5"]
    if method == "edit_address":
        callback.assert_called_once_with()
    elif method == "open_ssh":
        callback.assert_called_once_with("10.0.0.5", ["core-sw1"])
    elif method == "open_web":
        callback.assert_called_once_with("10.0.0.5", "http")
    else:
        callback.assert_called_once_with("10.0.0.5")


def test_create_terminal_session_files_it_under_the_network_and_subnet(address_page, monkeypatch):
    window, tab = address_page
    created = []
    window.terminal_tab.create_session = lambda *args: created.append(args)
    point = tab.table.visualRect(tab.model.index(5, 0)).center()
    monkeypatch.setattr(QMenu, "exec_", lambda menu, position: entries(menu)["Create Terminal Session..."])
    tab.address_menu(point)
    assert created == [("10.0.0.5", "SSH", "core-sw1", "Lab/LAN")]


def test_ssh_and_scp_use_the_saved_session(address_page, monkeypatch):
    window, tab = address_page
    window.terminal_tab = SessionPage([Session("Core-SW1", host="core-sw1", username="admin")])
    point = tab.table.visualRect(tab.model.index(5, 0)).center()
    shown = []
    monkeypatch.setattr(QMenu, "exec_", lambda menu, position: shown.append(entries(menu)))
    tab.address_menu(point)
    labels = shown[0]
    assert {"Open SSH Session (Core-SW1)", "Open New SSH Session", "Open SCP Session"}.issubset(labels)
    assert window.terminal_tab.asked == ("10.0.0.5", ["core-sw1"])  # Found by the address or the recorded name
    assert "Create Terminal Session..." not in labels  # It has one
    monkeypatch.setattr(QMenu, "exec_", lambda menu, position: entries(menu)["Open SSH Session (Core-SW1)"])
    tab.address_menu(point)
    monkeypatch.setattr(QMenu, "exec_", lambda menu, position: entries(menu)["Open SCP Session"])
    tab.address_menu(point)
    assert window.terminal_tab.opened == [("10.0.0.5", ["core-sw1"], "core-sw1", "Lab/LAN", True)]
    assert window.scp_tab.opened == [("10.0.0.5", ["core-sw1"], "core-sw1", "Lab/LAN", True)]


def test_real_ipam_context_event_preserves_menu_and_runs_added_action(app, address_page, monkeypatch):
    window, tab = address_page
    menus = IpContextMenus(window)
    callback = Mock()
    monkeypatch.setattr(HostActions, "show_map", callback)
    captured = []
    def choose():
        menu = app.activePopupWidget()
        captured.append(menu)
        action = next(action for action in menu.actions() if action.text() == "Show on Map")
        menu.setActiveAction(action)
        QTest.keyClick(menu, Qt.Key_Return)
    point = tab.table.visualRect(tab.model.index(5, 0)).center()
    QTimer.singleShot(0, choose)
    try:
        QApplication.sendEvent(tab.table.viewport(), QContextMenuEvent(
            QContextMenuEvent.Mouse, point, tab.table.viewport().mapToGlobal(point)))
        assert len(captured) == 1
        assert_address_actions(captured[0])
        callback.assert_called_once_with("10.0.0.5")
    finally:
        app.removeEventFilter(menus)
