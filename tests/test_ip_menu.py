"""Shared IP menus preserve each widget's existing right-click behavior."""
import os
from types import SimpleNamespace
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtCore import QPoint, Qt, QTimer
from PyQt5.QtGui import QContextMenuEvent
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication, QGraphicsScene, QGraphicsView, QLabel, QLineEdit, QListWidget, QMenu, \
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from nomad.ui.host_menu import HostActions
from nomad.ui.ip_menu import IpContextMenus, addresses_at, ip_addresses


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    widget = QWidget()
    QVBoxLayout(widget)
    widget.terminal_tab = Mock()
    widget.scp_tab = Mock()
    widget.terminal_tab.saved_matches.return_value = []
    widget.scp_tab.saved_matches.return_value = []
    widget.ip_context_menus = IpContextMenus(widget)
    yield widget
    app.removeEventFilter(widget.ip_context_menus)
    widget.close()
    widget.deleteLater()


def context(app, widget, point):
    QApplication.sendEvent(widget, QContextMenuEvent(QContextMenuEvent.Mouse, point, widget.mapToGlobal(point)))


def test_literals_and_socket_addresses():
    assert ip_addresses("10.0.0.1:22 https://[2001:db8::1]:443 fe80::1%12 10.0.0.1/24") == [
        "10.0.0.1", "2001:db8::1", "fe80::1%12"]
    assert ip_addresses("999.0.0.1 v1.2.3 mac aa:bb:cc:dd:ee:ff") == []
    assert ip_addresses("<a href='http://10.0.0.2'>10.0.0.1</a>") == ["10.0.0.1"]


def test_cell_target_and_row_fallback(app, window):
    table = QTableWidget(2, 3, window)
    window.layout().addWidget(table)
    for row, values in enumerate((("name", "10.0.0.1", "10.0.0.2"), ("other", "10.0.0.3", ""))):
        for column, value in enumerate(values):
            table.setItem(row, column, QTableWidgetItem(value))
    window.show()
    app.processEvents()
    table.selectRow(1)
    viewport = table.viewport()
    assert addresses_at(viewport, table.visualItemRect(table.item(0, 2)).center()) == ["10.0.0.2"]
    assert addresses_at(viewport, table.visualItemRect(table.item(0, 0)).center()) == ["10.0.0.1", "10.0.0.2"]
    assert addresses_at(table.horizontalHeader(), QPoint(10, 5)) == []


def test_list_widget_without_address_has_no_actions(app, window):
    # QListWidget's model hides columnCount(); the drawer's tool list must not raise.
    items = QListWidget(window)
    window.layout().addWidget(items)
    items.addItems(["Ping", "Gateway 10.0.0.9"])
    window.show()
    app.processEvents()
    assert addresses_at(items.viewport(), items.visualItemRect(items.item(0)).center()) == []
    assert addresses_at(items.viewport(), items.visualItemRect(items.item(1)).center()) == ["10.0.0.9"]


def test_existing_custom_menu_is_extended_and_original_action_runs(app, window):
    table = QTableWidget(1, 1, window)
    window.layout().addWidget(table)
    table.setItem(0, 0, QTableWidgetItem("10.0.0.1"))
    table.setContextMenuPolicy(Qt.CustomContextMenu)
    original = Mock()
    captured = []

    def show_menu(position):
        menu = QMenu(table)
        action = menu.addAction("Original action")
        def inspect():
            captured.extend(menu.actions())
            menu.setActiveAction(action)
            QTest.keyClick(menu, Qt.Key_Return)
        QTimer.singleShot(0, inspect)
        chosen = menu.exec_(table.viewport().mapToGlobal(position))
        # Match the dictionary dispatch used by existing pages.
        if chosen == action:
            original()

    table.customContextMenuRequested.connect(show_menu)
    window.show()
    app.processEvents()
    context(app, table.viewport(), table.visualItemRect(table.item(0, 0)).center())
    assert original.call_count == 1
    assert captured[0].text() == "Original action"
    submenu = captured[-1].menu()
    assert captured[-1].text() == "IP: 10.0.0.1"
    next(action for action in submenu.actions() if action.text() == "Open SSH Session").trigger()
    assert window.terminal_tab.open_address.call_args.args[0] == "10.0.0.1"


def test_standard_text_menu_keeps_edit_actions(app, window):
    edit = QLineEdit("10.0.0.1", window)
    window.layout().addWidget(edit)
    captured = []
    def inspect():
        menu = app.activePopupWidget()
        captured.extend(action.text().replace("&", "") for action in menu.actions())
        menu.close()
    window.show()
    app.processEvents()
    QTimer.singleShot(0, inspect)
    context(app, edit, QPoint(10, 10))
    app.processEvents()  # QLineEdit opens its standard menu with popup(), not exec_().
    assert any("Copy" in text for text in captured), captured
    assert any("Paste" in text for text in captured)
    assert "IP: 10.0.0.1" in captured


def test_label_without_menu_gets_actions(app, window):
    label = QLabel("Server: 10.0.0.2", window)
    window.layout().addWidget(label)
    captured = []
    def inspect():
        menu = app.activePopupWidget()
        captured.extend(action.text() for action in menu.actions()[0].menu().actions())
        menu.close()
    window.show()
    app.processEvents()
    QTimer.singleShot(0, inspect)
    context(app, label, QPoint(10, 10))
    assert {"SSH with PuTTY", "Show in IPAM", "Show on Map", "Open http://10.0.0.2",
            "Open https://10.0.0.2"}.issubset(captured)


def test_password_fields_do_not_expose_addresses(app):
    edit = QLineEdit("10.0.0.1")
    edit.setEchoMode(QLineEdit.Password)
    assert addresses_at(edit, QPoint()) == []


def test_default_table_gets_menu(app, window):
    table = QTableWidget(1, 1, window)
    window.layout().addWidget(table)
    table.setItem(0, 0, QTableWidgetItem("10.0.0.4"))
    captured = []
    def inspect():
        menu = app.activePopupWidget()
        captured.extend(action.text() for action in menu.actions())
        menu.close()
    window.show()
    app.processEvents()
    QTimer.singleShot(0, inspect)
    context(app, table.viewport(), table.visualItemRect(table.item(0, 0)).center())
    assert captured == ["IP: 10.0.0.4"]


def test_log_targets_clicked_line_and_graphics_text(app, window):
    editor = QPlainTextEdit(window)
    window.layout().addWidget(editor)
    editor.setPlainText("10.0.0.1\n10.0.0.2")
    view = QGraphicsView(window)
    scene = QGraphicsScene(view)
    view.setScene(scene)
    item = scene.addText("2001:db8::1")
    window.layout().addWidget(view)
    window.show()
    app.processEvents()
    cursor = editor.textCursor()
    cursor.setPosition(len("10.0.0.1\n"))
    point = editor.cursorRect(cursor).center()
    assert addresses_at(editor.viewport(), point) == ["10.0.0.2"]
    point = view.mapFromScene(item.sceneBoundingRect().center())
    assert addresses_at(view.viewport(), point) == ["2001:db8::1"]


def test_explicitly_consumed_context_event_keeps_original_behavior(app, window):
    class ConsumingLabel(QLabel):
        def contextMenuEvent(self, event):
            event.accept()
    label = ConsumingLabel("10.0.0.1", window)
    window.layout().addWidget(label)
    window.show()
    app.processEvents()
    context(app, label, QPoint(10, 10))
    assert app.activePopupWidget() is None
    assert window.ip_context_menus.pending == []


def test_ipv6_browser_authority(monkeypatch):
    browser = Mock()
    monkeypatch.setattr("nomad.ui.host_menu.webbrowser.open_new_tab", browser)
    HostActions(Mock(), None).open_web("fe80::1%12", "http")
    browser.assert_called_once_with("http://[fe80::1%2512]")


def test_ipam_single_match_navigates_to_address():
    store = Mock()
    network = SimpleNamespace(id="net", name="Network")
    store.networks.return_value = [network]
    page = Mock()
    page.ipam_stores.return_value = [("local", store)]
    window = SimpleNamespace(ipam_tab=page, navigator=Mock())
    HostActions(window, None).show_ipam("10.0.0.1")
    page.show_address.assert_called_once_with("local", "net", "10.0.0.1")


def test_map_finds_device_interface_address():
    from nomad.netmap.model import Device, NetworkMap
    device = Device("switch", mgmt_ip="10.0.0.1", addresses=["2001:db8::1"])
    network_map = NetworkMap()
    network_map.devices[device.key] = device
    page = Mock()
    page.displayed_map.return_value = network_map
    window = SimpleNamespace(netmap_tab=page, navigator=Mock(), show_status=Mock())
    HostActions(window, None).show_map("2001:0db8::1")
    page.show_in.assert_called_once_with(page.view, ["switch"])


def test_ipam_unknown_address_searches_all_networks():
    store = Mock()
    store.networks.return_value = [SimpleNamespace(id="net")]
    store.subnet_for.return_value = store.address.return_value = None
    page = Mock()
    page.ipam_stores.return_value = [("local", store)]
    window = SimpleNamespace(ipam_tab=page, navigator=Mock())
    HostActions(window, None).show_ipam("10.0.0.1")
    page.search_network_combo.setCurrentIndex.assert_called_once_with(0)
    page.search_input.setText.assert_called_once_with("10.0.0.1")
    page.search.assert_called_once_with()


def test_map_finds_host_and_missing_address_reports_status():
    from nomad.netmap.model import Host, NetworkMap
    network_map = NetworkMap()
    host = Host("aa:bb:cc:dd:ee:ff", "switch", "Gi1", ip="10.0.0.2")
    network_map.hosts.append(host)
    page = Mock()
    page.displayed_map.return_value = network_map
    page.l3_nodes = {}
    window = SimpleNamespace(netmap_tab=page, navigator=Mock(), show_status=Mock())
    actions = HostActions(window, None)
    actions.show_map("10.0.0.2")
    page.view.show_host.assert_called_once_with(host)
    actions.show_map("10.0.0.3")
    window.show_status.assert_called_once_with("10.0.0.3 isn't on the open network map.", "info")


def test_host_actions_are_grouped_into_connect_and_tools(app, window):
    menu = QMenu()
    HostActions(window, window).add_to(menu, "10.0.0.1")
    top = [action.text() for action in menu.actions()]
    assert top == ["Connect", "Tools", "Show in IPAM", "Show on Map", "Add Device to Map...", "Copy IP Address"]
    connect, tools = (action.menu() for action in menu.actions()[:2])
    assert {"Open SSH Session", "Open SCP Session", "Open Telnet Session", "Create Terminal Session...",
            "SSH with PuTTY", "Open https://10.0.0.1"} <= {action.text() for action in connect.actions()}
    assert [action.text() for action in tools.actions()] == [
        "Ping", "Traceroute", "Monitor Latency", "Scan Ports", "SNMP Details", "Capture Traffic..."]

    flat = QMenu()  # Already a submenu of just these (IP: 10.0.0.1): no further submenus
    HostActions(window, window).add_to(flat, "10.0.0.1", grouped=False, leave_out=("Show on Map",))
    labels = [action.text() for action in flat.actions()]
    assert "Open SSH Session" in labels and "Ping" in labels
    assert "Connect" not in labels and "Show on Map" not in labels


def test_page_entries_are_not_repeated_in_the_submenus(app, window):
    menu = QMenu()
    menu.addAction("Ping")
    HostActions(window, window).add_to(menu, "10.0.0.1", leave_out=("Capture Traffic...",))
    tools = next(action.menu() for action in menu.actions() if action.text() == "Tools")
    assert [action.text() for action in tools.actions()] == [
        "Traceroute", "Monitor Latency", "Scan Ports", "SNMP Details"]
