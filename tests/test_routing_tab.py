"""The Routing Table page: a route started from the IP Addresses page, the gateway list and the Persistent default."""
import json
import os
from pathlib import Path
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad.ipam.store import IpamStore  # noqa: E402
from nomad.snapshot import parse_snapshot  # noqa: E402
from nomad.ui.ipam_tab import LOCAL, IpamTab  # noqa: E402
from nomad.ui.routing_tab import RoutingTab  # noqa: E402

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot.json"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    """Stands in for the main window: the page reads its snapshot and asks it to run changes."""
    snapshot_changed = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.snapshot = parse_snapshot(json.loads(FIXTURE.read_text()))
        self.run_change = Mock()
        self.show_status = Mock()


class AnyWindow(QWidget):
    """Stands in for the main window on the IP Addresses page, which calls it for other pages."""

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


@pytest.fixture
def page(app):
    window = Window()
    tab = RoutingTab(window)
    yield tab
    window.deleteLater()


def test_persistent_is_checked_by_default_and_after_clearing(page):
    assert page.persistent_check.isChecked()
    page.persistent_check.setChecked(False)
    page.clear_route_form()
    assert page.persistent_check.isChecked()


def test_prefill_fills_the_network_and_leaves_the_next_hop(page):
    page.route_gateway_input.setText("192.168.1.99")
    page.prefill("172.20.0.0/16")  # Only the default route reaches it (172.16.0.0/12 is inactive)
    assert page.destination_input.text() == "172.20.0.0"
    assert page.netmask_input.text() == "255.255.0.0"
    assert page.route_gateway_input.text() == "" and page.route_interface_combo.currentData() is None
    assert page.selected_route is None and page.persistent_check.isChecked()
    assert page.route_filter_input.text() == "172.20.0.0/16"
    assert "goes to 0.0.0.0/0 via 192.168.1.1" in page.route_count_label.text()  # What reaches it now
    assert "Pick the next hop" in page.route_hint_label.text()
    page.route_gateway_input.setText("192.168.1.254")
    assert page.route_form_spec is not None and page.add_button.isEnabled()


def test_prefill_warns_when_this_computer_is_on_the_subnet(page):
    page.prefill("192.168.1.0/24")
    assert "already on 192.168.1.0/24" in page.route_hint_label.text()


def test_prefill_switches_to_ipv6(page):
    page.prefill("fd00:10::/64")
    assert page.current_route_family() == 6
    assert page.destination_input.text() == "fd00:10::/64"
    page.fill_gateway_menu()
    page.on_gateway_picked(page.gateway_menu.actions()[0])
    assert page.route_gateway_input.text() == "fe80::1" and page.route_interface_combo.currentData() == "11"
    assert page.route_form_spec is not None  # The picked gateway brought its interface with it


def test_gateway_menu_lists_this_computers_gateways(page):
    page.fill_gateway_menu()
    labels = [action.text() for action in page.gateway_menu.actions()]
    assert labels[0].startswith("192.168.1.1") and labels[1].startswith("192.168.1.254")
    page.on_gateway_picked(page.gateway_menu.actions()[1])
    assert page.route_gateway_input.text() == "192.168.1.254"


def test_gateway_menu_says_so_when_there_are_none(page):
    for adapter in page.adapters.values():
        adapter.gateways4.clear()
    page.window.snapshot.routes.clear()
    page.fill_gateway_menu()
    (action,) = page.gateway_menu.actions()
    assert not action.isEnabled()
    page.on_gateway_picked(action)
    assert page.route_gateway_input.text() == ""


def test_ipam_add_windows_route_opens_the_routing_page(app, tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.20.0.0/24", "LAN", gateway="10.20.0.1")
    window = AnyWindow()
    window.navigator, window.routing_tab = Mock(), Mock()
    tab = IpamTab(window)
    tab.local_store, tab.source, tab.network_id = store, LOCAL, network.id
    tab.fill_tree()
    tab.tree.setCurrentItem(tab.tree.topLevelItem(0))
    tab.add_windows_route()
    window.navigator.setCurrentWidget.assert_called_once_with(window.routing_tab)
    window.routing_tab.prefill.assert_called_once_with("10.20.0.0/24")  # Not the subnet's own gateway
    store.close()
    window.deleteLater()
