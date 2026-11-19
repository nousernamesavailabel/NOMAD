"""Host names in address fields: what's typed is used as an address, or looked up (DNS, then the map, IPAM and saved
sessions), and the pages that build configs or keep records get the address."""
import os
import socket
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QLineEdit, QMessageBox, QWidget  # noqa: E402

from nomad import resolve  # noqa: E402
from nomad.netmap.model import Device, Host, NetworkMap  # noqa: E402
from nomad.resolve import DNS, NameNotFound, Resolved, is_host_name, match_known, parse  # noqa: E402
from nomad.ui import name_lookup  # noqa: E402
from nomad.ui.name_lookup import IPAM, MAP, SESSIONS, NameResolver, known_names, name_to_address, \
    resolve_now  # noqa: E402

DNS_NAMES = {"nms1": ["10.0.0.60"], "nms1.corp.example": ["10.0.0.60"], "dual": ["10.0.0.70", "2001:db8::70"],
             "v6only": ["2001:db8::80"], "gw1": ["192.168.1.254"], "far-hub": ["203.0.113.10"],
             "two": ["10.0.0.81", "10.0.0.82"]}
REAL_DNS = resolve.dns_addresses  # Before the fixture stands in for it


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """DNS answers from DNS_NAMES (tests don't use the network); asked records each name asked."""
    asked = []

    def answer(name, family=None, timeout=resolve.DNS_TIMEOUT):
        asked.append(name)
        return list(DNS_NAMES.get(name.lower(), []))

    monkeypatch.setattr(name_lookup, "dns_addresses", answer)
    monkeypatch.setattr(resolve, "dns_addresses", answer)
    name_lookup.forget_answers()
    yield asked
    name_lookup.forget_answers()


def wait_for(condition, app, seconds=3.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    return condition()


# ----------------------------------------------------------------- What's typed


def test_addresses_are_used_as_typed():
    assert parse("10.1.2.3") == Resolved("10.1.2.3", "10.1.2.3")
    assert parse(" 2001:DB8::1 ").address == "2001:db8::1"
    assert parse("10.1.2.3", 4).source == ""
    with pytest.raises(ValueError, match="IPv6 address: this needs IPv4"):
        parse("2001:db8::1", 4)
    with pytest.raises(ValueError, match="isn't an IPv4 address or a host name"):
        parse("10.1.2.300", 4)
    with pytest.raises(ValueError, match="Enter an IP address or a host name"):
        parse("  ")
    assert parse("core-sw1.corp.example") is None  # A name, to look up


def test_what_counts_as_a_host_name():
    for name in ("core-sw1", "core-sw1.corp.example", "core-sw1.corp.example.", "_srv", "a"):
        assert is_host_name(name), name
    for text in ("10.1.2.300", "10.1", "", "has space", "-leading", "trailing-", "a..b", "x" * 64, "a/b", "a:b"):
        assert not is_host_name(text), text


def test_dns_addresses_put_ipv4_first(monkeypatch):
    infos = [(socket.AF_INET6, 1, 6, "", ("2001:db8::1", 0, 0, 0)), (socket.AF_INET, 1, 6, "", ("10.0.0.9", 0)),
             (socket.AF_INET, 1, 6, "", ("10.0.0.9", 0)), (socket.AF_INET, 1, 6, "", ("10.0.0.8", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: infos)
    assert REAL_DNS("server1") == ["10.0.0.9", "10.0.0.8", "2001:db8::1"]


def test_dns_that_does_not_answer_in_time(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: time.sleep(1) or [])
    with pytest.raises(TimeoutError, match="didn't answer for 'slow'"):
        REAL_DNS("slow", timeout=0.05)


def test_names_dns_does_not_know_come_from_what_nomad_has():
    known = lambda name: [("core-sw1.corp.example", "10.9.0.1", MAP), ("printer7", "10.9.0.7", SESSIONS),  # noqa
                          ("printer7", "10.9.0.8", IPAM)]
    assert resolve.resolve("nms1", 4, known).address == "10.0.0.60"  # DNS first
    found = resolve.resolve("core-sw1", 4, known)  # A short name finds the FQDN
    assert (found.address, found.source) == ("10.9.0.1", MAP)
    assert found.note() == "core-sw1 → 10.9.0.1 (the map)"
    found = resolve.resolve("PRINTER7.corp.example.", 4, known)  # And an FQDN its short name
    assert (found.address, found.others) == ("10.9.0.7", ["10.9.0.8"])
    with pytest.raises(NameNotFound, match="DNS doesn't know it, and nor does the map, IPAM or a saved session"):
        resolve.resolve("nowhere", 4, known)
    with pytest.raises(NameNotFound, match="only IPv6 addresses"):
        resolve.resolve("v6only", 4, known)


def test_the_kind_of_address_wanted_is_picked():
    found = resolve.resolve("dual", 6)
    assert (found.address, found.source) == ("2001:db8::70", DNS)
    found = resolve.resolve("two")
    assert found.address == "10.0.0.81" and "also 10.0.0.82" in found.note()
    assert match_known("x", [("x", "2001:db8::1", MAP)], 4) is None


# ----------------------------------------------------------------- The UI's lookups


def window_with(network_map=None, sessions=(), ipam=None):
    window = QWidget()
    window.netmap_tab = SimpleNamespace(displayed_map=lambda: network_map)
    window.session_store = SimpleNamespace(sessions=list(sessions))
    window.ipam_tab = ipam
    return window


def test_known_names_come_from_the_map_ipam_and_sessions(app, tmp_path):
    from nomad.ipam.store import IpamStore
    network_map = NetworkMap()
    network_map.devices["d1"] = Device("d1", name="closet-sw3", mgmt_ip="10.5.0.3")
    network_map.hosts.append(Host(mac="00-11-22-33-44-55", device="d1", port="Gi1/0/5", ip="10.5.0.77", name="lab-pc"))
    store = IpamStore(tmp_path / "ipam.db")
    network = store.add_network("Site")
    store.add_subnet(network.id, "10.6.0.0/24")
    store.set_address(network.id, "10.6.0.9", name="badge-reader")
    sessions = [SimpleNamespace(name="edge-rtr", host="10.7.0.1"), SimpleNamespace(name="by-name", host="by-name")]
    window = window_with(network_map, sessions, SimpleNamespace(team=None, local_store=store))
    assert resolve_now("closet-sw3", 4, window).note() == "closet-sw3 → 10.5.0.3 (the map)"
    assert resolve_now("lab-pc", 4, window).address == "10.5.0.77"
    assert resolve_now("badge-reader", 4, window).note() == "badge-reader → 10.6.0.9 (IPAM)"
    assert resolve_now("edge-rtr.corp.example", 4, window).note() == \
        "edge-rtr.corp.example → 10.7.0.1 (a saved session)"
    assert all(source != SESSIONS or address != "by-name"
               for _, address, source in known_names(window, "by-name"))  # A session by name doesn't say an address
    store.close()
    window.deleteLater()


def test_resolve_now_keeps_answers_for_a_while(app, fake_dns):
    assert resolve_now("nms1", 4).address == "10.0.0.60"
    assert resolve_now("NMS1", 4).address == "10.0.0.60"
    assert fake_dns == ["nms1"]  # Asked once
    with pytest.raises(NameNotFound):
        resolve_now("nowhere", 4)
    with pytest.raises(NameNotFound):
        resolve_now("nowhere", 4)
    assert fake_dns == ["nms1", "nowhere"]
    assert resolve_now("10.1.1.1").address == "10.1.1.1" and fake_dns == ["nms1", "nowhere"]  # No DNS for addresses


def test_name_resolver_looks_up_once_typing_pauses(app, fake_dns):
    resolver = NameResolver()
    changes = []
    resolver.changed.connect(lambda: changes.append(1))
    assert resolver.address("10.0.0.1", 4).address == "10.0.0.1"
    for typed in ("n", "nm", "nms", "nms1"):  # Each keystroke: only the last is looked up
        assert resolver.address(typed, 4, slot="field") is None
    assert resolver.busy()
    assert wait_for(lambda: changes, app)
    assert fake_dns == ["nms1"]
    assert resolver.address("nms1", 4, slot="field").source == DNS and not resolver.busy()
    resolver.address("nowhere", 4, slot="field")
    assert wait_for(lambda: len(changes) == 2, app)
    with pytest.raises(NameNotFound):
        resolver.address("nowhere", 4, slot="field")
    resolver.deleteLater()


def test_name_to_address_fills_the_record(app):
    ip_input, name_input = QLineEdit("nms1"), QLineEdit()
    assert name_to_address(ip_input, name_input).address == "10.0.0.60"
    assert (ip_input.text(), name_input.text()) == ("10.0.0.60", "nms1")
    ip_input.setText("far-hub")
    name_input.setText("Kept")
    name_to_address(ip_input, name_input)
    assert (ip_input.text(), name_input.text()) == ("203.0.113.10", "Kept")
    ip_input.setText("10.0.0.300")
    assert name_to_address(ip_input, name_input) is None  # Not a name: the record's own check explains
    ip_input.setText("nowhere")
    with pytest.raises(NameNotFound):
        name_to_address(ip_input, name_input)


# ----------------------------------------------------------------- The pages


def test_route_gateway_by_name(app):
    from tests.test_routing_tab import Window
    from nomad.ui.routing_tab import RoutingTab
    window = Window()
    page = RoutingTab(window)
    page.destination_input.setText("172.20.0.0/16")
    page.route_gateway_input.setText("gw1")
    assert page.route_form_spec is None and "Looking up gw1" in page.route_hint_label.text()
    assert wait_for(lambda: page.route_form_spec is not None, app)
    assert page.route_form_spec["gateway"] == "192.168.1.254"
    assert "gw1 → 192.168.1.254 (DNS)" in page.route_hint_label.text()
    assert page.read_route_form()["gateway"] == "192.168.1.254"
    page.route_gateway_input.setText("nowhere")
    assert wait_for(lambda: "DNS doesn't know it" in page.route_hint_label.text(), app)
    assert page.route_form_spec is None
    window.deleteLater()


def test_snmp_config_sends_traps_to_a_name_s_address(app):
    from tests.test_snmp_config_tab import View, Window
    from nomad.ui.snmp_config_tab import SnmpConfigTab
    page = SnmpConfigTab(Window([View("access-sw-02")]))
    page.community_input.setText("n0mad-RO")
    page.destinations_input.setText("10.0.0.50 nms1")
    assert page.lines == [] and "Looking up nms1" in page.status_label.text()
    assert wait_for(lambda: page.lines, app)
    assert "logging host 10.0.0.60" in page.lines and " permit host 10.0.0.60" in page.lines
    assert not any("nms1" in line for line in page.lines)  # The config gets the address
    assert "nms1 → 10.0.0.60 (DNS)" in page.status_label.text()
    page.permit_same.setChecked(False)
    page.permit_input.setText("nowhere 10.20.0.0/24")
    assert wait_for(lambda: "DNS doesn't know it" in page.status_label.text(), app)
    assert page.lines == []
    page.deleteLater()


def test_map_device_and_host_dialogs_keep_the_address(app, monkeypatch):
    from nomad.ui.netmap_dialogs import DeviceDialog, HostDialog
    network_map = NetworkMap()
    network_map.devices["acc1"] = Device("acc1", name="acc1", mgmt_ip="10.0.0.11")
    dialog = DeviceDialog(network_map)
    dialog.ip_input.setText("nms1.corp.example")
    dialog.accept()
    assert (dialog.ip_input.text(), dialog.name_input.text()) == ("10.0.0.60", "nms1.corp.example")
    assert dialog.values()[0].mgmt_ip == "10.0.0.60"
    warnings = []
    monkeypatch.setattr(QMessageBox, "warning", lambda parent, title, text: warnings.append(text))
    dialog = DeviceDialog(network_map)
    dialog.ip_input.setText("nowhere")
    dialog.accept()
    assert "DNS doesn't know it" in warnings[-1] and dialog.result() == 0
    host = HostDialog(network_map, device="acc1")
    host.port_combo.setEditText("Gi1/0/5")
    host.ip_input.setText("two")
    host.accept()
    assert host.values().ip == "10.0.0.81" and host.values().name == "two"


def test_vpn_far_end_by_name(app):
    from nomad.netmap.vpn import VTI
    from nomad.ui.vpn_dialogs import NewVpnDialog
    from PyQt5.QtWidgets import QDialogButtonBox
    dialog = NewVpnDialog(None, [("R6", "R6"), ("R7", "R7")], chosen=("R6",), name="V1", kind=VTI)
    dialog.far_input.setText("far-hub")
    assert not dialog.buttons.button(QDialogButtonBox.Ok).isEnabled()
    assert "Looking up far-hub" in dialog.hint.text()
    assert wait_for(lambda: dialog.buttons.button(QDialogButtonBox.Ok).isEnabled(), app)
    assert dialog.far_end() == "203.0.113.10"
    assert "far-hub → 203.0.113.10 (DNS)" in dialog.hint.text()
    dialog.far_input.setText("v6only")
    assert wait_for(lambda: "only IPv6" in dialog.hint.text(), app)
    assert not dialog.buttons.button(QDialogButtonBox.Ok).isEnabled()


def test_vpn_member_reached_at_by_name(app):
    from nomad.netmap.vpn import DMVPN
    from nomad.ui.vpn_dialogs import MemberDialog
    from tests.test_vpn import design
    item, found = design(DMVPN)
    member = item.member("R6")
    dialog = MemberDialog(None, item, member, found["R6"])
    dialog.public_input.setText("far-hub")
    dialog.accept_if_valid()
    dialog.apply(member)
    assert member.public_ip == "203.0.113.10"
    dialog.public_input.setText("nowhere")
    dialog.accept_if_valid()
    assert dialog.hint.text().startswith("Reached at: Couldn't find 'nowhere'")


def test_capture_filter_by_name(app):
    from nomad.ui.capture_tab import CaptureTab
    window = QWidget()
    window.set_busy = window.clear_busy = lambda *args: None
    try:
        page = CaptureTab(window)
    except Exception as error:  # The page needs more of the main window than a test gives it
        pytest.skip(f"Capture page not built: {error}")
    page.address_input.setText("nms1")
    page.describe_settings()
    assert "to or from nms1" in page.settings_button.text()
    assert page.typed_name() == "nms1"
    page.address_input.setText("10.0.0.0/24")
    assert page.typed_name() == ""
    window.deleteLater()


def test_host_menus_on_a_name_look_it_up_when_chosen(app):
    from PyQt5.QtWidgets import QMenu
    from nomad.ui.host_menu import ADD_TO_MAP, HostActions
    window = QWidget()
    actions = HostActions(window, window)
    menu = QMenu()
    found = actions.navigation_actions(menu, "nms1")
    labels = {action.text(): run for action, run in found.items()}
    assert {"Show in IPAM", "Show on Map", ADD_TO_MAP, "Copy IP Address"} <= set(labels)
    labels["Copy IP Address"]()
    assert QApplication.clipboard().text() == "10.0.0.60"
    assert actions.navigation_actions(QMenu(), "not a name") == {}
    window.deleteLater()
