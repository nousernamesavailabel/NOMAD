"""Carry VLAN on the Network Map page: opening it from the menus, Plan (reading the switches again first), sending
each switch's step, Verify, and the route set by hand (Pick on Map, Fill In Between, Edit This Route)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from netmap_fakes import CISCO_SWITCH, Device, FakeNetwork, number  # noqa: E402
from PyQt5.QtCore import Qt, pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMenu, QMessageBox, QWidget  # noqa: E402

from test_mirror import ConfigChannel, FakePushShell  # noqa: E402

from nomad.netmap import collect, macssh, store  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, Crawler, read_vlans_of  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.netmap_view import FADED, PATH_CARRIES, PATH_CHOSEN, PATH_OFFERED, PATH_PLANNED, PATH_ROUTE  # noqa: E402
from nomad.terminal.sessions import Session, SessionStore  # noqa: E402
from nomad.ui.terminal_view import CONNECTED  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)

    def current_adapter(self):
        return None

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class Model:
    def cursor_position(self):
        return type("Position", (), {"line": 0})()

    def line_text(self, line):
        return "sw2#"


class View:
    title, state, model = "sw2", CONNECTED, Model()

    def __init__(self):
        self.sent = []

    def send_block(self, text, final_enter=True, min_delay=0):
        self.sent.append(text)
        return True


def switch(name, address):
    device = Device(name, "Cisco IOS Software, Catalyst L3 Switch Software", CISCO_SWITCH)
    device.interface(51, "Vlan1")
    device.address(address, 51)
    device.set(collect.STP_TYPE, 0, number(5))  # Rapid-PVST+
    device.vlan(1, "default")
    return device


def chain():
    """core (VLAN 20 and its gateway, Vlan20) - sw1 (has 20; its link to sw2 allows only 1) - sw2 (no VLAN 20)."""
    network = FakeNetwork()
    core = network.add("10.0.0.1", switch("core", "10.0.0.1"))
    core.interface(1, "GigabitEthernet0/1")
    core.interface(50, "Vlan20")
    core.address("10.1.20.1", 50)
    core.vlan(20, "USERS")
    core.trunk(1, [1, 20])
    core.cdp(1, 1, "sw1", "GigabitEthernet0/1", "10.0.0.2", "cisco WS-C3850", 0x28)
    sw1 = network.add("10.0.0.2", switch("sw1", "10.0.0.2"))
    sw1.interface(1, "GigabitEthernet0/1")
    sw1.interface(2, "GigabitEthernet0/2")
    sw1.vlan(20, "USERS")
    sw1.trunk(1, [1, 20])
    sw1.trunk(2, [1])
    sw1.cdp(1, 1, "core", "GigabitEthernet0/1", "10.0.0.1", "cisco WS-C3850", 0x28)
    sw1.cdp(2, 2, "sw2", "GigabitEthernet0/1", "10.0.0.3", "cisco WS-C2960", 0x28)
    sw2 = network.add("10.0.0.3", switch("sw2", "10.0.0.3"))
    sw2.interface(1, "GigabitEthernet0/1")
    sw2.interface(5, "GigabitEthernet0/5")
    sw2.vlan(10, "STAFF")
    sw2.trunk(1, [1])
    sw2.access(5, 10)
    sw2.cdp(1, 1, "sw1", "GigabitEthernet0/2", "10.0.0.2", "cisco WS-C3850", 0x28)
    return network


@pytest.fixture
def setup(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    network = chain()
    window = Window()
    window.session_store = SessionStore(str(tmp_path / "sessions.json"))
    page = netmap_tab.NetworkMapTab(window)
    page.resize(1200, 800)
    page.read_vlans = lambda settings, address, **options: read_vlans_of(settings, address,
                                                                          client_factory=network.client, **options)
    network_map = Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False, collect_hosts=False),
                          client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    page.on_crawled(network_map)
    keys = {device.label: key for key, device in page.network_map.devices.items()}
    yield page, network, keys
    if page.carry_dialog is not None:
        page.carry_dialog.close()
    page.shutdown()


def wait_for(dialog):
    while dialog.thread is not None:
        dialog.thread.wait(10000)
        QApplication.processEvents()
    QApplication.processEvents()


def row_texts(table, column):
    return [table.item(row, column).text() for row in range(table.rowCount())]


def test_carry_a_vlan_plan_send_and_verify(setup, monkeypatch):
    page, network, keys = setup
    page.carry_vlan(b=keys["sw2"], port="Gi0/5")
    dialog = page.carry_dialog
    assert dialog.isVisible() and dialog.b_combo.currentData() == keys["sw2"]
    assert [dialog.edge_list.item(row).checkState() == Qt.Checked for row in range(dialog.edge_list.count())][0]
    dialog.set_vlan(20)
    assert dialog.vlan_combo.currentText() == "20"  # Only the number: the name has its own box
    assert dialog.name_input.text() == "USERS"  # The name the map already has for it
    dialog.plan_button.click()
    wait_for(dialog)
    plan = dialog.plan
    assert plan.ok and plan.route == [keys["sw1"], keys["sw2"]]
    assert row_texts(dialog.route_table, 0) == ["sw1", "sw2"]  # The way chosen shows in the route table
    assert {keys["sw1"], keys["sw2"]} <= dialog.read_keys
    assert dialog.stp[keys["sw1"]].mode == "rapid-pvst"
    assert row_texts(dialog.steps_table, 0) == ["1. sw1", "2. sw2"]
    assert "allow it on Gi0/2" in dialog.steps_table.item(0, 1).text()
    assert "create VLAN 20" in dialog.steps_table.item(1, 1).text()
    assert "Gi0/5" in dialog.steps_table.item(1, 1).text()
    assert "reachable" in dialog.gateway_label.text()
    assert page.view.items_by_key[keys["sw2"]].highlight is not None
    dialog.steps_table.selectRow(1)
    assert dialog.preview.toPlainText().startswith("configure terminal\nvlan 20\n name USERS")
    dialog.preview_combo.setCurrentIndex(1)
    assert "no vlan 20" in dialog.preview.toPlainText()

    view = View()
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.Yes)
    assert dialog.session_sender.send_to(view, dialog.step_text(1, "config"), tag=(1, "config"))
    assert view.sent and "switchport trunk allowed vlan add 20" in view.sent[0]
    assert dialog.steps_table.item(1, 2).text() == "Sent to sw2"

    # The switches as they'd be once both steps were typed in
    network.devices["10.0.0.2"].trunk(2, [1, 20])
    network.devices["10.0.0.3"].vlan(20, "USERS")
    network.devices["10.0.0.3"].trunk(1, [1, 20])
    network.devices["10.0.0.3"].access(5, 20)
    dialog.verify_button.click()
    wait_for(dialog)
    assert row_texts(dialog.steps_table, 2) == ["Done", "Done"]
    assert "Verified" in dialog.status_label.text()
    dialog.close()
    assert page.view.items_by_key[keys["sw2"]].highlight is None


def test_verify_says_what_isnt_done(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    network.devices["10.0.0.2"].trunk(2, [1, 20])  # Only sw1 done
    dialog.verify_button.click()
    wait_for(dialog)
    statuses = row_texts(dialog.steps_table, 2)
    assert statuses[0] == "Done" and statuses[1].startswith("Not done") and "VLAN 20 isn't on sw2" in statuses[1]


def test_route_set_by_hand_picked_on_the_map(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20)
    dialog = page.carry_dialog
    dialog.hand_radio.setChecked(True)
    dialog.toggle_picking()
    assert page.view.picking and dialog.pick_button.text() == "Stop Picking"
    page.view.device_picked.emit(keys["core"])
    page.view.device_picked.emit(keys["core"])  # The same one twice in a row: once
    page.view.device_picked.emit(keys["sw2"])
    page.on_escape()
    assert not page.view.picking and dialog.pick_button.text() == "Pick on Map"
    assert dialog.route == [keys["core"], keys["sw2"]]
    assert "No link between core and sw2" in dialog.route_table.item(0, 2).text()
    assert "Fix the route first" in dialog.check_ready()
    dialog.fill_in_between()
    assert dialog.route == [keys["core"], keys["sw1"], keys["sw2"]]
    assert dialog.check_ready() == ""
    dialog.plan_button.click()
    wait_for(dialog)
    plan = dialog.plan
    assert plan.by_hand and plan.route == [keys["core"], keys["sw1"], keys["sw2"]]
    assert not dialog.edit_route_button.isEnabled()  # Already set by hand


def test_edit_this_route_copies_the_way_nomad_chose(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    dialog.edit_route()
    assert dialog.hand_radio.isChecked() and dialog.route == [keys["sw1"], keys["sw2"]]
    assert dialog.plan is None  # Changed: plan again


def test_changing_anything_needs_a_new_plan(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    assert dialog.plan is not None and dialog.verify_button.isEnabled()
    dialog.set_vlan(30)
    assert dialog.plan is None and not dialog.verify_button.isEnabled() and dialog.steps_table.rowCount() == 0


def test_menus_open_it(setup):
    page, network, keys = setup
    menu, actions = QMenu(), {}
    page.carry_vlan_menu(menu, actions, keys["sw2"], [keys["sw2"], keys["core"]])
    labels = [action.text() for action in actions]
    assert labels == ["Carry a VLAN Here...", "Carry a VLAN Between These..."]
    next(handler for action, handler in actions.items() if action.text().startswith("Carry a VLAN Between"))()
    dialog = page.carry_dialog
    assert dialog.a_combo.currentData() == keys["core"] and dialog.b_combo.currentData() == keys["sw2"]
    page.vlan_panel.carry_requested.emit(20, "")
    assert dialog.vlan() == 20 and dialog.isVisible()


def test_ticking_a_redundant_link_plans_again_without_reading(setup):
    page, network, keys = setup
    # A second way to sw2, straight from core, allowing only VLAN 1: a triangle once 20 reaches sw2
    core, sw2 = network.devices["10.0.0.1"], network.devices["10.0.0.3"]
    core.interface(2, "GigabitEthernet0/2")
    core.trunk(2, [1])
    core.cdp(2, 2, "sw2", "GigabitEthernet0/2", "10.0.0.3", "cisco WS-C2960", 0x28)
    sw2.interface(2, "GigabitEthernet0/2")
    sw2.trunk(2, [1])
    sw2.cdp(2, 2, "core", "GigabitEthernet0/2", "10.0.0.1", "cisco WS-C3850", 0x28)
    page.on_crawled(Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False, collect_hosts=False),
                            client_factory=network.client, pinger=network.ping, echo=network.echo).run())
    keys = {device.label: key for key, device in page.network_map.devices.items()}
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    assert dialog.redundant_list.count() == 1 and "Rapid-PVST+" in dialog.redundant_list.item(0).text()
    steps = dialog.steps_table.rowCount()
    asked = len(network.requests)
    dialog.redundant_list.item(0).setCheckState(Qt.Checked)
    assert dialog.thread is None and len(network.requests) == asked  # Planned again from what was read
    assert dialog.steps_table.rowCount() > steps
    assert dialog.steps_table.item(dialog.steps_table.rowCount() - 1, 1).text().endswith("(redundant links)")


def test_a_switch_that_doesnt_answer_is_planned_from_the_map(setup):
    page, network, keys = setup
    page.read_vlans = lambda settings, address, **options: (None, None)
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    assert dialog.plan.ok and dialog.plan.route == [keys["sw1"], keys["sw2"]]
    assert any("Didn't answer SNMP" in dialog.findings_list.item(row).text()
               for row in range(dialog.findings_list.count()))


def test_open_session_to_a_switch_uses_its_saved_telnet_session_without_ssh(setup):
    from nomad.terminal.sessions import SSH, TELNET
    page, network, keys = setup
    opened = []

    class Terminal:
        def saved_matches(self, host, aliases=(), protocol=SSH):
            return ["r2s3 telnet"] if protocol == TELNET else []

        def open_address(self, address, protocol, **options):
            opened.append((address, protocol))
            return None

    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.session_sender.terminal = lambda: Terminal()
    dialog.session_sender.open_device({"address": "10.0.0.3", "aliases": ["sw2"], "name": "sw2"}, lambda: "")
    assert opened == [("10.0.0.3", TELNET)]


def link_kind(page, one, other):
    """The path style drawn on the link between two devices."""
    for item in page.view.link_items:
        if {item.a_item.key, item.b_item.key} == {one, other}:
            return item.path_kind, item.toolTip(), item.opacity()
    return None


def test_the_planned_path_is_drawn_on_the_map(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    kind, tip, opacity = link_kind(page, keys["sw1"], keys["sw2"])
    assert kind == PATH_PLANNED and opacity == 1.0
    assert "Carry VLAN 20: on the route: allowed vlan add 20 on sw1 Gi0/2 and sw2 Gi0/1" in tip
    assert link_kind(page, keys["core"], keys["sw1"])[0] is None  # Not on the route (it carries 20 already)
    sw2 = page.view.items_by_key[keys["sw2"]]
    assert sw2.opacity() == 1.0 and sw2.highlight  # On the route: not faded with what lacks VLAN 20
    network.devices["10.0.0.2"].trunk(2, [1, 20])
    network.devices["10.0.0.3"].vlan(20, "USERS")
    network.devices["10.0.0.3"].trunk(1, [1, 20])
    dialog.verify_button.click()
    wait_for(dialog)
    assert link_kind(page, keys["sw1"], keys["sw2"])[0] == PATH_CARRIES
    dialog.close()
    kind, tip, _ = link_kind(page, keys["sw1"], keys["sw2"])
    assert kind is None and "Carry VLAN" not in tip


def test_redundant_links_are_drawn_ticked_or_not(setup):
    page, network, keys = setup
    core, sw2 = network.devices["10.0.0.1"], network.devices["10.0.0.3"]
    core.interface(2, "GigabitEthernet0/2")
    core.trunk(2, [1])
    core.cdp(2, 2, "sw2", "GigabitEthernet0/2", "10.0.0.3", "cisco WS-C2960", 0x28)
    sw2.interface(2, "GigabitEthernet0/2")
    sw2.trunk(2, [1])
    sw2.cdp(2, 2, "core", "GigabitEthernet0/2", "10.0.0.1", "cisco WS-C3850", 0x28)
    page.on_crawled(Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False, collect_hosts=False),
                            client_factory=network.client, pinger=network.ping, echo=network.echo).run())
    keys = {device.label: key for key, device in page.network_map.devices.items()}
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    item = dialog.plan.redundant[0]
    assert link_kind(page, item.hop.a, item.hop.b)[0] == PATH_OFFERED
    dialog.redundant_list.item(0).setCheckState(Qt.Checked)
    assert link_kind(page, item.hop.a, item.hop.b)[0] == PATH_CHOSEN
    others = [key for key in page.network_map.devices if key not in dialog.plan.route
              and key not in (item.hop.a, item.hop.b)]
    assert all(page.view.items_by_key[key].opacity() == FADED for key in others
               if key in page.view.items_by_key and key not in page.view.vlan_focus.devices)


class Switch(ConfigChannel):
    """A switch logged in to over SSH whose configuration lines change what it answers over SNMP."""

    def __init__(self, device, ports, trunks, refuse=()):
        super().__init__(start="sw1#", refuse=refuse)
        self.device, self.ports = device, ports  # ports: name -> ifIndex
        self.trunks = {index: set(allowed) for index, allowed in trunks.items()}  # ifIndex -> allowed VLANs
        self.port = None
        self.lines = []

    def send(self, text):
        word = text.strip()
        self.lines.append(word)
        if word not in self.refuse:
            parts = word.split()
            if word.startswith("interface "):
                self.port = self.ports.get(parts[1])
            elif word.startswith("vlan ") and len(parts) == 2:
                self.device.vlan(int(parts[1]), "USERS")
            elif word.startswith("switchport trunk allowed vlan ") and self.port in self.trunks:
                allowed = self.trunks[self.port]
                (allowed.add if parts[4] == "add" else allowed.discard)(int(parts[5]))
                self.device.trunk(self.port, sorted(allowed))
            elif word.startswith("switchport access vlan ") and self.port is not None:
                self.device.access(self.port, int(parts[3]))
        super().send(text)


@pytest.fixture
def ssh(setup, monkeypatch):
    """Carry VLAN 20 to sw2 (and its Gi0/5) planned, with sw1 and sw2 answering SSH."""
    page, network, keys = setup
    monkeypatch.setattr(macssh, "QUIET", 0)
    switches = {"10.0.0.2": Switch(network.devices["10.0.0.2"], {"Gi0/2": 2}, {1: [1, 20], 2: [1]}),
                "10.0.0.3": Switch(network.devices["10.0.0.3"], {"Gi0/1": 1, "Gi0/5": 5}, {1: [1]})}
    FakePushShell.channels = switches
    asked = []
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: asked.append(args[2]) or QMessageBox.Yes)
    page.carry_vlan(vlan=20, b=keys["sw2"], port="Gi0/5")
    dialog = page.carry_dialog
    dialog.shell_factory = FakePushShell
    dialog.saved_logins = (macssh.SshLogins(fallback=Session("", username="admin"), password="pw"), "")
    dialog.plan_button.click()
    wait_for(dialog)
    assert dialog.plan.ok and dialog.send_button.isEnabled() and not dialog.undo_button.isEnabled()
    return dialog, switches, asked


def wait_for_push(dialog):
    for _ in range(500):
        thread = dialog.push_thread or dialog.thread
        if thread is None:
            break
        thread.wait(50)
        QApplication.processEvents()
    QApplication.processEvents()


def test_send_all_over_ssh_then_verify_and_undo(ssh):
    dialog, switches, asked = ssh
    dialog.send_button.click()
    assert "these 2 switches, one at a time in this order" in asked[0] and "sw1\nsw2" in asked[0]
    assert "Nothing is saved" in asked[0]
    wait_for_push(dialog)
    sw1, sw2 = switches["10.0.0.2"], switches["10.0.0.3"]
    assert "switchport trunk allowed vlan add 20" in sw1.lines and "vlan 20" in sw2.lines
    assert "switchport access vlan 20" in sw2.lines and "write memory" not in sw2.lines
    assert row_texts(dialog.steps_table, 2) == ["Done", "Done"]  # Verified straight after, over SNMP
    assert "Verified" in dialog.status_label.text()
    assert dialog.undo_button.isEnabled() and len(dialog.sent) == 2

    dialog.undo_button.click()
    assert "sw2\nsw1" in asked[-1]  # Last sent, first taken back out
    wait_for_push(dialog)
    assert "switchport trunk allowed vlan remove 20" in sw1.lines and "no vlan 20" in sw2.lines
    assert sw2.lines.index("no vlan 20") > sw2.lines.index("switchport access vlan 10")
    assert row_texts(dialog.steps_table, 2) == ["Undone over SSH", "Undone over SSH"]
    assert not dialog.sent and not dialog.undo_button.isEnabled() and "Taken back out" in dialog.status_label.text()


def test_a_switch_that_refuses_stops_it_and_offers_to_take_back_what_was_sent(ssh, monkeypatch):
    dialog, switches, asked = ssh
    switches["10.0.0.3"].refuse = {"vlan 20"}
    offered = []
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: offered.append(self.text()) or QMessageBox.Yes)
    dialog.send_button.click()
    wait_for_push(dialog)
    assert offered and "sw2 didn't take it" in offered[0]
    assert "already sent to sw1, sw2 (with what sw2 took before it refused)?" in offered[0]
    wait_for_push(dialog)  # The undo it said yes to
    sw1, sw2 = switches["10.0.0.2"], switches["10.0.0.3"]
    assert "switchport trunk allowed vlan remove 20" in sw1.lines
    assert "switchport access vlan 20" not in sw2.lines  # Stopped at the refused line
    assert "no vlan 20" in sw2.lines  # What it took before refusing is taken back out too
    assert row_texts(dialog.steps_table, 2) == ["Undone over SSH", "Undone over SSH"]
    assert not dialog.sent


def test_a_refusal_shows_on_its_row_when_nothing_is_taken_back(ssh, monkeypatch):
    dialog, switches, asked = ssh
    switches["10.0.0.3"].refuse = {"vlan 20"}
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.No)
    dialog.send_button.click()
    wait_for_push(dialog)
    statuses = row_texts(dialog.steps_table, 2)
    assert statuses[0] == "Sent over SSH" and statuses[1].startswith("Refused: vlan 20: % Invalid input")
    assert "sw2 didn't take it" in dialog.status_label.text() and dialog.undo_button.isEnabled()


def test_one_switch_over_ssh_from_its_send_menu(ssh):
    dialog, switches, asked = ssh
    dialog.session_sender.terminal = lambda: None  # No Terminal page: no sessions to list
    menu = dialog.steps_table.cellWidget(1, 3).menu()
    menu.aboutToShow.emit()
    first = menu.actions()[0]
    assert first.text() == "Over SSH (no one watching)"
    undo = next(action.menu() for action in menu.actions() if action.text() == "Send Undo")
    assert undo.actions()[0].text() == "Over SSH (no one watching)"
    dialog.save_check.setChecked(True)
    first.trigger()
    assert "this switch over SSH" in asked[-1] and "write memory" in asked[-1]
    wait_for_push(dialog)
    assert "write memory" in switches["10.0.0.3"].lines and not switches["10.0.0.2"].lines
    assert row_texts(dialog.steps_table, 2)[0] == "Not done: Gi0/2 doesn't allow VLAN 20 yet."
    assert row_texts(dialog.steps_table, 2)[1] == "Done"


def route_numbers(page):
    return {item.label: item.route_text for item in page.view.items_by_key.values() if item.route_text}


def test_the_route_set_by_hand_shows_on_the_map_while_picking(setup):
    page, network, keys = setup
    view = page.view
    page.carry_vlan(vlan=20)
    dialog = page.carry_dialog
    dialog.hand_radio.setChecked(True)
    dialog.toggle_picking()
    view.device_picked.emit(keys["core"])
    assert route_numbers(page) == {"core": "1"}
    assert view.pick_anchor == keys["core"]  # The line to the mouse goes from the last one picked
    view.pick_mouse = view.items_by_key[keys["sw2"]].pos()
    view.update_pick_rubber()
    assert view.pick_rubber is not None and view.pick_rubber.line().p1() == view.items_by_key[keys["core"]].pos()

    view.device_picked.emit(keys["sw2"])  # Skipping sw1: no link between core and sw2
    assert route_numbers(page) == {"core": "1", "sw2": "2"}
    assert view.pick_anchor == keys["sw2"]
    assert view.items_by_key[keys["sw2"]].highlight is not None
    assert len(view.gap_items) == 1 and "No link between core and sw2" in view.gap_items[0].toolTip()
    page.on_escape()
    assert view.pick_rubber is None and view.pick_anchor is None
    assert route_numbers(page) == {"core": "1", "sw2": "2"}  # Still shown once picking stops

    dialog.fill_in_between()
    assert route_numbers(page) == {"core": "1", "sw1": "2", "sw2": "3"} and not view.gap_items
    kind, tip, _ = link_kind(page, keys["core"], keys["sw1"])
    assert kind == PATH_ROUTE and "Carry VLAN 20: the route set by hand (1 to 2, core to sw1)" in tip
    assert link_kind(page, keys["sw1"], keys["sw2"])[0] == PATH_ROUTE

    dialog.route_table.selectRow(1)
    dialog.remove_switch()  # The gap comes back
    assert route_numbers(page) == {"core": "1", "sw2": "2"} and len(view.gap_items) == 1
    assert link_kind(page, keys["core"], keys["sw1"])[0] is None

    dialog.auto_radio.setChecked(True)  # Not by hand: nothing drawn
    assert not route_numbers(page) and not view.gap_items and view.items_by_key[keys["sw2"]].highlight is None
    dialog.hand_radio.setChecked(True)
    assert route_numbers(page) == {"core": "1", "sw2": "2"}
    dialog.close()
    assert not route_numbers(page) and not view.gap_items


def test_several_links_between_two_switches_are_offered_until_one_is_chosen(setup):
    page, network, keys = setup
    sw1, sw2 = network.devices["10.0.0.2"], network.devices["10.0.0.3"]
    sw1.interface(3, "GigabitEthernet0/3")
    sw1.trunk(3, [1])
    sw1.cdp(3, 3, "sw2", "GigabitEthernet0/3", "10.0.0.3", "cisco WS-C2960", 0x28)
    sw2.interface(3, "GigabitEthernet0/3")
    sw2.trunk(3, [1])
    sw2.cdp(3, 3, "sw1", "GigabitEthernet0/3", "10.0.0.2", "cisco WS-C3850", 0x28)
    page.on_crawled(Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False, collect_hosts=False),
                            client_factory=network.client, pinger=network.ping, echo=network.echo).run())
    keys = {device.label: key for key, device in page.network_map.devices.items()}
    page.carry_vlan(vlan=20, route=[keys["sw1"], keys["sw2"]])
    dialog = page.carry_dialog
    kind, tip, _ = link_kind(page, keys["sw1"], keys["sw2"])
    assert kind == PATH_OFFERED and "one of 2 links" in tip
    combo = dialog.route_table.cellWidget(0, 1)
    combo.setCurrentIndex(1)
    assert link_kind(page, keys["sw1"], keys["sw2"])[0] == PATH_ROUTE


def test_the_planned_route_is_numbered_too(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    dialog.plan_button.click()
    wait_for(dialog)
    assert route_numbers(page) == {"sw1": "1", "sw2": "2"}
    assert link_kind(page, keys["sw1"], keys["sw2"])[0] == PATH_PLANNED


def test_trunks_among_the_edge_ports_are_warned_about(setup):
    page, network, keys = setup
    sw2 = network.devices["10.0.0.3"]
    sw2.interface(6, "GigabitEthernet0/6")
    sw2.trunk(6, [1, 10])  # A trunk to something not on the map (a server, an AP...)
    page.on_crawled(Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False, collect_hosts=False),
                            client_factory=network.client, pinger=network.ping, echo=network.echo).run())
    keys = {device.label: key for key, device in page.network_map.devices.items()}
    page.carry_vlan(vlan=20, b=keys["sw2"])
    dialog = page.carry_dialog
    items = {dialog.edge_list.item(row).data(Qt.UserRole): dialog.edge_list.item(row)
             for row in range(dialog.edge_list.count())}
    from nomad.ui.theme import COLORS
    assert items["Gi0/1"].text().endswith("Warning: Trunk to sw1")
    assert items["Gi0/6"].text().endswith("Warning: Trunk") and "stays a trunk" in items["Gi0/6"].toolTip()
    assert items["Gi0/6"].foreground().color().name() == COLORS["warning"].lower()
    assert "Warning" not in items["Gi0/5"].text()  # An access port
    items["Gi0/6"].setCheckState(Qt.Checked)
    dialog.plan_button.click()
    wait_for(dialog)
    dialog.steps_table.selectRow(1)
    preview = dialog.preview.toPlainText()
    assert "interface Gi0/6\n switchport trunk allowed vlan add 20" in preview
    assert "switchport mode access" not in preview  # Kept a trunk, as the warning says


def test_choosing_another_b_lists_its_ports_with_none_ticked(setup):
    page, network, keys = setup
    page.carry_vlan(vlan=20, b=keys["sw2"], port="Gi0/1")
    dialog = page.carry_dialog

    def listed():
        return {dialog.edge_list.item(row).data(Qt.UserRole): dialog.edge_list.item(row).checkState() == Qt.Checked
                for row in range(dialog.edge_list.count())}
    assert listed() == {"Gi0/5": False, "Gi0/1": True} and "<b>sw2</b>" in dialog.edge_label.text()
    dialog.b_combo.setCurrentIndex(dialog.b_combo.findData(keys["sw1"]))
    # sw1 has a Gi0/1 too: sw2's tick isn't carried over to it
    assert listed() == {"Gi0/1": False, "Gi0/2": False} and "<b>sw1</b>" in dialog.edge_label.text()
    dialog.edge_list.item(1).setCheckState(Qt.Checked)
    dialog.vlan_combo.setEditText("30")  # B unchanged: the tick stays
    assert listed() == {"Gi0/1": False, "Gi0/2": True}
