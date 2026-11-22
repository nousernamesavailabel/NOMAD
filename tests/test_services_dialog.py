"""Tools > Services & Firewall: NOMAD's firewall rules (reading them, telling what's wrong, opening and removing
them), the list of services, and the window installing, removing and fixing them in the right order."""
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402

from nomad import firewall  # noqa: E402
from nomad import services_catalog as catalog  # noqa: E402
from nomad.firewall import Found  # noqa: E402


def wait_for(condition, seconds=5, app=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if app is not None:
            app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


# --------------------------------------------------------------------- Rules

SYSLOG_SERVICE = firewall.rule_named("NOMAD Syslog Collector")
IPERF = firewall.rule_named("NOMAD-iperf-server")


def test_rule_states():
    assess = firewall.assess
    assert assess(SYSLOG_SERVICE, [], 514, ("UDP",), needed=False) == (firewall.NOT_OPEN, "")
    assert assess(SYSLOG_SERVICE, [], 514, ("UDP",), needed=True)[0] == firewall.MISSING
    assert assess(IPERF, [], needed=None)[0] == firewall.NOT_OPEN  # A page's rule is opened when it's wanted
    udp = Found("NOMAD Syslog Collector", protocol="UDP", ports="514")
    assert assess(SYSLOG_SERVICE, [udp], 514, ("UDP",), True) == (firewall.OPEN, "")
    assert assess(SYSLOG_SERVICE, [udp], 514, ("UDP",), False)[0] == firewall.LEFT_OVER
    assert assess(SYSLOG_SERVICE, [udp], 1514, ("UDP",), True) == (firewall.NEEDS_FIXING, "port 514, should be 1514")
    assert assess(SYSLOG_SERVICE, [udp], 514, ("UDP", "TCP"), True) == (firewall.NEEDS_FIXING, "no TCP")
    assert assess(SYSLOG_SERVICE, [udp], None, ("UDP",), True)[0] == firewall.OPEN  # Port not known: not checked
    off = Found("NOMAD Syslog Collector", enabled=False, protocol="UDP", ports="514")
    assert assess(SYSLOG_SERVICE, [udp, off], 514, ("UDP",), True)[0] == firewall.TURNED_OFF
    blocking = Found("NOMAD Syslog Collector", allow=False, protocol="UDP", ports="514")
    assert assess(SYSLOG_SERVICE, [blocking], 514, ("UDP",), True)[0] == firewall.NEEDS_FIXING
    both = [Found("NOMAD-iperf-server", protocol="TCP", ports="5201"),
            Found("NOMAD-iperf-server", protocol="UDP", ports="5201")]
    assert assess(IPERF, both, 5201, ("TCP", "UDP"), None)[0] == firewall.OPEN


class ComRule:
    def __init__(self, name, protocol=17, ports="514", enabled=True, direction=1, action=1):
        self.Name, self.Protocol, self.LocalPorts = name, protocol, ports
        self.Enabled, self.Direction, self.Action = enabled, direction, action


class Policy:
    def __init__(self, rules, active=2, enabled=(True, True, True), modify=0):
        self.Rules = rules
        self.CurrentProfileTypes = active
        self.enabled = dict(zip((1, 2, 4), enabled))
        self.LocalPolicyModifyState = modify

    def FirewallEnabled(self, profile):
        return self.enabled[profile]


def test_reading_windows_firewall_keeps_nomads_rules_and_says_what_stops_them():
    policy = Policy([ComRule("NOMAD syslog"), ComRule("Remote Desktop", 6, "3389"),
                     ComRule("NOMAD IPAM Server", 6, "8443"), ComRule("NICManager-iperf-server", 6, "5201"),
                     ComRule("NOMAD something new", 6, "9000")], active=4, enabled=(True, True, False))
    state = firewall.read_state(policy)
    assert [item.name for item in state.found] == ["NOMAD syslog", "NOMAD IPAM Server", "NICManager-iperf-server",
                                                   "NOMAD something new"]
    assert state.named("NOMAD IPAM Server")[0].protocol == "TCP"
    assert state.unknown() == ["NOMAD something new"]
    assert state.legacy_found() == [(IPERF, "NICManager-iperf-server")]
    assert len(state.warnings()) == 1 and "off for the Public network" in state.warnings()[0]
    assert "Group Policy" in firewall.read_state(Policy([], modify=firewall.GP_OVERRIDE)).warnings()[0]
    assert "block all incoming" in firewall.read_state(Policy([], modify=firewall.INBOUND_BLOCKED)).warnings()[0]
    assert firewall.read_state(Policy([])).warnings() == []


def test_opening_replaces_the_rule_and_its_old_names(monkeypatch):
    commands = []

    def run(command):
        commands.append(" ".join(command[3:]))
        if command[3] == "delete" and "Old" in command[-1]:
            raise firewall.CommandError(command, "No rules match the specified criteria.")
        return ""

    monkeypatch.setattr(firewall, "run_command", run)
    firewall.open_rule("NOMAD X", 1514, ("UDP", "TCP"), legacy=("Old X",))
    assert commands == ["delete rule name=NOMAD X", "delete rule name=Old X",
                        "add rule name=NOMAD X dir=in action=allow protocol=UDP localport=1514 profile=any",
                        "add rule name=NOMAD X dir=in action=allow protocol=TCP localport=1514 profile=any"]


# --------------------------------------------------------------------- The services

def test_services_are_listed_in_install_order_with_their_ports(tmp_path, monkeypatch):
    assert [entry.key for entry in catalog.SERVICES] == ["tribe", "syslog", "flows", "watcher", "dashboard"]
    assert {rule.service for rule in firewall.RULES if rule.service} == {"tribe", "syslog", "flows", "watcher",
                                                                         "dashboard"}
    rules = {name for entry in catalog.SERVICES for name in entry.firewall()}
    assert rules == {rule.name for rule in firewall.RULES if rule.service}
    assert catalog.read_config(tmp_path, {"port": 1}) == {"port": 1}  # Not installed yet
    (tmp_path / "config.json").write_text(json.dumps({"port": 1514, "tcp": True}), encoding="utf-8")
    assert catalog.read_config(tmp_path, {"port": 514, "tcp": False}) == {"port": 1514, "tcp": True}
    (tmp_path / "config.json").write_text("{", encoding="utf-8")
    assert catalog.read_config(tmp_path, {"port": 514}) is None  # Can't be read: not known
    from nomad.syslogs import service as syslog_service
    monkeypatch.setattr(syslog_service, "collector_dir", lambda: tmp_path)
    syslog = catalog.entry("syslog")
    assert catalog.ports_text(syslog) == "UDP ?"
    assert catalog.ports_text(syslog, {"NOMAD Syslog Collector": "514"}.get) == "UDP 514"
    (tmp_path / "config.json").write_text(json.dumps({"port": 1514, "tcp": True}), encoding="utf-8")
    assert catalog.ports_text(syslog) == "UDP and TCP 1514"
    assert catalog.ports_text(catalog.entry("watcher")) == "UDP 514 and 162"
    from nomad.dashboard import service as dashboard_service
    monkeypatch.setattr(dashboard_service, "dashboard_dir", lambda: tmp_path / "dashboard")
    assert catalog.ports_text(catalog.entry("dashboard")) == "TCP 8444"


# --------------------------------------------------------------------- The window

@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.admin = True
        self.calls = []
        self.states = None  # Shared with the fake services

    def show_tribe_management(self):
        self.calls.append("tribe dialog")
        self.states["tribe"] = "Running"

    def show_map_watcher(self):
        self.calls.append("watcher dialog")  # Closed without installing

    def tribe_key_changed(self):
        self.calls.append("tribe key changed")


FIREWALL = {"tribe": {"NOMAD IPAM Server": (8443, ("TCP",))},
            "syslog": {"NOMAD Syslog Collector": (514, ("UDP",))},
            "flows": {"NOMAD Flow Collector": (2055, ("UDP",))},
            "watcher": {"NOMAD Map Watcher syslog": (514, ("UDP",)), "NOMAD Map Watcher traps": (162, ("UDP",))}}


def fake_entry(key, title, states, calls, quiet):
    """A service that only pretends (its settings: the usual ones)."""
    def install():
        calls.append(f"install {key}")
        states[key] = "Running"

    def uninstall():
        calls.append(f"uninstall {key}")
        states[key] = "Not installed"

    def update():
        calls.append(f"update {key}")

    return catalog.ServiceEntry(key, title, "", lambda: SimpleNamespace(argument=key), Path, FIREWALL[key].copy,
                                uninstall, install if quiet else None, catalog.entry(key).dialog, update)


@pytest.fixture
def dialog(app, monkeypatch):
    from nomad.ui import services_dialog, syslog_service_dialog
    window = Window()
    states = {"tribe": "Not installed", "syslog": "Not installed", "flows": "Not installed",
              "watcher": "Not installed"}
    window.states = states
    calls = window.calls
    entries = [fake_entry("tribe", "Tribe Server", states, calls, False),
               fake_entry("syslog", "Syslog Collector", states, calls, True),
               fake_entry("flows", "Flow Collector", states, calls, True),
               fake_entry("watcher", "Map Watcher", states, calls, False)]
    monkeypatch.setattr(catalog, "SERVICES", entries)
    monkeypatch.setattr(catalog, "status", lambda entry: states[entry.key])
    found = [Found("NOMAD IPAM Server", protocol="TCP", ports="8443"),
             Found("NOMAD Flow Collector", protocol="UDP", ports="2056"),
             Found("NICManager-iperf-server", protocol="TCP", ports="5201")]
    monkeypatch.setattr(firewall, "read_state", lambda: firewall.FirewallState(list(found)))
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    monkeypatch.setattr(syslog_service_dialog, "free_syslog_port",
                        lambda window: calls.append("free 514") or "watcher")
    monkeypatch.setattr(syslog_service_dialog, "give_syslog_port_back",
                        lambda window, released: calls.append(f"give 514 back to {released}"))
    shown = services_dialog.ServicesDialog(window)
    shown.found = found
    assert wait_for(lambda: shown.firewall_state is not None, app=app)
    yield shown
    shown.busy = ""
    shown.reject()
    shown.deleteLater()


def tick(dialog, *keys):
    for row, entry in enumerate(catalog.SERVICES):
        dialog.services_table.item(row, 0).setCheckState(Qt.Checked if entry.key in keys else Qt.Unchecked)


def tick_rules(dialog, *names):
    for index, row in enumerate(dialog.rows):
        dialog.rules_table.item(index, 0).setCheckState(Qt.Checked if row.name in names else Qt.Unchecked)


def rows(dialog):
    return {row.name: row.state for row in dialog.rows}


def test_window_lists_the_rules_and_what_is_wrong(app, dialog, monkeypatch):
    states = rows(dialog)
    assert states["NOMAD IPAM Server"] == firewall.LEFT_OVER  # The Tribe Server isn't installed
    assert states["NOMAD Flow Collector"] == firewall.LEFT_OVER
    assert states["NICManager-iperf-server"] == firewall.LEFT_OVER  # NOMAD's old name
    assert states["NOMAD TFTP server"] == firewall.NOT_OPEN
    dialog.window.states["flows"] = "Running"
    dialog.refresh_services()
    assert rows(dialog)["NOMAD Flow Collector"] == firewall.NEEDS_FIXING  # 2056, but the service has 2055
    assert dialog.services_table.item(2, 1).text() == "Running"
    opened = []
    monkeypatch.setattr(firewall, "open_rule", lambda *rule: opened.append(rule))
    dialog.fix_all()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert opened == [("NOMAD Flow Collector", 2055, ("UDP",), ())]
    removed = []
    monkeypatch.setattr(firewall, "close_rule", removed.append)
    dialog.found[:] = [item for item in dialog.found if item.name != "NICManager-iperf-server"]
    dialog.remove_left_over()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert removed == ["NOMAD IPAM Server", "NICManager-iperf-server"]
    assert "Couldn't remove NOMAD IPAM Server" in dialog.message_label.text()  # Still there when read again


def test_page_rules_follow_the_page_setting(app, dialog, monkeypatch):
    from nomad.ui.services_dialog import page_wants
    page = type("Page", (), {})()
    page.port_input = type("Input", (), {"value": lambda self: 1514})()
    page.tcp_check = type("Check", (), {"isChecked": lambda self: True})()
    dialog.window.syslog_tab = page
    assert page_wants(dialog.window, firewall.rule_named("NOMAD syslog")) == (1514, ("UDP", "TCP"))
    assert page_wants(dialog.window, firewall.rule_named("NOMAD TFTP server")) == (69, ("UDP",))  # No page here
    opened = []
    monkeypatch.setattr(firewall, "open_rule", lambda *rule: opened.append(rule))
    tick_rules(dialog, "NOMAD syslog", "NOMAD TFTP server")
    assert dialog.open_rule_button.isEnabled() and not dialog.remove_rule_button.isEnabled()  # Neither is there
    dialog.open_rules()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert opened == [("NOMAD syslog", 1514, ("UDP", "TCP"), ()), ("NOMAD TFTP server", 69, ("UDP",), ())]
    assert {row.name for row in dialog.ticked_rules()} == {"NOMAD syslog", "NOMAD TFTP server"}  # Still ticked
    dialog.found.append(Found("NOMAD syslog", protocol="UDP", ports="514"))  # The page opened it meanwhile
    dialog.read_firewall()
    assert wait_for(lambda: rows(dialog)["NOMAD syslog"] == firewall.NEEDS_FIXING, app=app)
    assert {row.name for row in dialog.ticked_rules()} == {"NOMAD syslog", "NOMAD TFTP server"}  # Kept
    removed = []
    monkeypatch.setattr(firewall, "close_rule", removed.append)
    dialog.found.pop()
    dialog.remove_rules()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert removed == ["NOMAD syslog"]  # The TFTP rule isn't there to remove


def test_install_ticked_goes_in_order_and_asks_where_it_must(app, dialog):
    calls = dialog.window.calls
    flows_page = type("FlowsPage", (), {"local": "collecting"})()
    flows_page.stop_collect_here = lambda: calls.append("stop collect here")
    flows_page.check_source = lambda: calls.append("flows page checks")
    dialog.window.flows_tab = flows_page
    tick(dialog, "watcher", "flows", "syslog", "tribe")
    dialog.install_ticked()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert calls == ["tribe dialog", "free 514", "install syslog", "give 514 back to watcher", "stop collect here",
                     "install flows", "flows page checks", "watcher dialog"]
    assert dialog.window.states == {"tribe": "Running", "syslog": "Running", "flows": "Running",
                                    "watcher": "Not installed"}
    assert "Map Watcher wasn't installed" in dialog.message_label.text()
    calls.clear()
    tick(dialog, "tribe", "syslog", "watcher")
    dialog.uninstall_ticked()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert [call for call in calls if call.startswith("uninstall")] == ["uninstall syslog", "uninstall tribe"]
    assert "tribe key changed" in calls and "Removed Syslog Collector and Tribe Server." in \
        dialog.message_label.text()


def test_updating_a_service_opens_no_window(app, dialog, monkeypatch):
    """A service that wants updating is updated with the settings it has, even one installed in its own window."""
    from nomad import service_versions
    calls = dialog.window.calls
    dialog.window.states.update(tribe="Running", syslog="Running", watcher="Running")
    old = {"tribe", "watcher", "syslog"}
    monkeypatch.setattr(service_versions, "read_note", lambda argument: {"version": "1.0.0" if argument in old
                                                                         else "99.0.0"})
    dialog.refresh_services()
    assert dialog.services_table.item(0, 2).text() == "1.0.0: update"
    tick(dialog, "watcher", "tribe")
    dialog.install_ticked()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert calls == ["update tribe", "tribe key changed", "update watcher"]  # No window opened
    calls.clear()
    dialog.services_table.selectRow(1)  # The Syslog Collector, with Update
    assert dialog.update_button.isEnabled()
    dialog.update_service()
    assert wait_for(lambda: not dialog.busy, app=app)
    assert calls == ["free 514", "update syslog", "give 514 back to watcher"]
    dialog.services_table.selectRow(2)  # Not installed: nothing to update
    assert not dialog.update_button.isEnabled()


def test_without_administrator_rights_it_only_shows(app, dialog):
    dialog.window.admin = False
    dialog.window.states["syslog"] = "Stopped"
    tick(dialog, "flows")
    dialog.refresh_services()
    for button in (dialog.install_ticked_button, dialog.start_all_button, dialog.fix_button,
                   dialog.remove_left_over_button, dialog.start_button):
        assert not button.isEnabled()
    assert dialog.restart_button.isVisibleTo(dialog) and dialog.set_up_button.isEnabled()
