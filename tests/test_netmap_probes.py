"""Monitoring devices from a router on the map: IP SLA probes found on routers (CISCO-RTTMON-MIB), which router and
VRF should reach a device, the configuration, and the monitor checking probed devices from their routers."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from nomad.netmap import configpush, monitor, probes  # noqa: E402
from nomad.netmap.model import FIREWALL, ROUTER, SNMP, SWITCH, Device, NetworkMap  # noqa: E402
from nomad.netmap.monitor import DOWN, UNKNOWN, UP  # noqa: E402
from nomad.snmp import GAUGE32, INTEGER, OCTET_STRING, TIMETICKS, SnmpError, Value, parse_oid  # noqa: E402
from nomad.ui import netmap_monitor, netmap_probes  # noqa: E402

CISCO = "1.3.6.1.4.1.9.1.2494"

# What R5 (IOS XE 17.4) said to `show running-config | section ip sla`
R5_SLA = """ip sla 9998
 icmp-echo 10.251.5.9
  vrf NOMAD-TEST
  tag NOMAD gone
  threshold 1000
  timeout 1000
  frequency 10
ip sla schedule 9998 life forever start-time now
ip sla 9999
 icmp-echo 10.251.5.1
  vrf NOMAD-TEST
  owner NOMAD tester
  tag NOMAD test
  threshold 1000
  timeout 1000
  frequency 10
ip sla schedule 9999 life forever start-time now
ip sla 12
 udp-jitter 10.9.9.9 16384
ip sla schedule 12 start-time now
ip sla responder"""


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def router(key, mgmt, l3=(), routes=(), vrf_routes=None, port_vrfs=None, kind=ROUTER, descr="Cisco IOS XE Software",
           object_id=CISCO):
    return Device(key, name=key, mgmt_ip=mgmt, addresses=[mgmt] + [item[0] for item in l3], kind=kind,
                  source=SNMP, sys_descr=descr, sys_object_id=object_id, interfaces_l3=[list(item) for item in l3],
                  routes=[list(item) for item in routes], vrf_routes=vrf_routes or {}, port_vrfs=port_vrfs or {})


def lab_map():
    """r1 has 10.20.5.0/24 on Gi0/1 in VRF MGMT-B; r2 only a route to 10.20.0.0/16; r3 only a default route; nx is
    NX-OS (no probes from it); fw a firewall. sw-b (10.20.5.11) is behind r1's VRF."""
    devices = {
        "r1": router("r1", "10.0.0.1", [("10.0.0.1", 24, "GigabitEthernet0/0"), ("10.20.5.1", 24, "GigabitEthernet0/1")],
                     port_vrfs={"Gi0/1": "MGMT-B"},
                     vrf_routes={"MGMT-B": [["10.20.5.0/24", "", "Gi0/1", "local"]]}),
        "r2": router("r2", "10.0.0.2", [("10.0.0.2", 24, "GigabitEthernet0/0")],
                     routes=[["10.20.0.0/16", "10.0.0.1", "Gi0/0", "ospf"], ["0.0.0.0/0", "10.0.0.254", "Gi0/0",
                                                                             "static"]]),
        "r3": router("r3", "10.0.0.3", [("10.0.0.3", 24, "GigabitEthernet0/0")],
                     routes=[["0.0.0.0/0", "10.0.0.254", "Gi0/0", "static"]]),
        "nx": router("nx", "10.0.0.4", [("10.20.5.4", 24, "Ethernet1/1")], kind=SWITCH,
                     descr="Cisco Nexus Operating System (NX-OS) Software"),
        "fw": router("fw", "10.0.0.5", [("10.20.5.5", 24, "ethernet1/1")], kind=FIREWALL, descr="Palo Alto Networks",
                     object_id="1.3.6.1.4.1.25461.2.3.1"),
        "sw-b": Device("sw-b", name="sw-b", mgmt_ip="10.20.5.11", kind=SWITCH, source="unreachable"),
    }
    return NetworkMap(devices=devices)


class FakeRouter:
    """A router's CISCO-RTTMON-MIB, handed out like SnmpClient."""

    def __init__(self):
        self.mib = {}
        self.uptime = 100000
        self.silent = False

    def probe(self, entry, target, vrf="", tag="NOMAD sw-b", owner="NOMAD tester", frequency=30, kind=1, state=6):
        values = {probes.CTRL_TAG: Value(OCTET_STRING, tag.encode()),
                  probes.CTRL_OWNER: Value(OCTET_STRING, owner.encode()),
                  probes.CTRL_RTT_TYPE: Value(INTEGER, kind),
                  probes.CTRL_FREQUENCY: Value(INTEGER, frequency),
                  probes.ECHO_PROTOCOL: Value(INTEGER, 2),
                  probes.ECHO_TARGET: Value(OCTET_STRING, bytes(int(part) for part in target.split("."))),
                  probes.ECHO_VRF: Value(OCTET_STRING, vrf.encode()),
                  probes.OPER_STATE: Value(INTEGER, state)}
        for column, value in values.items():
            self.mib[parse_oid(f"{column}.{entry}")] = value

    def result(self, entry, sense, rtt, age_seconds=5):
        self.mib[parse_oid(f"{probes.LATEST_SENSE}.{entry}")] = Value(INTEGER, sense)
        self.mib[parse_oid(f"{probes.LATEST_RTT}.{entry}")] = Value(GAUGE32, rtt)
        self.mib[parse_oid(f"{probes.LATEST_TIME}.{entry}")] = Value(TIMETICKS, self.uptime - age_seconds * 100)

    def client(self, host, credential, version, timeout=2000, retries=1):
        if self.silent:
            raise SnmpError(f"No answer from {host}.")
        return self

    def get(self, oids):
        found = []
        for oid in oids:
            oid = tuple(oid)
            if oid == parse_oid(probes.SYS_UPTIME):
                found.append((oid, Value(TIMETICKS, self.uptime)))
            else:
                found.append((oid, self.mib.get(oid, Value(0x81, None))))
        return found

    def walk(self, root, **_):
        root = tuple(root)
        for oid, value in sorted(self.mib.items()):
            if oid[:len(root)] == root:
                yield oid, value


class Routers:
    """Several FakeRouters by address."""

    def __init__(self, **by_address):
        self.by_address = by_address

    def client(self, host, credential, version, timeout=2000, retries=1):
        if host not in self.by_address:
            raise SnmpError(f"No answer from {host}.")
        return self.by_address[host].client(host, credential, version, timeout, retries)


# ----------------------------------------------------------------- Configuration

def test_running_config_is_read():
    config = probes.parse_sla_config(R5_SLA)
    assert config[9998] == {"target": "10.251.5.9", "vrf": "NOMAD-TEST", "tag": "NOMAD gone", "scheduled": True}
    assert config[9999]["tag"] == "NOMAD test"
    assert config[12] == {"target": "", "vrf": "", "tag": "", "scheduled": True}  # Not ICMP echo: no target
    assert probes.existing_entry(config, "10.251.5.1", "NOMAD-TEST") == 9999
    assert probes.existing_entry(config, "10.251.5.1", "") is None  # Another VRF is another probe
    assert probes.free_entry(set(config)) == 9000
    assert probes.free_entry({9000, 9001, 9003}) == 9002


def test_setup_lines_put_the_threshold_before_the_timeout():
    text = probes.setup_text(9000, "10.20.5.11", "MGMT-B", "NOMAD sw-b", "NOMAD jared", 30)
    assert text.splitlines() == ["configure terminal", "ip sla 9000", " icmp-echo 10.20.5.11", "  vrf MGMT-B",
                                 "  tag NOMAD sw-b", "  owner NOMAD jared", "  threshold 1000", "  timeout 1000",
                                 "  frequency 30", " exit", "ip sla schedule 9000 life forever start-time now", "end"]
    assert "vrf" not in probes.setup_text(9000, "10.20.5.11", "", "NOMAD x", "")
    assert probes.removal_text(9000) == "configure terminal\nno ip sla 9000\nend"


def test_tags_pings_and_addresses():
    assert probes.make_tag("core-sw3") == "NOMAD core-sw3"
    assert probes.make_tag("café – sw") == "NOMAD caf  sw"  # Printable ASCII only
    assert len(probes.make_tag("x" * 200)) == probes.TAG_LENGTH
    assert probes.is_nomad_tag("nomad sw-b") and not probes.is_nomad_tag("WAN check")
    assert probes.make_owner("jared") == "NOMAD jared"
    assert probes.ping_command("10.1.1.1", "B") == "ping vrf B 10.1.1.1 repeat 2 timeout 1"
    assert probes.ping_summary("Success rate is 100 percent (2/2), round-trip min/avg/max = 1/1/2 ms") == \
        "2 of 2 answered (1 ms)"
    assert probes.ping_summary("Success rate is 0 percent (0/2)") == "0 of 2 answered"
    assert probes.address_ok("10.1.1.1") and not probes.address_ok("fe80::1") and not probes.address_ok("sw-b")


# ----------------------------------------------------------------- Which router

def test_candidates_connected_first_then_routes():
    found = probes.candidates(lab_map(), "10.20.5.11")
    assert [(item.router, item.vrf, item.connected) for item in found] == [("r1", "MGMT-B", True),
                                                                           ("r2", "", False)]
    assert found[0].why == "Gi0/1 10.20.5.1/24"
    assert found[1].why == "route 10.20.0.0/16 via 10.0.0.1 (ospf)"  # r3's default route doesn't count
    assert probes.candidates(lab_map(), "not an address") == []
    assert probes.readable_routers(lab_map()) == ["r1", "r2", "r3"]  # Not NX-OS, the firewall or unreachable


def test_probes_are_matched_to_devices_by_address():
    network_map = lab_map()
    old = probes.Probe("r2", "10.0.0.2", 9001, "10.20.5.11", state="active")
    new = probes.Probe("r1", "10.0.0.1", 9000, "10.20.5.11", "MGMT-B", state="active")
    stray = probes.Probe("r1", "10.0.0.1", 9002, "10.99.0.1", state="active")
    pending = probes.Probe("r1", "10.0.0.1", 8000, "10.20.5.11", state="pending")
    assert probes.assign(network_map, [old, stray, pending, new]) == {"sw-b": new}
    # A probe of an address the router has too (found on R5 in the lab: its own loopback) is the device's whose
    # management address it is; failing that, a device other than the router with it
    network_map.devices["r1"].interfaces_l3.append(["10.20.5.11", 32, "Loopback9"])
    assert probes.assign(network_map, [new]) == {"sw-b": new}
    network_map.devices["r2"].addresses.append("10.30.0.1")
    network_map.devices["r1"].addresses.append("10.30.0.1")
    own = probes.Probe("r1", "10.0.0.1", 9003, "10.30.0.1", state="active")
    assert probes.assign(network_map, [own]) == {"r2": own}


# ----------------------------------------------------------------- Reading the routers

def test_discover_and_read_results():
    r1 = FakeRouter()
    r1.probe(9000, "10.20.5.11", "MGMT-B", frequency=10)
    r1.probe(9001, "10.20.5.12", tag="WAN check")  # Not NOMAD's: left alone
    r1.probe(9002, "10.20.5.13", tag="NOMAD jitter", kind=9)  # Not an ICMP echo
    r1.result(9000, 1, 3)
    network = Routers(**{"10.0.0.1": r1})
    found = probes.discover([("r1", "10.0.0.1", "public", 1, 2000), ("r2", "10.0.0.2", "public", 1, 2000)],
                            network.client)
    assert [(probe.entry, probe.target, probe.vrf, probe.frequency, probe.state, probe.device_label)
            for probe in found.probes] == [(9000, "10.20.5.11", "MGMT-B", 10, "active", "sw-b")]
    assert found.read == {"r1"} and set(found.problems) == {"r2"}
    read = probes.poll([("r1", "10.0.0.1", "public", 1, 2000, [9000]), ("r2", "10.0.0.2", "public", 1, 2000, [9])],
                       network.client)
    reading = read["r1"][9000]
    assert reading.ok and reading.rtt == 3 and reading.age == 5
    assert isinstance(read["r2"], str)  # Didn't answer: why
    probe = found.probes[0]
    assert probes.stale(probe, reading) == ""
    r1.result(9000, 1, 3, age_seconds=600)
    assert "600 s old" in probes.stale(probe, probes.poll([("r1", "10.0.0.1", "p", 1, 2000, [9000])],
                                                          network.client)["r1"][9000])
    assert probes.stale(probe, probes.Reading()) == "the probe has no result yet"
    assert "pending" in probes.stale(probes.Probe("r1", "a", 1, "b", state="pending"), reading)


# ----------------------------------------------------------------- The monitor's rules

def test_cannot_check_is_unknown_not_down():
    clock = [1000.0]
    tracker = monitor.StatusTracker(clock=lambda: clock[0])
    via = {"b": "r1 (vrf MGMT-B)"}
    changes = tracker.update({"b": 4}, via)
    assert tracker.get("b").via == "r1 (vrf MGMT-B)" and changes[0].via == "r1 (vrf MGMT-B)"
    clock[0] += 30
    changes = tracker.cannot_check({"b": "r1 isn't answering SNMP"}, via)
    assert [(change.status, change.problem) for change in changes] == [(UNKNOWN, "r1 isn't answering SNMP")]
    assert tracker.cannot_check({"b": "r1 isn't answering SNMP"}, via) == []  # Said once
    assert monitor.change_text(changes[0], "sw-b", "10.20.5.11") == \
        "sw-b (10.20.5.11) can't be checked: r1 isn't answering SNMP"
    clock[0] += 30
    tracker.update({"b": None}, via)
    tracker.update({"b": None}, via)
    down = tracker.get("b")
    assert down.status == DOWN and down.problem == ""
    text = monitor.change_text(monitor.Change("b", DOWN, 0, 60, None, "r1 (vrf MGMT-B)"), "sw-b", "10.20.5.11")
    assert text == "sw-b (10.20.5.11) is down: no answer to the IP SLA ping from r1 (vrf MGMT-B) (it had been up " \
                   "for 1 min)"
    up = monitor.Change("b", UP, 0, None, 2, "r1 (vrf MGMT-B)")
    assert monitor.change_text(up, "sw-b", "10.20.5.11") == "sw-b (10.20.5.11) is up (2 ms, pinged from r1 (vrf " \
                                                             "MGMT-B))"


def test_monitor_checks_probed_devices_from_their_router(app):
    network_map = lab_map()
    r1 = FakeRouter()
    r1.probe(9000, "10.20.5.11", "MGMT-B", frequency=10)
    r1.result(9000, 1, 3)
    network = Routers(**{"10.0.0.1": r1})
    watcher = netmap_monitor.NetworkMonitor(pinger=lambda address: None)
    watcher.client_factory = network.client
    watcher.access = lambda address: ("public", 1, 2000)
    watcher.set_map(network_map)
    assert watcher.probes == {}
    watcher.on_discovered(probes.discover([("r1", "10.0.0.1", "public", 1, 2000)], network.client))
    assert set(watcher.probes) == {"sw-b"} and watcher.via("sw-b") == "r1 (vrf MGMT-B)"
    assert watcher.probe_targets() == [("r1", "10.0.0.1", "public", 1, 2000, [9000])]
    watcher.timer.start(60000)  # Running, without a poll of its own
    watcher.on_results({"sw-b": None}, {})  # A poll started before the probe was found: nothing said about it
    assert watcher.status("sw-b").status == UNKNOWN and watcher.lines == []
    pings = {key: None for key in watcher.targets if key != "sw-b"}

    def poll():
        watcher.on_results(dict(pings), probes.poll(watcher.probe_targets(), network.client))

    poll()
    state = watcher.status("sw-b")
    assert state.status == UP and state.rtt == 3 and state.via == "r1 (vrf MGMT-B)"
    assert watcher.status_text("sw-b") == "Up (from r1 (vrf MGMT-B))"
    r1.uptime += 1000
    r1.result(9000, 4, 0)  # Timed out
    poll()
    poll()  # The same result read twice counts once
    assert watcher.status("sw-b").status == UP
    r1.uptime += 1000
    r1.result(9000, 4, 0)
    poll()
    assert watcher.status("sw-b").status == DOWN
    assert "no answer to the IP SLA ping from r1 (vrf MGMT-B)" in watcher.lines[-1]
    r1.silent = True
    poll()
    assert watcher.status("sw-b").status == UNKNOWN and watcher.status_text("sw-b") == "Can't check"
    assert "r1 isn't answering SNMP" in watcher.lines[-1]
    assert "1 can't check" in watcher.summary()
    watcher.shutdown()


def test_box_of_a_device_checked_from_a_router(app):
    """The crawl couldn't reach it but a router can: the box names the router, not Unreachable, and isn't red."""
    from nomad.ui.netmap_view import DeviceItem
    from nomad.ui.theme import COLORS
    device = Device("sw-b", name="sw-b", mgmt_ip="10.20.5.11", kind=SWITCH, source="unreachable")
    item = DeviceItem(device, {}, None)
    assert item.detail_lines()[1] == ("Unreachable", COLORS["error"]) and item.name_color() == COLORS["error"]
    assert "Unreachable when crawled" in item.toolTip()
    item.monitor_state = monitor.DeviceStatus(status=UP, rtt=4, via="r1 (vrf MGMT-B)")
    item.update_tip()
    assert item.detail_lines() == [("10.20.5.11  ·  4 ms", COLORS["muted"]), ("Via r1", COLORS["muted"])]
    assert item.name_color() == COLORS["text"]
    assert "Checked from r1 (vrf MGMT-B) with an IP SLA ping" in item.toolTip()
    item.monitor_state = monitor.DeviceStatus(status=DOWN, since=1.0, via="r1 (vrf MGMT-B)")
    assert item.detail_lines()[1][0].startswith("Down for")  # Down still says so, router or not
    item.monitor_state = None  # Not monitored: back to what the crawl found
    item.update_tip()
    assert item.detail_lines()[1][0] == "Unreachable" and "Checked from" not in item.toolTip()


# ----------------------------------------------------------------- Sending

class FakeShell:
    def __init__(self, config=R5_SLA, ping="Success rate is 100 percent (2/2), round-trip min/avg/max = 1/1/2 ms"):
        self.config, self.ping, self.commands = config, ping, []

    def run(self, command, timeout=None):
        self.commands.append(command)
        return self.config if command.startswith("show running-config") else self.ping


class FakePusher:
    def __init__(self, shell, refuse=""):
        self.the_shell, self.refuse = shell, refuse
        self.sent, self.taken, self.saved, self.problems = [], [], [], {}

    def shell(self, address, names=()):
        return self.the_shell

    def set_up(self, address, text, applet="", names=()):
        self.sent.append(text)
        if self.refuse and self.refuse in text:
            return configpush.Outcome(transcript=text, refused=[(self.refuse, ["% Invalid input"])])
        return configpush.Outcome(ok=True, transcript=text)

    def take_away(self, address, text, names=()):
        self.taken.append(text)
        return configpush.Outcome(ok=True, transcript=text)

    def save_config(self, address, names=()):
        self.saved.append(address)
        return True, "[OK]"

    def forget(self, address):
        pass

    def close(self):
        pass


def run_thread(jobs, pusher, adding=True, save=False):
    thread = netmap_probes.ProbeThread(jobs, lambda should_stop: pusher, adding, save)
    done, notes = [], []
    thread.item_done.connect(lambda item, ok, text: done.append((item.device, ok, text)))
    thread.note.connect(notes.append)
    thread.run()  # On this thread: the signals arrive at once
    return done, notes


def test_adding_uses_a_probe_already_there_and_numbers_new_ones(app):
    pusher = FakePusher(FakeShell())
    job = netmap_probes.Job("r1", "R5", "10.0.0.1", ["R5"], [
        netmap_probes.Item(0, "lo", "lo", "10.251.5.1", "NOMAD-TEST", tag="NOMAD lo"),
        netmap_probes.Item(1, "sw-b", "sw-b", "10.20.5.11", "MGMT-B", tag="NOMAD sw-b", owner="NOMAD jared"),
        netmap_probes.Item(2, "sw-c", "sw-c", "10.20.5.12", "MGMT-B", tag="NOMAD sw-c")])
    done, notes = run_thread([job], pusher, save=True)
    assert done[0] == ("lo", True, "R5 already has IP SLA 9999 for it: using that")
    assert done[1] == ("sw-b", True, "Added IP SLA 9000 on R5 (test ping: 2 of 2 answered (1 ms))")
    assert done[2][2].startswith("Added IP SLA 9001 on R5")  # The next free number
    assert "ip sla 9000" in pusher.sent[0] and "  vrf MGMT-B" in pusher.sent[0]
    assert pusher.saved == ["10.0.0.1"] and notes == ["R5: configuration saved (write memory)."]
    assert "ping vrf MGMT-B 10.20.5.11 repeat 2 timeout 1" in pusher.the_shell.commands


def test_a_refused_probe_is_cleaned_away(app):
    pusher = FakePusher(FakeShell(ping="Success rate is 0 percent (0/2)"), refuse="vrf NOPE")
    job = netmap_probes.Job("r1", "R5", "10.0.0.1", [], [netmap_probes.Item(0, "x", "x", "10.9.9.9", "NOPE"),
                                                         netmap_probes.Item(1, "y", "y", "10.9.9.10", "")])
    done, notes = run_thread([job], pusher)
    assert done[0][1] is False and "refused it: vrf NOPE" in done[0][2]
    assert pusher.taken == ["configure terminal\nno ip sla 9000\nend"]
    assert done[1][1] is True and "test ping got no answer" in done[1][2]
    assert notes == []  # Nothing saved unless asked


def test_taking_away(app):
    pusher = FakePusher(FakeShell())
    job = netmap_probes.Job("r1", "R5", "10.0.0.1", [], [netmap_probes.Item(-1, "lo", "lo", "10.251.5.1", entry=9999),
                                                         netmap_probes.Item(-1, "", "gone", "10.9.9.9", entry=4)])
    done, _ = run_thread([job], pusher, adding=False)
    assert done == [("lo", True, "Took IP SLA 9999 off R5"), ("", True, "IP SLA 4 isn't on R5 any more")]
    assert pusher.taken == ["configure terminal\nno ip sla 9999\nend"]


# ----------------------------------------------------------------- The page

def test_monitor_from_a_router_on_the_page(app, tmp_path, monkeypatch):
    from PyQt5.QtCore import pyqtSignal
    from PyQt5.QtWidgets import QMenu, QWidget

    from nomad.netmap import store
    from nomad.ui import netmap_tab

    class Window(QWidget):
        adapter_changed = pyqtSignal(object)
        snapshot_changed = pyqtSignal(object)

        def current_adapter(self):
            return None

        def __getattr__(self, name):
            return lambda *args, **kwargs: None

    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    try:
        from unittest.mock import Mock
        for name in ("terminal_tab", "scp_tab"):
            stub = Mock()
            stub.saved_matches.return_value = []
            setattr(page.window, name, stub)
        page.window.session_store = None
        page.on_crawled(lab_map())
        shown = []
        monkeypatch.setattr(QMenu, "exec_", lambda menu, *args: shown.append(
            {action.text(): action.menu() for action in menu.actions() if not action.isSeparator()}))
        page.show_device_menu("sw-b", None)
        tools = shown[-1]["Tools"]
        assert "Monitor from a Router..." in [action.text() for action in tools.actions()]
        page.update_map_menu()
        page.probes_action.trigger()  # The Map menu's way in: the dialog, with no devices added
        assert page.probe_dialog.isVisible() and not page.probe_dialog.items
        page.show_probes(["sw-b", "r3"])
        dialog = page.probe_dialog
        assert sorted(dialog.items.values()) == ["r3", "sw-b"]
        row = next(row for row, key in dialog.items.items() if key == "sw-b")
        assert dialog.add_table.cellWidget(row, 2).currentText() == "r1 (vrf MGMT-B)"
        assert dialog.add_table.cellWidget(row, 3).text() == "MGMT-B"
        assert dialog.add_table.item(row, 4).text() == "Gi0/1 10.20.5.1/24"
        dialog.add_table.cellWidget(row, 2).setCurrentIndex(1)  # r2, by its route
        assert dialog.add_table.cellWidget(row, 3).text() == ""
        dialog.add_table.cellWidget(row, 2).setCurrentIndex(0)
        jobs = dialog.planned()
        by_router = {job.router: [(item.device, item.target, item.vrf, item.tag) for item in job.items]
                     for job in jobs}
        assert sorted(by_router["r1"]) == [("r3", "10.0.0.3", "", "NOMAD r3"),  # r1 shares its subnet
                                           ("sw-b", "10.20.5.11", "MGMT-B", "NOMAD sw-b")]
        dialog.add_table.cellWidget(row, 1).setText("sw-b.corp")
        assert dialog.planned() is None and "isn't an IP address" in dialog.status_label.text()
        dialog.close()
    finally:
        page.shutdown()
