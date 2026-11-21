"""The NetFlow and NetFlow Config pages: what the flows show, choosing a router and interface (also from the Network
Map), collecting here, and building and pushing the Flexible NetFlow configuration."""
import os
import socket
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QSettings, Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad import flowconfig  # noqa: E402
from nomad.flows import store  # noqa: E402
from nomad.flows.api import FlowSource  # noqa: E402
from nomad.netmap import configpush  # noqa: E402
from nomad.netmap.model import ROUTER, SNMP, Device, Link, NetworkMap  # noqa: E402
from nomad.ui import flows_tab  # noqa: E402
from nomad.ui.flow_config_tab import FlowConfigTab, FlowPushThread  # noqa: E402
from nomad.ui.flows_tab import FlowsTab  # noqa: E402
from nomad.ui.table_filter import FilterHeader  # noqa: E402
from tests.flow_samples import FNF_FIELDS, data_set, fnf_record, v9_packet, v9_template  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class MapPage:
    def __init__(self):
        self.network_map = NetworkMap()
        self.network_map.devices["r1"] = Device("r1", name="core-rtr", mgmt_ip="10.0.0.1", kind=ROUTER, source=SNMP,
                                                interfaces_l3=[["10.9.9.1", 30, "Gi0/1"]])
        self.network_map.devices["sw"] = Device("sw", name="sw1", mgmt_ip="10.0.0.2", kind="switch", source=SNMP)
        self.network_map.links.append(Link("r1", "sw", "Gi0/0", "Gi1/0/1"))
        self.timeout = 1000

    def snmp_access(self, address):
        return None, None


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.netmap_tab = MapPage()
        self.statuses = []

    def show_status(self, text):
        self.statuses.append(text)


class FakeSource(FlowSource):
    description = "a test"

    def __init__(self):
        self.asked = []
        self.found_for = []

    def status(self):
        return {"running": True, "port": 2055, "exporters": {"10.9.9.1": {"problem": "", "waiting": 0}},
                "raw_seconds": 7200}

    def exporters(self):
        return [{"exporter": "10.9.9.1", "first_seen": 0, "last_seen": 0, "packets": 1, "flows": 1, "bytes": 1,
                 "version": 9, "interfaces": 2}, {"exporter": "192.0.2.77", "first_seen": 0, "last_seen": 0,
                                                  "packets": 1, "flows": 1, "bytes": 1, "version": 9,
                                                  "interfaces": 0}]

    def interfaces(self, exporter):
        if exporter != "10.9.9.1":
            return []
        return [{"ifindex": 1, "name": "Gi0/0", "description": "GigabitEthernet0/0", "seen": 0},
                {"ifindex": 2, "name": "Gi0/1", "description": "To the ISP", "seen": 0}]

    def top(self, exporter, ifindex, direction, kind, start, end, limit=25):
        self.asked.append((exporter, ifindex, direction, kind))
        rows = {store.SOURCES: [["10.0.0.2", 6000, 10, 2], ["10.5.5.5", 2000, 4, 1]],
                store.DESTINATIONS: [["8.8.8.8", 8000, 14, 3]],
                store.APPLICATIONS: [["HTTPS", 7000, 12, 2], ["DNS", 1000, 2, 1]],
                store.CONVERSATIONS: [["10.0.0.2|8.8.8.8|6|443", 6000, 10, 2]]}[kind]
        return {"rows": rows, "other": [500, 1, 1] if kind == store.SOURCES else [0, 0, 0],
                "total": [8500, 15, 4]}

    def series(self, exporter, ifindex, start, end):
        return [[int(end // 60) * 60 - 60, 6000, 2500]]

    def flows(self, address="", start=0.0, end=None, exporter="", limit=500):
        self.found_for.append(address)
        return [{"end": time.time(), "start": time.time() - 5, "exporter": "10.9.9.1", "in_if": 1, "out_if": 2,
                 "src": "10.0.0.2", "dst": "8.8.8.8", "sport": 51000, "dport": 443, "proto": 6, "app": "HTTPS",
                 "bytes": 6000, "packets": 10, "flags": 0}]


def settle(condition, ms=5000):
    deadline = time.monotonic() + ms / 1000
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        QTest.qWait(20)
    QApplication.processEvents()


@pytest.fixture
def page(app):
    window = Window()
    page = FlowsTab(window)
    page.restore_settings(QSettings("NOMAD-test-flows", "none"))
    page.resize(1000, 700)
    page.source = FakeSource()
    window.show()  # The page refreshes only while it shows
    page.show()
    yield page
    page.shutdown()
    window.close()
    window.deleteLater()


def test_page_shows_the_flows_of_the_first_router(page):
    page.refresh()
    settle(lambda: page.tables[store.SOURCES].rowCount() == 3)
    assert page.exporter_combo.itemText(0) == "core-rtr (10.9.9.1)"  # Named from the map (an interface address)
    assert page.interface_combo.itemText(0) == "Every interface"
    assert page.interface_combo.itemText(1) == "Gi0/0  (ifIndex 1)"  # IOS's long name isn't repeated
    assert page.interface_combo.itemText(2) == "Gi0/1 - To the ISP  (ifIndex 2)"
    sources = page.tables[store.SOURCES]
    rows = [[sources.item(row, column).text() for column in (0, 1)] for row in range(3)]
    assert rows == [["10.0.0.2", "sw1"], ["10.5.5.5", ""], ["Other addresses", ""]]
    assert page.tables[store.CONVERSATIONS].item(0, 2).text() == "HTTPS"
    assert page.graph.minutes and page.graph.minutes[0][1] == pytest.approx(800)  # 6000 bytes a minute in
    totals = page.total_label.text()  # Every interface: what came in, from the minutes
    assert "<b>Through the router</b> 5.9 KB" in totals and "peak 800 b/s" in totals
    assert "<b>Out</b>" not in totals and "4 flows over the" in totals
    assert not page.direction_combo.isEnabled()  # Every interface: counted as it came in


def test_tables_filter_and_keep_their_sort(page):
    page.refresh()
    sources = page.tables[store.SOURCES]
    settle(lambda: sources.rowCount() == 3)
    table_filter = page.table_filters[sources]
    assert isinstance(sources.horizontalHeader(), FilterHeader)  # The funnel in each header, as on the map
    assert sources.horizontalHeader().sortIndicatorSection() == 2  # Bytes, biggest first
    table_filter.set_filter(0, {"10.5.5.5"})
    assert [sources.isRowHidden(row) for row in range(3)] == [True, False, True]
    assert page.tabs.tabText(0) == "Top Talkers (1 of 3)"
    table_filter.sort(0, Qt.AscendingOrder)  # By address
    sources.setRowCount(0)
    page.refresh()  # Filled again: the filter and the sort stay
    settle(lambda: sources.rowCount() == 3)
    shown = [sources.item(row, 0).text() for row in range(3) if not sources.isRowHidden(row)]
    assert shown == ["10.5.5.5"] and page.tabs.tabText(0) == "Top Talkers (1 of 3)"
    assert sources.item(0, 0).text() == "10.0.0.2"  # A to Z, not by Bytes
    table_filter.clear()
    assert page.tabs.tabText(0) == "Top Talkers"
    page.find_flows()
    settle(lambda: page.find_table.rowCount() == 1)
    assert page.find_table.horizontalHeader().sortIndicatorOrder() == Qt.DescendingOrder  # Newest first


def test_choosing_an_interface_and_direction_asks_for_them(page):
    page.refresh()
    settle(lambda: page.interface_combo.count() == 3)
    page.source.asked.clear()
    page.interface_combo.setCurrentIndex(2)
    page.direction_combo.setCurrentIndex(page.direction_combo.findData(store.IN))
    settle(lambda: ("10.9.9.1", 2, store.IN, store.SOURCES) in page.source.asked)
    assert page.direction_combo.isEnabled()
    settle(lambda: "<b>Out</b>" in page.total_label.text())
    totals = page.total_label.text()  # One interface: in and out side by side
    assert "<b>In</b> 5.9 KB" in totals and "<b>Out</b> 2.4 KB" in totals
    assert "peak 333 b/s" in totals and "4 flows arriving over the" in totals
    assert "No live rate" in page.rate_label.text()  # The map has no SNMP credentials


def test_from_the_map_chooses_the_router_and_port(page):
    page.refresh()
    settle(lambda: page.exporter_combo.count() == 2)
    page.exporter_combo.setCurrentIndex(1)
    page.source.asked.clear()
    page.show_flows_for(["10.0.0.1", "10.9.9.1"], "GigabitEthernet0/1")
    settle(lambda: page.interface_combo.currentData() == 2 and page.exporter_combo.currentData() == "10.9.9.1")
    settle(lambda: any(item[:2] == ("10.9.9.1", 2) for item in page.source.asked))
    assert page.wanted is None


def test_find_flows_and_right_click_find(page):
    page.find_input.setText("10.0.0.2")
    page.find_flows()
    settle(lambda: page.find_table.rowCount() == 1)
    assert page.source.found_for == ["10.0.0.2"]
    assert page.find_table.item(0, 2).text() == "core-rtr"
    assert page.find_table.item(0, 10).text() == "HTTPS"
    page.find_address("8.8.8.8")
    settle(lambda: page.source.found_for[-1:] == ["8.8.8.8"])


def free_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_collect_here_reads_flows_sent_to_it(app, tmp_path, monkeypatch):
    monkeypatch.setattr(flows_tab, "flows_db_path", lambda: tmp_path / "flows.db")
    from nomad.flows import collector
    monkeypatch.setattr(collector, "FLUSH_SECONDS", 0.1)
    window = Window()
    page = FlowsTab(window)
    page.resize(1000, 700)
    window.show()
    page.show()
    try:
        port = free_udp_port()
        page.port_input.setValue(port)
        page.start_collect_here()
        assert page.local is not None and page.collect_button.text() == "Stop Collecting Here"
        assert "this NOMAD" in page.source_label.text()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        now = int(time.time())
        sock.sendto(v9_packet([v9_template(256, FNF_FIELDS), data_set(256, [fnf_record(
            "10.1.1.5", "10.2.2.9", 51000, 443, octets=777)])], export_time=now), ("127.0.0.1", port))
        sock.close()
        settle(lambda: page.local.status()["flows"] == 1)
        settle(lambda: page.source.exporters() != [])  # Written
        page.refresh()
        settle(lambda: page.tables[store.SOURCES].rowCount() >= 1, 8000)
        assert page.tables[store.SOURCES].item(0, 0).text() == "10.1.1.5"
        assert "1 router sending" in page.source_label.text()
        # A second NOMAD on this computer can't take the port
        other = FlowsTab(Window())
        other.port_input.setValue(port)
        other.start_collect_here()
        assert other.local is None and "in use" in other.source_label.text()
        other.shutdown()
        page.stop_collect_here()
        assert page.local is None and page.collect_button.text() == "Collect Here"
    finally:
        page.shutdown()
        window.close()
        window.deleteLater()


# --------------------------------------------------------------------- NetFlow Config


@pytest.fixture
def config_page(app):
    page = FlowConfigTab(Window())
    page.destinations_input.setText("10.0.0.50")
    page.interfaces_input.setText("Gi0/0, Gi0/1")
    yield page
    page.shutdown()


def test_config_preview_follows_the_form(config_page):
    lines = config_page.lines
    assert lines[0] == "configure terminal" and lines[-1] == "end"
    assert " destination 10.0.0.50" in lines and " transport udp 2055" in lines
    assert lines.count(" ip flow monitor NOMAD-MONITOR input") == 2
    assert " cache timeout active 60" in lines
    config_page.applications_check.setChecked(True)
    config_page.sampling_input.setValue(100)
    config_page.vrf_input.setText("Mgmt-intf")
    assert " match application name" in config_page.lines
    assert " ip flow monitor NOMAD-MONITOR sampler NOMAD-SAMPLER input" in config_page.lines
    assert " destination 10.0.0.50 vrf Mgmt-intf" in config_page.lines
    assert "NBAR2" in config_page.status_label.text()
    config_page.show_combo.setCurrentIndex(1)
    assert " no ip flow monitor NOMAD-MONITOR sampler NOMAD-SAMPLER input" in config_page.lines
    assert "no flow record NOMAD-RECORD" in config_page.lines


def test_config_problems_stop_sending(config_page):
    config_page.destinations_input.setText("")
    assert config_page.lines == [] and not config_page.send_button.isEnabled()
    config_page.destinations_input.setText("10.0.0.50 10.0.0.51 10.0.0.52")
    assert "2 computers at most" in config_page.status_label.text()
    config_page.destinations_input.setText("10.0.0.50 10.0.0.51")
    assert "flow exporter NOMAD-EXPORTER-2" in config_page.lines
    config_page.routers_input.setText("10.0.0.1")
    assert config_page.push_button.isEnabled()


def test_config_settings_round_trip(config_page, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    config_page.applications_check.setChecked(True)
    config_page.routers_input.setText("10.0.0.1")
    config_page.save_settings(settings)
    other = FlowConfigTab(Window())
    other.restore_settings(settings)
    assert other.applications_check.isChecked() and other.routers_input.text() == "10.0.0.1"
    assert other.lines == config_page.lines
    other.shutdown()


def test_prefill_from_the_map(config_page):
    config_page.interfaces_input.setText("")
    config_page.prefill(["10.0.0.1"], ["Gi0/0", "Gi0/1"])
    assert config_page.routers_input.text() == "10.0.0.1"
    assert config_page.interfaces_input.text() == "Gi0/0, Gi0/1" and not config_page.routed_check.isChecked()


class FakeShell:
    def __init__(self, running):
        self.running = running

    def run(self, command, timeout=None):
        if command.startswith("show ip interface brief"):
            return ("Interface              IP-Address      OK? Method Status                Protocol\n"
                    "GigabitEthernet1       unassigned      YES unset  up                    up\n"
                    "GigabitEthernet1.172   172.18.0.15     YES NVRAM  up                    up\n"
                    "GigabitEthernet2       8.0.0.18        YES NVRAM  up                    up\n"
                    "GigabitEthernet4       10.4.4.4        YES NVRAM  administratively down down\n"
                    "Loopback0              10.18.0.15      YES NVRAM  up                    up\n")
        return self.running


class FakePusher:
    def __init__(self, running="", refuse=()):
        self.shell_ = FakeShell(running)
        self.sent = []
        self.refuse = refuse
        self.problems = {}

    def shell(self, address, names=()):
        return self.shell_

    def take_away(self, address, text, names=()):
        self.sent.append(("take away", text))
        refused = [(line, ["% sampler: Failed to delete sampler: No details provided"])
                   for line in text.splitlines() if line.startswith("no sampler")]
        return configpush.Outcome(ok=not refused, refused=refused, transcript=text,
                                  problem=f"It refused {refused[0][0]}" if refused else "")

    def set_up(self, address, text, applet="", names=()):
        self.sent.append(("set up", text))
        refused = [(line, ["% Invalid input"]) for line in text.splitlines() if line.strip() in self.refuse]
        return configpush.Outcome(ok=not refused, refused=refused, transcript=text,
                                  problem=f"It refused {refused[0][0]}" if refused else "")

    def save_config(self, address, names=()):
        return True, "[OK]"


RUNNING = ("interface GigabitEthernet1.172\n ip flow monitor NOMAD-MONITOR input\n"
           "interface GigabitEthernet9\n ip flow monitor OTHER input\n")


def test_push_takes_out_the_old_then_sets_up_every_routed_interface():
    options = flowconfig.FlowOptions(destinations=["192.168.5.25"], source_interface="Loopback0")
    thread = FlowPushThread(["10.18.0.15"], options, [], True, True, None)
    pusher = FakePusher(RUNNING)
    ok, message, _ = thread.one(pusher, "10.18.0.15")
    assert ok and message.startswith("Set up on Gi1.172, Gi2.")
    (first, removal), (second, setup) = pusher.sent
    assert first == "take away" and "interface GigabitEthernet1.172\n no ip flow monitor NOMAD-MONITOR input" in \
        removal and "GigabitEthernet9" not in removal  # Another monitor is left alone
    assert second == "set up" and "interface GigabitEthernet2\n ip flow monitor NOMAD-MONITOR input" in setup
    assert "GigabitEthernet4" not in setup and "Loopback0\n ip flow" not in setup


def test_push_refused_and_take_out():
    options = flowconfig.FlowOptions(destinations=["192.168.5.25"], applications=True)
    refused = FlowPushThread(["r"], options, ["Gi0/0"], False, True, None)
    ok, message, _ = refused.one(FakePusher(refuse={"match application name"}), "r")
    assert not ok and "match application name" in message
    taking = FlowPushThread(["r"], options, [], False, False, None)
    ok, message, _ = taking.one(FakePusher(RUNNING), "r")
    assert ok and message == "Taken out (from 1 interface)."  # The sampler that never was is harmless


def test_routed_interfaces_and_monitored_parsing():
    brief = FakeShell("").run("show ip interface brief")
    assert flowconfig.routed_interfaces(brief) == ["GigabitEthernet1.172", "GigabitEthernet2"]
    assert flowconfig.parse_monitored(RUNNING, ["NOMAD-MONITOR"]) == [
        ("GigabitEthernet1.172", "ip flow monitor NOMAD-MONITOR input")]


class CounterClient:
    """Answers an interface's octet counters, 1.25 MB more in and 0.25 MB more out each time it's asked."""
    reads = 0

    def __init__(self, host, credential, version, timeout=2000, retries=0):
        self.host = host

    def get(self, oids):
        from nomad.netmap import collect
        from nomad.snmp import Value, parse_oid
        CounterClient.reads += 1
        values = {collect.IF_HC_IN_OCTETS: 1_250_000 * CounterClient.reads,
                  collect.IF_HC_OUT_OCTETS: 250_000 * CounterClient.reads, collect.IF_HIGH_SPEED: 1000}
        found = []
        for oid in oids:
            text = ".".join(str(part) for part in oid)
            column = next((column for column in values if text.startswith(column + ".")), None)
            found.append((oid, Value(0x46, values[column]) if column else Value(0x02, 0)))
        return found


def test_live_rate_from_snmp(page, monkeypatch):
    import nomad.snmp
    monkeypatch.setattr(flows_tab, "LIVE_SECONDS", 0.2)
    monkeypatch.setattr(nomad.snmp, "SnmpClient", CounterClient)  # The page's own thread too: no network
    page.refresh()
    settle(lambda: page.interface_combo.count() == 3)
    page.window.netmap_tab.snmp_access = lambda address: ("n0mad", "2c")
    thread = flows_tab.LiveRateThread("10.9.9.1", "n0mad", "2c", 1000, 2, client_factory=CounterClient)
    samples = []
    thread.sampled.connect(samples.append)
    thread.start()
    settle(lambda: len(samples) >= 2)
    thread.stop()
    thread.wait(2000)
    page.interface_combo.setCurrentIndex(2)
    page.live_where = ("10.9.9.1", 2)
    first, second = samples[:2]
    page.last_sample = None
    page.on_live_sample(first)
    page.on_live_sample((first[0] + 1.0, first[1] + 1_250_000, first[2] + 250_000, 1000))
    assert page.live[-1][1] == pytest.approx(10_000_000) and page.live[-1][2] == pytest.approx(2_000_000)
    assert page.rate_label.text().startswith("Now: in 10.0 Mb/s, out 2.0 Mb/s of 1.0 Gb/s (1% in, 0% out)")
    assert second[1] > first[1]
    page.stop_live()


def test_same_interface_names():
    assert flows_tab.same_interface("GigabitEthernet0/1", "Gi0/1")
    assert flows_tab.same_interface("Loopback0", "Lo0") and flows_tab.same_interface("BDI96", "BD96")
    assert not flows_tab.same_interface("To the ISP", "Gi0/1")
    assert not flows_tab.same_interface("Loopback10", "Lo0")
