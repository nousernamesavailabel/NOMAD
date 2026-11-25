"""Web servers on the Network Map: checked on a TCP port (or a web address) instead of ping, so one that drops ping
still has a status and a round trip time; refused is down, a 5xx answer is up with a warning."""
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from nomad import tcpcheck  # noqa: E402
from nomad.httpcheck import HttpResult  # noqa: E402
from nomad.netmap import checks, monitor, shared  # noqa: E402
from nomad.netmap.model import NO_SNMP, SERVER, SNMP, SWITCH, WEB, Device, NetworkMap  # noqa: E402
from nomad.netmap.monitor import DOWN, UP  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# ----------------------------------------------------------------- Timing a TCP connection

def test_connect_time_times_an_open_port_and_says_refused_for_a_closed_one():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    try:
        result = tcpcheck.connect_time("127.0.0.1", listener.getsockname()[1], timeout=2)
        assert result.ok and result.rtt is not None and result.rtt >= 0
    finally:
        listener.close()
    refused = tcpcheck.connect_time("127.0.0.1", free_port(), timeout=5)  # (Windows takes 2 s to say so)
    assert refused.outcome == tcpcheck.REFUSED and not refused.ok


def test_tcp_targets_are_split_into_host_and_port():
    assert tcpcheck.split_target("web1:8443") == ("web1", 8443)
    assert tcpcheck.split_target("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert tcpcheck.split_target("https://web1/health") == ("web1", 443)
    assert tcpcheck.split_target("http://web1:8080") == ("web1", 8080)
    assert tcpcheck.split_target("web1") is None and tcpcheck.split_target("2001:db8::1") is None


# ----------------------------------------------------------------- How a device is checked

def test_a_web_server_is_checked_on_tcp_443_unless_changed():
    web = Device("w", "web1", "10.0.0.5", kind=WEB)
    assert checks.spec_of(web) == checks.CheckSpec(checks.TCP, 443)
    assert checks.spec_of(Device("s", kind=SWITCH)).pings
    web.check = "tcp:8443"
    assert checks.spec_of(web).port == 8443 and checks.describe(checks.spec_of(web)) == "TCP 8443"
    web.check = "http:intranet/health"
    spec = checks.spec_of(web)
    assert spec == checks.CheckSpec(checks.HTTP, url="https://intranet/health") and spec.tcp_port == 443
    assert checks.parse("http:") == checks.CheckSpec(checks.HTTP)  # https://<its address>/
    assert checks.url_for(checks.CheckSpec(checks.HTTP), "10.0.0.5") == "https://10.0.0.5/"
    assert checks.parse("tcp:0") is None and checks.parse("nonsense") is None  # Its kind's way, then
    # Kept as "" when it's the kind's own way, so changing the kind changes it too
    assert checks.stored(checks.CheckSpec(checks.TCP, 443), WEB) == ""
    assert checks.stored(checks.CheckSpec(checks.TCP, 443), SERVER) == "tcp:443"
    assert checks.stored(checks.CheckSpec(checks.PING), WEB) == "ping"


class FakeConnect:
    def __init__(self, *results):
        self.results, self.asked = list(results), []

    def __call__(self, address, port, timeout):
        self.asked.append((address, port))
        return self.results.pop(0)


def test_tcp_check_outcomes():
    spec = checks.CheckSpec(checks.TCP, 443)
    assert checks.run(spec, "10.0.0.5", FakeConnect(tcpcheck.TcpResult(tcpcheck.OK, 3.6))) == checks.Outcome(4)
    refused = checks.run(spec, "10.0.0.5", FakeConnect(tcpcheck.TcpResult(tcpcheck.REFUSED, 1.0)))
    assert refused == checks.Outcome(None, "TCP 443 refused (nothing listening)")  # Refused is down
    connect = FakeConnect(tcpcheck.TcpResult(tcpcheck.TIMEOUT), tcpcheck.TcpResult(tcpcheck.OK, 0.2))
    assert checks.run(spec, "10.0.0.5", connect) == checks.Outcome(0)  # One answer of two tries is enough
    assert connect.asked == [("10.0.0.5", 443)] * 2
    lost = checks.run(spec, "10.0.0.5", FakeConnect(*[tcpcheck.TcpResult(tcpcheck.TIMEOUT)] * 2))
    assert lost == checks.Outcome(None, "no answer on TCP 443")


def test_http_check_outcomes():
    spec = checks.CheckSpec(checks.HTTP, url="https://intranet/health")
    asked = []

    def fetch(result):
        def answer(url, timeout, address=None):
            asked.append((url, address))
            return result
        return answer

    ok = HttpResult("u", connect_ms=2.2, first_byte_ms=40.0, status=200, reason="OK")
    assert checks.run(spec, "10.0.0.5", fetch=fetch(ok)) == checks.Outcome(2)  # The connection's time, not the page's
    assert asked == [("https://intranet/health", "10.0.0.5")]  # Fetched from the device's own address
    busy = HttpResult("u", connect_ms=2.0, status=503, reason="Service Unavailable")
    assert checks.run(spec, "10.0.0.5", fetch=fetch(busy)) == checks.Outcome(2, "HTTP 503 Service Unavailable")
    assert checks.run(spec, "10.0.0.5", fetch=fetch(HttpResult("u", connect_ms=2.0, status=404))).note == ""
    refused = HttpResult("u", error="10.0.0.5 refused the connection: nothing is listening on port 443.")
    assert checks.run(spec, "10.0.0.5", fetch=fetch(refused)) == checks.Outcome(None, "TCP 443 refused (nothing "
                                                                                       "listening)")
    silent = HttpResult("u", connect_ms=2.0, error="The server didn't send a valid HTTP reply: timed out")
    assert checks.run(spec, "10.0.0.5", fetch=fetch(silent)).rtt is None


def test_http_check_against_a_local_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(503 if self.path == "/broken" else 200)
            self.end_headers()
            self.wfile.write(b"x")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        good = checks.run(checks.CheckSpec(checks.HTTP, url=f"http://intranet:{port}/"), "127.0.0.1")
        assert good.rtt is not None and good.note == ""
        broken = checks.run(checks.CheckSpec(checks.HTTP, url=f"http://intranet:{port}/broken"), "127.0.0.1")
        assert broken.rtt is not None and broken.note.startswith("HTTP 503")
    finally:
        server.shutdown()
        server.server_close()


# ----------------------------------------------------------------- Monitoring

def test_poll_checks_web_servers_their_way_and_pings_the_rest():
    pinged, notes = [], {}

    def runner(spec, address):
        return checks.Outcome(None, "TCP 443 refused (nothing listening)") if address == "10.0.0.6" else \
            checks.Outcome(3)

    specs = {"w1": checks.CheckSpec(checks.TCP, 443), "w2": checks.CheckSpec(checks.TCP, 443)}
    results = monitor.poll({"s1": "10.0.0.2", "w1": "10.0.0.5", "w2": "10.0.0.6"},
                           lambda address: pinged.append(address) or 1, checks=specs, notes=notes, runner=runner)
    assert results == {"s1": 1, "w1": 3, "w2": None} and pinged == ["10.0.0.2"]
    assert notes == {"w1": "", "w2": "TCP 443 refused (nothing listening)"}


def test_refused_is_down_and_a_server_error_is_up_with_a_warning():
    clock = [1000.0]
    tracker = monitor.StatusTracker(clock=lambda: clock[0])
    tracker.update({"w": 4}, notes={"w": ""})
    refused = {"w": "TCP 443 refused (nothing listening)"}
    clock[0] += 30
    assert tracker.update({"w": None}, notes=refused) == []  # One miss isn't down yet
    clock[0] += 30
    [change] = tracker.update({"w": None}, notes=refused)
    assert change.status == DOWN and tracker.get("w").problem == "TCP 443 refused (nothing listening)"
    assert monitor.change_text(change, "web1", "10.0.0.5", "TCP 443") == \
        "web1 (10.0.0.5) is down: TCP 443 refused (nothing listening) (it had been up for 1 min)"
    clock[0] += 30
    [change] = tracker.update({"w": 5}, notes={"w": "HTTP 503 Service Unavailable"})
    assert change.status == UP and tracker.get("w").problem == "HTTP 503 Service Unavailable"
    assert monitor.change_text(change, "web1", "10.0.0.5", "HTTPS 443") == \
        "web1 (10.0.0.5) is up again, after being down for 30 s (5 ms on HTTPS 443, with a warning: HTTP 503 " \
        "Service Unavailable)"
    clock[0] += 30
    [change] = tracker.update({"w": 5}, notes={"w": ""})  # The warning ends: noted, not a change of status
    assert change.noted and change.status == UP and tracker.get("w").problem == ""
    assert monitor.change_text(change, "web1", "10.0.0.5") == "web1 (10.0.0.5) answers without a warning again"
    clock[0] += 30
    [change] = tracker.update({"w": 5}, notes={"w": "HTTP 500 Internal Server Error"})
    assert change.noted and monitor.change_text(change, "web1", "10.0.0.5").startswith(
        "web1 (10.0.0.5) answers with a warning: HTTP 500")
    assert tracker.update({"w": 5}, notes={"w": "HTTP 500 Internal Server Error"}) == []  # Said once
    assert tracker.get("w").since == 1090.0  # Still up since it came back: a warning doesn't restart it


def test_status_text_says_why_and_warns():
    from nomad.netmap import monitor_record
    down = monitor.DeviceStatus(DOWN, problem="TCP 443 refused (nothing listening)")
    assert monitor_record.status_text(down).endswith(": TCP 443 refused (nothing listening)")
    up = monitor.DeviceStatus(UP, rtt=3, problem="HTTP 503 Service Unavailable")
    assert monitor_record.status_text(up) == "Up, 3 ms, with a warning: HTTP 503 Service Unavailable"


def a_map():
    devices = {"s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP),
               "w1": Device("w1", "web1", "10.0.0.5", kind=WEB, manual=True)}
    return NetworkMap(devices=devices)


def test_nomads_monitor_checks_a_web_server_on_its_port(app):
    from nomad.ui import netmap_monitor
    page_monitor = netmap_monitor.NetworkMonitor(pinger=lambda address: 1)
    page_monitor.set_map(a_map())
    assert page_monitor.checks == {"w1": checks.CheckSpec(checks.TCP, 443)}
    page_monitor.timer.start(60000)  # Running, without a poll of its own
    page_monitor.on_results({"s1": 1, "w1": 7}, {}, {"w1": "HTTP 503 Service Unavailable"})
    assert page_monitor.status("w1").status == UP and page_monitor.status("w1").rtt == 7
    assert page_monitor.status_text("w1") == "Up with a warning"
    assert "web1 (10.0.0.5) is up (7 ms on TCP 443, with a warning: HTTP 503 Service Unavailable)" in \
        page_monitor.lines[-1]  # Said even on the first poll, as there's something to say
    assert page_monitor.counts()[UP] == 2
    page_monitor.shutdown()


def test_the_poll_thread_runs_the_checks(app):
    from nomad.ui import netmap_monitor
    got = []
    thread = netmap_monitor.PollThread({"w1": "10.0.0.5"}, lambda address: 1, (), object, None,
                                       {"w1": checks.CheckSpec(checks.TCP, 443)},
                                       lambda spec, address: checks.Outcome(None, "no answer on TCP 443"))
    thread.finished_poll.connect(lambda *args: got.append(args))
    thread.run()
    assert got == [({"w1": None}, {}, {"w1": "no answer on TCP 443"})]


def test_the_map_watcher_checks_a_web_server_on_its_port(tmp_path, monkeypatch):
    from nomad.netmap import counters, probes, tunnels
    from nomad.netmap.watch import WatchOptions
    from nomad.netmap.watch_monitor import MonitorRunner, MonitorStore, StatusReader
    from tests.test_watch_monitor import FakeAccess, FakeMaps
    clock = [1000.0]
    monkeypatch.setattr(probes, "discover", lambda routers, factory: probes.Discovery())
    monkeypatch.setattr(counters, "poll", lambda targets, indexes, factory: {})
    monkeypatch.setattr(tunnels, "poll", lambda *args, **kwargs: {})
    store = MonitorStore(tmp_path / "status.db", clock=lambda: clock[0])
    runner = MonitorRunner(FakeMaps(a_map()), [1], store, lambda map_id, settings: WatchOptions(),
                           {"interval": 60}, client_factory=object, pinger=lambda address: 2,
                           clock=lambda: clock[0], access=FakeAccess())
    checked = []
    runner.runner = lambda spec, address: checked.append((spec, address)) or \
        checks.Outcome(None, "TCP 443 refused (nothing listening)")
    for _ in range(3):
        runner.step()
        clock[0] += 61
    assert checked[0] == (checks.CheckSpec(checks.TCP, 443), "10.0.0.5")
    reader = StatusReader(tmp_path / "status.db")
    rows = {row["key"]: row for row in reader.statuses()}
    assert rows["s1"]["status"] == "up"
    assert rows["w1"]["status"] == "down" and rows["w1"]["problem"] == "TCP 443 refused (nothing listening)"
    [change] = reader.changes_after(0)
    assert change["text"] == "web1 (10.0.0.5) is down: TCP 443 refused (nothing listening)"
    reader.close()
    store.close()


# ----------------------------------------------------------------- The map

def test_the_check_is_kept_corrected_folded_and_shared():
    found = Device("w", "web1", "10.0.0.5", kind=SERVER, source=NO_SNMP)
    found.correct("kind", WEB)
    found.correct("check", "tcp:8443")
    assert found.corrections() == {"kind": WEB, "check": "tcp:8443"}
    again = Device("w", "web1", "10.0.0.5", kind=SERVER, source=NO_SNMP)  # The next crawl finds it as before
    again.apply_corrections(found.corrections())
    assert again.kind == WEB and again.check == "tcp:8443"
    assert again.found_by == "Answers on TCP 8443, no SNMP"
    network_map = NetworkMap(devices={"w": again})
    copy = shared.build(shared.flatten(network_map))  # A tribe map keeps it
    assert copy.devices["w"].check == "tcp:8443"
    manual = Device("m", "web1", "10.0.0.5", kind=WEB, manual=True, check="http:https://web1/health")
    read = Device("r", "web1", "10.0.0.5", kind=WEB, source=SNMP)
    network_map = NetworkMap(devices={"m": manual, "r": read})
    network_map.fold_device("m", read)
    assert read.check == "http:https://web1/health"


def test_device_dialog_sets_the_check(app):
    from nomad.ui.netmap_dialogs import DeviceDialog
    dialog = DeviceDialog(NetworkMap())
    dialog.name_input.setText("web1")
    dialog.ip_input.setText("10.0.0.5")
    assert dialog.check_row.spec().pings  # A switch, to start with
    dialog.kind_combo.setCurrentIndex(dialog.kind_combo.findData(WEB))
    assert dialog.check_row.spec() == checks.CheckSpec(checks.TCP, 443)  # Its kind's way follows the kind
    device, _ = dialog.values()
    assert device.kind == WEB and device.check == ""
    dialog.check_row.port_spin.setValue(8443)
    assert dialog.values()[0].check == "tcp:8443"
    dialog.kind_combo.setCurrentIndex(dialog.kind_combo.findData(SERVER))
    assert dialog.check_row.spec().port == 8443  # Set by hand: kept
    dialog.check_row.method_combo.setCurrentIndex(dialog.check_row.method_combo.findData(checks.HTTP))
    dialog.check_row.url_input.setText("ftp://nope")
    with pytest.raises(ValueError):
        dialog.values()
    dialog.check_row.url_input.setText("intranet/health")
    assert dialog.values()[0].check == "http:https://intranet/health"
    dialog.deleteLater()


def test_box_of_a_web_server_with_a_warning(app):
    from nomad.ui.netmap_view import DeviceItem, short_warning
    from nomad.ui.theme import COLORS
    item = DeviceItem(Device("w", "web1", "10.0.0.5", kind=WEB, manual=True), {}, None)
    item.monitor_state = monitor.DeviceStatus(status=UP, rtt=4, problem="HTTP 503 Service Unavailable")
    item.update_tip()
    assert item.detail_lines()[1] == ("Warning: HTTP 503", COLORS["warning"])
    assert "Monitored on TCP 443, with a warning: HTTP 503 Service Unavailable" in item.toolTip()
    assert short_warning("TCP 443 refused") == "TCP 443 refused"


def test_web_servers_are_server_assets_and_an_ansible_group():
    from nomad.inventory import KIND_GROUPS
    from nomad.ipam.asset_compare import sightings
    network_map = NetworkMap(devices={"w": Device("w", "web1", "10.0.0.5", kind=WEB, manual=True,
                                                  serial="ABC123")})
    [sighting] = sightings(network_map)
    assert sighting.kind == SERVER
    assert KIND_GROUPS[WEB] == "web_servers"


def test_dashboard_says_how_a_device_is_checked():
    from nomad.dashboard import views
    assert views.check_text(Device("w", kind=WEB)) == "TCP 443"
    assert views.check_text(Device("s", kind=SWITCH)) == ""
