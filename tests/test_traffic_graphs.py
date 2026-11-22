"""Traffic Graphs: ports' traffic kept over time (traffic_history) by the Map Watcher (shared on its computer and sent
to the tribe, API 19) and by NOMAD's own Monitor, drawn on the Traffic Graphs page, the NetFlow page's graph and
linked from the details pane (NOMAD's and the dashboard's)."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QObject, QSettings, QUrl  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad.ipam.client import IpamError, OldServerError, ServerUnreachable, TeamClient  # noqa: E402
from nomad.netmap import counters, details, traffic_history, watch_monitor, watch_service  # noqa: E402
from nomad.netmap.model import ROUTER, SNMP, SWITCH, Device, Link, NetworkMap  # noqa: E402
from nomad.netmap.traffic_history import TrafficReader, TrafficStore  # noqa: E402


def reading(port="Gi0/0", at=1000.0, rate_in=1000.0, rate_out=500.0, device="r1", speed=1000):
    return {"device": device, "port": port, "at": at, "in_bps": rate_in, "out_bps": rate_out, "speed": speed}


def small_map():
    network_map = NetworkMap()
    network_map.devices = {
        "r1": Device("r1", "R1", "10.0.0.1", kind=ROUTER, source=SNMP,
                     port_status={"Gi0/0": {"oper": "up"}, "Gi0/2": {"oper": "down"}, "Gi0/3": {"oper": "up"}}),
        "s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP),
    }
    network_map.links = [Link("r1", "Gi0/0", "s1", "Gi1/0/1")]
    network_map.graphed = {"r1": ["Gi0/2"]}
    return network_map


# --------------------------------------------------------------------- Keeping it

def test_each_reading_is_kept_once_and_added_to_its_hour(tmp_path):
    store = TrafficStore(tmp_path / "traffic.db")
    rows = [reading(at=7200 + 60 * step, rate_in=1000 * (step + 1)) for step in range(3)]
    assert store.add("tribe-x-1", rows) == 3
    assert store.add("tribe-x-1", rows) == 0  # Sent again (a retry): not counted twice
    raw = store.points("tribe-x-1", "r1", "GigabitEthernet0/0", 7000, 8000)  # The same port written out
    assert [point[1] for point in raw] == [1000, 2000, 3000]
    [hour] = store.points("tribe-x-1", "r1", "Gi0/0", 7000, 8000, hourly=True)
    assert hour == [7200, 2000, 500, 3000, 500]  # Average in, average out, peak in, peak out
    assert store.points("tribe-x-2", "r1", "Gi0/0", 7000, 8000) == []  # Another map's
    assert store.has_map("tribe-x-1") and not store.has_map("tribe-x-2")
    assert store.ports("tribe-x-1", since=0) == {("r1", "gi0/0"): ("Gi0/0", 7320)}


def test_long_spans_use_the_hours_as_the_dashboard_does():
    assert not traffic_history.use_hourly(0, 3 * 86400)
    assert traffic_history.use_hourly(0, 3 * 86400 + 1)
    from nomad.dashboard import views
    assert views.SPANS is traffic_history.SPANS  # The same spans on both


def test_old_readings_and_maps_no_longer_kept_go(tmp_path):
    now = 10 * 86400.0
    store = TrafficStore(tmp_path / "traffic.db", clock=lambda: now)
    store.add("a", [reading(at=now - traffic_history.RAW_SECONDS - 10), reading(at=now - 60)])
    store.add("b", [reading(at=now - 60)])
    store.prune(force=True, keep_maps=["a"])
    assert len(store.points("a", "r1", "Gi0/0", 0, now, hourly=False)) == 1
    assert len(store.points("a", "r1", "Gi0/0", 0, now, hourly=True)) == 2  # Its hours stay a year
    assert not store.has_map("b")


def test_bad_readings_in_a_request_are_left_out():
    rows = traffic_history.clean_rows([reading(), {"device": "r1"}, reading(rate_in=-1), "nonsense",
                                       reading(rate_in=float("nan")), dict(reading(), device="x" * 300)])
    assert rows == [reading()]
    with pytest.raises(ValueError):
        traffic_history.clean_rows("nope")
    with pytest.raises(ValueError):
        traffic_history.clean_rows([reading()] * 3, limit=2)


def test_the_watchers_file_is_read_without_writing_beside_it(tmp_path):
    path = tmp_path / "shared" / "traffic.db"
    assert TrafficReader(path).points("m", "r1", "Gi0/0", 0, 10 ** 9) == []  # No Map Watcher here
    store = TrafficStore(path, shared=True)
    store.add("m", [reading()])
    reader = TrafficReader(path)
    assert reader.has_map("m") and len(reader.points("m", "r1", "Gi0/0", 0, 2000)) == 1
    assert not (tmp_path / "shared" / "traffic.db-wal").exists()  # A rollback journal: readers needn't write
    reader.close()
    store.close()


def test_this_computers_readings_only_fill_the_watchers_gaps():
    watcher = [[1000.0 + 300 * step, 1, 1, 1, 1] for step in range(4)]  # 1000..1900
    own = [[1100.0, 5, 5, 5, 5], [5000.0, 6, 6, 6, 6]]
    assert traffic_history.outside(own, watcher, hourly=False) == [[5000.0, 6, 6, 6, 6]]
    assert traffic_history.outside(own, [], hourly=False) == own
    assert traffic_history.gap_seconds(watcher, hourly=False) == 750.0


# --------------------------------------------------------------------- Where it's read from

class FakeMaps:
    def __init__(self, reply=None, error=None):
        self.reply, self.error, self.asked = reply, error, []

    def fetch_traffic(self, map_id, device, port, start, end):
        self.asked.append((map_id, device, port))
        if self.error is not None:
            raise self.error
        return self.reply


def test_history_comes_from_the_watcher_here_else_through_the_tribe(tmp_path):
    own = TrafficStore(tmp_path / "own.db")
    own.add("tribe-x-1", [reading(at=1500.0, rate_in=7)])
    shared = tmp_path / "shared.db"
    maps = FakeMaps({"points": [[1200.0, 9, 9, 9, 9]], "hourly": False})
    history = traffic_history.history_for("tribe-x-1", "r1", "Gi0/0", 1000, 2000, maps=maps, map_id=1,
                                          watcher_file=shared, own=own)
    assert history.watcher == [[1200.0, 9, 9, 9, 9]] and not history.watcher_here
    assert [point[1] for point in history.own] == [7]
    assert maps.asked == [(1, "r1", "Gi0/0")]
    TrafficStore(shared, shared=True).add("tribe-x-1", [reading(at=1300.0, rate_in=3)])
    history = traffic_history.history_for("tribe-x-1", "r1", "Gi0/0", 1000, 2000, maps=maps, map_id=1,
                                          watcher_file=shared, own=own)
    assert history.watcher_here and [point[1] for point in history.watcher] == [3]
    assert len(maps.asked) == 1  # The Map Watcher runs here: the tribe isn't asked


def test_an_old_or_unreachable_tribe_server_says_why(tmp_path):
    own = TrafficStore(tmp_path / "own.db")
    old = traffic_history.history_for("tribe-x-1", "r1", "Gi0/0", 0, 10, maps=FakeMaps(error=OldServerError("old")),
                                      map_id=1, watcher_file=tmp_path / "none.db", own=own)
    assert "needs updating" in old.note and old.watcher == []
    away = traffic_history.history_for("tribe-x-1", "r1", "Gi0/0", 0, 10, maps=FakeMaps(error=OSError("down")),
                                       map_id=1, watcher_file=tmp_path / "none.db", own=own)
    assert "down" in away.note
    local = traffic_history.history_for("map-abc", "r1", "Gi0/0", 0, 10, watcher_file=tmp_path / "none.db", own=own)
    assert local.note == "" and local.watcher == []  # A map file: nothing to ask


# --------------------------------------------------------------------- The tribe server (API 19)

@pytest.fixture
def server(tmp_path):
    from nomad.ipam.server import IpamServer
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def team(server):
    from nomad.ipam.client import TeamKey
    from nomad.ipam.server import load_config, team_key
    config = load_config(server.directory)
    return TeamKey.from_dict(dict(team_key(config, server.directory), hosts=["127.0.0.1"], port=server.port))


def test_the_watchers_readings_go_through_the_tribe_to_every_nomad(server, tmp_path):
    from nomad.ipam.client import read_key_file
    from nomad.ipam.server import write_viewer_key
    from nomad.netmap.tribe import TribeMaps
    maps = TribeMaps(server.config["server_id"], TeamClient(team(server), user="watcher"), tmp_path / "team.db")
    map_id = maps.create("HQ", small_map(), {}, {})
    now = time.time()
    rows = [reading(at=now - 600 + 300 * step, rate_in=100 * (step + 1)) for step in range(2)]
    maps.send_traffic(map_id, rows)
    maps.send_traffic(map_id, rows)  # Again (a retry): kept once
    other = TribeMaps(server.config["server_id"], TeamClient(team(server), user="bob"), tmp_path / "bob.db")
    reply = other.fetch_traffic(map_id, "r1", "GigabitEthernet0/0", now - 3600, now)
    assert [point[1] for point in reply["points"]] == [100, 200] and reply["hourly"] is False
    long = other.fetch_traffic(map_id, "r1", "Gi0/0", now - 7 * 86400, now)
    assert long["hourly"] is True and long["points"]
    path = tmp_path / "viewer.nomadkey"
    write_viewer_key(path, server.directory)
    key = read_key_file(path, viewer=True)
    key.hosts, key.port = ["127.0.0.1"], server.port
    viewer = TeamClient(key, user="dashboard")
    assert viewer.map_traffic(map_id, "r1", "Gi0/0", now - 3600, now)["points"]  # A viewer may read it
    with pytest.raises(IpamError, match="viewer key"):
        viewer.map_request("traffic", map_id=map_id, rates=rows)  # but not send any
    with pytest.raises(IpamError):
        maps.send_traffic(map_id + 99, rows)  # No such map


# --------------------------------------------------------------------- The Map Watcher

class WatcherMaps:
    def __init__(self, error=None):
        self.sent, self.error = [], error

    def map_info(self, map_id):
        return {"name": f"map {map_id}", "record_id": "local1"}

    def send_traffic(self, map_id, rows):
        if self.error is not None:
            raise self.error
        self.sent.append((map_id, rows))


class Runner:
    def __init__(self, store, map_ids):
        self.store, self.map_ids = store, map_ids


def watcher_engine(tmp_path, maps):
    store = watch_monitor.MonitorStore(tmp_path / "status.db")
    rate = counters.Rate(800.0, 400.0, 1000, 0, 0, 300.0)
    at = time.time() - 300  # Kept a few days in traffic.db
    store.add_rates(1, [("r1", "Gi0/0", at, rate), ("r1", "Gi0/2", at, rate)])
    store.add_rates(-1, [("x1", "Gi0/1", at, rate)])  # A map on this computer, not the tribe's
    engine = watch_service.WatchEngine(maps, [], "test", listen=False, clock=lambda: 5000.0)
    engine.server_id = "srv"
    engine.monitoring = Runner(store, [1, -1])
    engine.traffic = TrafficStore(tmp_path / "shared" / "traffic.db", shared=True)
    return engine, store


def test_the_watcher_shares_its_readings_here_and_sends_the_tribes_on(tmp_path):
    maps = WatcherMaps()
    engine, store = watcher_engine(tmp_path, maps)
    engine.share_traffic()
    reader = TrafficReader(tmp_path / "shared" / "traffic.db")
    start, end = time.time() - 3600, time.time()
    assert len(reader.points("tribe-srv-1", "r1", "Gi0/0", start, end)) == 1
    assert len(reader.points("map-local1", "x1", "Gi0/1", start, end)) == 1  # Its local map's too
    assert [(map_id, [row["port"] for row in rows]) for map_id, rows in maps.sent] == [(1, ["Gi0/0", "Gi0/2"])]
    engine.share_traffic()  # Nothing new: nothing copied or sent again
    assert len(maps.sent) == 1 and len(reader.points("tribe-srv-1", "r1", "Gi0/0", start, end)) == 1
    reader.close()


def test_the_watcher_sends_again_once_the_tribe_is_back(tmp_path):
    maps = WatcherMaps(error=ServerUnreachable("away"))
    engine, store = watcher_engine(tmp_path, maps)
    engine.share_traffic()
    assert store.get_meta(watch_service.TRAFFIC_SENT, 0) == 0  # Kept for later
    assert store.get_meta(watch_service.TRAFFIC_COPIED, 0) > 0  # Copied here all the same
    maps.error = None
    engine.share_traffic()
    assert len(maps.sent) == 1


def test_an_old_tribe_server_is_asked_again_in_an_hour(tmp_path):
    maps = WatcherMaps(error=OldServerError("old"))
    engine, store = watcher_engine(tmp_path, maps)
    engine.share_traffic()
    assert engine.traffic_refused_until == 5000.0 + watch_service.MONITORING_RETRY_SECONDS
    maps.error = None
    engine.share_traffic()
    assert maps.sent == []  # Not before the hour's up


def test_graphed_ports_are_read_besides_the_links():
    assert counters.graph_ports(small_map()) == {"r1": ["Gi0/0", "Gi0/2"], "s1": ["Gi1/0/1"]}
    assert watch_monitor.MonitorRunner.ports_to_read(small_map()) == counters.graph_ports(small_map())


# --------------------------------------------------------------------- NOMAD's own

@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeMonitor:
    running = True


class MapPage(QObject):
    def __init__(self, network_map=None):
        super().__init__()
        self.network_map = network_map or small_map()
        self.record_shown = "map-test"
        self.tribe_map_id = None
        self.tribe = None
        self.monitor = FakeMonitor()
        self.timeout = 1000
        self.worker = None
        self.graphed_calls = []

    def snmp_access(self, address):
        return None, None

    def set_graphed(self, key, port, on):
        self.graphed_calls.append((key, port, on))
        ports = [item for item in self.network_map.graphed.get(key, []) if item != port]
        self.network_map.graphed[key] = ports + [port] if on else ports
        return True, "Kept."


def test_monitor_keeps_each_new_rate_under_the_maps_record(app):
    from nomad.ui.netmap_counters import LinkCounters
    page = MapPage()
    link_counters = LinkCounters(page)
    link_counters.port_names = {("r1", "gi0/0"): "Gi0/0"}
    rate = counters.Rate(800.0, 400.0, 1000, 0, 0, 30.0)
    link_counters.tracker.rates = {("r1", "gi0/0"): rate}
    link_counters.record()
    link_counters.record()  # The same rate (no new poll): kept once
    store = traffic_history.own_store()
    points = store.points("map-test", "r1", "Gi0/0", time.time() - 60, time.time() + 1)
    assert [point[1:3] for point in points] == [[800.0, 400.0]]


class Window(QWidget):
    def __init__(self, network_map=None):
        super().__init__()
        self.netmap_tab = MapPage(network_map)


def settle(condition, ms=5000):
    deadline = time.monotonic() + ms / 1000
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        QTest.qWait(20)
    QApplication.processEvents()


@pytest.fixture
def page(app):
    from nomad.ui.traffic_tab import TrafficTab
    window = Window()
    page = TrafficTab(window)
    page.restore_settings(QSettings("NOMAD-test-traffic", "none"))
    page.resize(1000, 600)
    window.show()  # The page reads only while it shows
    yield page
    page.shutdown()
    window.close()
    window.deleteLater()


def test_the_page_lists_the_maps_devices_and_kept_ports_first(page):
    page.show_port("r1")
    page.show()
    assert [page.device_combo.itemData(row) for row in range(page.device_combo.count())] == ["r1", "s1"]
    ports = [page.port_combo.itemData(row) for row in range(page.port_combo.count())]
    assert ports[:2] == ["Gi0/0", "Gi0/2"]  # The link's, then the one ticked to keep
    assert "to S1 Gi1/0/1" in page.port_combo.itemText(0)
    assert page.chosen() == ("r1", "Gi0/0")
    assert page.keep_check.isChecked() and not page.keep_check.isEnabled()  # A link: always kept
    assert "credentials" in page.rate_label.text()  # The map has none: no live readings


def test_the_page_draws_this_computers_readings(page):
    now = time.time()
    traffic_history.own_store().add("map-test", [reading(at=now - 600, rate_in=4000), reading(at=now - 300)])
    page.show_port("r1", "GigabitEthernet0/0")
    page.show()
    settle(lambda: page.history_of is not None)
    assert [point[1] for point in page.graph.own] == [4000, 1000]
    assert page.graph.watcher == []
    assert "this computer" in page.source_label.text()


def test_keep_its_history_ticks_the_port_on_the_map(page):
    page.show_port("r1", "Gi0/3")
    page.show()
    assert page.chosen() == ("r1", "Gi0/3")
    assert not page.keep_check.isChecked() and page.keep_check.isEnabled()
    page.keep_check.click()
    assert page.window.netmap_tab.graphed_calls == [("r1", "Gi0/3", True)]
    assert page.chosen() == ("r1", "Gi0/3") and page.keep_check.isChecked()


def test_a_span_choice_is_remembered(page):
    settings = QSettings("NOMAD-test-traffic-span", "none")
    button = next(button for button, code in page.span_buttons.items() if code == "7d")
    button.click()
    page.save_settings(settings)
    assert settings.value("traffic/span") == "7d"


def test_the_graph_breaks_lines_at_gaps_and_shows_the_nearest_reading(app):
    from nomad.ui.traffic_graph import TrafficGraph, runs
    assert [len(run) for run in runs([[0], [300], [600], [5000], [5300]], 750)] == [3, 2]
    graph = TrafficGraph()
    graph.resize(800, 300)
    graph.set_data([[1000.0, 10, 20, 10, 20]], [[1100.0, 1, 1, 1, 1], [9000.0, 5, 5, 5, 5]], [(9500.0, 7, 8)],
                   0, 10000)
    assert [point[0] for point in graph.own] == [9000.0, 9500.0]  # Not where the Watcher has a reading
    graph.grab()  # Draws
    point, source = graph.nearest(graph.plot.left() + graph.plot.width() * 0.1)
    assert point[0] == 1000.0 and source == "the Map Watcher"
    assert "In 10 b/s, out 20 b/s" in graph.tooltip_text(point, source)


# --------------------------------------------------------------------- The details pane

def test_the_details_offer_a_graph_of_each_link_and_graphed_port():
    info = details.device_details(small_map(), "r1")
    links = next(section for section in info["sections"] if section["title"] == "Links")
    assert links["blocks"][0]["graph"] == ["Gi0/0"]
    graphed = next(section for section in info["sections"] if section["title"] == "Ports Graphed")
    assert graphed["blocks"][0]["graph"] == ["Gi0/2"]
    network_map = small_map()
    network_map.devices["s1"].mgmt_ip = ""  # Nothing to read it with
    links = next(section for section in details.device_details(network_map, "s1")["sections"]
                 if section["title"] == "Links")
    assert "graph" not in links["blocks"][0]


def test_the_details_panes_graph_link_opens_the_ports_graph(app):
    from nomad.ui import netmap_tab
    html = netmap_tab.device_html(small_map(), "r1")
    assert "href='graph:Gi0%2F0'" in html

    class Opened:
        def __init__(self):
            self.shown = []

        def show_traffic(self, key, port=""):
            self.shown.append((key, port))

    fake = type("Fake", (), {})()
    fake.window, fake.details_shown = Opened(), (("device", "r1"), html)
    netmap_tab.NetworkMapTab.on_details_link(fake, QUrl("graph:Gi0%2F0"))
    assert fake.window.shown == [("r1", "Gi0/0")]


# --------------------------------------------------------------------- The NetFlow page

def test_the_netflow_graph_draws_the_kept_rate_before_the_live_one(app):
    from nomad.ui.flows_tab import RateGraph
    graph = RateGraph()
    graph.set_data([], [(2000.0, 5, 5)], 0, 3000, recorded=[(1000.0, 1, 1), (1300.0, 2, 2), (2100.0, 9, 9)])
    assert [point[0] for point in graph.recorded] == [1000.0, 1300.0]  # Up to the live readings
    graph.set_data([], [(2000.0, 5, 5), (2005.0, 6, 6)], 0, 3000)  # A live reading: the kept ones stay
    assert len(graph.recorded) == 2
    graph.resize(600, 200)
    graph.grab()
