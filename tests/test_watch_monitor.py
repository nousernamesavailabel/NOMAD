"""The Map Watcher's monitoring for the NOMAD Dashboard: pings and probes into status.db, link traffic, and
scheduled sweeps of the maps' IPAM subnets."""
import ipaddress

import pytest

from nomad.netmap import counters, probes, tunnels, watch_monitor
from nomad.netmap.model import ROUTER, SNMP, SWITCH, Device, Link, NetworkMap
from nomad.netmap.watch import WatchOptions
from nomad.netmap.watch_monitor import MonitorRunner, MonitorStore, StatusReader, SweepRunner, subnets_to_sweep


def a_map():
    network_map = NetworkMap()
    network_map.devices = {"r1": Device("r1", "R1", "10.0.0.1", kind=ROUTER, source=SNMP),
                           "s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP)}
    network_map.links = [Link("r1", "Gi0/0", "s1", "Gi1/0/1")]
    network_map.graphed = {"s1": ["Gi1/0/9"]}
    network_map.ipam_network = "team:net1"
    return network_map


class FakeMaps:
    def __init__(self, network_map):
        self.network_map = network_map

    def map_info(self, map_id):
        return {"id": map_id, "name": "Campus"}

    def load(self, map_id):
        return self.network_map, {}


class FakeAccess:
    def access(self, map_id, network_map, keys, options, workers=16):
        return {key: (network_map.devices[key].mgmt_ip, "public") for key in keys if key in network_map.devices}

    def forget(self, map_id, address):
        pass


def test_pings_become_statuses_and_changes(tmp_path, monkeypatch):
    clock = [1000.0]
    answers = {"10.0.0.1": 3, "10.0.0.2": 4}
    monkeypatch.setattr(probes, "discover", lambda routers, factory: probes.Discovery())
    monkeypatch.setattr(counters, "poll", lambda targets, indexes, factory: {})
    monkeypatch.setattr(tunnels, "poll", lambda *args, **kwargs: {})
    store = MonitorStore(tmp_path / "status.db", clock=lambda: clock[0])
    runner = MonitorRunner(FakeMaps(a_map()), [1], store, lambda map_id, settings: WatchOptions(),
                           {"interval": 60}, client_factory=object, pinger=lambda address: answers.get(address),
                           clock=lambda: clock[0], access=FakeAccess())
    runner.step()
    reader = StatusReader(tmp_path / "status.db")
    assert {row["key"]: row["status"] for row in reader.statuses()} == {"r1": "up", "s1": "up"}
    assert reader.changes_after(0) == []  # Up on the first poll: nothing happened
    del answers["10.0.0.2"]
    for _ in range(2):  # Down after missing two polls in a row
        clock[0] += 61
        runner.step()
    [change] = reader.changes_after(0)
    assert (change["key"], change["status"]) == ("s1", "down") and "S1" in change["text"]
    assert reader.meta()["monitor_at"] == clock[0]
    # The map's summary, for the dashboard to show as it is (what NOMAD shows)
    summary = reader.summaries()[1]
    assert summary["devices"]["s1"]["status"] == "down" and summary["devices"]["s1"]["since"] == change["at"]
    reader.close()
    store.close()


def test_the_watcher_takes_the_dashboards_older_changes_once(tmp_path):
    from nomad.dashboard.history import HistoryStore
    from nomad.netmap import monitor
    history = HistoryStore(tmp_path / "history.db")
    history.add_changes([
        {"map_id": 1, "key": "r1", "label": "R1", "status": "down", "at": 1000.0, "lasted": None, "text": "R1 is down"},
        {"map_id": 1, "key": "r1", "label": "R1", "status": "up", "at": 2000.0, "lasted": 1000.0, "text": "R1 is up"},
        {"map_id": 1, "key": "r1", "label": "R1", "status": "down", "at": 9000.0, "lasted": None, "text": "R1 is down"}])
    history.add_gaps([{"start_at": 3000.0, "end_at": 4000.0}])
    history.close()
    store = MonitorStore(tmp_path / "status.db", clock=lambda: 10000.0)
    store.add_changes(1, [(monitor.Change("r1", "down", 9000.0), "R1", "R1 is down")])  # Its own go back to 9000
    assert store.take_older_history(tmp_path / "history.db") == 2  # Only those from before its own
    assert store.take_older_history(tmp_path / "history.db") == 0  # Once
    assert [row["at"] for row in store.rows("SELECT at FROM changes ORDER BY at")] == [1000.0, 2000.0, 9000.0]
    assert store.gaps() == [(3000.0, 4000.0)]
    assert store.runs(1)["r1"].start == 9000.0
    store.set_summary(1, {"version": 1, "devices": {}})
    store.set_summary(2, {"version": 1, "devices": {}})
    store.forget_maps([1])  # Map 2 isn't watched any more
    reader = StatusReader(tmp_path / "status.db")
    assert list(reader.summaries()) == [1] and not [name for name in reader.meta() if name.startswith("summary:")]
    reader.close()
    store.close()


def test_link_and_graphed_ports_are_read_and_rates_kept(tmp_path, monkeypatch):
    clock = [1000.0]
    read = {}

    def poll(targets, indexes, factory):
        read["ports"] = {key: ports for key, *_rest, ports in targets}
        sample = counters.Sample(clock[0], int(clock[0] * 1000), int(clock[0] * 500), 0, 0, 1000)
        return {key: ({}, {counters.port_key(port): sample for port in ports}) for key, *_rest, ports in targets}

    monkeypatch.setattr(counters, "poll", poll)
    monkeypatch.setattr(tunnels, "poll", lambda *args, **kwargs: {})
    monkeypatch.setattr(probes, "discover", lambda routers, factory: probes.Discovery())
    store = MonitorStore(tmp_path / "status.db", clock=lambda: clock[0])
    runner = MonitorRunner(FakeMaps(a_map()), [1], store, lambda map_id, settings: WatchOptions(),
                           {"counter_interval": 60}, client_factory=object, pinger=lambda address: 1,
                           clock=lambda: clock[0], access=FakeAccess())
    runner.step()
    assert read["ports"] == {"r1": ["Gi0/0"], "s1": ["Gi1/0/1", "Gi1/0/9"]}
    clock[0] += 100
    runner.step()
    rates = StatusReader(tmp_path / "status.db").rates_after(0)
    assert {(row["device"], row["port"]) for row in rates} == {("r1", "Gi0/0"), ("s1", "Gi1/0/1"),
                                                              ("s1", "Gi1/0/9")}
    assert rates[0]["in_bps"] == pytest.approx(8000.0)  # 1000 bytes a second
    store.close()


def test_sweeps_pick_leaf_subnets_no_larger_than_the_limit():
    swept = subnets_to_sweep(["10.0.0.0/16", "10.0.0.0/22", "10.0.0.0/24", "10.0.4.0/24", "10.9.0.0/21",
                              "2001:db8::/64", "bad"], 22)
    assert swept == [ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("10.0.4.0/24")]


def test_sweeps_record_what_answered_in_the_tribe(tmp_path):
    class Subnet:
        def __init__(self, cidr, loopbacks=False):
            self.cidr, self.loopbacks = cidr, loopbacks

    class Copy:
        def subnets(self, network_id):
            return [Subnet("10.0.0.0/30"), Subnet("10.0.5.0/30", loopbacks=True)]

    class Team:
        copy = Copy()
        recorded, sent = [], []

        def sync(self):
            pass

        def record_sightings(self, network_id, hosts, ranges):
            self.recorded.append((network_id, hosts, ranges))

        def outgoing_sightings(self):
            return [{"seq": 1}]

        def send_sightings(self, entries):
            self.sent.append(entries)
            return [1]

        def apply_sent_sightings(self, seqs):
            pass

    team = Team()
    runner = SweepRunner(FakeMaps(a_map()), [1], team, {"sweep_hours": 4},
                         pinger=lambda address, timeout: 2 if str(address) == "10.0.0.1" else None,
                         clock=lambda: 5000.0)
    assert runner.step() == 1
    [(network_id, hosts, ranges)] = team.recorded
    assert network_id == "net1" and [host["ip"] for host in hosts] == ["10.0.0.1"]
    assert ranges[0]["cidr"] == "10.0.0.0/30"
    assert team.sent
    assert runner.step() == 0  # Not due again for 4 hours


def test_monitor_settings_are_kept_in_bounds():
    settings = watch_monitor.monitor_settings({"monitor": {"interval": 1, "sweep_max_prefix": 8,
                                                           "sweep_hours": "x"}})
    assert settings["interval"] == 10 and settings["sweep_max_prefix"] == 16 and settings["sweep_hours"] == 1
