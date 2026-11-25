"""The NOMAD Dashboard's back end: the tribe's viewer key, graphed ports on tribe maps, the collectors' new questions,
the dashboard's logins and history, and what its pages show."""
import datetime
import json
import threading

import pytest

from nomad.dashboard import accounts as accounts_module, views
from nomad.dashboard.accounts import AccountError, Accounts, UserFile
from nomad.dashboard.engine import Engine, Snapshot, count_hosts, mac_only_hosts
from nomad.dashboard.history import HistoryStore
from nomad.dashboard.sources import MapEntry, SubnetEntry, TribeData
from nomad.ipam.client import TeamClient, TeamKey, TeamKeyError, read_key_file
from nomad.ipam.server import VIEWER, IpamServer, load_config, team_key, write_viewer_key
from nomad.ipam.store import IpamError
from nomad.netmap import shared
from nomad.netmap.model import ROUTER, SNMP, SWITCH, Device, Group, Host, Link, NetworkMap
from nomad.netmap.tribe import TribeMaps


@pytest.fixture
def server(tmp_path):
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def local(key, server):
    key.hosts, key.port = ["127.0.0.1"], server.port
    return key


def team(server):
    config = load_config(server.directory)
    return TeamKey.from_dict(dict(team_key(config, server.directory), hosts=["127.0.0.1"], port=server.port))


def small_map():
    network_map = NetworkMap()
    network_map.devices = {
        "r1": Device("r1", "R1", "10.0.0.1", kind=ROUTER, source=SNMP,
                     interfaces_l3=[["10.0.0.1", 24, "Gi0/0"], ["10.1.0.1", 24, "Gi0/1"]],
                     port_status={"Gi0/0": {"oper": "up", "speed": 1000}, "Gi0/2": {"oper": "up"}}),
        "s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP),
        "s2": Device("s2", "S2", "10.0.0.3", kind=SWITCH, source=SNMP),
    }
    network_map.links = [Link("r1", "Gi0/0", "s1", "Gi1/0/1"), Link("s1", "Gi1/0/2", "s2", "Gi1/0/1")]
    network_map.hosts = [Host("aa:aa", "s1", "Gi1/0/5", ip="10.0.0.50"), Host("bb:bb", "s2", "Gi1/0/6", vlan=20)]
    network_map.groups = [Group("site:hq", "HQ")]
    network_map.group_of = {"r1": "site:hq", "s1": "site:hq"}
    return network_map


# --------------------------------------------------------------------- The viewer key

def test_a_viewer_key_reads_but_never_changes_or_gets_secrets(server, tmp_path):
    maps = TribeMaps(server.config["server_id"], TeamClient(team(server), user="alice"), tmp_path / "team.db")
    map_id = maps.create("HQ", small_map(), {}, {"communities": ["s3cret"]})
    path = tmp_path / "viewer.nomadkey"
    write_viewer_key(path, server.directory)
    assert json.loads(path.read_text())["role"] == VIEWER
    with pytest.raises(TeamKeyError, match="viewer key"):  # NOMAD can't join the tribe with it
        read_key_file(path)
    key = local(read_key_file(path, viewer=True), server)
    assert key.role == VIEWER
    client = TeamClient(key, user="dashboard")
    assert client.status()["role"] == VIEWER and client.status()["api"] >= 17
    payload, _ = client.map_changes(0)
    assert [item["name"] for item in payload["maps"]] == ["HQ"]
    with pytest.raises(IpamError, match="viewer key"):
        client.map_secrets(map_id)
    with pytest.raises(IpamError, match="viewer key"):
        client.edit("add_network", name="Nope")
    with pytest.raises(IpamError, match="viewer key"):
        client.map_request("rename", map_id=map_id, name="Mine")
    copy = TribeMaps(key.server_id, client, tmp_path / "viewer.db", with_secrets=False)
    copy.sync()  # Doesn't ask for the credentials
    assert copy.load(map_id)[0].devices["r1"].label == "R1"
    assert copy.secrets(map_id) == {}
    assert client.config_reviews(10)["to_review"] == 0  # Reviews, yes (no config text in them)
    with pytest.raises(IpamError, match="viewer key"):  # NOMAD's pushes carry the lines typed: no
        client.config_pushes(1)


def test_the_watchers_monitoring_goes_through_the_tribe_to_every_nomad(server, tmp_path):
    maps = TribeMaps(server.config["server_id"], TeamClient(team(server), user="watcher"), tmp_path / "team.db")
    map_id = maps.create("HQ", small_map(), {}, {})
    other = TribeMaps(server.config["server_id"], TeamClient(team(server), user="bob"), tmp_path / "bob.db")
    assert other.fetch_monitoring(map_id) is None  # Nothing sent yet
    summary = {"version": 1, "updated": 1000.0, "interval": 60, "source": "the Map Watcher on PC1",
               "devices": {"r1": {"status": "up", "since": 900.0, "exact": True, "uptime": {"24h": 1.0}}}}
    maps.send_monitoring(map_id, summary)
    assert other.fetch_monitoring(map_id) == summary
    assert other.kept_monitoring(map_id) == summary  # Kept for when the server can't be reached
    path = tmp_path / "viewer.nomadkey"
    write_viewer_key(path, server.directory)
    viewer = TeamClient(local(read_key_file(path, viewer=True), server), user="dashboard")
    assert viewer.map_monitoring(map_id)["summary"] == summary  # A viewer key may read it
    with pytest.raises(IpamError, match="viewer key"):
        viewer.map_request("monitoring", map_id=map_id, summary=summary)  # but not send one


def test_a_new_viewer_key_works_without_restarting_the_server(server, tmp_path, monkeypatch):
    from nomad.ipam import server as server_module
    monkeypatch.setattr(server_module, "VIEWER_RECHECK_SECONDS", 0)
    path = tmp_path / "viewer.nomadkey"
    write_viewer_key(path, server.directory)  # After the server started
    key = local(read_key_file(path, viewer=True), server)
    assert TeamClient(key).status()["role"] == VIEWER


# --------------------------------------------------------------------- Graphed ports on tribe maps

def test_graphed_ports_travel_with_a_tribe_map():
    network_map = small_map()
    network_map.graphed = {"r1": ["Gi0/2"]}
    items = shared.flatten(network_map)
    assert items[(shared.GRAPHED, "r1|gi0/2")] == "Gi0/2"
    assert shared.build(items).graphed == {"r1": ["Gi0/2"]}
    network_map.remove_devices(["r1"])
    assert network_map.graphed == {}


def test_a_save_leaves_parts_of_a_map_it_does_not_know():
    base = {(shared.DEVICE, "r1"): {"key": "r1"}, ("from_the_future", "x"): 1}
    assert shared.diff(base, {(shared.DEVICE, "r1"): {"key": "r1"}}) == []


def test_graphed_ports_wait_for_a_server_that_keeps_them(tmp_path):
    class OldServer:
        def status(self):
            return {"api": 16}

    maps = TribeMaps("id", OldServer(), tmp_path / "copy.db")
    maps.note_server_api()
    assert shared.GRAPHED in maps.held_sections() and shared.LOCKED not in maps.held_sections()


def test_graphed_ports_are_saved_in_map_files():
    network_map = small_map()
    network_map.graphed = {"r1": ["Gi0/2"], "gone": ["Gi1"]}
    assert NetworkMap.from_json(network_map.to_json()).graphed == {"r1": ["Gi0/2"]}


# --------------------------------------------------------------------- The collectors' new questions

def test_syslog_counts_by_sender_and_severity_without_text(tmp_path):
    from nomad.syslog import SyslogMessage
    from nomad.syslogs import store
    now = datetime.datetime.now()
    kept = store.SyslogStore(tmp_path / "syslog.db")
    kept.add([SyslogMessage(now, "10.0.0.1", severity=3, raw="<11>secret text"),
              SyslogMessage(now, "10.0.0.1", severity=3, raw="<11>more"),
              SyslogMessage(now, "10.0.0.2", severity=6, raw="<14>hello"),
              SyslogMessage(now - datetime.timedelta(days=3), "10.0.0.2", severity=0, raw="<8>old")])
    queries = store.SyslogQueries(tmp_path / "syslog.db")
    assert queries.counts(now.timestamp() - 86400) == [["10.0.0.1", 3, 2], ["10.0.0.2", 6, 1]]
    queries.close()
    kept.close()


def test_flow_addresses_seen_lately(tmp_path):
    from nomad.flows import store
    connection = store.connect(tmp_path / "flows.db")
    connection.executemany("INSERT INTO flows (end, start, exporter, src, dst, bytes) VALUES (?, ?, ?, ?, ?, ?)",
                           [(100.0, 90.0, "r1", "10.0.0.5", "8.8.8.8", 10), (200.0, 190.0, "r1", "10.0.0.6",
                                                                              "10.0.0.5", 10),
                            (10.0, 5.0, "r1", "10.9.9.9", "10.0.0.7", 10)])
    connection.commit()
    queries = store.FlowQueries(tmp_path / "flows.db")
    assert queries.addresses(50, 300) == [["10.0.0.5", 200.0], ["10.0.0.6", 200.0], ["8.8.8.8", 100.0]]
    # A sweep's pings reach every address: only the ones that sent something are hosts
    assert queries.addresses(50, 300, senders=True) == [["10.0.0.5", 100.0], ["10.0.0.6", 200.0]]
    queries.close()
    connection.close()


def test_the_flow_collector_service_names_the_senders(tmp_path):
    from nomad.flows import api, store
    connection = store.connect(tmp_path / "flows.db")
    connection.executemany("INSERT INTO flows (end, start, exporter, src, dst, bytes) VALUES (?, ?, ?, ?, ?, ?)",
                           [(100.0, 90.0, "r1", "192.168.5.25", f"10.0.0.{n}", 10) for n in range(1, 255)] +
                           [(100.0, 90.0, "r1", "10.0.0.9", "192.168.5.25", 10)])
    connection.commit()
    queries = store.FlowQueries(tmp_path / "flows.db")
    server = api.FlowApi(queries, lambda: {}, port=0)
    server.start()
    try:
        source = api.ServiceSource(port=server.port)
        assert [address for address, _ in source.senders(0)] == ["10.0.0.9", "192.168.5.25"]
    finally:
        server.stop()
        queries.close()
        connection.close()


# --------------------------------------------------------------------- Logins

def test_logins_sign_in_lock_out_and_survive_a_restart(tmp_path):
    clock = [1000.0]
    users = UserFile(tmp_path)
    users.add("alice", "correct horse")
    users.add("wall", "kiosk password", kiosk=True)
    with pytest.raises(AccountError, match="already"):
        users.add("ALICE", "something else")
    with pytest.raises(AccountError, match="at least"):
        users.add("bob", "short")
    accounts = Accounts(tmp_path, clock=lambda: clock[0])
    token = accounts.sign_in("alice", "correct horse", "10.0.0.9")
    assert token and accounts.session(token).user == "alice"
    assert "correct horse" not in (tmp_path / "users.json").read_text()
    assert token not in (tmp_path / "sessions.json").read_text()  # Only its hash is kept
    again = Accounts(tmp_path, clock=lambda: clock[0])  # The service restarted
    assert again.session(token).user == "alice"
    for _ in range(accounts_module.MAX_FAILURES):
        assert again.sign_in("alice", "wrong", "10.0.0.9") is None
    with pytest.raises(AccountError, match="Too many"):
        again.sign_in("alice", "correct horse", "10.0.0.9")
    clock[0] += accounts_module.LOCK_SECONDS + 1
    assert again.sign_in("alice", "correct horse", "10.0.0.9")
    clock[0] += accounts_module.SESSION_HOURS * 3600 + 1  # Idle too long
    assert again.session(token) is None
    kiosk = again.sign_in("wall", "kiosk password", "10.0.0.10")
    clock[0] += 30 * 86400
    assert again.session(kiosk).kiosk
    users.set_password("wall", "a new password")  # Signed out everywhere
    clock[0] += 1
    assert again.session(kiosk) is None


# --------------------------------------------------------------------- History

def test_history_rolls_up_rates_and_keeps_each_change_once(tmp_path):
    clock = [100000.0]
    history = HistoryStore(tmp_path / "history.db", clock=lambda: clock[0])
    rate = {"map_id": 1, "device": "r1", "port": "Gi0/0", "speed": 1000}
    history.add_rates([dict(rate, at=100000.0, in_bps=1e6, out_bps=2e6),
                       dict(rate, at=100300.0, in_bps=3e6, out_bps=2e6)])
    [hourly] = history.rate_series(1, "r1", "Gi0/0", 90000, 101000, hourly=True)
    assert hourly[1:] == [2e6, 2e6, 3e6, 2e6]
    assert len(history.rate_series(1, "r1", "Gi0/0", 90000, 101000)) == 2
    history.add_changes([{"map_id": 1, "key": "r1", "label": "R1", "status": "down", "at": 99000.0, "lasted": None,
                          "text": "R1 is down"},
                         {"map_id": 1, "key": "r1", "label": "R1", "status": "up", "at": 99500.0, "lasted": 500.0,
                          "text": "R1 is up again"}])
    # A watcher that took in this history's older changes hands them back: each is kept once
    history.add_changes([{"map_id": 1, "key": "r1", "label": "R1", "status": "down", "at": 99000.0, "lasted": None,
                          "text": "R1 is down"}])
    assert len(history.recent_changes(0)) == 2
    history.add_host_counts(100000.0, [{"subnet": "10.0.0.0/24", "network": "n", "total": 4, "map": 2, "sweep": 3,
                                        "flow": 1}])
    assert history.host_series("10.0.0.0/24", 90000, 101000) == [[100000.0, 4, 4]]
    clock[0] = 100000.0 + 40 * 86400
    history.prune(raw_days=30, hourly_days=365)
    assert history.rate_series(1, "r1", "Gi0/0", 0, clock[0], hourly=False) == []
    assert history.rate_series(1, "r1", "Gi0/0", 0, clock[0], hourly=True)  # Hourly kept longer
    history.close()


# --------------------------------------------------------------------- What the pages show

def snapshot_of(network_map, statuses=None, **extra):
    tribe = TribeData(maps=[MapEntry(1, "Campus", network_map, "net1")], networks=[{"id": "net1", "name": "Campus"}],
                      subnets=[SubnetEntry("net1", "10.0.0.0/24", "LAN", 254, 20),
                               SubnetEntry("net1", "10.1.0.0/24", "Servers", 254, 250)],
                      sightings={"net1": {"10.0.0.60": 5000.0, "10.1.0.9": 10.0}}, online=True, synced_at=1.0,
                      server="tribe")
    tribe.reviews = extra.pop("tribe_reviews", {})
    return Snapshot(revision=3, tribe=tribe, statuses=statuses or {}, **extra)


def test_pages_show_devices_sites_and_the_map():
    network_map = small_map()
    statuses = {(1, "r1"): {"status": "up", "since": 10.0, "checked": 20.0, "rtt": 3, "via": "", "problem": ""},
                (1, "s1"): {"status": "down", "since": 15.0, "checked": 20.0, "rtt": None, "via": "",
                            "problem": ""}}
    snapshot = snapshot_of(network_map, statuses,
                           watcher={"available": True, "monitor_at": 1000.0, "interval": 60, "maps": [1]},
                           rates={(1, "r1", "Gi0/0"): {"in_bps": 9e8, "out_bps": 1e8, "speed": 1000, "at": 1.0}},
                           uptime={"24h": {(1, "r1"): 0.995}})
    rows = views.device_rows(snapshot)
    assert [row["name"] for row in rows] == ["S1", "R1", "S2"]  # Down first
    assert rows[0]["status"] == views.DOWN and rows[1]["uptime_24h"] == 99.5
    assert rows[2]["status"] == views.UNMONITORED
    tiles = views.sites(snapshot, now=1000.0)["sites"]
    assert tiles[0]["site"] == "HQ" and tiles[0]["down"] == ["S1"]
    drawn = views.topology(snapshot, 1, "l2", now=1000.0)
    assert {node["key"] for node in drawn["nodes"]} == {"r1", "s1", "s2"}
    link = next(item for item in drawn["links"] if item["a"] == "r1")
    assert link["percent"] == 90.0
    assert drawn["groups"][0]["name"] == "HQ"
    assert views.topology(snapshot, 1, "l3", now=1000.0)["nodes"]
    overview = views.overview(snapshot, now=1000.0)
    assert overview["counts"]["down"] == 1 and overview["fullest"][0]["subnet"] == "10.1.0.0/24"
    assert overview["freshness"]["watcher"]["ok"]
    assert not views.overview(snapshot, now=5000.0)["freshness"]["watcher"]["ok"]  # It stopped checking


def test_device_rows_have_site_building_and_room_in_their_own_columns():
    network_map = small_map()
    network_map.groups += [Group("building:a", "Building A", kind="building", parent="site:hq"),
                           Group("room:1", "Room 1", kind="room", parent="building:a"),
                           Group("building:b", "Building B", kind="building")]  # In no site
    network_map.group_of = {"r1": "room:1", "s1": "site:hq", "s2": "building:b"}
    snapshot = snapshot_of(network_map)
    rows = {row["key"]: row for row in views.device_rows(snapshot)}
    assert [rows["r1"][name] for name in ("site", "building", "room")] == ["HQ", "Building A", "Room 1"]
    assert [rows["s1"][name] for name in ("site", "building", "room")] == ["HQ", "", ""]
    assert [rows["s2"][name] for name in ("site", "building", "room")] == ["", "Building B", ""]
    assert rows["r1"]["group"] == "HQ / Building A / Room 1"  # Still there for the Overview's Down now
    tiles = {tile["site"]: tile["total"] for tile in views.sites(snapshot, now=1000.0)["sites"]}
    assert tiles == {"HQ": 2, "Building B": 1}  # A building in no site keeps its own tile
    _, text = views.csv_table("devices", snapshot)
    header, *lines = text.splitlines()
    assert header.startswith("Map,Site,Building,Room,Name")
    assert any(line.startswith("Campus,HQ,Building A,Room 1,R1") for line in lines)


def test_hosts_per_subnet_count_each_address_once_from_every_source():
    network_map = small_map()
    snapshot = snapshot_of(network_map)
    rows = count_hosts(snapshot.tribe, {"10.0.0.50": 5000.0}, {"10.0.0.50": 5000.0, "10.0.0.70": 5000.0,
                                                               "192.168.9.9": 5000.0}, 4000.0)
    [lan] = [row for row in rows if row["subnet"] == "10.0.0.0/24"]
    assert (lan["total"], lan["map"], lan["sweep"], lan["flow"]) == (3, 1, 1, 2)
    assert not [row for row in rows if row["subnet"] == "10.1.0.0/24"]  # Its sighting is too old
    assert mac_only_hosts(snapshot.tribe) == [{"map": "Campus", "vlan": 20, "count": 1}]


def test_hosts_count_once_leave_out_network_devices_and_hand_added_hosts():
    network_map = small_map()
    network_map.hosts += [Host("cc:cc", "s1", "Gi1/0/7", ip="10.0.0.80", manual=True),
                          Host("dd:dd", "s2", "Gi1/0/8", manual=True)]
    snapshot = snapshot_of(network_map)
    tribe = snapshot.tribe
    tribe.networks.append({"id": "net2", "name": "Branch"})  # The same subnet at another site
    tribe.subnets.append(SubnetEntry("net2", "10.0.0.0/24", "Branch LAN", 254, 5))
    tribe.sightings["net2"] = {"10.0.0.90": 5000.0}
    tribe.sightings["net1"]["10.0.0.2"] = 5000.0  # S1 answering a sweep isn't a host
    seen_map = {"10.0.0.50": 5000.0, "10.0.0.80": 5000.0}
    flows = {"10.0.0.50": 5000.0, "10.0.0.90": 5000.0, "10.0.0.70": 5000.0, "10.0.0.1": 5000.0}
    rows = {(row["network"], row["subnet"]): row for row in count_hosts(tribe, seen_map, flows, 4000.0)}
    campus, branch = rows[("net1", "10.0.0.0/24")], rows[("net2", "10.0.0.0/24")]
    # 10.0.0.50 is Campus's (on its map), 10.0.0.90 Branch's (its sweep), 10.0.0.70 counted once, R1 never
    assert (campus["total"], campus["map"], campus["sweep"], campus["flow"]) == (3, 1, 1, 2)
    assert (branch["total"], branch["flow"]) == (1, 1)
    assert mac_only_hosts(tribe) == [{"map": "Campus", "vlan": 20, "count": 1}]  # The hand-added one isn't seen


class FakeHostEngine:
    def __init__(self, tribe, seen_map, flows):
        self.tribe, self.seen_map, self.flows = tribe, seen_map, flows

    def hosts(self, window):
        return count_hosts(self.tribe, self.seen_map, self.flows, 4000.0)


def test_the_overview_hosts_page_and_trend_give_the_same_count(tmp_path):
    snapshot = snapshot_of(small_map())
    engine = FakeHostEngine(snapshot.tribe, {"10.0.0.50": 5000.0}, {"10.0.0.70": 5000.0})
    page = views.hosts(snapshot, engine, "1h", now=5000.0)
    overview = views.overview(snapshot, now=5000.0, engine=engine)
    assert page["total"] == overview["hosts"]["total"] == 3  # .50 (map), .60 (sweep), .70 (NetFlow)
    assert page["mac_only_total"] == overview["hosts"]["mac_only"] == 1
    # The map's subnets (from R1's interfaces), as IPAM has them, with their hosts; the map's count adds them up
    assert [(row["subnet"], row["name"], row["total"]) for row in overview["map_subnets"]] == \
        [("10.0.0.0/24", "LAN", 3), ("10.1.0.0/24", "Servers", 0)]
    assert overview["maps"][0]["hosts"] == 3
    history = HistoryStore(tmp_path / "history.db", clock=lambda: 5000.0)
    history.add_host_counts(4800.0, [{"subnet": "10.0.0.0/24", "network": "net1", "total": 2, "map": 1, "sweep": 1,
                                      "flow": 0}])  # Five minutes ago, before NetFlow saw .70
    history.add_host_counts(4800.0, [{"subnet": "10.0.0.0/24", "network": "net2", "total": 40, "map": 0, "sweep": 40,
                                      "flow": 0}])  # The same subnet in another network stays apart
    points = views.series(history, "subnet", {"subnet": "10.0.0.0/24", "network": "net1", "span": "1h"}, now=5000.0,
                          engine=engine)["points"]
    assert [point[1] for point in points] == [2, 3]  # The last sample, then the count now
    lan = next(row for row in views.trends(snapshot)["subnets"] if row["subnet"] == "10.0.0.0/24")
    assert lan["network"] == "net1" and lan["network_name"] == "Campus"
    history.close()


def test_hours_kept_before_networks_still_show(tmp_path):
    import sqlite3
    path = tmp_path / "history.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE host_counts_hourly (subnet TEXT, hour INTEGER, sum_total REAL, max_total INTEGER, "
                "samples INTEGER, PRIMARY KEY (subnet, hour)) WITHOUT ROWID")
    old.execute("INSERT INTO host_counts_hourly VALUES ('10.0.0.0/24', 10, 30, 12, 3)")
    old.commit()
    old.close()
    history = HistoryStore(path, clock=lambda: 20 * 3600.0)
    history.add_host_counts(11 * 3600.0, [{"subnet": "10.0.0.0/24", "network": "net1", "total": 7, "map": 7,
                                           "sweep": 0, "flow": 0}])
    history.add_host_counts(11 * 3600.0, [{"subnet": "10.0.0.0/24", "network": "net2", "total": 50, "map": 50,
                                           "sweep": 0, "flow": 0}])
    assert history.host_series("10.0.0.0/24", 0, 20 * 3600.0, hourly=True, network="net1") == \
        [[36000, 10.0, 12], [39600, 7.0, 7]]
    history.close()


def test_csv_tables_never_start_a_cell_with_a_formula():
    network_map = small_map()
    network_map.devices["s2"].name = "=HYPERLINK(\"x\")"
    _, text = views.csv_table("devices", snapshot_of(network_map))
    assert "'=HYPERLINK" in text and "\n=HYPERLINK" not in text


def test_syslog_rows_name_the_sender_and_never_carry_text():
    snapshot = snapshot_of(small_map(), syslog={"available": True, "counts": [["10.0.0.1", 3, 4], ["10.0.0.1", 6, 1]]})
    [row] = views.syslog_rows(snapshot)
    assert (row["name"], row["error"], row["info"], row["total"]) == ("R1", 4, 1, 5)


def test_syslog_page_level_lists_the_senders_behind_the_overview_count():
    counts = [["10.0.0.1", 3, 4], ["10.0.0.1", 6, 1], ["10.0.0.2", 4, 2], ["10.0.0.3", 7, 9], ["10.0.0.4", 0, 1]]
    snapshot = snapshot_of(small_map(), syslog={"available": True, "counts": counts})
    every = views.syslog(snapshot)
    assert every["level"] == "" and len(every["senders"]) == 4
    errors = views.syslog(snapshot, "error")
    assert [row["source"] for row in errors["senders"]] == ["10.0.0.1", "10.0.0.4"]
    severe = sum(row[name] for row in errors["senders"] for name in ("emergency", "alert", "critical", "error"))
    assert severe == errors["severe"] == views.overview(snapshot)["syslog_severe"] == 5
    assert {row["source"] for row in views.syslog(snapshot, "warning")["senders"]} == {"10.0.0.1", "10.0.0.2",
                                                                                     "10.0.0.4"}
    assert views.syslog(snapshot, "nonsense")["level"] == ""
    assert "syslog" not in views.events(snapshot)
    _, text = views.csv_table("syslog", snapshot, query={"level": "error"})
    assert "10.0.0.4" in text and "10.0.0.3" not in text


# --------------------------------------------------------------------- The engine

class FakeReader:
    def __init__(self):
        self.changes = [{"id": 1, "map_id": 1, "key": "s1", "label": "S1", "status": "down", "at": 900.0,
                         "lasted": 100.0, "text": "S1 is down"}]
        self.rates = [{"id": 7, "map_id": 1, "device": "r1", "port": "Gi0/0", "at": 990.0, "in_bps": 5e8,
                       "out_bps": 1e8, "speed": 1000, "errors": 0, "discards": 0}]

    def meta(self):
        return {"monitor_at": 995.0, "monitor": {"maps": [1], "interval": 60, "counter_interval": 300}}

    def changes_after(self, after, limit=5000):
        return [row for row in self.changes if row["id"] > after]

    def gaps_after(self, after):
        return [row for row in getattr(self, "gaps", []) if row["id"] > after]

    def rates_after(self, after, limit=20000):
        return [row for row in self.rates if row["id"] > after]

    def rows(self, sql, parameters=()):
        return [{"id": 0}]

    def statuses(self):
        return [{"map_id": 1, "key": "s1", "label": "S1", "address": "10.0.0.2", "kind": SWITCH, "status": "down",
                 "since": 900.0, "checked": 990.0, "rtt": None, "via": "", "problem": ""}]

    def summaries(self):
        return getattr(self, "summary", {1: {"version": 1, "devices": {"s1": {
            "status": "down", "since": 900.0, "exact": True, "uptime": {"24h": 0.0}}}}})

    def tunnels(self):
        return []

    def close(self):
        pass


class FakeCollectors:
    def read_syslog(self):
        return {"available": True, "error": "", "counts": [["10.0.0.1", 2, 1]], "at": 1000.0}

    def read_flows(self):
        return {"available": False, "error": "not here", "exporters": [], "top": {}, "total": [0, 0, 0],
                "span": 3600, "at": 1000.0}

    def flow_addresses(self, start):
        return {"10.0.0.70": 999.0}


def test_the_engine_takes_in_the_watcher_and_the_collectors(tmp_path):
    engine = Engine(tmp_path, status_reader=FakeReader(), collectors=FakeCollectors(), clock=lambda: 1000.0)
    engine.publish(tribe=snapshot_of(small_map()).tribe)
    engine.step()
    snapshot = engine.snapshot
    assert snapshot.statuses[(1, "s1")]["status"] == "down"
    assert snapshot.rates[(1, "r1", "Gi0/0")]["in_bps"] == 5e8
    assert snapshot.syslog["counts"] == [["10.0.0.1", 2, 1]]
    assert snapshot.uptime["24h"][(1, "s1")] == 0.0
    assert engine.history.recent_changes(0)[0]["text"] == "S1 is down"
    hosts = {row["subnet"]: row for row in engine.hosts(3600)}
    assert hosts["10.0.0.0/24"]["flow"] == 1 and hosts["10.0.0.0/24"]["map"] == 1
    revision = snapshot.revision
    engine.step()  # Nothing new: no new revision for the pages
    assert engine.snapshot.revision == revision
    engine.stop()


def test_group_boxes_hold_the_boxes_inside_them_with_room_for_their_title():
    network_map = small_map()
    network_map.groups.append(Group("building:a", "Building A", kind="building", parent="site:hq"))
    network_map.group_of["s1"] = "building:a"
    positions = {"r1": (0, 0), "s1": (0, 200), "s2": (300, 200)}
    site, building = views.group_boxes(network_map, positions)  # Outermost first
    assert (site["key"], building["key"]) == ("site:hq", "building:a")
    assert site["x"] < building["x"] and site["x"] + site["w"] > building["x"] + building["w"]
    assert building["y"] - site["y"] >= views.GROUP_TITLE  # The site's title band is clear of the building's box
    assert site["y"] + site["h"] > building["y"] + building["h"]


def _rows_of(details):
    return {left: right for section in details["sections"] for block in section["blocks"]
            for left, right in block.get("rows", [])}


def test_details_are_the_apps_with_the_watchers_status_and_uptime():
    from nomad.ui import netmap_tab
    network_map = small_map()
    network_map.devices["r1"].software = "IOS-XE 17.9"
    statuses = {(1, "r1"): {"status": "up", "since": 400.0, "checked": 990.0, "rtt": 3, "via": "", "problem": ""},
                (1, "s1"): {"status": "unknown", "since": 400.0, "checked": 990.0, "rtt": None, "via": "",
                            "problem": "no answer from the router"}}
    snapshot = snapshot_of(network_map, statuses, uptime={"24h": {(1, "r1"): 0.995}, "7d": {(1, "r1"): 0.9}})
    details = views.node_details(snapshot, 1, "r1", now=1000.0)
    rows = _rows_of(details)
    assert rows["Status"].startswith("Up for 10 min, 3 ms (since ") and rows["Uptime"] == "99.5% (24 h) · 90% (7 days)"
    from nomad.netmap import monitor  # NOMAD's pane says the same of the same status
    state = monitor.DeviceStatus("up", 3, 400.0, 0, 990.0)
    assert netmap_tab.monitor_record.status_text(state, 1000.0) == rows["Status"]
    assert rows["Last checked"] == "10 s ago" and rows["Software"] == "IOS-XE 17.9"
    titles = [section["title"] for section in details["sections"]]
    assert "Links" in titles and "Hardware" in titles and "IP Interfaces" in titles
    # The app's pane shows the same, from the same code
    html = netmap_tab.device_html(network_map, "r1")
    for title in titles[1:]:
        assert f"<h4>{title}</h4>" in html
    cant = _rows_of(views.node_details(snapshot, 1, "s1", now=1000.0))["Status"]
    assert cant == "Can't check: no answer from the router"
    assert _rows_of(views.node_details(snapshot, 1, "s2", now=1000.0))["Status"] == "Not monitored by the Map Watcher"
    subnet = views.node_details(snapshot, 1, "net:10.0.0.0/24", now=1000.0)
    assert subnet["title"] == "10.0.0.0/24" and "R1" in _rows_of(subnet)
    with pytest.raises(KeyError):
        views.node_details(snapshot, 1, "nothing")
    drawn = views.topology(snapshot, 1, "l2", now=1000.0)
    r1 = next(node for node in drawn["nodes"] if node["key"] == "r1")
    assert r1["uptime"] == 99.5 and r1["rtt"] == 3


def test_the_dashboard_shows_the_watchers_since_and_uptime_as_they_are(tmp_path):
    clock = [100000.0]
    reader = FakeReader()
    reader.changes = [{"id": 1, "map_id": 1, "key": "s1", "label": "S1", "status": "down", "at": 900.0,
                       "lasted": 100.0, "text": "S1 is down"}]
    reader.gaps = [{"id": 1, "start_at": 4000.0, "end_at": 5000.0}]
    reader.statuses = lambda: [
        {"map_id": 1, "key": "s1", "label": "S1", "address": "10.0.0.2", "kind": SWITCH, "status": "down",
         "since": 5000.0, "checked": 99990.0, "rtt": None, "via": "", "problem": "", "exact": 0},
        {"map_id": 1, "key": "r1", "label": "R1", "address": "10.0.0.1", "kind": ROUTER, "status": "up",
         "since": 5000.0, "checked": 99990.0, "rtt": 2, "via": "", "problem": "", "exact": 0},
        {"map_id": 1, "key": "s2", "label": "S2", "address": "10.0.0.3", "kind": SWITCH, "status": "up",
         "since": 99000.0, "checked": 99990.0, "rtt": 2, "via": "", "problem": "", "exact": 1}]
    # The watcher's summary (what NOMAD shows); s2's is from before it came back up, so it isn't used
    reader.summary = {1: {"version": 1, "devices": {
        "s1": {"status": "down", "since": 900.0, "exact": True, "uptime": {"24h": 0.0, "30d": 0.04}},
        "r1": {"status": "up", "since": 5000.0, "exact": False, "uptime": {"24h": 1.0, "30d": 0.9693877}},
        "s2": {"status": "down", "since": 50000.0, "exact": True, "uptime": {"24h": 0.5}}}}}
    engine = Engine(tmp_path, status_reader=reader, collectors=FakeCollectors(), clock=lambda: clock[0],
                    local_maps=lambda: [])
    engine.publish(tribe=snapshot_of(small_map()).tribe)
    engine.step()
    statuses = engine.snapshot.statuses
    assert (statuses[(1, "s1")]["since"], statuses[(1, "s1")]["exact"]) == (900.0, True)
    assert (statuses[(1, "r1")]["since"], statuses[(1, "r1")]["exact"]) == (5000.0, False)  # Up at least since then
    assert (statuses[(1, "s2")]["since"], statuses[(1, "s2")]["exact"]) == (99000.0, True)
    assert engine.snapshot.uptime["30d"][(1, "r1")] == 0.9693877  # As it is, not worked out again
    assert (1, "s2") not in engine.snapshot.uptime["24h"]
    texts = [event["text"] for event in views.event_rows(engine.snapshot, engine.history, now=clock[0], since=10 ** 6)]
    assert any(text.startswith("The Map Watcher wasn't monitoring for 16 min 40 s") for text in texts)
    box = views.node_status(engine.snapshot, 1, "r1")
    assert box["exact"] is False and box["since"] == 5000.0 and box["uptime"] == 100.0
    assert views.status_text("up", statuses[(1, "r1")], clock[0]).startswith("Up for at least 1 day")
    revision = engine.snapshot.revision
    reader.summary[1]["devices"]["r1"]["uptime"]["24h"] = 0.99  # A new round of pings: the pages are told
    reader.summary[1].update(updated=clock[0], interval=60)
    clock[0] += 20
    engine.step()
    assert engine.snapshot.revision > revision and engine.snapshot.uptime["24h"][(1, "r1")] == 0.99
    assert not engine.snapshot.statuses[(1, "r1")]["stale_at"]
    clock[0] += 3600  # The watcher stopped: still shown, grayed, as it was then (as NOMAD shows it)
    engine.step()
    assert engine.snapshot.statuses[(1, "r1")]["stale_at"] == clock[0] - 3620
    box = views.node_status(engine.snapshot, 1, "r1")
    assert box["status"] == "up" and box["stale_text"].startswith("Not checked since ")
    assert views.status_text("up", engine.snapshot.statuses[(1, "r1")], clock[0]).endswith("(it was up then)")
    engine.stop()


def review_snapshot():
    blocks = [{"index": 0, "kind": "added", "path": "", "fingerprint": "f0", "sensitive": True, "verdict": "unexpected",
               "note": "who is eve", "seconds": 4, "push": ""},
              {"index": 1, "kind": "changed", "path": "interface Gi0/1", "fingerprint": "f1", "sensitive": False,
               "verdict": "expected", "note": "", "seconds": 2, "push": ""}]
    reviews = {"to_review": 1, "raised": 1, "allow_acknowledge": False,
               "changes": [{"id": 3, "device_id": "10.0.0.1", "device_name": "R1", "which": "running",
                            "pulled_at": 300.0, "added": 1, "removed": 0, "first": 0, "changed_by": "",
                            "pulled_by": "alice (PC1)", "reviewed_by": None, "reviewed_at": None,
                            "review_state": None},
                           {"id": 2, "device_id": "10.0.0.1", "device_name": "R1", "which": "running",
                            "pulled_at": 200.0, "added": 2, "removed": 1, "first": 0, "changed_by": "eve",
                            "pulled_by": "alice (PC1)", "reviewed_by": "bob (PC2)", "reviewed_at": 250.0,
                            "review_state": "raised"}],
               "reviews": [{"id": 1, "version_id": 2, "device_id": "10.0.0.1", "device_name": "R1", "kind": "review",
                            "outcome": "raised", "user": "bob (PC2)", "at": 250.0, "seconds": 2.0,
                            "reason": "=Who is eve?", "blocks": blocks, "total": 2, "seen": 2, "unexpected": 1,
                            "self_review": False, "quick": True, "pulled_at": 200.0, "added": 2, "removed": 1,
                            "which": "running", "changed_by": "eve"}]}
    return snapshot_of(small_map(), tribe_reviews=reviews)


def test_reviews_page_shows_states_flags_and_notes_never_lines():
    snapshot = review_snapshot()
    page = views.reviews(snapshot)
    assert page["available"] and page["counts"] == {"available": True, "to_review": 1, "raised": 1}
    newest, raised = page["changes"]
    assert (newest["state"], newest["state_text"], newest["reviewed_by"]) == ("to_review", "To review", "")
    assert (raised["state_text"], raised["reason"], raised["blocks"], raised["quick"]) == ("Raised", "=Who is eve?", 2,
                                                                                          True)
    [logged] = page["log"]
    assert logged["notes"] == "1 (top level, unexpected): who is eve"
    assert (logged["changed_by"], logged["user"]) == ("eve", "bob (PC2)")  # Who made it, and who reviewed it
    assert [row["id"] for row in views.reviews(snapshot, "raised")["changes"]] == [2]
    assert [row["id"] for row in views.reviews(snapshot, "attention")["changes"]] == [3, 2]
    assert [row["id"] for row in views.reviews(snapshot, "flagged")["changes"]] == [2]
    assert views.overview(snapshot)["reviews"] == page["counts"]
    _, text = views.csv_table("reviews", snapshot)
    assert "'=Who is eve?" in text and "Raised" in text
    _, text = views.csv_table("review-log", snapshot)
    assert "who is eve" in text
    header, first = text.splitlines()[:2]
    assert header.split(",")[5] == "Changed by" and first.split(",")[5] == "eve"
    old = views.reviews(snapshot_of(small_map()))  # A tribe server too old to keep reviews
    assert not old["available"] and old["changes"] == []
