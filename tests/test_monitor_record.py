"""Monitoring records (monitor_record): picking up after a restart, gaps left out of the uptime, when each status
began, the changes an older record never got, and sharing a map's monitoring with NOMAD on this computer and through
the tribe; and the Map Watcher monitoring maps on this computer that aren't shared with the tribe (watch_local)."""
import json

import pytest

from nomad.netmap import counters, monitor, monitor_record, probes, store, tunnels, watch_local, watch_service
from nomad.netmap.model import ROUTER, SNMP, SWITCH, Device, NetworkMap
from nomad.netmap.monitor import DOWN, UNKNOWN, UP, Change, DeviceStatus, StatusTracker
from nomad.netmap.monitor_record import LocalRecord, Run
from nomad.netmap.watch import WatchOptions
from nomad.netmap.watch_monitor import MonitorRunner, MonitorStore, StatusReader

DAY = 86400


def test_uptime_leaves_out_the_gaps_and_counts_only_known_time():
    # Up for 10 s, down for 10 s, up again; nothing monitoring from 25 to 35
    events = [(10.0, DOWN), (20.0, UP)]
    assert monitor_record.fraction_up(UP, events, 0.0, 40.0) == pytest.approx(30 / 40)
    assert monitor_record.fraction_up(UP, events, 0.0, 40.0, [(25.0, 35.0)]) == pytest.approx(20 / 30)
    assert monitor_record.fraction_up(None, [], 0.0, 40.0) is None  # Never known
    assert monitor_record.merge_gaps([(5, 10), (8, 12), (20, 21), (30, 30)]) == [(5.0, 12.0), (20.0, 21.0)]


def test_a_run_of_the_same_status_counts_once_and_says_whether_its_start_is_known():
    changes = [("s1", DOWN, 100.0, 50.0), ("s1", DOWN, 500.0, None),  # Noted again after a restart
               ("r1", DOWN, 200.0, None), ("ap", UP, 300.0, 60.0)]
    runs = monitor_record.advance_runs({}, changes)
    assert runs["s1"] == Run(DOWN, 100.0, True)
    assert runs["r1"] == Run(DOWN, 200.0, False)  # Seen down when monitoring first saw it
    # The record goes back further than the monitoring (it started again since): the record's start wins
    assert monitor_record.since_of(DOWN, 500.0, False, runs["s1"]) == (100.0, True)
    assert monitor_record.since_of(UP, 500.0, False, runs["s1"]) == (500.0, False)  # Another status: its own
    assert monitor_record.since_of(UP, 300.0, True, runs["ap"]) == (300.0, True)
    assert monitor_record.since_of(UP, 900.0, False, None) == (900.0, False)
    assert monitor_record.since_of(DOWN, 100.0, False, runs["s1"]) == (100.0, True)  # The same change


def test_a_device_that_came_back_while_nothing_was_monitoring_is_filled_in():
    runs = {"s1": Run(DOWN, 100.0, True), "r1": Run(UP, 50.0, True)}
    states = {"s1": (UP, 400.0), "r1": (UP, 60.0), "new": (UP, 10.0), "x": (UNKNOWN, 500.0)}
    assert monitor_record.missing_changes(runs, states) == [("s1", UP, 400.0)]


def test_restore_carries_on_and_a_down_device_stays_down_until_it_answers():
    tracker = StatusTracker(clock=lambda: 1000.0)
    monitor_record.restore(tracker, [
        {"key": "s1", "status": DOWN, "since": 100.0, "checked": 900.0, "rtt": None, "via": "", "problem": "",
         "exact": 1},
        {"key": "r1", "status": UP, "since": 50.0, "checked": 900.0, "rtt": 2, "via": "", "problem": "", "exact": 0}])
    assert tracker.update({"s1": None, "r1": 3}) == []  # Still down, still up: nothing new
    assert tracker.get("r1").since == 50.0 and not tracker.get("r1").exact
    [change] = tracker.update({"s1": 4})
    assert (change.status, change.lasted) == (UP, 900.0)  # Down since 100, not since the restart
    assert tracker.get("s1").exact


def test_the_tracker_knows_when_a_since_is_only_when_it_was_first_seen():
    clock = [1000.0]
    tracker = StatusTracker(clock=lambda: clock[0])
    tracker.update({"r1": 2})
    assert not tracker.get("r1").exact  # Up when first seen: up for at least that long
    tracker.update({"r1": None})
    clock[0] += 60
    tracker.update({"r1": None})
    assert tracker.get("r1").status == DOWN and tracker.get("r1").exact


def test_a_local_record_picks_up_after_a_restart_and_notes_the_gap(tmp_path):
    clock = [10 * DAY]
    record = LocalRecord(tmp_path / "map.db", clock=lambda: clock[0])
    tracker = StatusTracker(clock=lambda: clock[0])
    changes = tracker.update({"r1": 2, "s1": None})
    clock[0] += 60
    changes += tracker.update({"r1": 2, "s1": None})  # s1 down after two misses
    record.add_changes(0, [(change, change.key, f"{change.key} {change.status}") for change in changes
                           if not (change.status == UP and change.lasted is None)])
    record.write_statuses(0, [(key, key, "", SWITCH, state) for key, state in tracker.devices.items()])
    record.checked(clock[0])
    record.close()

    clock[0] += 3600  # NOMAD closed for an hour
    record = LocalRecord(tmp_path / "map.db", clock=lambda: clock[0])
    again = StatusTracker(clock=lambda: clock[0])
    monitor_record.restore(again, record.saved_statuses(0))
    assert record.note_restart(clock[0], 60) == (10 * DAY + 60, clock[0])
    record.checked(clock[0])
    assert record.note_restart(clock[0] + 30, 60) is None  # A quick restart isn't a gap
    assert again.get("s1").status == DOWN and again.get("s1").since == 10 * DAY + 60
    assert "24h" not in record.view(0, again.devices)["s1"].uptime  # Known only for the gap: no uptime yet
    view = record.view(0, again.devices, now=clock[0] + 120)
    # Down the whole time it was known (the hour nothing was monitoring is left out)
    assert view["s1"].uptime["24h"] == pytest.approx(0.0)
    assert view["r1"].uptime["24h"] == pytest.approx(1.0)
    assert [row["text"] for row in record.recent_changes(0)] == ["s1 down"]
    record.close()


def test_a_maps_old_status_log_goes_into_its_record_once(tmp_path):
    record = LocalRecord(tmp_path / "map.db")
    log = [["2026-09-30T14:00:00", "s1", "S1", DOWN, "S1 is down"],
           ["2026-09-30T14:10:00", "s1", "S1", UP, "S1 is up again"]]
    record.import_log(log)
    record.import_log(log)  # Not twice
    rows = record.recent_changes(0)
    assert [row["text"] for row in rows] == ["S1 is down", "S1 is up again"]
    assert rows[0]["lasted"] is None and rows[1]["lasted"] == pytest.approx(600.0)
    record.close()


def test_a_summary_goes_back_into_statuses_grayed_once_its_watcher_stops():
    view = {"r1": DeviceStatus(UP, 2, 500.0, 0, 990.0, "", "", False, {"24h": 0.99})}
    summary = monitor_record.make_summary(view, "the Map Watcher on PC1", 60, 1000.0)
    summary = json.loads(json.dumps(summary))  # As shared: plain JSON
    states = monitor_record.from_summary(summary, now=1100.0)
    assert states["r1"].status == UP and states["r1"].uptime == {"24h": 0.99} and not states["r1"].exact
    assert states["r1"].source == "the Map Watcher on PC1"
    assert not states["r1"].stale_at
    stopped = monitor_record.from_summary(summary, now=1000.0 + 601)["r1"]  # The watcher stopped checking
    assert stopped.stale_at == 1000.0 and stopped.status == UP  # As it was then
    text = monitor_record.status_text(stopped, 1000.0 + 601)
    assert text.startswith("Not checked since ") and text.endswith(" (it was up then)")
    assert monitor_record.not_checked_text(stopped, 1000.0 + 601) == \
        f"Not checked since {monitor_record.clock_text(1000.0, 1601.0)}"
    assert monitor_record.from_summary({"version": 99}, now=1000.0) == {}


def test_texts_for_the_boxes_and_details():
    state = DeviceStatus(UP, 2, 1000.0, exact=False, uptime={"24h": 0.9998, "30d": 0.5})
    assert monitor_record.duration_since(state, 1000.0 + 3 * DAY) == "for at least 3 days"
    assert monitor_record.uptime_text(state.uptime) == "99.98% (24 h) · 50% (30 days)"
    assert monitor_record.short_duration(3 * DAY + 5) == "3 d" and monitor_record.short_duration(59) == "59 s"
    # Never rounded up, and the next unit too (the dashboard's map.js says it the same way)
    assert monitor_record.short_duration(30 * 3600 + 59) == "1 d 6 h"
    assert monitor_record.short_duration(5 * 3600 + 12 * 60 + 59) == "5 h 12 min"
    assert monitor_record.short_duration(119) == "1 min"


# --------------------------------------------------------------------- The Map Watcher

def a_map():
    network_map = NetworkMap()
    network_map.devices = {"r1": Device("r1", "R1", "10.0.0.1", kind=ROUTER, source=SNMP),
                           "s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP)}
    return network_map


class FakeMaps:
    def __init__(self, network_map):
        self.network_map = network_map

    def map_info(self, map_id):
        return {"id": map_id, "name": "Campus", "record_id": "abc"}

    def load(self, map_id):
        return self.network_map, {}


class FakeAccess:
    def access(self, map_id, network_map, keys, options, workers=16):
        return {}

    def forget(self, map_id, address):
        pass


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(probes, "discover", lambda routers, factory: probes.Discovery())
    monkeypatch.setattr(counters, "poll", lambda targets, indexes, factory: {})
    monkeypatch.setattr(tunnels, "poll", lambda *args, **kwargs: {})


def runner_for(tmp_path, clock, answers, shared=None):
    store_ = MonitorStore(tmp_path / "status.db", clock=lambda: clock[0])
    runner = MonitorRunner(FakeMaps(a_map()), [1], store_, lambda map_id, settings: WatchOptions(),
                           {"interval": 60}, client_factory=object, pinger=lambda address: answers.get(address),
                           clock=lambda: clock[0], access=FakeAccess(),
                           on_summary=(lambda map_id, summary: shared.__setitem__(map_id, summary))
                           if shared is not None else None)
    return runner, store_


def test_the_watcher_picks_up_after_a_restart_without_noting_anything_again(tmp_path, quiet):
    clock = [10 * DAY]
    answers = {"10.0.0.1": 3}
    runner, store_ = runner_for(tmp_path, clock, answers)
    runner.start = runner.restore  # No thread: step by hand
    runner.restore()
    for _ in range(2):
        runner.step()
        clock[0] += 61
    store_.close()

    clock[0] += 600  # Stopped for ten minutes (an update), S1 still down, R1 still up
    shared = {}
    runner, store_ = runner_for(tmp_path, clock, answers, shared)
    runner.restore()
    runner.step()
    reader = StatusReader(tmp_path / "status.db")
    assert [row["status"] for row in reader.changes_after(0)] == ["down"]  # Not "down" again
    statuses = {row["key"]: row for row in reader.statuses()}
    assert statuses["s1"]["since"] == 10 * DAY + 61 and statuses["r1"]["since"] == 10 * DAY
    [gap] = reader.gaps_after(0)
    assert gap["end_at"] - gap["start_at"] == pytest.approx(600 + 61)
    devices = shared[1]["devices"]
    assert devices["s1"]["status"] == DOWN and devices["s1"]["exact"] is False  # Down when first seen
    assert devices["r1"]["uptime"]["24h"] == pytest.approx(1.0)

    answers["10.0.0.2"] = 5  # S1 answers: it was down since before the restart
    clock[0] += 61
    runner.step()
    change = reader.changes_after(0)[-1]
    assert change["status"] == "up" and change["lasted"] == pytest.approx(clock[0] - (10 * DAY + 61))
    reader.close()
    store_.close()


def test_the_watcher_shares_each_maps_monitoring_on_this_computer_and_with_the_tribe(tmp_path):
    sent = []

    class Maps:
        def map_info(self, map_id):
            return {"name": "Campus", "record_id": "local1"} if map_id < 0 else {"name": "Campus"}

        def send_monitoring(self, map_id, summary):
            sent.append((map_id, summary))

    engine = watch_service.WatchEngine(Maps(), [], "pc-service", listen=False)
    engine.server_id, engine.shared_dir = "srv", tmp_path
    engine.share_summary(4, {"version": 1, "devices": {}})
    engine.share_summary(-1, {"version": 1, "devices": {"x": {}}})
    assert monitor_record.read_shared("tribe-srv-4", tmp_path) == {"version": 1, "devices": {}}
    assert monitor_record.read_shared("map-local1", tmp_path)["devices"] == {"x": {}}
    engine.send_summaries()
    assert sent == [(4, {"version": 1, "devices": {}})]  # Only the tribe map goes to the tribe


def test_an_older_tribe_server_isnt_asked_again_for_an_hour():
    from nomad.ipam.client import OldServerError

    class Maps:
        def send_monitoring(self, map_id, summary):
            raise OldServerError("old")

    clock = [1000.0]
    engine = watch_service.WatchEngine(Maps(), [], "pc-service", listen=False, clock=lambda: clock[0])
    engine.summaries = {4: {}}
    engine.send_summaries()
    assert engine.monitoring_refused_until == 1000.0 + watch_service.MONITORING_RETRY_SECONDS


# --------------------------------------------------------------------- Maps on this computer

def test_maps_on_this_computer_are_copied_in_and_monitored_without_the_tribe(tmp_path):
    network_map = a_map()
    record_id, made = watch_local.ensure_record_id(network_map)
    assert made and watch_local.ensure_record_id(network_map) == (record_id, False)
    config = watch_service.make_config(None, [], monitoring={"interval": 60})
    assert not watch_service.has_tribe(config) and "secret" not in config
    secrets = {"communities": ["lab"]}
    entry = watch_local.add(config, tmp_path, network_map, "Lab", tmp_path / "lab.nomadmap", secrets,
                            protect=lambda text: "x" + text)
    assert entry["id"] == -1 and (tmp_path / watch_local.FOLDER / f"{record_id}.nomadmap").exists()
    other = NetworkMap(record_id="second")
    assert watch_local.add(config, tmp_path, other, "Other", "", {}, protect=str)["id"] == -2
    config["local_maps"] = [item for item in config["local_maps"] if item["record_id"] != "second"]
    watch_local.remove_others(config, tmp_path)
    assert not (tmp_path / watch_local.FOLDER / "second.nomadmap").exists()

    local = watch_local.LocalMaps(tmp_path, config, unprotect=lambda text: text[1:])
    maps = watch_local.CombinedMaps(None, local)
    assert maps.map_info(-1)["record_id"] == record_id and maps.map_info(3) is None
    assert set(maps.load(-1)[0].devices) == {"r1", "s1"}
    assert maps.secrets(-1) == secrets
    maps.sync()  # No tribe: nothing to sync

    watch_service.save_config(config, tmp_path)
    engine = watch_service.make_engine(tmp_path)
    assert engine.watched == {} and engine.monitoring is not None
    assert engine.monitoring.map_ids == [-1]
    engine.monitoring.store.close()


def test_the_dashboard_reads_the_watchers_maps_on_this_computer(tmp_path):
    from nomad.dashboard.engine import LocalMapReader
    network_map = a_map()
    watch_local.ensure_record_id(network_map)
    config = watch_service.make_config(None, [])
    watch_local.add(config, tmp_path, network_map, "Lab", "", {}, protect=str)
    watch_service.save_config(config, tmp_path)
    reader = LocalMapReader(tmp_path)
    [entry] = reader()
    assert (entry.id, entry.name, set(entry.network_map.devices)) == (-1, "Lab", {"r1", "s1"})
    assert reader()[0].network_map is entry.network_map  # Read again only when the copy changes


def test_a_maps_record_id_is_saved_with_it(tmp_path):
    network_map = NetworkMap(record_id="abc")
    path = store.save(network_map, tmp_path / "m.nomadmap")
    assert store.load(path).record_id == "abc"


def test_the_tribe_keeps_the_watchers_monitoring_of_a_map(tmp_path):
    from nomad.netmap.shared import MapStore
    maps = MapStore(tmp_path / "maps.db")
    map_id, _ = maps.create("Campus", "alice", [])
    assert maps.monitoring(map_id) == {}
    maps.set_monitoring(map_id, {"version": 1, "devices": {}}, "Map Watcher service", 1000.0)
    assert maps.monitoring(map_id) == {"summary": {"version": 1, "devices": {}}, "updated": 1000.0,
                                       "by": "Map Watcher service"}
    maps.delete(map_id)
    assert maps.db.execute("SELECT count(*) FROM monitoring").fetchone()[0] == 0
    maps.close()


def test_change_text_is_unchanged_for_the_log():
    change = Change("s1", UP, 100.0, 120.0, 3)
    assert monitor.change_text(change, "S1", "10.0.0.2") == "S1 (10.0.0.2) is up again, after being down for 2 min (3 ms)"
