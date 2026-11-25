"""The Map Watcher's monitoring, for the NOMAD Dashboard: whether each device on the maps it watches is up (ping, or an
IP SLA probe on a router), the traffic on the ports at the ends of links and on the ports marked Graph on Dashboard,
the routers' tunnels, and scheduled sweeps of the maps' IPAM subnets.

What it finds goes in status.db in the watcher's folder (MonitorStore), which the NOMAD Dashboard service reads (read
only, with StatusReader). Each device's status, since and uptime are worked out here only, after each round of pings,
and shared as each map's summary (monitor_record): in status.db for the dashboard, and for NOMAD (see watch_service),
so the two always show the same. Status changes are kept a year; traffic only a few days (the dashboard keeps its own
history of that). Sweep results go to the tribe's IPAM like a sweep from the IP Addresses page.

NOMAD's own Monitor (the Monitor tick box on the Network Map) is separate: it still pings from that computer.

Qt-free and driven by a clock, like the rest of the watcher, so it's tested with fakes. MonitorRunner and SweepRunner
each run on a thread of their own, so a long crawl doesn't hold up the pings, or a sweep the crawls.
"""
import ipaddress
import json
import logging
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import counters, monitor, monitor_record, probes, tunnels
from .model import SNMP, port_key

log = logging.getLogger(__name__)

STATUS_FILE = "status.db"
KEEP_SECONDS = 3 * 86400  # Rates kept here: the dashboard keeps its own history
CHANGES_KEEP_SECONDS = 366 * 86400  # Status changes (and gaps) kept here: since and uptime are worked out from them
SUMMARY_META = "summary:"  # status.db's meta name for each map's summary ("summary:<map id>"), for the dashboard
OLDER_HISTORY_META = "older_history_taken"
DISCOVER_EVERY = 600  # Seconds between looks over the routers for NOMAD's IP SLA probes
ACCESS_RETRY = 900  # Seconds before a device no credential answered is asked again
STEP_SECONDS = 2
MONITOR_DEFAULTS = {"enabled": True, "interval": 60, "counter_interval": 300, "sweep_hours": 1,
                    "sweep_max_prefix": 22}
INTERVALS = [30, 60, 120, 300, 600]  # Seconds between pings, on offer
COUNTER_INTERVALS = [60, 120, 300, 600, 900]  # Seconds between counter reads, on offer
SWEEP_HOURS = [0, 1, 2, 4, 8, 12, 24]  # 0: no sweeps
SWEEP_PREFIXES = [20, 21, 22, 23, 24]  # The largest subnet swept (/20 = 4094 addresses)
SWEEP_WORKERS = 64
SWEEP_PASSES = 2
SWEEP_TIMEOUT_MS = 1000
SWEEPER = "Map Watcher service"

SCHEMA = """
CREATE TABLE IF NOT EXISTS rates (id INTEGER PRIMARY KEY AUTOINCREMENT, map_id INTEGER, device TEXT, port TEXT,
    at REAL, in_bps REAL, out_bps REAL, speed INTEGER, errors INTEGER, discards INTEGER);
CREATE INDEX IF NOT EXISTS rates_at ON rates(at);
CREATE TABLE IF NOT EXISTS tunnels (map_id INTEGER, device TEXT, at REAL, data TEXT, PRIMARY KEY (map_id, device));
"""  # With monitor_record's: device_status, changes, gaps and meta


def monitor_settings(config):
    """The monitoring settings in a watcher config (MONITOR_DEFAULTS for any left out, within sensible bounds)."""
    given = (config or {}).get("monitor") or {}
    settings = dict(MONITOR_DEFAULTS)
    for name, default in MONITOR_DEFAULTS.items():
        if name in given:
            try:
                settings[name] = type(default)(given[name])
            except (TypeError, ValueError):
                pass
    settings["interval"] = max(10, settings["interval"])
    settings["counter_interval"] = max(30, settings["counter_interval"])
    settings["sweep_hours"] = max(0, settings["sweep_hours"])
    settings["sweep_max_prefix"] = min(30, max(16, settings["sweep_max_prefix"]))
    return settings


# --------------------------------------------------------------------- Where it's kept

class MonitorStore(monitor_record.RecordStore):
    """status.db, written by the watcher's monitoring (any thread: one connection, behind a lock): the monitoring
    record of the maps it watches (monitor_record), and their ports' traffic and routers' tunnels."""

    def __init__(self, path, clock=time.time):
        super().__init__(path, clock)
        with self.lock:
            self.db.executescript(SCHEMA)
        self.next_prune = 0.0

    def add_rates(self, map_id, rows):
        """[(device key, port, when, Rate)]"""
        if rows:
            with self.lock, self.db:
                self.db.executemany("INSERT INTO rates (map_id, device, port, at, in_bps, out_bps, speed, errors, "
                                    "discards) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                    [(int(map_id), device, port, when, rate.in_bps, rate.out_bps, rate.speed,
                                      rate.errors, rate.discards) for device, port, when, rate in rows])

    def set_tunnels(self, map_id, readings, when):
        """{device key: tunnels.read_live's reading}"""
        with self.lock, self.db:
            self.db.execute("DELETE FROM tunnels WHERE map_id = ?", (int(map_id),))
            self.db.executemany("INSERT INTO tunnels VALUES (?, ?, ?, ?)",
                                [(int(map_id), key, when, json.dumps(reading)) for key, reading in readings.items()])

    def forget_maps(self, keep):
        """Drop what's kept for maps no longer watched."""
        super().forget_maps(keep)
        keep = [int(map_id) for map_id in keep]
        marks = ", ".join("?" * len(keep)) or "NULL"
        names = [f"{SUMMARY_META}{map_id}" for map_id in keep]
        name_marks = ", ".join("?" * len(names)) or "''"
        with self.lock, self.db:
            self.db.execute(f"DELETE FROM tunnels WHERE map_id NOT IN ({marks})", keep)
            self.db.execute(f"DELETE FROM meta WHERE name LIKE ? AND name NOT IN ({name_marks})",
                            [SUMMARY_META + "%", *names])

    def set_summary(self, map_id, summary):
        """A map's summary, for the dashboard to show as it is."""
        self.set_meta(f"{SUMMARY_META}{int(map_id)}", summary)

    def rates_after(self, after, limit=5000):
        """The readings after id `after`, oldest first (to copy and send on)."""
        return self.rows("SELECT * FROM rates WHERE id > ? ORDER BY id LIMIT ?", (int(after), int(limit)))

    def take_older_history(self, path):
        """Once: the status changes and gaps the NOMAD Dashboard's history (history.db at path) has from before this
        record's own (a Map Watcher before 2.8 kept only three days), so since and uptime here go back as far as the
        dashboard's did. Returns how many changes were taken."""
        if self.get_meta(OLDER_HISTORY_META) or not Path(path).exists():
            return 0
        try:
            source = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True, timeout=10)
            try:
                source.row_factory = sqlite3.Row
                changes = [dict(row) for row in source.execute(
                    "SELECT map_id, key, label, status, at, lasted, text FROM changes ORDER BY at, id")]
                try:
                    gaps = [(row["start_at"], row["end_at"]) for row in source.execute("SELECT * FROM gaps")]
                except sqlite3.OperationalError:  # A dashboard before 2.8
                    gaps = []
            finally:
                source.close()
        except sqlite3.Error as error:  # Asked again next start
            log.warning("Couldn't read the NOMAD Dashboard's history for the older status changes: %s", error)
            return 0
        firsts = {row["map_id"]: row["at"] for row in self.rows(
            "SELECT map_id, min(at) AS at FROM changes GROUP BY map_id")}
        older = [row for row in changes if row["map_id"] not in firsts or row["at"] < firsts[row["map_id"]]]
        have = set(self.gaps())
        with self.lock, self.db:
            self.db.executemany("INSERT INTO changes (map_id, key, label, status, at, lasted, text) VALUES "
                                "(:map_id, :key, :label, :status, :at, :lasted, :text)", older)
            self.db.executemany("INSERT INTO gaps (start_at, end_at) VALUES (?, ?)",
                                [gap for gap in gaps if tuple(gap) not in have])
            self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES (?, 'true')", (OLDER_HISTORY_META,))
        self.uptime_cache.clear()
        if older:
            log.info("Took %s older status changes from the NOMAD Dashboard's history", len(older))
        return len(older)

    def prune(self, keep_seconds=None, now=None):
        now = self.clock() if now is None else now
        if keep_seconds is None and now < self.next_prune:
            return
        self.next_prune = now + 3600
        super().prune(CHANGES_KEEP_SECONDS if keep_seconds is None else keep_seconds, now)
        with self.lock, self.db:
            self.db.execute("DELETE FROM rates WHERE at < ?", (now - KEEP_SECONDS,))


class StatusReader:
    """status.db read only (the NOMAD Dashboard). Every call opens it afresh if it couldn't be opened before, so the
    dashboard copes with a watcher installed after it."""

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.db = None

    def _connect(self):
        if self.db is None:
            if not self.path.exists():
                raise FileNotFoundError(str(self.path))
            self.db = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10, check_same_thread=False)
            self.db.row_factory = sqlite3.Row
        return self.db

    def rows(self, sql, parameters=()):
        with self.lock:
            try:
                return [dict(row) for row in self._connect().execute(sql, parameters).fetchall()]
            except sqlite3.Error:
                if self.db is not None:
                    self.db.close()
                    self.db = None
                raise

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

    def statuses(self):
        return self.rows("SELECT * FROM device_status")

    def gaps_after(self, after):
        """The gaps in the monitoring after id `after` ([] from a status.db before 2.8)."""
        try:
            return self.rows("SELECT * FROM gaps WHERE id > ? ORDER BY id", (int(after),))
        except sqlite3.OperationalError:
            return []

    def changes_after(self, after, limit=5000):
        return self.rows("SELECT * FROM changes WHERE id > ? ORDER BY id LIMIT ?", (int(after), int(limit)))

    def rates_after(self, after, limit=20000):
        return self.rows("SELECT * FROM rates WHERE id > ? ORDER BY id LIMIT ?", (int(after), int(limit)))

    def tunnels(self):
        return [dict(row, data=json.loads(row["data"])) for row in self.rows("SELECT * FROM tunnels")]

    def meta(self):
        return {row["name"]: json.loads(row["value"]) for row in self.rows("SELECT * FROM meta")
                if not row["name"].startswith(SUMMARY_META)}

    def summaries(self):
        """{map id: its summary (monitor_record.make_summary)}, as the watcher worked it out last."""
        found = {}
        for row in self.rows("SELECT * FROM meta WHERE name LIKE ?", (SUMMARY_META + "%",)):
            try:
                found[int(row["name"][len(SUMMARY_META):])] = json.loads(row["value"])
            except ValueError:
                continue
        return found


# --------------------------------------------------------------------- Which credential each device answers

class AccessFinder:
    """The credential each device answers SNMP with, found by asking it with the map's credentials in turn (as a
    crawl would) and kept, until reading it fails."""

    def __init__(self, client_factory, clock=time.time, check=None):
        self.client_factory, self.clock = client_factory, clock
        self.check = check
        self.found = {}  # (map id, address) -> (credential or None, when)
        self.lock = threading.Lock()

    def credential(self, map_id, address, options):
        with self.lock:
            known = self.found.get((map_id, address))
        if known is not None and (known[0] is not None or self.clock() - known[1] < ACCESS_RETRY):
            return known[0]
        credential = self.ask(address, options)
        with self.lock:
            self.found[(map_id, address)] = (credential, self.clock())
        return credential

    def ask(self, address, options):
        from .crawl import CrawlSettings, check_device
        settings = CrawlSettings(seeds=[], communities=list(options.communities),
                                 overrides=[tuple(item) for item in options.overrides], scope=list(options.scope),
                                 version=options.version, timeout=options.timeout)
        check = (self.check or check_device)(settings, address, self.client_factory, pinger=lambda _: False)
        return check.community if check is not None and check.source == SNMP else None

    def forget(self, map_id, address):
        with self.lock:
            self.found.pop((map_id, address), None)

    def access(self, map_id, network_map, keys, options, workers=16):
        """{device key: (address, credential)} of these devices, asking those not known yet at once."""
        wanted = {key: network_map.devices[key].mgmt_ip for key in keys
                  if key in network_map.devices and network_map.devices[key].mgmt_ip}
        if not wanted:
            return {}
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(wanted)))) as executor:
            found = dict(zip(wanted, executor.map(lambda address: self.credential(map_id, address, options),
                                                  wanted.values())))
        return {key: (wanted[key], credential) for key, credential in found.items() if credential is not None}


# --------------------------------------------------------------------- One map

class MapState:
    """What the monitoring knows of one map between polls."""

    def __init__(self, clock=time.time):
        self.tracker = monitor.StatusTracker(clock=clock)
        self.counters = counters.CounterTracker()
        self.indexes = {}  # Device key -> {port key: ifIndex}
        self.probes = {}  # Device key -> probes.Probe
        self.discovered_at = 0.0
        self.discovered_routers = None
        self.last_results = {}  # Device key -> (router, entry, time of the result used last)
        self.next_ping = 0.0
        self.next_counters = 0.0


class MonitorRunner:
    """Pings the watched maps' devices (or reads their IP SLA probes) every interval, and their linked and graphed
    ports' counters every counter interval, into a MonitorStore.

    maps: the watcher's TribeMaps; options_for(map_id, settings): a watch.WatchOptions with the map's credentials."""

    def __init__(self, maps, map_ids, store, options_for, settings=None, client_factory=None, pinger=monitor.ping,
                 clock=time.time, access=None, on_summary=None, source="the Map Watcher", older_history=None):
        """on_summary(map id, summary): handed each map's monitoring_record summary after each round of pings (to
        share it); source: who the summaries say they're from; older_history: the NOMAD Dashboard's history.db, to
        take the status changes from that are older than status.db's (once)."""
        from ..snmp import SnmpClient
        self.maps, self.store, self.options_for = maps, store, options_for
        self.on_summary, self.source = on_summary, source
        self.older_history = older_history
        self.map_ids = [int(map_id) for map_id in map_ids]
        self.settings = monitor_settings({"monitor": settings or {}})
        self.client_factory = client_factory or SnmpClient
        self.pinger, self.clock = pinger, clock
        self.access = access or AccessFinder(self.client_factory, clock)
        self.states = {map_id: MapState(clock) for map_id in self.map_ids}
        self.stop_event = threading.Event()
        self.thread = None

    # ----------------------------------------------------------------- Running

    def start(self):
        self.restore()
        self.store.set_meta("monitor", {"maps": self.map_ids, "interval": self.settings["interval"],
                                        "counter_interval": self.settings["counter_interval"],
                                        "started": self.clock()})
        self.thread = threading.Thread(target=self.run, name="Map Watcher monitoring", daemon=True)
        self.thread.start()

    def restore(self):
        """Carry on from where monitoring stopped: each map's statuses as saved, and the time since its last check
        noted as a gap (left out of the uptime)."""
        self.store.forget_maps(self.map_ids)
        if self.older_history is not None:
            self.store.take_older_history(self.older_history)
        for map_id in self.map_ids:
            monitor_record.restore(self.states[map_id].tracker, self.store.saved_statuses(map_id))
        gap = self.store.note_restart(self.clock(), self.settings["interval"])
        if gap is not None:
            log.info("Nothing was monitoring for %s (from %s): left out of the uptime",
                     monitor.duration_text(gap[1] - gap[0]), time.strftime("%Y-%m-%d %H:%M", time.localtime(gap[0])))

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.step()
            except Exception:  # One bad round shouldn't stop the monitoring
                log.exception("Monitoring failed this time round")
            self.stop_event.wait(STEP_SECONDS)

    def stop(self, wait=10):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(wait)

    def step(self):
        now = self.clock()
        for map_id in self.map_ids:
            if self.stop_event.is_set():
                return
            state = self.states[map_id]
            ping_due, counters_due = now >= state.next_ping, now >= state.next_counters
            if not ping_due and not counters_due:
                continue
            if self.maps.map_info(map_id) is None:
                continue  # Not synced yet, or deleted
            network_map, settings = self.maps.load(map_id)
            options = self.options_for(map_id, settings)
            if ping_due:
                state.next_ping = now + self.settings["interval"]
                self.ping(map_id, state, network_map, options)
            if counters_due:
                state.next_counters = now + self.settings["counter_interval"]
                self.read_counters(map_id, state, network_map, options)
        self.store.set_meta("monitor_at", self.clock())
        self.store.prune()

    # ----------------------------------------------------------------- Up or down

    def discover(self, map_id, state, network_map, options):
        routers = probes.readable_routers(network_map)
        found = self.access.access(map_id, network_map, routers, options)
        targets = [(key, address, credential, options.version, options.timeout)
                   for key, (address, credential) in sorted(found.items())]
        discovery = probes.discover(targets, self.client_factory)
        usable = [probe for probe in discovery.probes if probe.router in network_map.devices
                  and network_map.devices[probe.router].mgmt_ip == probe.address]
        state.probes = probes.assign(network_map, usable)
        state.discovered_at = self.clock()
        state.discovered_routers = frozenset(routers)

    def ping(self, map_id, state, network_map, options):
        if state.discovered_routers != frozenset(probes.readable_routers(network_map)) or \
                self.clock() - state.discovered_at > DISCOVER_EVERY:
            self.discover(map_id, state, network_map, options)
        devices = network_map.devices
        state.probes = {key: probe for key, probe in state.probes.items() if key in devices}
        targets = {key: device.mgmt_ip for key, device in devices.items() if device.mgmt_ip}
        for key, probe in state.probes.items():
            targets.setdefault(key, probe.target)
        state.tracker.forget_others(set(targets))
        labels = {key: device.label for key, device in devices.items()}
        pings = {key: address for key, address in targets.items() if key not in state.probes}
        results = monitor.poll(pings, self.pinger)
        if any(rtt is None for rtt in results.values()) and \
                self.clock() - state.discovered_at > probes.LOOK_AGAIN_AFTER_MISS:
            # Someone may have just given a device it can't ping a probe: look now, not up to DISCOVER_EVERY later
            # (till then it would be down here while NOMAD, which found the probe at once, has it up)
            self.discover(map_id, state, network_map, options)
            state.probes = {key: probe for key, probe in state.probes.items() if key in devices}
            results = {key: rtt for key, rtt in results.items() if key not in state.probes}
            for key, probe in state.probes.items():
                targets.setdefault(key, probe.target)
        via, problems = {}, {}
        if state.probes:
            entries = {}
            for probe in state.probes.values():
                entries.setdefault(probe.router, []).append(probe.entry)
            found = self.access.access(map_id, network_map, list(entries), options)
            read = probes.poll([(router, found[router][0], found[router][1], options.version, options.timeout,
                                 sorted(numbers)) for router, numbers in sorted(entries.items()) if router in found],
                               self.client_factory)
            for key, probe in state.probes.items():
                router = labels.get(probe.router, probe.router)
                via[key] = probe.where(router)
                got = read.get(probe.router)
                if probe.router not in found:
                    problems[key] = f"no SNMP credential of the map answers on {router}"
                elif isinstance(got, str) or got is None:
                    problems[key] = f"{router} isn't answering SNMP"
                    self.access.forget(map_id, found[probe.router][0])
                elif probe.entry not in got:
                    problems[key] = f"{router} didn't give IP SLA {probe.entry}'s result"
                else:
                    reading = got[probe.entry]
                    why = probes.stale(probe, reading)
                    if why:
                        problems[key] = f"{why} (IP SLA {probe.entry} on {router})"
                        continue
                    stamp = (probe.router, probe.entry, reading.time)
                    if state.last_results.get(key) == stamp:
                        continue  # No new result since the last poll: it counts once
                    state.last_results[key] = stamp
                    results[key] = reading.rtt if reading.ok else None
        changes = state.tracker.update(results, via) + state.tracker.cannot_check(problems, via)
        logged = []
        for change in changes:
            if change.status == monitor.UP and change.lasted is None:
                continue  # Answered the first poll: nothing's happened to it
            label = labels.get(change.key, change.key)
            text = monitor.change_text(change, label, targets.get(change.key, ""))
            log.info("%s", text)
            logged.append((change, label, text))
        self.store.add_changes(map_id, logged)
        self.store.write_statuses(map_id, [(key, labels.get(key, key), address, devices[key].kind,
                                            state.tracker.get(key)) for key, address in targets.items()
                                           if key in devices])
        self.store.fill_in(map_id, labels, state.tracker.devices)
        self.store.checked(self.clock())
        summary = self.store.summary(map_id, self.source, self.settings["interval"], dict(state.tracker.devices))
        self.store.set_summary(map_id, summary)
        if self.on_summary is not None:
            try:
                self.on_summary(map_id, summary)
            except Exception:  # Sharing it further is a nicety: monitoring carries on
                log.exception("Couldn't share the monitoring of map %s", map_id)

    # ----------------------------------------------------------------- Traffic

    @staticmethod
    def ports_to_read(network_map):
        """{device key: [port]}: the ports at the ends of links and those marked to graph, on the devices that answer
        SNMP."""
        return counters.graph_ports(network_map)

    def read_counters(self, map_id, state, network_map, options):
        ports = self.ports_to_read(network_map)
        routers = tunnels.tunnel_routers(network_map)
        found = self.access.access(map_id, network_map, set(ports) | set(routers), options)
        targets = [(key, found[key][0], found[key][1], options.version, options.timeout, wanted)
                   for key, wanted in sorted(ports.items()) if key in found]
        tunnel_targets = [(key, found[key][0], found[key][1], options.version, options.timeout, wanted)
                          for key, wanted in sorted(routers.items()) if key in found]
        state.counters.forget_others(set(network_map.devices))
        results = counters.poll(targets, state.indexes, self.client_factory) if targets else {}
        names = {(key, port_key(port)): port for key, wanted in ports.items() for port in wanted}
        rows = []
        for key, (index, samples) in results.items():
            state.indexes[key] = index
            before = {where: state.counters.rates.get(where) for where in ((key, port) for port in samples)}
            state.counters.update(key, samples)
            for port, sample in samples.items():
                rate = state.counters.rates.get((key, port))
                if rate is not None and rate is not before.get((key, port)):
                    rows.append((key, names.get((key, port), port), self.clock(), rate))
        for key, address, *_ in targets:
            if key not in results:
                self.access.forget(map_id, address)  # Asked again next time: its credential may have changed
        self.store.add_rates(map_id, rows)
        if tunnel_targets:
            indexes = dict(state.indexes)
            live = tunnels.poll(tunnel_targets, indexes, self.client_factory, counters.interface_index)
            for key, (index, _) in live.items():
                state.indexes[key] = index
            self.store.set_tunnels(map_id, {key: reading for key, (_, reading) in live.items()}, self.clock())


# --------------------------------------------------------------------- Scheduled sweeps

def team_network_id(network_map):
    """The tribe IPAM network a map is of, or ""."""
    link = network_map.ipam_network or ""
    return link.split(":", 1)[1] if link.startswith("team:") else ""


def subnets_to_sweep(subnets, max_prefix):
    """The IPv4 subnets to sweep, as ip_networks: those no larger than /max_prefix, leaving out any that hold other
    subnets (their subnets are swept instead)."""
    blocks = []
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(str(subnet), strict=False)
        except ValueError:
            continue
        if network.version == 4:
            blocks.append(network)
    swept = []
    for network in blocks:
        if network.prefixlen < max_prefix:
            continue
        if any(other != network and other.subnet_of(network) for other in blocks):
            continue
        swept.append(network)
    return sorted(set(swept))


class SweepRunner:
    """Every sweep_hours, ping-sweeps the IPAM subnets of each watched map's tribe network and records what answered
    in the tribe's IPAM (Last Seen on the IP Addresses page; hosts per subnet on the dashboard).

    team: a TeamStore of its own, or team_factory() to make one on this runner's thread (its SQLite copy is used on
    that thread only). Pings only: no names, and no ARP (a router's proxy ARP would make every address look
    taken)."""

    def __init__(self, maps, map_ids, team=None, settings=None, pinger=None, clock=time.time, store=None,
                 team_factory=None):
        self.maps, self.team, self.clock, self.store = maps, team, clock, store
        self.team_factory = team_factory
        self.map_ids = [int(map_id) for map_id in map_ids]
        self.settings = monitor_settings({"monitor": settings or {}})
        self.pinger = pinger
        self.next_sweep = 0.0
        self.stop_event = threading.Event()
        self.thread = None

    @property
    def enabled(self):
        return self.settings["sweep_hours"] > 0

    def start(self):
        if not self.enabled:
            return
        self.thread = threading.Thread(target=self.run, name="Map Watcher sweeps", daemon=True)
        self.thread.start()

    def run(self):
        self.stop_event.wait(120)  # Let the tribe sync first
        while not self.stop_event.is_set():
            try:
                self.step()
            except Exception:
                log.exception("Sweeping failed this time round")
            self.stop_event.wait(60)

    def stop(self, wait=10):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(wait)

    def step(self):
        now = self.clock()
        if not self.enabled or now < self.next_sweep:
            return 0
        self.next_sweep = now + self.settings["sweep_hours"] * 3600
        if self.team is None:
            self.team = self.team_factory()
        try:
            self.team.sync()
        except Exception as error:
            log.info("Couldn't sync the tribe's IP addresses before sweeping: %s", error)
        networks = {}
        for map_id in self.map_ids:
            if self.maps.map_info(map_id) is None:
                continue
            network_map, _ = self.maps.load(map_id)
            network_id = team_network_id(network_map)
            if network_id:
                networks[network_id] = map_id
        answered = 0
        for network_id in networks:
            if self.stop_event.is_set():
                break
            try:
                subnets = [subnet.cidr for subnet in self.team.copy.subnets(network_id) if not subnet.loopbacks]
            except Exception as error:
                log.info("Couldn't read the subnets of tribe network %s: %s", network_id, error)
                continue
            for network in subnets_to_sweep(subnets, self.settings["sweep_max_prefix"]):
                if self.stop_event.is_set():
                    break
                answered += self.sweep(network_id, network)
        self.send()
        if self.store is not None:
            self.store.set_meta("sweep_at", self.clock())
        return answered

    def sweep(self, network_id, network):
        from .. import sweep
        hosts = list(network.hosts()) or [network.network_address]
        started = self.clock()
        probe = sweep.make_probe(SWEEP_TIMEOUT_MS, arp_networks=(), find_by_arp=False, ping=self.pinger)
        alive = sweep.run_sweep(hosts, probe, SWEEP_WORKERS, passes=SWEEP_PASSES, should_stop=self.stop_event.is_set)
        if self.stop_event.is_set():
            return 0
        finished = self.clock()
        found = [{"ip": str(address), "seen": finished, "rtt": hit.rtt} for address, hit in alive]
        self.team.record_sightings(network_id, found, [{"cidr": str(network), "started": started,
                                                        "finished": finished}])
        log.info("Swept %s: %s answered", network, len(found))
        return len(found)

    def send(self):
        try:
            done = self.team.send_sightings(self.team.outgoing_sightings())
            self.team.apply_sent_sightings(done)
        except Exception as error:  # Sent with the next round
            log.info("Couldn't send the sweep results yet: %s", error)
