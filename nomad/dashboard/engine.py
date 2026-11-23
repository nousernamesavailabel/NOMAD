"""The NOMAD Dashboard's engine: threads that keep a Snapshot of everything the pages show, and its history.

- The tribe thread syncs the tribe (viewer key) and waits on it for changes.
- The main thread takes in the Map Watcher's status.db every INGEST_SECONDS, reads the collectors every
  COLLECTOR_SECONDS, counts hosts per subnet every HOST_COUNT_SECONDS, and prunes the history every hour.

Each device's status, since and uptime are the Map Watcher's, as it worked them out last (its summary of each map in
status.db, the same NOMAD shows), never worked out again here, so the dashboard and NOMAD always agree.

Each new Snapshot replaces the last as a whole (the web server's threads only read it) and bumps the revision, which
the pages are told about over Server-Sent Events.
"""
import ipaddress
import logging
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..netmap import monitor_record
from . import history as history_module
from .sources import CollectorView, MapEntry, TribeData, TribeView

log = logging.getLogger(__name__)

INGEST_SECONDS = 15
COLLECTOR_SECONDS = 60
HOST_COUNT_SECONDS = 300
PRUNE_SECONDS = 3600
TRIBE_RETRY_SECONDS = 30
HOST_TREND_WINDOW = 3600  # Hosts seen in the last hour, for the trend
UPTIME_SPANS = monitor_record.UPTIME_SPANS
MAP, SWEEP, FLOW = "map", "sweep", "flow"


@dataclass
class Snapshot:
    revision: int = 0
    built_at: float = 0.0
    tribe: TribeData = field(default_factory=TribeData)
    # (map id, device key) -> status.db's device_status row, with since (and exact) from the Map Watcher's summary
    statuses: dict = field(default_factory=dict)
    watcher: dict = field(default_factory=dict)  # {"available", "error", "monitor_at", "sweep_at", "maps", ...}
    tunnels: dict = field(default_factory=dict)  # (map id, device key) -> {"at", "data": tunnels.read_live's}
    rates: dict = field(default_factory=dict)  # (map id, device key, port) -> the newest rate row
    peaks: dict = field(default_factory=dict)  # (map id, device key, port) -> (peak in, peak out, speed) today
    uptime: dict = field(default_factory=dict)  # "24h"/"7d"/"30d" -> {(map id, device key): fraction up}, the watcher's
    syslog: dict = field(default_factory=dict)
    flows: dict = field(default_factory=dict)


# --------------------------------------------------------------------- Hosts per subnet

class SubnetIndex:
    """Finds the most specific subnet an address is in, from many subnets, quickly."""

    def __init__(self, cidrs):
        self.by_length = {}
        for cidr in cidrs:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            self.by_length.setdefault((network.version, network.prefixlen), {})[int(network.network_address)] = cidr
        self.lengths = sorted(self.by_length, key=lambda item: (item[0], -item[1]))

    def find(self, address):
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        bits = ip.max_prefixlen
        value = int(ip)
        for version, length in self.lengths:
            if version != ip.version:
                continue
            masked = value & (((1 << length) - 1) << (bits - length)) if length else 0
            found = self.by_length[(version, length)].get(masked)
            if found is not None:
                return found
        return None


def map_subnets(entry):
    """For a map with no IPAM network: the subnets its devices have addresses in (from their L3 interfaces)."""
    found = set()
    for device in entry.network_map.devices.values():
        for address, prefix, _port in device.interfaces_l3:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.version == 4 and 8 <= network.prefixlen <= 30 and not network.is_loopback:
                found.add(str(network))
    return found


def map_host_addresses(entry):
    """{address} of the hosts on a map that its switches' tables and controllers listed (hand-added hosts aren't
    seen by anything, so they never count as seen)."""
    return {host.ip for host in entry.network_map.hosts if host.ip and not host.manual}


def device_addresses(tribe):
    """{address} of the maps' network devices: switches, routers and the like aren't hosts, though they answer
    sweeps and turn up in NetFlow."""
    found = set()
    for entry in tribe.maps:
        for device in entry.network_map.devices.values():
            found.update(address for address in [device.mgmt_ip, *device.addresses] if address)
            found.update(item[0] for item in device.interfaces_l3 if item and item[0])
    return found


def subnet_groups(tribe):
    """({network key: (SubnetIndex, {cidr: SubnetEntry or None}, name)}, {map id: network key}): the tribe IPAM's
    networks, and for maps with no IPAM network the subnets of their devices' interfaces."""
    groups = {}
    for network in tribe.networks:
        subnets = {subnet.cidr: subnet for subnet in tribe.subnets if subnet.network_id == network["id"]}
        groups[network["id"]] = (SubnetIndex(subnets), subnets, network["name"])
    map_networks = {}
    for entry in tribe.maps:
        if entry.network_id and entry.network_id in groups:
            map_networks[entry.id] = entry.network_id
            continue
        cidrs = map_subnets(entry)
        if cidrs:
            key = f"map:{entry.id}"
            groups[key] = (SubnetIndex(cidrs), {cidr: None for cidr in cidrs}, entry.name)
            map_networks[entry.id] = key
    return groups, map_networks


def host_subnets(tribe):
    """Every subnet hosts can be counted in: [{network, network_name, subnet, name}], as count_hosts names them."""
    rows = []
    for key, (_index, subnets, name) in subnet_groups(tribe)[0].items():
        for cidr, subnet in subnets.items():
            rows.append({"network": key, "network_name": name, "subnet": cidr,
                         "name": subnet.name if subnet is not None else ""})
    rows.sort(key=lambda row: (row["network_name"].lower(), _cidr_order(row["subnet"])))
    return rows


def _cidr_order(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.version, int(network.network_address), network.prefixlen
    except ValueError:
        return 9, 0, 0


def count_hosts(tribe, seen_map, seen_flow, start):
    """Hosts seen since start in each subnet: [{subnet, network, name, total, map, sweep, flow, size}].

    Subnets are the tribe IPAM's (for the maps of a tribe network, and the sweeps of each network), and for maps with
    no IPAM network the subnets of their devices' interfaces. An address counts once in its most specific subnet,
    whatever saw it; map hosts and sweeps count in their own network. A NetFlow address says nothing of its network,
    so it counts once: in the networks where the maps or sweeps saw it too, else in the one with the most specific
    subnet for it. The network devices' own addresses aren't hosts and never count."""
    groups, map_networks = subnet_groups(tribe)
    infrastructure = device_addresses(tribe)
    found = {}  # (network key, cidr) -> {source: {address}}
    placed = {}  # address -> {network key} it counted in, from the maps and sweeps

    def note(network_key, address, source):
        cidr = groups[network_key][0].find(address)
        if cidr is not None:
            found.setdefault((network_key, cidr), {}).setdefault(source, set()).add(address)
            placed.setdefault(address, set()).add(network_key)

    map_addresses = {address for address, when in seen_map.items() if when >= start} - infrastructure
    for entry in tribe.maps:
        network_key = map_networks.get(entry.id)
        if network_key is not None:
            for address in map_host_addresses(entry) & map_addresses:
                note(network_key, address, MAP)
    for network_id, seen in tribe.sightings.items():
        if network_id in groups:
            for address, when in seen.items():
                if when >= start and address not in infrastructure:
                    note(network_id, address, SWEEP)
    for address, when in seen_flow.items():
        if when < start or address in infrastructure:
            continue
        targets = placed.get(address)
        if not targets:
            matches = [(key, cidr) for key in groups for cidr in [groups[key][0].find(address)] if cidr is not None]
            if not matches:
                continue
            targets = [max(matches, key=lambda match: _cidr_order(match[1])[2])[0]]  # First of the most specific
        for network_key in list(targets):
            note(network_key, address, FLOW)
    rows = []
    for (network_key, cidr), sources in found.items():
        _, subnets, name = groups[network_key]
        subnet = subnets.get(cidr)
        everyone = set().union(*sources.values())
        try:
            size = subnet.size if subnet is not None else max(1, ipaddress.ip_network(cidr).num_addresses - 2)
        except ValueError:
            size = 1
        rows.append({"subnet": cidr, "network": network_key, "network_name": name,
                     "name": subnet.name if subnet is not None else "", "total": len(everyone),
                     MAP: len(sources.get(MAP, ())), SWEEP: len(sources.get(SWEEP, ())),
                     FLOW: len(sources.get(FLOW, ())), "size": size})
    rows.sort(key=lambda row: (row["network_name"].lower(), ipaddress.ip_network(row["subnet"]).version,
                               int(ipaddress.ip_network(row["subnet"]).network_address)))
    return rows


def mac_only_hosts(tribe):
    """Hosts on the maps with no address, by map and VLAN: [{map, vlan, count}] (hand-added ones left out, as
    count_hosts leaves them out)."""
    counts = {}
    for entry in tribe.maps:
        for host in entry.network_map.hosts:
            if not host.ip and not host.manual:
                key = (entry.name, host.vlan or 0)
                counts[key] = counts.get(key, 0) + 1
    return [{"map": name, "vlan": vlan, "count": count} for (name, vlan), count in sorted(counts.items())]


# --------------------------------------------------------------------- The watcher's statuses

def statuses_with_summaries(rows, summaries, now):
    """The watcher's device_status rows {(map id, key): row}, each with since and exact as its summary of the map has
    them (and stale_at once the watcher has stopped checking), and the uptimes {"24h": {(map id, key): fraction}...}
    from the summaries: what NOMAD shows, as it is."""
    statuses, uptime = {}, {name: {} for name in UPTIME_SPANS}
    stopped = {map_id: monitor_record.stale_at(summary, now) for map_id, summary in summaries.items()
               if isinstance(summary, dict)}
    for row in rows:
        device = (row["map_id"], row["key"])
        item = ((summaries.get(row["map_id"]) or {}).get("devices") or {}).get(row["key"])
        if isinstance(item, dict) and item.get("status") == row["status"]:
            row = dict(row, since=item.get("since") or row["since"], exact=bool(item.get("exact")))
            for name, value in (item.get("uptime") or {}).items():
                if name in uptime and isinstance(value, (int, float)):
                    uptime[name][device] = float(value)
        else:
            row = dict(row, exact=bool(row.get("exact")))
        row["stale_at"] = stopped.get(row["map_id"], 0.0)
        statuses[device] = row
    return statuses, uptime


# --------------------------------------------------------------------- The maps on this computer

class LocalMapReader:
    """The maps on this computer the Map Watcher monitors (watch_local), read from its folder: [MapEntry], each read
    again only when its copy changes."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.cache = {}  # record ID -> (modified time, NetworkMap)

    def __call__(self):
        from ..netmap import store, watch_local
        from ..netmap.watch_service import load_config
        try:
            config = load_config(self.directory)
        except (OSError, ValueError):
            return []
        found = []
        for entry in watch_local.entries(config):
            path = self.directory / watch_local.FOLDER / f"{entry['record_id']}{store.EXTENSION}"
            try:
                modified = path.stat().st_mtime
                cached = self.cache.get(entry["record_id"])
                if cached is None or cached[0] != modified:
                    cached = (modified, store.load(path))
                    self.cache[entry["record_id"]] = cached
            except (OSError, ValueError):
                continue
            found.append(MapEntry(entry["id"], entry.get("name") or "Map", cached[1]))
        return found


# --------------------------------------------------------------------- The engine

class Engine:
    def __init__(self, directory, key=None, settings=None, status_reader=None, collectors=None, tribe=None,
                 clock=time.time, on_moved=None, local_maps=None):
        """local_maps(): [MapEntry] of the maps on this computer the Map Watcher monitors (default: read from its
        folder)."""
        from ..netmap.watch_monitor import STATUS_FILE, StatusReader
        from ..netmap.watch_service import watcher_dir
        self.directory = Path(directory)
        self.settings = dict(settings or {})
        self.clock = clock
        self.history = history_module.HistoryStore(self.directory / history_module.HISTORY_FILE, clock)
        if not self.history.get("flow_senders_only"):
            # Up to 2.9.0 every address a flow went to counted as seen, every address a sweep pinged among them:
            # those go, and the senders of the last week are read again from the Flow Collector
            self.history.forget_seen(FLOW)
            self.history.set("flow_addresses_at", clock() - 7 * 86400)
            self.history.set("flow_senders_only", 1)
        self.reader = status_reader or StatusReader(watcher_dir() / STATUS_FILE)
        self.collectors = collectors or CollectorView(clock=clock)
        self.tribe = tribe or (TribeView(key, self.directory, on_moved, clock) if key is not None else None)
        self.snapshot = Snapshot()
        if self.tribe is None:  # No viewer key given yet: the pages say so
            self.snapshot = Snapshot(tribe=TribeData(error="no viewer key: choose one in NOMAD (Tools > NOMAD "
                                                           "Dashboard Service)"))
        self.lock = threading.Lock()
        self.changed = threading.Condition()
        self.stop_event = threading.Event()
        self.threads = []
        self.next = {"ingest": 0.0, "collectors": 0.0, "hosts": 0.0, "prune": 0.0}
        self.last_status_signature = None
        self.tribe_data = self.snapshot.tribe  # As the tribe thread last had it (the snapshot's adds the local maps)
        self.local_maps = local_maps or LocalMapReader(watcher_dir())
        self.local_entries = []

    # ----------------------------------------------------------------- The snapshot

    def publish(self, **changes):
        """A new snapshot with these parts changed, and a new revision announced."""
        with self.lock:
            self.snapshot = replace(self.snapshot, revision=self.snapshot.revision + 1, built_at=self.clock(),
                                    **changes)
        with self.changed:
            self.changed.notify_all()

    def wait_for_change(self, revision, timeout):
        """Block until the revision passes `revision` (or timeout). Returns the current revision."""
        with self.changed:
            self.changed.wait_for(lambda: self.snapshot.revision != revision or self.stop_event.is_set(), timeout)
        return self.snapshot.revision

    # ----------------------------------------------------------------- Running

    def start(self):
        if self.tribe is not None:
            self.threads.append(threading.Thread(target=self.run_tribe, name="Dashboard tribe", daemon=True))
        self.threads.append(threading.Thread(target=self.run, name="Dashboard engine", daemon=True))
        for thread in self.threads:
            thread.start()

    def stop(self):
        self.stop_event.set()
        with self.changed:
            self.changed.notify_all()
        for thread in self.threads:
            thread.join(10)
        self.reader.close()
        self.history.close()

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.step()
            except Exception:
                log.exception("The dashboard couldn't refresh this time round")
            self.stop_event.wait(1)

    def run_tribe(self):
        try:
            while not self.stop_event.is_set():
                try:
                    data = self.tribe.sync()
                    self.publish_tribe(data)
                    self.note_map_hosts(data)
                    while not self.stop_event.is_set() and not self.tribe.wait(self.stop_event):
                        pass
                except Exception as error:
                    log.info("Couldn't sync the tribe: %s", error)
                    self.publish_tribe(self.tribe.data)
                    self.stop_event.wait(TRIBE_RETRY_SECONDS)
        finally:
            self.tribe.close()

    def publish_tribe(self, data):
        """The tribe as synced, with the maps on this computer the Map Watcher monitors added to its maps."""
        self.tribe_data = data
        self.publish(tribe=replace(data, maps=list(data.maps) + list(self.local_entries)))

    def read_local_maps(self):
        try:
            entries = self.local_maps()
        except Exception as error:
            log.info("Couldn't read the Map Watcher's local maps: %s", error)
            return
        if [(entry.id, entry.name, id(entry.network_map)) for entry in entries] != \
                [(entry.id, entry.name, id(entry.network_map)) for entry in self.local_entries]:
            self.local_entries = entries
            self.publish_tribe(self.tribe_data)

    def step(self):
        now = self.clock()
        if now >= self.next["ingest"]:
            self.next["ingest"] = now + INGEST_SECONDS
            self.read_local_maps()
            self.ingest()
        if now >= self.next["collectors"]:
            self.next["collectors"] = now + COLLECTOR_SECONDS
            self.read_collectors()
        if now >= self.next["hosts"]:
            self.next["hosts"] = now + HOST_COUNT_SECONDS
            self.sample_hosts()
        if now >= self.next["prune"]:
            self.next["prune"] = now + PRUNE_SECONDS
            self.history.prune(float(self.settings.get("raw_days", history_module.RAW_DAYS)),
                               float(self.settings.get("hourly_days", history_module.HOURLY_DAYS)),
                               float(self.settings.get("max_gb", history_module.MAX_GB)))

    def ingest(self):
        """Take in what the Map Watcher has found since last time."""
        try:
            meta = self.reader.meta()
            last_change = int(self.history.get("watcher_change_id"))
            changes = self.reader.changes_after(last_change)
            if not changes and last_change:
                newest = self.reader.rows("SELECT max(id) AS id FROM changes")[0]["id"] or 0
                if newest < last_change:  # Its status.db was made again: start from its beginning
                    self.history.set("watcher_change_id", 0)
                    changes = self.reader.changes_after(0)
            self.history.add_changes(changes)
            if changes:
                self.history.set("watcher_change_id", changes[-1]["id"])
            last_gap = int(self.history.get("watcher_gap_id"))
            gaps = self.reader.gaps_after(last_gap)
            if not gaps and last_gap:
                newest = (self.reader.gaps_after(0) or [{"id": 0}])[-1]["id"]
                if newest < last_gap:  # Its status.db was made again
                    self.history.set("watcher_gap_id", 0)
                    gaps = self.reader.gaps_after(0)
            self.history.add_gaps(gaps)
            if gaps:
                self.history.set("watcher_gap_id", gaps[-1]["id"])
            last_rate = int(self.history.get("watcher_rate_id"))
            rates = self.reader.rates_after(last_rate)
            if not rates and last_rate:
                newest = self.reader.rows("SELECT max(id) AS id FROM rates")[0]["id"] or 0
                if newest < last_rate:
                    self.history.set("watcher_rate_id", 0)
                    rates = self.reader.rates_after(0)
            self.history.add_rates(rates)
            if rates:
                self.history.set("watcher_rate_id", rates[-1]["id"])
            statuses, uptime = statuses_with_summaries(self.reader.statuses(), self.reader.summaries(),
                                                       self.clock())
            tunnels = {(row["map_id"], row["device"]): row for row in self.reader.tunnels()}
            watcher = {"available": True, "error": "", "monitor_at": meta.get("monitor_at", 0),
                       "sweep_at": meta.get("sweep_at", 0), **(meta.get("monitor") or {})}
        except Exception as error:  # No Map Watcher here (yet), or it isn't monitoring
            if self.snapshot.watcher.get("error") != str(error):  # Said once, not every round
                log.info("Can't read the Map Watcher's monitoring: %s", error)
                self.publish(watcher={"available": False, "error": str(error)})
            return
        counter_interval = float(watcher.get("counter_interval") or 300)
        latest = self.history.latest_rates(self.clock() - 2.5 * counter_interval)
        signature = (tuple(sorted((key, row["status"], row["problem"], row["since"], row["exact"], row["stale_at"])
                                  for key, row in statuses.items())),
                     tuple(sorted((key, row["at"]) for key, row in tunnels.items())),
                     tuple(sorted((name, key, round(value, 4)) for name, values in uptime.items()
                                  for key, value in values.items())))
        if changes or gaps or rates or signature != self.last_status_signature or not self.snapshot.watcher.get(
                "available"):
            self.last_status_signature = signature
            self.publish(statuses=statuses, tunnels=tunnels, watcher=watcher, rates=latest, uptime=uptime,
                         peaks=self.history.peak_rates(self.clock() - 86400) if rates or not self.snapshot.peaks
                         else self.snapshot.peaks)

    def read_collectors(self):
        syslog = self.collectors.read_syslog()
        flows = self.collectors.read_flows()
        now = self.clock()
        start = max(float(self.history.get("flow_addresses_at")) or now - 7200, now - 7 * 86400)
        seen = self.collectors.flow_addresses(start - 120)
        if seen is not None:  # Read again from the same time once the Flow Collector answers (or is updated)
            self.history.note_seen(FLOW, seen)
            self.history.set("flow_addresses_at", now)
        self.publish(syslog=syslog, flows=flows)

    def note_map_hosts(self, tribe):
        """The maps' hosts with an address count as seen now (they're on the switches' tables as last read)."""
        now = self.clock()
        self.history.note_seen(MAP, {address: now for entry in tribe.maps for address in map_host_addresses(entry)})


    def sample_hosts(self):
        tribe = self.snapshot.tribe
        if not tribe.synced_at:
            return
        self.note_map_hosts(tribe)
        now = self.clock()
        start = now - HOST_TREND_WINDOW
        rows = count_hosts(tribe, self.history.seen_since(MAP, start), self.history.seen_since(FLOW, start), start)
        self.history.add_host_counts(now, rows)

    def hosts(self, window):
        """Hosts per subnet seen in the last `window` seconds (the Hosts page, the Overview's count and the newest
        point of a subnet's trend: all the same count)."""
        tribe = self.snapshot.tribe
        start = self.clock() - window
        return count_hosts(tribe, self.history.seen_since(MAP, start), self.history.seen_since(FLOW, start), start)

    def host_subnets(self):
        return host_subnets(self.snapshot.tribe)
