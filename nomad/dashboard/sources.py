"""Where the NOMAD Dashboard's data comes from: the tribe (read with a viewer key), and the Syslog and Flow Collector
services on this computer. The Map Watcher's status.db is read with watch_monitor.StatusReader.

Nothing here asks the network itself.
"""
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

DASHBOARD_USER = "NOMAD Dashboard"
WAIT_SECONDS = 25
BACKUP_RESULTS = 200


@dataclass
class MapEntry:
    id: int
    name: str
    network_map: object  # NetworkMap
    network_id: str = ""  # The tribe IPAM network it's of ("" if none)


@dataclass
class SubnetEntry:
    network_id: str
    cidr: str
    name: str
    size: int  # Addresses that can be handed out
    used: int  # Addresses recorded in IPAM
    vlan: str = ""
    swept: float = 0.0  # When it was last swept in full (0: never)


@dataclass
class TribeData:
    """The tribe as last synced: built on the tribe thread, then only read."""
    maps: list = field(default_factory=list)  # [MapEntry]
    networks: list = field(default_factory=list)  # [{"id", "name"}]
    subnets: list = field(default_factory=list)  # [SubnetEntry]
    sightings: dict = field(default_factory=dict)  # Network id -> {address: when it last answered a sweep}
    backups: list = field(default_factory=list)  # Scheduled backups' outcomes, newest first
    online: bool = False
    error: str = ""
    synced_at: float = 0.0
    server: str = ""
    api: int = 0


class TribeView:
    """The dashboard's copy of the tribe (its own IPAM copy and map copy, in its folder), synced on one thread: make
    it, then call run() on that thread (its SQLite copy belongs to it)."""

    def __init__(self, key, directory, on_moved=None, clock=time.time, client=None):
        from ..ipam.client import TeamClient
        self.key, self.directory, self.clock = key, Path(directory), clock
        self.client = client or TeamClient(key, user=DASHBOARD_USER, on_moved=on_moved or (lambda moved: None))
        self.team = None
        self.maps = None
        self.data = TribeData()
        self.configs_seen = 0

    def open(self):
        from ..ipam.client import TeamStore
        from ..netmap.tribe import TribeMaps
        if self.team is None:
            self.team = TeamStore(self.key, self.directory / "ipam-copy.db", self.client)
        if self.maps is None:
            self.maps = TribeMaps(self.key.server_id, self.client, self.directory / "maps-copy.db",
                                  with_secrets=False)

    def close(self):
        if self.team is not None:
            self.team.close()
        if self.maps is not None:
            self.maps.close()

    def sync(self):
        """Fetch everything new and rebuild self.data (network). Returns the new TribeData."""
        from ..ipam.client import OldServerError
        self.open()
        try:
            status, items, revision = self.client.fetch_all_changes(self.team.revision)
            self.team.apply_sync(items, revision, status)
            fetched = self.client.fetch_sightings(self.team.sighting_revision)
            if fetched is not None and (fetched[0]["hosts"] or fetched[0]["ranges"]):
                self.team.apply_sightings(*fetched)
            elif fetched is not None:
                self.team.copy.set_meta("sighting_revision", fetched[1])
            self.maps.sync()
            try:
                backups = self.client.config_results(BACKUP_RESULTS)
            except (OldServerError, Exception) as error:  # An older server: no config archive
                log.debug("No config backup results: %s", error)
                backups = []
        except Exception as error:
            self.data = self.build(online=False, error=str(error), backups=self.data.backups,
                                   synced_at=self.data.synced_at, server=self.data.server, api=self.data.api)
            raise
        self.data = self.build(online=True, error="", backups=backups, synced_at=self.clock(),
                               server=status.get("name", ""), api=int(status.get("api") or 0))
        return self.data

    def build(self, **extra):
        from ..netmap.watch_monitor import team_network_id
        maps = []
        for item in self.maps.maps():
            try:
                network_map, _ = self.maps.load(item["id"])
            except Exception as error:  # One unreadable map shouldn't take the rest away
                log.warning("Couldn't read tribe map %s: %s", item.get("name"), error)
                continue
            maps.append(MapEntry(int(item["id"]), item["name"], network_map, team_network_id(network_map)))
        copy = self.team.copy
        networks, subnets, sightings = [], [], {}
        for network in copy.networks():
            networks.append({"id": network.id, "name": network.name})
            hosts, ranges = copy.sightings(network.id)
            sightings[network.id] = {str(address): row["seen"] for address, row in hosts.items()}
            for subnet in copy.subnets(network.id):
                block = subnet.network
                size = block.num_addresses - (2 if block.version == 4 and block.prefixlen < 31 and
                                              not subnet.loopbacks else 0)
                swept = max([finished for swept_block, _started, finished, _by in ranges
                             if swept_block.version == block.version and block.subnet_of(swept_block)] or [0.0])
                subnets.append(SubnetEntry(network.id, subnet.cidr, subnet.name or "", max(1, size),
                                           copy.count_addresses(network.id, block),
                                           str((subnet.fields or {}).get("VLAN", "") or ""), swept))
        return TribeData(maps=maps, networks=networks, subnets=subnets, sightings=sightings, **extra)

    def wait(self, stop_event):
        """Block until the tribe changes (or about WAIT_SECONDS pass). Returns whether something changed."""
        query = (f"/api/wait?since={self.team.revision}&timeout={WAIT_SECONDS}"
                 f"&sightings_since={self.team.sighting_revision}&maps_since={self.maps.revision}"
                 f"&configs_since={self.configs_seen}")
        reply = self.client.request("GET", query)
        changed = (reply.get("revision", 0) > self.team.revision
                   or (reply.get("sightings") or 0) > self.team.sighting_revision
                   or (reply.get("maps") or 0) > self.maps.revision
                   or (reply.get("configs") or 0) > self.configs_seen)
        self.configs_seen = max(self.configs_seen, reply.get("configs") or 0)
        return changed and not stop_event.is_set()


class CollectorView:
    """The Syslog and Flow Collector services on this computer: what the dashboard shows of them (counts and tops,
    never a message's text)."""

    def __init__(self, syslog=None, flows=None, clock=time.time):
        self.clock = clock
        self.syslog_source, self.flow_source = syslog, flows

    def syslog(self):
        if self.syslog_source is None:
            from ..syslogs.api import SyslogServiceSource
            from ..syslogs.service import load_config
            self.syslog_source = SyslogServiceSource(int(load_config().get("api_port")), timeout=10)
        return self.syslog_source

    def flows(self):
        if self.flow_source is None:
            from ..flows.api import ServiceSource
            from ..flows.service import load_config
            self.flow_source = ServiceSource(int(load_config().get("api_port")))
        return self.flow_source

    def read_syslog(self):
        """{"available", "error", "counts": [[source, severity, count]] in the last day, "at"}"""
        now = self.clock()
        try:
            counts = self.syslog().counts(now - 86400)
        except Exception as error:
            return {"available": False, "error": str(error), "counts": [], "at": now}
        return {"available": True, "error": "", "counts": counts, "at": now}

    def read_flows(self, span=3600):
        """{"available", "error", "exporters", "top": {kind: rows}, "total", "span", "at"} for the last span seconds."""
        from ..flows.store import APPLICATIONS, BOTH, CONVERSATIONS, DESTINATIONS, SOURCES, conversation_text
        now = self.clock()
        source = self.flows()
        try:
            exporters = source.exporters()
            top, total = {}, [0, 0, 0]
            for kind in (SOURCES, DESTINATIONS, APPLICATIONS, CONVERSATIONS):
                answer = source.top("", None, BOTH, kind, now - span, now, 10)
                top[kind] = answer.get("rows", [])
                if kind == CONVERSATIONS:  # "10.0.0.5 → 8.8.8.8  dns", not the stored key
                    top[kind] = [[conversation_text(row[0]), *row[1:]] for row in top[kind]]
                total = answer.get("total", total)
        except Exception as error:
            return {"available": False, "error": str(error), "exporters": [], "top": {}, "total": [0, 0, 0],
                    "span": span, "at": now}
        return {"available": True, "error": "", "exporters": exporters, "top": top, "total": total, "span": span,
                "at": now}

    def flow_addresses(self, start):
        """{address: when it last sent something} in the flows since start (None if the Flow Collector can't be
        read, or is too old to tell senders apart: an address only sent to, by a sweep say, isn't a host)."""
        try:
            return {address: when for address, when in self.flows().senders(start)}
        except Exception as error:
            log.debug("No flow addresses: %s", error)
            return None
