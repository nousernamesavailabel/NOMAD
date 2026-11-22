"""Where flows are kept (SQLite), and the questions asked of them.

Two kinds of data:
- Raw flows, kept a short while (2 hours by default): what one address was talking to at 2:05.
- Minute summaries, kept for days (14 by default): each interface's bytes in and out per minute, and its top
  sources, destinations, applications and conversations that minute (the rest summed as "Other").

Each flow counts on the interface it came in on (as "in") and the one it left by (as "out"), so input-only monitors
on a router's interfaces give both directions of every one of them. A flow from an output monitor counts only as
"out" (its input interface may have a monitor of its own).

A flow's bytes are spread over the minutes it lasted. Minutes stay open a few minutes for late records (routers send
a long flow every active timeout, a minute as NOMAD sets them up): bytes for minutes already closed go in the oldest
one still open. Summarizer is the writer's side (the collector's thread); FlowQueries reads, from any thread, with a
connection of its own.
"""
import ipaddress
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from ..packets.decode import IP_PROTOCOLS, TCP_PORTS, UDP_PORTS

log = logging.getLogger(__name__)

IN, OUT, BOTH = "in", "out", "both"
SOURCES, DESTINATIONS, APPLICATIONS, CONVERSATIONS = "src", "dst", "app", "conv"
KINDS = (SOURCES, DESTINATIONS, APPLICATIONS, CONVERSATIONS)
TOP_N = 25  # Kept per kind per interface per minute; the rest is "Other" (key "")
MAX_KEYS = 20000  # Per kind in an open minute: past this the smaller half is summed as "Other" (bounds memory)
OPEN_MINUTES = 3  # Minutes kept open for late records
RAW_SECONDS = 2 * 3600
SUMMARY_DAYS = 14
TCP, UDP = 6, 17
IANA_L3_ENGINE, IANA_L4_ENGINE = 1, 3  # NBAR's classification engines for "this IP protocol" and "this port"

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (end REAL, start REAL, exporter TEXT, in_if INTEGER, out_if INTEGER,
    egress INTEGER, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, proto INTEGER, app TEXT, bytes INTEGER,
    packets INTEGER, flags INTEGER);
CREATE INDEX IF NOT EXISTS flows_end ON flows(end);
CREATE INDEX IF NOT EXISTS flows_src ON flows(src, end);
CREATE INDEX IF NOT EXISTS flows_dst ON flows(dst, end);
CREATE TABLE IF NOT EXISTS totals (exporter TEXT, ifindex INTEGER, direction TEXT, minute INTEGER, bytes INTEGER,
    packets INTEGER, flows INTEGER, PRIMARY KEY (exporter, ifindex, direction, minute)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS totals_minute ON totals(minute);
CREATE TABLE IF NOT EXISTS tops (exporter TEXT, ifindex INTEGER, direction TEXT, minute INTEGER, kind TEXT, key TEXT,
    bytes INTEGER, packets INTEGER, flows INTEGER);
CREATE INDEX IF NOT EXISTS tops_where ON tops(exporter, ifindex, direction, minute);
CREATE INDEX IF NOT EXISTS tops_minute ON tops(minute);
CREATE TABLE IF NOT EXISTS interfaces (exporter TEXT, ifindex INTEGER, name TEXT, description TEXT, seen REAL,
    PRIMARY KEY (exporter, ifindex)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS applications (exporter TEXT, app_id INTEGER, name TEXT, description TEXT,
    PRIMARY KEY (exporter, app_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS exporters (exporter TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, packets INTEGER,
    flows INTEGER, bytes INTEGER, version INTEGER);
"""


def connect(path, readonly=False):
    if readonly:
        uri = f"file:{path}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10, check_same_thread=False)
    else:
        connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.executescript(SCHEMA)
    return connection


# --------------------------------------------------------------------- Names


def service_port(proto, sport, dport):
    """The server's side of a conversation: a well-known port if either is one, else the lower."""
    if proto not in (TCP, UDP):
        return 0
    known = TCP_PORTS if proto == TCP else UDP_PORTS
    if dport in known and sport not in known:
        return dport
    if sport in known and dport not in known:
        return sport
    return min(sport, dport) if sport and dport else (sport or dport)


def protocol_name(proto):
    return IP_PROTOCOLS.get(proto, str(proto)) if proto else "IP"


def port_application(proto, port):
    """A name from the protocol and port, when the router didn't name the application (no NBAR)."""
    if proto in (TCP, UDP):
        known = (TCP_PORTS if proto == TCP else UDP_PORTS).get(port)
        return known or f"{protocol_name(proto)}/{port}"
    return protocol_name(proto)


def application_name(flow, names):
    """The flow's application: NBAR's name for it (from the router's application table), else from the port."""
    port = service_port(flow.proto, flow.sport, flow.dport)
    if flow.app_id:
        name = names.get((flow.exporter, flow.app_id))
        if name and name.lower() != "unknown":  # NBAR couldn't tell: the port says more
            return name
        if flow.app_id >> 24 == IANA_L4_ENGINE:
            return port_application(flow.proto, flow.app_id & 0xFFFFFF)
        if flow.app_id >> 24 == IANA_L3_ENGINE:
            return protocol_name(flow.app_id & 0xFFFFFF)
    return port_application(flow.proto, port)


def conversation_key(src, dst, proto, port):
    return f"{src}|{dst}|{proto}|{port}"


def split_conversation(key):
    """(src, dst, proto, port) from a conversation key."""
    src, dst, proto, port = (key.split("|") + ["", "", "0", "0"])[:4]
    return src, dst, int(proto or 0), int(port or 0)


def conversation_text(key):
    src, dst, proto, port = split_conversation(key)
    service = port_application(proto, port) if proto in (TCP, UDP) else protocol_name(proto)
    return f"{src} → {dst}  {service}"


# --------------------------------------------------------------------- Writing


@dataclass
class Bucket:
    """One minute of one interface in one direction."""
    bytes: int = 0
    packets: int = 0
    flows: int = 0
    keys: dict = field(default_factory=lambda: {kind: {} for kind in KINDS})  # kind -> {key: [bytes, packets, flows]}
    others: dict = field(default_factory=lambda: {kind: [0, 0, 0] for kind in KINDS})  # Summed away (MAX_KEYS)

    def add(self, octets, packets, flows, keys):
        self.bytes += octets
        self.packets += packets
        self.flows += flows
        for kind, key in keys:
            entries = self.keys[kind]
            entry = entries.get(key)
            if entry is None:
                entries[key] = [octets, packets, flows]
                if len(entries) > MAX_KEYS:
                    self.sum_away(kind)
            else:
                entry[0] += octets
                entry[1] += packets
                entry[2] += flows

    def sum_away(self, kind):
        """Keep the bigger half of a kind's keys; the rest is counted in others."""
        ranked = sorted(self.keys[kind].items(), key=lambda item: item[1][0], reverse=True)
        keep = len(ranked) // 2
        other = self.others[kind]
        for _, values in ranked[keep:]:
            for index in range(3):
                other[index] += values[index]
        self.keys[kind] = dict(ranked[:keep])

    def top_rows(self, limit=TOP_N):
        """[(kind, key, bytes, packets, flows)]: the top of each kind, and the rest as key ""."""
        rows = []
        for kind, entries in self.keys.items():
            ranked = sorted(entries.items(), key=lambda item: item[1][0], reverse=True)
            rows.extend((kind, key, *values) for key, values in ranked[:limit])
            rest = [values for _, values in ranked[limit:]] + [self.others[kind]]
            if any(values[0] or values[2] for values in rest):
                rows.append((kind, "", sum(values[0] for values in rest), sum(values[1] for values in rest),
                             sum(values[2] for values in rest)))
        return rows


class Summarizer:
    """Takes flows, keeps the raw ones and the open minutes, and writes them to the store when flushed. Not thread
    safe: one writer (the collector's thread) uses it."""

    def __init__(self, path, raw_seconds=RAW_SECONDS, summary_days=SUMMARY_DAYS, clock=time.time, top_n=TOP_N):
        self.path = path
        self.connection = connect(path)
        self.raw_seconds, self.summary_days, self.clock, self.top_n = raw_seconds, summary_days, clock, top_n
        self.buckets = {}  # (exporter, ifindex, direction, minute) -> Bucket
        self.raw = []
        self.names = {(exporter, app_id): name for exporter, app_id, name in self.connection.execute(
            "SELECT exporter, app_id, name FROM applications")}
        self.seen = {}  # (exporter, ifindex) -> last seen, written on flush
        self.exporters = {}  # exporter -> [packets, flows, bytes, version, last seen]
        self.next_trim = 0.0

    def add_packet(self, exporter, version, flows):
        entry = self.exporters.setdefault(exporter, [0, 0, 0, version, 0.0])
        entry[0] += 1
        entry[1] += len(flows)
        entry[2] += sum(flow.bytes for flow in flows)
        entry[3] = version
        entry[4] = self.clock()

    def add_flows(self, flows, now=None):
        now = self.clock() if now is None else now
        earliest = int(now // 60) - OPEN_MINUTES
        for flow in flows:
            app = application_name(flow, self.names)
            port = service_port(flow.proto, flow.sport, flow.dport)
            keys = ((SOURCES, flow.src), (DESTINATIONS, flow.dst), (APPLICATIONS, app),
                    (CONVERSATIONS, conversation_key(flow.src, flow.dst, flow.proto, port)))
            self.raw.append((flow.end, flow.start, flow.exporter, flow.in_if, flow.out_if, int(flow.egress), flow.src,
                             flow.dst, flow.sport, flow.dport, flow.proto, app, flow.bytes, flow.packets,
                             flow.tcp_flags))
            places = []
            if flow.egress:
                if flow.out_if:
                    places.append((flow.out_if, OUT))
            else:
                places.append((flow.in_if, IN))
                if flow.out_if:
                    places.append((flow.out_if, OUT))
            for ifindex, _ in places:
                self.seen[(flow.exporter, ifindex)] = now
            for minute, share in spread(flow.start, flow.end, earliest):
                octets, packets = round(flow.bytes * share), round(flow.packets * share)
                counted = 1 if minute == max(earliest, int(flow.end // 60)) else 0
                for ifindex, direction in places:
                    where = (flow.exporter, ifindex, direction, minute)
                    bucket = self.buckets.get(where)
                    if bucket is None:
                        bucket = self.buckets[where] = Bucket()
                    bucket.add(octets, packets, counted, keys)

    def add_names(self, interfaces, applications):
        if not interfaces and not applications:
            return
        now = self.clock()
        with self.connection:
            self.connection.executemany(
                "INSERT INTO interfaces (exporter, ifindex, name, description, seen) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (exporter, ifindex) DO UPDATE SET name = excluded.name, "
                "description = excluded.description", [(*item, now) for item in interfaces])
            self.connection.executemany(
                "INSERT OR REPLACE INTO applications (exporter, app_id, name, description) VALUES (?, ?, ?, ?)",
                applications)
        for exporter, app_id, name, _ in applications:
            self.names[(exporter, app_id)] = name

    def flush(self, now=None):
        """Write the raw flows and the open minutes (closing those too old to stay open), and trim what's past
        keeping."""
        now = self.clock() if now is None else now
        earliest = int(now // 60) - OPEN_MINUTES
        raw, self.raw = self.raw, []
        closing = [where for where in self.buckets if where[3] < earliest]
        with self.connection:
            if raw:
                self.connection.executemany("INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                            raw)
            for where, bucket in self.buckets.items():
                self.connection.execute("DELETE FROM tops WHERE exporter = ? AND ifindex = ? AND direction = ? AND "
                                        "minute = ?", where)
                self.connection.executemany("INSERT INTO tops VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                            [(*where, *row) for row in bucket.top_rows(self.top_n)])
                self.connection.execute("INSERT OR REPLACE INTO totals VALUES (?, ?, ?, ?, ?, ?, ?)",
                                        (*where, bucket.bytes, bucket.packets, bucket.flows))
            for (exporter, ifindex), seen in self.seen.items():
                self.connection.execute(
                    "INSERT INTO interfaces (exporter, ifindex, name, description, seen) VALUES (?, ?, '', '', ?) "
                    "ON CONFLICT (exporter, ifindex) DO UPDATE SET seen = excluded.seen", (exporter, ifindex, seen))
            for exporter, (packets, flows, octets, version, seen) in self.exporters.items():
                self.connection.execute(
                    "INSERT INTO exporters VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (exporter) DO UPDATE SET "
                    "last_seen = excluded.last_seen, packets = packets + excluded.packets, "
                    "flows = flows + excluded.flows, bytes = bytes + excluded.bytes, version = excluded.version",
                    (exporter, seen, seen, packets, flows, octets, version))
        for where in closing:
            del self.buckets[where]
        self.seen, self.exporters = {}, {}
        if now >= self.next_trim:
            self.next_trim = now + 60
            self.trim(now)

    def trim(self, now):
        oldest_minute = int(now // 60) - self.summary_days * 1440
        with self.connection:
            self.connection.execute("DELETE FROM flows WHERE end < ?", (now - self.raw_seconds,))
            self.connection.execute("DELETE FROM tops WHERE minute < ?", (oldest_minute,))
            self.connection.execute("DELETE FROM totals WHERE minute < ?", (oldest_minute,))

    def close(self):
        self.connection.close()


def spread(start, end, earliest):
    """[(minute, share of the flow)] over the minutes [start, end] covers; minutes before earliest count as earliest."""
    first, last = int(start // 60), int(end // 60)
    if end <= start or first == last:
        return [(max(earliest, last), 1.0)]
    duration = end - start
    shares = {}
    for minute in range(first, last + 1):
        overlap = min(end, (minute + 1) * 60) - max(start, minute * 60)
        if overlap > 0:
            target = max(earliest, minute)
            shares[target] = shares.get(target, 0.0) + overlap / duration
    return sorted(shares.items())


# --------------------------------------------------------------------- Reading


def minute_range(start, end):
    return int(start // 60), int(end // 60)


class FlowQueries:
    """The questions the Flows page asks, answered from the store (read-only). Thread-safe."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.connection = None

    def db(self):
        if self.connection is None:
            self.connection = connect(self.path, readonly=True)
        return self.connection

    def rows(self, sql, parameters=()):
        with self.lock:
            return self.db().execute(sql, parameters).fetchall()

    def close(self):
        with self.lock:
            if self.connection is not None:
                self.connection.close()
                self.connection = None

    def exporters(self):
        """[{exporter, first_seen, last_seen, packets, flows, bytes, version, interfaces}]"""
        counts = dict(self.rows("SELECT exporter, COUNT(*) FROM interfaces GROUP BY exporter"))
        return [{"exporter": exporter, "first_seen": first, "last_seen": last, "packets": packets, "flows": flows,
                 "bytes": octets, "version": version, "interfaces": counts.get(exporter, 0)}
                for exporter, first, last, packets, flows, octets, version in self.rows(
                    "SELECT exporter, first_seen, last_seen, packets, flows, bytes, version FROM exporters "
                    "ORDER BY exporter")]

    def interfaces(self, exporter):
        """[{ifindex, name, description, seen}], the interfaces flows have been seen on (and those the router
        named)."""
        return [{"ifindex": ifindex, "name": name or "", "description": description or "", "seen": seen or 0}
                for ifindex, name, description, seen in self.rows(
                    "SELECT ifindex, name, description, seen FROM interfaces WHERE exporter = ? ORDER BY ifindex",
                    (exporter,))]

    @staticmethod
    def where(exporter, ifindex, direction):
        """SQL conditions and parameters for an exporter (None: every one), an interface (None: every one, counted
        as they came in) and a direction."""
        clauses, parameters = [], []
        if exporter:
            clauses.append("exporter = ?")
            parameters.append(exporter)
        if ifindex is None:
            direction = IN
        else:
            clauses.append("ifindex = ?")
            parameters.append(int(ifindex))
        if direction in (IN, OUT):
            clauses.append("direction = ?")
            parameters.append(direction)
        return clauses, parameters

    def top(self, exporter, ifindex, direction, kind, start, end, limit=TOP_N):
        """{"rows": [[key, bytes, packets, flows]], "other": [bytes, packets, flows], "total": [bytes, packets,
        flows]} over the minutes from start to end (seconds since 1970)."""
        first, last = minute_range(start, end)
        clauses, parameters = self.where(exporter, ifindex, direction)
        condition = " AND ".join(clauses + ["minute BETWEEN ? AND ?"])
        # NOCASE: a router's NBAR names (snmp) and NOMAD's from the port (SNMP) before its names came are one
        found = self.rows(f"SELECT key, SUM(bytes), SUM(packets), SUM(flows) FROM tops WHERE {condition} AND kind = ? "
                          "GROUP BY key COLLATE NOCASE ORDER BY SUM(bytes) DESC", (*parameters, first, last, kind))
        named = [list(row) for row in found if row[0]]
        other = [0, 0, 0]
        for row in [row for row in found if not row[0]] + [[None, *row[1:]] for row in named[limit:]]:
            for index in range(3):
                other[index] += row[index + 1] or 0
        total = self.rows(f"SELECT SUM(bytes), SUM(packets), SUM(flows) FROM totals WHERE {condition}",
                          (*parameters, first, last))[0]
        return {"rows": named[:limit], "other": other, "total": [value or 0 for value in total]}

    def series(self, exporter, ifindex, start, end):
        """[[minute start (seconds), bytes in, bytes out]] for each minute with traffic."""
        first, last = minute_range(start, end)
        clauses, parameters = [], []
        if exporter:
            clauses.append("exporter = ?")
            parameters.append(exporter)
        if ifindex is not None:
            clauses.append("ifindex = ?")
            parameters.append(int(ifindex))
        condition = " AND ".join(clauses + ["minute BETWEEN ? AND ?"])
        by_minute = {}
        for minute, direction, octets in self.rows(
                f"SELECT minute, direction, SUM(bytes) FROM totals WHERE {condition} GROUP BY minute, direction",
                (*parameters, first, last)):
            entry = by_minute.setdefault(minute, [minute * 60, 0, 0])
            entry[1 if direction == IN else 2] += octets or 0
        if ifindex is None:  # Every interface: what came in is what went through
            for entry in by_minute.values():
                entry[2] = 0
        return [by_minute[minute] for minute in sorted(by_minute)]

    def flows(self, address="", start=0.0, end=None, exporter="", limit=500):
        """The raw flows (newest first) to or from address (an address, or a subnet such as 10.1.2.0/24), ending
        between start and end: [{end, start, exporter, in_if, out_if, src, dst, sport, dport, proto, app, bytes,
        packets, flags}]."""
        end = time.time() + 60 if end is None else end
        clauses, parameters = ["end BETWEEN ? AND ?"], [start, end]
        if exporter:
            clauses.append("exporter = ?")
            parameters.append(exporter)
        network = None
        if address:
            try:
                network = ipaddress.ip_network(address.strip(), strict=False)
            except ValueError:
                raise ValueError(f"{address} isn't an address or a subnet")
            if network.num_addresses == 1:
                clauses.append("(src = ? OR dst = ?)")
                parameters += [str(network.network_address)] * 2
                network = None
        columns = ("end", "start", "exporter", "in_if", "out_if", "src", "dst", "sport", "dport", "proto", "app",
                   "bytes", "packets", "flags")
        sql = f"SELECT {', '.join(columns)} FROM flows WHERE {' AND '.join(clauses)} ORDER BY end DESC"
        found = []
        with self.lock:
            cursor = self.db().execute(sql, parameters)
            for row in cursor:
                item = dict(zip(columns, row))
                if network is not None and not (in_network(item["src"], network) or in_network(item["dst"], network)):
                    continue
                found.append(item)
                if len(found) >= limit:
                    break
        return found

    def addresses(self, start, end=None):
        """[[address, when last seen]] of every address in the raw flows (as source or destination) ending between
        start and end: who's been on the network lately (for the NOMAD Dashboard's hosts per subnet)."""
        end = time.time() + 60 if end is None else float(end)
        seen = {}
        for address, last in self.rows("SELECT src, MAX(end) FROM flows WHERE end BETWEEN ? AND ? GROUP BY src "
                                       "UNION ALL SELECT dst, MAX(end) FROM flows WHERE end BETWEEN ? AND ? GROUP BY "
                                       "dst", (float(start), end, float(start), end)):
            if address and (address not in seen or last > seen[address]):
                seen[address] = last
        return [[address, last] for address, last in sorted(seen.items())]

    def summary(self):
        """{raw_flows, oldest_raw, oldest_minute}"""
        count, oldest = self.rows("SELECT COUNT(*), MIN(end) FROM flows")[0]
        oldest_minute = self.rows("SELECT MIN(minute) FROM totals")[0][0]
        return {"raw_flows": count, "oldest_raw": oldest, "oldest_minute": oldest_minute}


def in_network(address, network):
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False
