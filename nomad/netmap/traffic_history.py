"""Ports' traffic over time, from their SNMP counters, kept for graphs: each reading for a few days, and each hour's
average and peak for a year. The same code keeps it everywhere a port's graph is drawn from, so it shows the same
numbers wherever it's drawn:

- the Map Watcher's, of the maps it monitors: traffic.db in %ProgramData%\\NOMAD\\monitoring, which anyone on its
  computer can read, and for tribe maps sent on to the tribe server (API 19), which keeps it in traffic.db in its
  folder for every NOMAD to ask;
- NOMAD's own, of the map open while its Monitor is on: traffic.db in %LOCALAPPDATA%\\NOMAD\\monitoring.

The NOMAD Dashboard keeps its own history (history.db), but draws its graphs with points() here too.

Each map's readings go by the map's record name (monitor_record.record_name: tribe-<server>-<id>, or map-<id> for a
map on one computer), or by its tribe map ID on the tribe server. A port is matched by its port_key, so "Gi1/0/1"
and "GigabitEthernet1/0/1" are the same port. Qt-free: the services import it.
"""
import bisect
import sqlite3
import threading
import time
from pathlib import Path

from .model import port_key

FILE_NAME = "traffic.db"
RAW_SECONDS = 4 * 86400  # Each reading is kept this long: graphs over more than HOURLY_AFTER use the hours
HOURLY_SECONDS = 366 * 86400
HOURLY_AFTER = 3 * 86400  # A graph over more than this uses each hour's average and peak
SPANS = {"6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "1y": 365 * 86400}
SPAN_NAMES = {"6h": "6 hours", "24h": "24 hours", "7d": "7 days", "30d": "30 days", "1y": "1 year"}
PRUNE_SECONDS = 3600
MAX_ROWS = 20000  # Readings taken in one request to the tribe server

SCHEMA = """
CREATE TABLE IF NOT EXISTS rates (map TEXT NOT NULL, device TEXT NOT NULL, pkey TEXT NOT NULL, port TEXT NOT NULL,
    at REAL NOT NULL, in_bps REAL NOT NULL, out_bps REAL NOT NULL, speed INTEGER NOT NULL,
    PRIMARY KEY (map, device, pkey, at)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rates_at ON rates(at);
CREATE TABLE IF NOT EXISTS rates_hourly (map TEXT NOT NULL, device TEXT NOT NULL, pkey TEXT NOT NULL,
    port TEXT NOT NULL, hour INTEGER NOT NULL, sum_in REAL NOT NULL, sum_out REAL NOT NULL, max_in REAL NOT NULL,
    max_out REAL NOT NULL, speed INTEGER NOT NULL, samples INTEGER NOT NULL,
    PRIMARY KEY (map, device, pkey, hour)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS rates_hourly_hour ON rates_hourly(hour);
"""


# --------------------------------------------------------------------- Points for a graph

def use_hourly(start, end):
    """Whether a graph from start to end uses each hour's average and peak rather than each reading."""
    return end - start > HOURLY_AFTER


def raw_points(rows):
    """[[time, in b/s, out b/s, peak in, peak out]] of readings (rows with at, in_bps and out_bps)."""
    return [[row["at"], row["in_bps"], row["out_bps"], row["in_bps"], row["out_bps"]] for row in rows]


def hourly_points(rows):
    """[[hour's start, average in b/s, average out b/s, peak in, peak out]] of hours (rows with hour, sum_in,
    sum_out, max_in, max_out and samples)."""
    return [[row["hour"] * 3600, row["sum_in"] / row["samples"], row["sum_out"] / row["samples"], row["max_in"],
             row["max_out"]] for row in rows if row["samples"]]


def span_range(span, now=None):
    """(start, end) of a graph over a span ("24h"...: SPANS), ending now."""
    now = time.time() if now is None else now
    return now - SPANS.get(span, SPANS["24h"]), now


def clean_rows(rows, limit=MAX_ROWS):
    """The readings in a request ([{device, port, at, in_bps, out_bps, speed}]), checked: anything that isn't one is
    left out. Raises ValueError when it isn't a list or there are too many."""
    if not isinstance(rows, list):
        raise ValueError("The traffic readings aren't valid.")
    if len(rows) > limit:
        raise ValueError(f"Send at most {limit} traffic readings at a time.")
    clean = []
    for row in rows:
        try:
            device, port = row["device"], row["port"]
            if not isinstance(device, str) or not isinstance(port, str) or not device or not port \
                    or len(device) > 256 or len(port) > 128:
                continue
            values = float(row["at"]), float(row["in_bps"]), float(row["out_bps"])
            if min(values) < 0 or any(value != value or value == float("inf") for value in values):
                continue
            clean.append({"device": device, "port": port, "at": values[0], "in_bps": values[1],
                          "out_bps": values[2], "speed": max(0, int(row.get("speed") or 0))})
        except (KeyError, TypeError, ValueError, AttributeError):
            continue
    return clean


# --------------------------------------------------------------------- Keeping it

def _connect(path, readonly=False, shared=False):
    if readonly:
        connection = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True, timeout=10, check_same_thread=False)
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        # Read by others with read-only rights (the Map Watcher's): a rollback journal, which they can read without
        # writing beside it, as they'd have to with WAL's
        connection.execute("PRAGMA journal_mode=" + ("DELETE" if shared else "WAL"))
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.executescript(SCHEMA)
    connection.row_factory = sqlite3.Row
    return connection


class TrafficStore:
    """Writing and reading the traffic of ports. Any thread: one connection, behind a lock.

    shared: others read the file (with TrafficReader) without the right to write beside it."""

    def __init__(self, path, clock=time.time, shared=False):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.Lock()
        self.db = _connect(self.path, shared=shared)
        self.next_prune = 0.0

    def close(self):
        with self.lock:
            self.db.close()

    def add(self, map_name, rows):
        """A map's readings ([{device, port, at, in_bps, out_bps, speed}]): each kept, and added to its hour, once (a
        reading sent again is left out). Returns how many were new."""
        added = 0
        if not rows:
            return 0
        with self.lock, self.db:
            for row in rows:
                pkey = port_key(row["port"])
                cursor = self.db.execute(
                    "INSERT OR IGNORE INTO rates (map, device, pkey, port, at, in_bps, out_bps, speed) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?)", (str(map_name), row["device"], pkey, row["port"], float(row["at"]),
                                                 float(row["in_bps"]), float(row["out_bps"]), int(row["speed"] or 0)))
                if not cursor.rowcount:
                    continue
                added += 1
                self.db.execute(
                    "INSERT INTO rates_hourly (map, device, pkey, port, hour, sum_in, sum_out, max_in, max_out, speed, "
                    "samples) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1) ON CONFLICT(map, device, pkey, hour) DO UPDATE "
                    "SET sum_in = sum_in + excluded.sum_in, sum_out = sum_out + excluded.sum_out, "
                    "max_in = max(max_in, excluded.max_in), max_out = max(max_out, excluded.max_out), "
                    "speed = excluded.speed, port = excluded.port, samples = samples + 1",
                    (str(map_name), row["device"], pkey, row["port"], int(float(row["at"]) // 3600),
                     float(row["in_bps"]), float(row["out_bps"]), float(row["in_bps"]), float(row["out_bps"]),
                     int(row["speed"] or 0)))
        return added

    def rows(self, sql, parameters=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, parameters).fetchall()]

    def points(self, map_name, device, port, start, end=None, hourly=None):
        return points(self.rows, map_name, device, port, start, self.clock() if end is None else end, hourly)

    def has_map(self, map_name):
        return has_map(self.rows, map_name)

    def ports(self, map_name, since=None):
        return ports(self.rows, map_name, self.clock() - RAW_SECONDS if since is None else since)

    def prune(self, now=None, force=False, keep_maps=None):
        """Forget readings older than RAW_SECONDS and hours older than HOURLY_SECONDS (at most hourly, unless
        forced), and every map but keep_maps' when given."""
        now = self.clock() if now is None else now
        if not force and now < self.next_prune:
            return
        self.next_prune = now + PRUNE_SECONDS
        with self.lock, self.db:
            self.db.execute("DELETE FROM rates WHERE at < ?", (now - RAW_SECONDS,))
            self.db.execute("DELETE FROM rates_hourly WHERE hour < ?", (int((now - HOURLY_SECONDS) // 3600),))
            if keep_maps is not None:
                keep = [str(name) for name in keep_maps]
                marks = ", ".join("?" * len(keep)) or "''"
                for table in ("rates", "rates_hourly"):
                    self.db.execute(f"DELETE FROM {table} WHERE map NOT IN ({marks})", keep)

    def forget_map(self, map_name):
        with self.lock, self.db:
            for table in ("rates", "rates_hourly"):
                self.db.execute(f"DELETE FROM {table} WHERE map = ?", (str(map_name),))


class TrafficReader:
    """A traffic.db someone else writes (the Map Watcher's), read only. It's opened again after anything goes wrong,
    so it copes with a Map Watcher installed later."""

    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.Lock()
        self.db = None

    def rows(self, sql, parameters=()):
        with self.lock:
            try:
                if self.db is None:
                    if not self.path.exists():
                        return []
                    self.db = _connect(self.path, readonly=True)
                return [dict(row) for row in self.db.execute(sql, parameters).fetchall()]
            except sqlite3.Error:
                if self.db is not None:
                    self.db.close()
                    self.db = None
                return []

    def close(self):
        with self.lock:
            if self.db is not None:
                self.db.close()
                self.db = None

    def points(self, map_name, device, port, start, end=None, hourly=None):
        return points(self.rows, map_name, device, port, start, self.clock() if end is None else end, hourly)

    def has_map(self, map_name):
        return has_map(self.rows, map_name)

    def ports(self, map_name, since=None):
        return ports(self.rows, map_name, self.clock() - RAW_SECONDS if since is None else since)


def points(rows, map_name, device, port, start, end, hourly=None):
    """A port's graph from start to end (raw_points, or hourly_points over a long span) with rows(sql, parameters)."""
    if hourly is None:
        hourly = use_hourly(start, end)
    where = (str(map_name), device, port_key(port))
    if hourly:
        return hourly_points(rows(
            "SELECT * FROM rates_hourly WHERE map = ? AND device = ? AND pkey = ? AND hour BETWEEN ? AND ? "
            "ORDER BY hour", (*where, int(start // 3600), int(end // 3600))))
    return raw_points(rows("SELECT * FROM rates WHERE map = ? AND device = ? AND pkey = ? AND at BETWEEN ? AND ? "
                           "ORDER BY at", (*where, float(start), float(end))))


def has_map(rows, map_name):
    return bool(rows("SELECT 1 FROM rates_hourly WHERE map = ? LIMIT 1", (str(map_name),)))


def ports(rows, map_name, since):
    """{(device, port key): (port, when last read)} of a map's ports read since a time."""
    return {(row["device"], row["pkey"]): (row["port"], row["at"]) for row in rows(
        "SELECT device, pkey, port, max(at) AS at FROM rates WHERE map = ? AND at >= ? GROUP BY device, pkey",
        (str(map_name), float(since)))}


# --------------------------------------------------------------------- Where

def watcher_path(directory=None):
    """The Map Watcher's traffic.db, beside its shared summaries."""
    from .monitor_record import shared_dir
    return Path(directory or shared_dir()) / FILE_NAME


def own_path():
    """This NOMAD's traffic.db, beside its monitoring records."""
    from .monitor_record import records_dir
    return records_dir() / FILE_NAME


_own = None
_own_lock = threading.Lock()


def own_store():
    """This NOMAD's TrafficStore (one for the whole program), or None when it can't be opened."""
    global _own
    with _own_lock:
        if _own is None:
            try:
                _own = TrafficStore(own_path())
            except (OSError, sqlite3.Error):
                return None
        return _own


def close_own_store():
    global _own
    with _own_lock:
        if _own is not None:
            _own.close()
            _own = None


def gap_seconds(points_list, hourly):
    """How far apart a series' points may be and still be joined by a line: twice their usual spacing (an hour and
    a half for hours), so a pause in the readings shows as a gap."""
    if hourly:
        return 5400.0
    steps = sorted(later[0] - earlier[0] for earlier, later in zip(points_list, points_list[1:])
                   if later[0] > earlier[0])
    usual = steps[len(steps) // 2] if steps else 300.0
    return max(120.0, usual * 2.5)


def outside(points_list, others, hourly):
    """The points of points_list at times others has no points near (others' gap_seconds), so one series only fills
    the other's gaps."""
    if not others:
        return list(points_list)
    times = [point[0] for point in others]
    reach = gap_seconds(others, hourly) / 2
    kept = []
    for point in points_list:
        index = bisect.bisect_left(times, point[0])
        nearest = min((abs(times[place] - point[0]) for place in (index - 1, index) if 0 <= place < len(times)),
                      default=None)
        if nearest is None or nearest > reach:
            kept.append(point)
    return kept


# --------------------------------------------------------------------- A port's history, from wherever it's kept

class PortHistory:
    """What's known of a port's traffic between two times: the Map Watcher's readings (the same as the NOMAD
    Dashboard's graph), this computer's own (kept while its Monitor was on), and why the Watcher's are missing."""

    def __init__(self, watcher=(), own=(), hourly=False, note="", watcher_here=False):
        self.watcher, self.own, self.hourly = list(watcher), list(own), hourly
        self.note = note  # Why there's nothing from the Map Watcher, when something got in the way
        self.watcher_here = watcher_here  # Read from the Map Watcher on this computer


def history_for(record, device, port, start, end, maps=None, map_id=None, watcher_file=None, own=None):
    """A port's PortHistory: the Map Watcher's readings from this computer when it monitors the map here, else from
    the tribe server for a tribe map (maps: its TribeMaps, map_id: the tribe map's ID), and this computer's own.
    Asks the network for a tribe map: call it on a worker thread."""
    hourly = use_hourly(start, end)
    store = own if own is not None else own_store()
    mine = store.points(record, device, port, start, end, hourly) if store is not None and record else []
    reader = TrafficReader(watcher_file or watcher_path())
    try:
        if record and reader.has_map(record):
            return PortHistory(reader.points(record, device, port, start, end, hourly), mine, hourly,
                               watcher_here=True)
    finally:
        reader.close()
    if maps is None or map_id is None:
        return PortHistory((), mine, hourly)
    from ..ipam.client import OldServerError
    try:
        reply = maps.fetch_traffic(map_id, device, port, start, end)
    except OldServerError:
        return PortHistory((), mine, hourly, "The tribe server needs updating to share the Map Watcher's traffic "
                                             "history (Tools > Tribe Management > Update Service, on the server).")
    except Exception as error:
        return PortHistory((), mine, hourly, f"Couldn't ask the tribe server for the Map Watcher's readings: {error}")
    return PortHistory(reply.get("points") or [], mine, bool(reply.get("hourly", hourly)))
