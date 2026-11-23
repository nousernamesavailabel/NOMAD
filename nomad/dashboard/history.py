"""The NOMAD Dashboard's own history (history.db in its folder), for its trends: devices' status changes (the Events
page), the Map Watcher's gaps in monitoring, ports' traffic (utilization), hosts per subnet, and when each address
was last seen on a map or in the flows. Uptime and since aren't worked out from it: they're the Map Watcher's.

The Map Watcher keeps only a few days of traffic; this keeps raw samples for raw_days and hourly averages and peaks
for hourly_days (both set in the Dashboard Service dialog), within a size limit. Written by the dashboard's engine
thread only; read by the web server's threads with connections of their own.
"""
import sqlite3
import threading
import time
from pathlib import Path

from ..netmap import traffic_history

HISTORY_FILE = "history.db"
RAW_DAYS = 30
HOURLY_DAYS = 365
MAX_GB = 2.0
UP, DOWN, UNKNOWN = "up", "down", "unknown"

SCHEMA = """
CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value REAL);
CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY AUTOINCREMENT, map_id INTEGER, key TEXT, label TEXT,
    status TEXT, at REAL, lasted REAL, text TEXT);
CREATE INDEX IF NOT EXISTS changes_device ON changes(map_id, key, at);
CREATE INDEX IF NOT EXISTS changes_at ON changes(at);
CREATE TABLE IF NOT EXISTS rates (map_id INTEGER, device TEXT, port TEXT, at REAL, in_bps REAL, out_bps REAL,
    speed INTEGER);
CREATE INDEX IF NOT EXISTS rates_port ON rates(map_id, device, port, at);
CREATE INDEX IF NOT EXISTS rates_at ON rates(at);
CREATE TABLE IF NOT EXISTS rates_hourly (map_id INTEGER, device TEXT, port TEXT, hour INTEGER, sum_in REAL,
    sum_out REAL, max_in REAL, max_out REAL, speed INTEGER, samples INTEGER,
    PRIMARY KEY (map_id, device, port, hour)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS host_counts (subnet TEXT, network TEXT, at REAL, total INTEGER, map INTEGER, sweep INTEGER,
    flow INTEGER);
CREATE INDEX IF NOT EXISTS host_counts_subnet ON host_counts(subnet, at);
CREATE INDEX IF NOT EXISTS host_counts_at ON host_counts(at);
CREATE TABLE IF NOT EXISTS subnet_hosts_hourly (network TEXT, subnet TEXT, hour INTEGER, sum_total REAL,
    max_total INTEGER, samples INTEGER, PRIMARY KEY (network, subnet, hour)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS ip_seen (ip TEXT, source TEXT, last_seen REAL, PRIMARY KEY (ip, source)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS gaps (start_at REAL, end_at REAL, PRIMARY KEY (start_at, end_at)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ip_seen_when ON ip_seen(source, last_seen);
"""


def connect(path, readonly=False):
    if readonly:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10, check_same_thread=False)
    else:
        connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.executescript(SCHEMA)
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name = 'host_counts_hourly'").fetchone():
            # 2.8.0-2.9.0 kept a subnet's hours whatever network it was in: kept, with no network
            with connection:
                connection.execute("INSERT OR IGNORE INTO subnet_hosts_hourly SELECT '', subnet, hour, sum_total, "
                                   "max_total, samples FROM host_counts_hourly")
                connection.execute("DROP TABLE host_counts_hourly")
    connection.row_factory = sqlite3.Row
    return connection


class HistoryStore:
    """Writing and reading the history. Thread-safe (one connection behind a lock)."""

    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.Lock()
        self.db = connect(self.path)

    def close(self):
        with self.lock:
            self.db.close()

    def rows(self, sql, parameters=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, parameters).fetchall()]

    def get(self, name, default=0.0):
        with self.lock:
            row = self.db.execute("SELECT value FROM state WHERE name = ?", (name,)).fetchone()
        return default if row is None else row["value"]

    def set(self, name, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (name, float(value)))

    # ----------------------------------------------------------------- Taking it in

    def add_changes(self, changes):
        """The watcher's changes ({map_id, key, label, status, at, lasted, text}), each once (a watcher that took in
        this history's older changes hands them back)."""
        if changes:
            with self.lock, self.db:
                self.db.executemany(
                    "INSERT INTO changes (map_id, key, label, status, at, lasted, text) SELECT :map_id, :key, :label, "
                    ":status, :at, :lasted, :text WHERE NOT EXISTS (SELECT 1 FROM changes WHERE map_id = :map_id AND "
                    "key = :key AND at = :at AND status = :status)", changes)

    def add_gaps(self, gaps):
        """The watcher's gaps in its monitoring ({start_at, end_at}): left out of the uptime."""
        if gaps:
            with self.lock, self.db:
                self.db.executemany("INSERT OR IGNORE INTO gaps VALUES (:start_at, :end_at)", gaps)

    def add_rates(self, rates):
        """The watcher's rates ({map_id, device, port, at, in_bps, out_bps, speed}): kept, and added to their hour."""
        if not rates:
            return
        with self.lock, self.db:
            self.db.executemany("INSERT INTO rates VALUES (:map_id, :device, :port, :at, :in_bps, :out_bps, :speed)",
                                rates)
            for rate in rates:
                hour = int(rate["at"] // 3600)
                self.db.execute(
                    "INSERT INTO rates_hourly VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1) ON CONFLICT(map_id, device, port, "
                    "hour) DO UPDATE SET sum_in = sum_in + excluded.sum_in, sum_out = sum_out + excluded.sum_out, "
                    "max_in = max(max_in, excluded.max_in), max_out = max(max_out, excluded.max_out), "
                    "speed = excluded.speed, samples = samples + 1",
                    (rate["map_id"], rate["device"], rate["port"], hour, rate["in_bps"], rate["out_bps"],
                     rate["in_bps"], rate["out_bps"], rate["speed"]))

    def add_host_counts(self, at, counts):
        """counts: [{subnet, network, total, map, sweep, flow}]"""
        if not counts:
            return
        hour = int(at // 3600)
        with self.lock, self.db:
            self.db.executemany("INSERT INTO host_counts VALUES (:subnet, :network, :at, :total, :map, :sweep, :flow)",
                                [dict(count, at=float(at)) for count in counts])
            for count in counts:
                self.db.execute(
                    "INSERT INTO subnet_hosts_hourly VALUES (?, ?, ?, ?, ?, 1) ON CONFLICT(network, subnet, hour) DO "
                    "UPDATE SET sum_total = sum_total + excluded.sum_total, max_total = max(max_total, "
                    "excluded.max_total), samples = samples + 1",
                    (count["network"], count["subnet"], hour, count["total"], count["total"]))

    def note_seen(self, source, seen):
        """{address: when last seen} by a source ("map" or "flow")."""
        if seen:
            with self.lock, self.db:
                self.db.executemany(
                    "INSERT INTO ip_seen VALUES (?, ?, ?) ON CONFLICT(ip, source) DO UPDATE SET last_seen = "
                    "max(last_seen, excluded.last_seen)", [(ip, source, float(when)) for ip, when in seen.items()])

    def forget_seen(self, source):
        with self.lock, self.db:
            self.db.execute("DELETE FROM ip_seen WHERE source = ?", (source,))

    # ----------------------------------------------------------------- Reading

    def seen_since(self, source, start):
        """{address: when last seen} by a source since start."""
        with self.lock:
            return {row["ip"]: row["last_seen"] for row in self.db.execute(
                "SELECT ip, last_seen FROM ip_seen WHERE source = ? AND last_seen >= ?", (source, float(start)))}

    def recent_changes(self, start, limit=500):
        """Changes with something to say, newest first."""
        return self.rows("SELECT * FROM changes WHERE at >= ? AND text != '' ORDER BY at DESC LIMIT ?",
                         (float(start), int(limit)))

    def gaps(self, start=0.0):
        return [(row["start_at"], row["end_at"]) for row in self.rows(
            "SELECT * FROM gaps WHERE end_at > ? ORDER BY start_at", (float(start),))]

    def rate_series(self, map_id, device, port, start, end=None, hourly=None):
        """[[time, in b/s, out b/s, peak in, peak out]] of a port: raw samples, or hourly ones for a long span (as
        traffic_history draws every port's graph, NOMAD's too)."""
        end = self.clock() if end is None else end
        if hourly is None:
            hourly = traffic_history.use_hourly(start, end)
        if hourly:
            return traffic_history.hourly_points(self.rows(
                "SELECT * FROM rates_hourly WHERE map_id = ? AND device = ? AND port = ? AND hour BETWEEN ? AND ? "
                "ORDER BY hour", (int(map_id), device, port, int(start // 3600), int(end // 3600))))
        return traffic_history.raw_points(self.rows(
            "SELECT * FROM rates WHERE map_id = ? AND device = ? AND port = ? AND at BETWEEN ? AND ? ORDER BY at",
            (int(map_id), device, port, float(start), float(end))))

    def latest_rates(self, since):
        """{(map_id, device, port): the newest rate} since a time."""
        rows = self.rows("SELECT r.* FROM rates r JOIN (SELECT map_id, device, port, max(at) AS at FROM rates WHERE "
                         "at >= ? GROUP BY map_id, device, port) last ON r.map_id = last.map_id AND r.device = "
                         "last.device AND r.port = last.port AND r.at = last.at", (float(since),))
        return {(row["map_id"], row["device"], row["port"]): row for row in rows}

    def peak_rates(self, start):
        """{(map_id, device, port): (peak in, peak out, speed)} since start, from the hourly table."""
        return {(row["map_id"], row["device"], row["port"]): (row["peak_in"], row["peak_out"], row["speed"])
                for row in self.rows("SELECT map_id, device, port, max(max_in) AS peak_in, max(max_out) AS peak_out, "
                                     "max(speed) AS speed FROM rates_hourly WHERE hour >= ? GROUP BY map_id, device, "
                                     "port", (int(start // 3600),))}

    def host_series(self, subnet, start, end=None, hourly=None, network=None):
        """[[time, hosts, peak]] of a subnet in a network (the same subnet can be in two networks: two sites both
        with 10.0.0.0/24). Hours kept before networks were (network "") count with every network."""
        end = self.clock() if end is None else end
        if hourly is None:
            hourly = end - start > 3 * 86400
        where, parameters = "subnet = ?", [subnet]
        if network is not None:
            where, parameters = where + " AND network IN (?, '')", parameters + [network]
        if hourly:
            return [[row["hour"] * 3600, round(row["sum_total"] / row["samples"], 1), row["max_total"]]
                    for row in self.rows(
                        f"SELECT hour, sum(sum_total) AS sum_total, sum(samples) AS samples, max(max_total) AS "
                        f"max_total FROM subnet_hosts_hourly WHERE {where} AND hour BETWEEN ? AND ? GROUP BY hour "
                        "ORDER BY hour", (*parameters, int(start // 3600), int(end // 3600)))]
        if network is not None:
            where = "subnet = ? AND network = ?"
        return [[row["at"], row["total"], row["total"]] for row in self.rows(
            f"SELECT at, total FROM host_counts WHERE {where} AND at BETWEEN ? AND ? ORDER BY at",
            (*parameters, float(start), float(end)))]

    # ----------------------------------------------------------------- Keeping it in bounds

    def used_bytes(self):
        try:
            return sum(path.stat().st_size for path in (self.path, Path(f"{self.path}-wal")) if path.exists())
        except OSError:
            return 0

    def prune(self, raw_days=RAW_DAYS, hourly_days=HOURLY_DAYS, max_gb=MAX_GB, now=None):
        now = self.clock() if now is None else now
        raw_start, hourly_start = now - raw_days * 86400, now - hourly_days * 86400
        with self.lock, self.db:
            self.db.execute("DELETE FROM rates WHERE at < ?", (raw_start,))
            self.db.execute("DELETE FROM host_counts WHERE at < ?", (raw_start,))
            self.db.execute("DELETE FROM rates_hourly WHERE hour < ?", (int(hourly_start // 3600),))
            self.db.execute("DELETE FROM subnet_hosts_hourly WHERE hour < ?", (int(hourly_start // 3600),))
            self.db.execute("DELETE FROM changes WHERE at < ?", (hourly_start,))
            self.db.execute("DELETE FROM ip_seen WHERE last_seen < ?", (now - 30 * 86400,))
            self.db.execute("DELETE FROM gaps WHERE end_at < ?", (hourly_start,))
        limit = max_gb * 1024 ** 3
        for _ in range(20):  # Over the size limit: the oldest raw samples go first, a day at a time
            if self.used_bytes() <= limit:
                break
            with self.lock, self.db:
                oldest = self.db.execute("SELECT min(at) FROM rates").fetchone()[0]
                if oldest is None:
                    break
                self.db.execute("DELETE FROM rates WHERE at < ?", (oldest + 86400,))
                self.db.execute("DELETE FROM host_counts WHERE at < ?", (oldest + 86400,))
            with self.lock:
                self.db.execute("PRAGMA incremental_vacuum")
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
