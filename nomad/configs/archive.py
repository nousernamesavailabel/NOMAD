"""The config archive: every change to each device's configuration, kept for good. The Tribe server keeps the tribe's
(configs.db beside maps.db); without a tribe, NOMAD keeps one on this computer; and a laptop's copy of the tribe's is
one too (with the texts fetched as they're opened).

A pull the same as the last copy (noise aside) only notes when it was checked; a different one is a new version,
which shows in Recent changes (and on the map) until someone reviews it. A device's first copy isn't a change.

Scheduled backups (a work queue, device by device): the devices on tribe maps that are routers, switches, firewalls or
WLCs are in scope (sync_devices). Each is due once an interval (a day unless set), spread over the day. Computers
that run backups ask for a few due devices at a time (claim), which are theirs for CLAIM_SECONDS; one that can't
reach a device (or log in to it) reports it, and the device goes to another computer (each skips a device it failed
on for a while). While a Map Watcher service is asking, NOMAD windows only get devices well overdue, so the service
does most of it. A device nobody has backed up for two intervals is overdue, with each computer's reason.

Use under self.lock from more than one thread."""
import json
import sqlite3
import threading
import time
import zlib

from . import diff, noise

CLAIM_SECONDS = 600
SERVICE_SEEN_SECONDS = 300  # A service that asked this recently is still about
RESULTS_KEPT = 500  # Scheduled backups' outcomes kept for Recent Backups (every computer's)
RUNNER_SEEN_SECONDS = 180  # A computer running backups asks every half minute: one quiet this long has stopped
GUI_GRACE_SECONDS = 900  # While a service is about, NOMAD windows get only devices due this long ago
DEFAULT_INTERVAL_HOURS = 24
GUI, SERVICE = "gui", "service"
SCHEDULED, MANUAL, TERMINAL, TFTP, FILE = "scheduled", "manual", "terminal", "tftp", "file"
SOURCE_NAMES = {SCHEDULED: "Scheduled backup", MANUAL: "Pulled", TERMINAL: "Terminal", TFTP: "TFTP", FILE: "File"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT, address TEXT, names TEXT, platform TEXT,
                                    kind TEXT, facts TEXT, in_scope INTEGER NOT NULL DEFAULT 0,
                                    excluded INTEGER NOT NULL DEFAULT 0, created REAL, next_due REAL, last_ok REAL,
                                    last_checked REAL, last_try REAL, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS versions (id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, which TEXT NOT NULL,
                                     text BLOB, hash TEXT, pulled_at REAL, pulled_by TEXT, source TEXT,
                                     changed_by TEXT, previous_id INTEGER, added INTEGER, removed INTEGER,
                                     first INTEGER NOT NULL DEFAULT 0, reviewed_by TEXT, reviewed_at REAL,
                                     revision INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS versions_device ON versions (device_id, which, id);
CREATE INDEX IF NOT EXISTS versions_revision ON versions (revision);
CREATE TABLE IF NOT EXISTS claims (device_id TEXT PRIMARY KEY, holder TEXT, computer TEXT, kind TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS failures (device_id TEXT NOT NULL, computer TEXT NOT NULL, reason TEXT, at REAL,
                                     PRIMARY KEY (device_id, computer));
CREATE TABLE IF NOT EXISTS standards (name TEXT PRIMARY KEY, text TEXT, updated_by TEXT, updated REAL,
                                      deleted INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS compliance (device_id TEXT NOT NULL, standard TEXT NOT NULL, failed INTEGER, total INTEGER,
                                       results TEXT, version_id INTEGER, checked REAL,
                                       revision INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (device_id, standard));
CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runners (holder TEXT PRIMARY KEY, computer TEXT, kind TEXT, user TEXT, last_seen REAL,
                                    status TEXT);
CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, at REAL, by TEXT, device_id TEXT, device_name TEXT,
                                    ok INTEGER, note TEXT);
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT);
"""
VERSION_FIELDS = ("id", "device_id", "which", "hash", "pulled_at", "pulled_by", "source", "changed_by", "previous_id",
                  "added", "removed", "first", "reviewed_by", "reviewed_at", "revision")


class ArchiveError(Exception):
    pass


def pack(text):
    return zlib.compress((text or "").encode("utf-8"))


def unpack(blob):
    if blob is None:
        return None
    if isinstance(blob, str):
        return blob
    return zlib.decompress(blob).decode("utf-8")


def spread(device_id, interval):
    """Where in the interval a device's backups fall (seconds), the same each time, so they spread over the day."""
    return zlib.crc32(device_id.encode("utf-8")) % max(int(interval), 1)


class ConfigStore:
    def __init__(self, path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()

    def close(self):
        self.db.close()

    # ----------------------------------------------------------------- Revisions and settings

    def revision(self):
        return int(self.meta("revision") or 0)

    def meta(self, name, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, name, value):
        self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES (?, ?)", (name, str(value)))

    def next_revision(self):
        revision = self.revision() + 1
        self.set_meta("revision", revision)
        return revision

    def interval(self):
        """Seconds between a device's scheduled backups."""
        return float(self.settings().get("interval_hours", DEFAULT_INTERVAL_HOURS)) * 3600

    def settings(self):
        values = {"interval_hours": DEFAULT_INTERVAL_HOURS}
        for row in self.db.execute("SELECT name, value FROM settings"):
            values[row["name"]] = json.loads(row["value"])
        return values

    def set_settings(self, values):
        with self.db:
            revision = self.next_revision()
            for name, value in values.items():
                if name == "interval_hours":
                    value = float(value)
                    if not 1 <= value <= 24 * 30:
                        raise ArchiveError("Back up every 1 to 720 hours.")
                self.db.execute("INSERT OR REPLACE INTO settings (name, value, revision) VALUES (?, ?, ?)",
                                (name, json.dumps(value), revision))
        return revision

    # ----------------------------------------------------------------- Devices

    def device(self, device_id):
        row = self.db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return self._device(row) if row else None

    def _device(self, row, now=None):
        item = dict(row)
        item["names"] = json.loads(item["names"] or "[]")
        item["facts"] = json.loads(item["facts"] or "{}")
        item["failures"] = [dict(failure) for failure in self.db.execute(
            "SELECT computer, reason, at FROM failures WHERE device_id = ? ORDER BY at DESC", (item["id"],))]
        return item

    def devices(self):
        return [self._device(row) for row in self.db.execute("SELECT * FROM devices ORDER BY lower(name), id")]

    def ensure_device(self, device_id, name="", address="", platform="", now=None, revision=None):
        """The device's row, made (out of the schedule) when it's new: for pulls by hand and saved files."""
        now = time.time() if now is None else now
        row = self.db.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            self.db.execute("INSERT INTO devices (id, name, address, names, platform, kind, facts, created, "
                            "revision) VALUES (?, ?, ?, '[]', ?, '', '{}', ?, ?)",
                            (device_id, name or device_id, address, platform, now,
                             revision if revision is not None else self.next_revision()))
        elif name or platform:
            self.db.execute("UPDATE devices SET name = coalesce(nullif(?, ''), name), "
                            "platform = coalesce(nullif(?, ''), platform), address = coalesce(nullif(?, ''), address) "
                            "WHERE id = ?", (name, platform, address, device_id))

    def sync_devices(self, rows, now=None):
        """Put the schedule's devices in scope ([{"id", "name", "address", "names", "platform", "kind", "facts"}]);
        the others leave it (their copies stay). Returns the ids of the devices that changed (a set)."""
        now = time.time() if now is None else now
        interval = self.interval()
        wanted = {row["id"]: row for row in rows if row.get("id")}
        changed = set()
        with self.db:
            current = {row["id"]: dict(row) for row in self.db.execute("SELECT * FROM devices")}
            revision = None
            for device_id, row in wanted.items():
                values = (row.get("name") or device_id, row.get("address") or "", json.dumps(row.get("names") or []),
                          row.get("platform") or "", row.get("kind") or "", json.dumps(row.get("facts") or {}))
                old = current.get(device_id)
                if old is None:
                    revision = revision or self.next_revision()
                    self.db.execute("INSERT INTO devices (id, name, address, names, platform, kind, facts, in_scope, "
                                    "created, next_due, revision) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                                    (device_id, *values, now, now + spread(device_id, interval), revision))
                    changed.add(device_id)
                elif (old["name"], old["address"], old["names"], old["platform"], old["kind"], old["facts"]) != \
                        values or not old["in_scope"]:
                    revision = revision or self.next_revision()
                    next_due = old["next_due"] if old["next_due"] else now + spread(device_id, interval)
                    self.db.execute("UPDATE devices SET name = ?, address = ?, names = ?, platform = ?, kind = ?, "
                                    "facts = ?, in_scope = 1, next_due = ?, revision = ? WHERE id = ?",
                                    (*values, next_due, revision, device_id))
                    changed.add(device_id)
            for device_id, old in current.items():
                if old["in_scope"] and device_id not in wanted:
                    revision = revision or self.next_revision()
                    self.db.execute("UPDATE devices SET in_scope = 0, revision = ? WHERE id = ?",
                                    (revision, device_id))
                    changed.add(device_id)
        return changed

    def set_excluded(self, device_id, excluded):
        with self.db:
            if self.device(device_id) is None:
                raise ArchiveError("That device isn't in the config archive.")
            revision = self.next_revision()
            self.db.execute("UPDATE devices SET excluded = ?, revision = ? WHERE id = ?",
                            (1 if excluded else 0, revision, device_id))
        return revision

    def facts(self, device_id):
        device = self.device(device_id)
        return device["facts"] if device else {}

    # ----------------------------------------------------------------- The queue

    def claim(self, holder, computer, kind=GUI, limit=3, now=None, status="", user=""):
        """Up to limit due devices for a computer to back up, each its own for CLAIM_SECONDS:
        [{"id", "name", "address", "names", "platform"}]. status: how its last round went (for Who's Backing Up)."""
        now = time.time() if now is None else now
        interval = self.interval()
        retry = max(interval / 4, 600)
        with self.db:
            self.db.execute("DELETE FROM claims WHERE expires <= ?", (now,))
            self.db.execute("INSERT OR REPLACE INTO runners (holder, computer, kind, user, last_seen, status) "
                            "VALUES (?, ?, ?, ?, ?, ?)", (holder, computer, kind, user or "", now,
                                                          (status or "")[:300]))
            if kind == SERVICE:
                self.set_meta("service_seen", now)
            seen = self.meta("service_seen")
            service_about = kind != SERVICE and seen is not None and float(seen) > now - SERVICE_SEEN_SECONDS
            due_by = now - GUI_GRACE_SECONDS if service_about else now
            rows = self.db.execute(
                "SELECT d.* FROM devices d WHERE d.in_scope = 1 AND d.excluded = 0 AND d.next_due <= ? "
                "AND d.id NOT IN (SELECT device_id FROM claims) "
                "AND NOT EXISTS (SELECT 1 FROM failures f WHERE f.device_id = d.id AND f.computer = ? AND f.at > ? "
                "AND f.at > coalesce(d.last_ok, 0)) ORDER BY d.next_due LIMIT ?",
                (due_by, computer, now - retry, int(limit))).fetchall()
            given = []
            for row in rows:
                self.db.execute("INSERT OR REPLACE INTO claims (device_id, holder, computer, kind, expires) "
                                "VALUES (?, ?, ?, ?, ?)", (row["id"], holder, computer, kind, now + CLAIM_SECONDS))
                self.db.execute("UPDATE devices SET last_try = ? WHERE id = ?", (now, row["id"]))
                given.append({"id": row["id"], "name": row["name"], "address": row["address"],
                              "names": json.loads(row["names"] or "[]"), "platform": row["platform"]})
        return given

    def report_failure(self, device_id, computer, reason, now=None, by=""):
        """A computer couldn't back a device up: it goes back in the queue for another computer. by: who to say
        tried, for Recent Backups (the computer, when not given)."""
        now = time.time() if now is None else now
        with self.db:
            self.db.execute("DELETE FROM claims WHERE device_id = ?", (device_id,))
            self.note_result(device_id, by or computer, False, reason or "", now)
            self.db.execute("INSERT OR REPLACE INTO failures (device_id, computer, reason, at) VALUES (?, ?, ?, ?)",
                            (device_id, computer, (reason or "")[:500], now))
            revision = self.next_revision()
            self.db.execute("UPDATE devices SET revision = ? WHERE id = ?", (revision, device_id))
        return revision

    def note_result(self, device_id, by, ok, note, now):
        """Keep a scheduled backup's outcome (the newest RESULTS_KEPT)."""
        row = self.db.execute("SELECT name FROM devices WHERE id = ?", (device_id,)).fetchone()
        cursor = self.db.execute("INSERT INTO results (at, by, device_id, device_name, ok, note) VALUES (?, ?, ?, ?, ?, "
                                 "?)", (now, by, device_id, row["name"] if row else device_id, 1 if ok else 0,
                                        (note or "")[:300]))
        self.db.execute("DELETE FROM results WHERE id <= ?", (cursor.lastrowid - RESULTS_KEPT,))

    def results(self, limit=200):
        """Scheduled backups' outcomes, newest first: [{"at", "by", "device_id", "device_name", "ok", "note"}]."""
        rows = self.db.execute("SELECT * FROM results ORDER BY id DESC LIMIT ?", (int(limit),))
        return [dict(row, ok=bool(row["ok"])) for row in rows]

    def runners(self, now=None):
        """The computers backing up now (seen in the last RUNNER_SEEN_SECONDS): [{"holder", "computer", "kind",
        "user", "last_seen", "status", "working_on": [device names]}], services first."""
        now = time.time() if now is None else now
        working = {}
        for row in self.db.execute("SELECT c.holder, coalesce(d.name, c.device_id) AS name FROM claims c LEFT JOIN "
                                   "devices d ON d.id = c.device_id WHERE c.expires > ?", (now,)):
            working.setdefault(row["holder"], []).append(row["name"])
        rows = self.db.execute("SELECT * FROM runners WHERE last_seen > ? ORDER BY kind DESC, computer",
                               (now - RUNNER_SEEN_SECONDS,))
        return [dict(row, working_on=sorted(working.get(row["holder"], []))) for row in rows]

    def make_due(self, device_ids=None, now=None):
        """Bring scheduled backups forward to now: of these devices, or (None) every one in scope. They then keep
        their usual interval from when they're backed up. Returns how many."""
        now = time.time() if now is None else now
        with self.db:
            if device_ids is None:
                ids = [row["id"] for row in self.db.execute(
                    "SELECT id FROM devices WHERE in_scope = 1 AND excluded = 0")]
            else:
                ids = [row["id"] for row in self.db.execute(
                    f"SELECT id FROM devices WHERE in_scope = 1 AND excluded = 0 AND id IN "
                    f"({', '.join('?' for _ in device_ids)})", list(device_ids))] if device_ids else []
            if not ids:
                return 0
            revision = self.next_revision()
            for device_id in ids:
                self.db.execute("UPDATE devices SET next_due = ?, revision = ? WHERE id = ?", (now, revision,
                                                                                            device_id))
                self.db.execute("DELETE FROM failures WHERE device_id = ?", (device_id,))  # Everyone tries again
        return len(ids)

    def release(self, device_id):
        with self.db:
            self.db.execute("DELETE FROM claims WHERE device_id = ?", (device_id,))

    def overdue(self, now=None):
        """The devices in scope nobody has backed up for two intervals (with each computer's reason)."""
        now = time.time() if now is None else now
        limit = now - 2 * self.interval()
        rows = self.db.execute("SELECT * FROM devices WHERE in_scope = 1 AND excluded = 0 AND "
                               "coalesce(last_ok, created) < ? ORDER BY name", (limit,))
        return [self._device(row) for row in rows]

    # ----------------------------------------------------------------- Versions

    def latest(self, device_id, which="running", with_text=True):
        row = self.db.execute("SELECT * FROM versions WHERE device_id = ? AND which = ? ORDER BY id DESC LIMIT 1",
                              (device_id, which)).fetchone()
        return self._version(row, with_text) if row else None

    def _version(self, row, with_text=True):
        item = {name: row[name] for name in VERSION_FIELDS}
        if with_text:
            item["text"] = unpack(row["text"])
        return item

    def version(self, version_id, with_text=True):
        row = self.db.execute("SELECT * FROM versions WHERE id = ?", (int(version_id),)).fetchone()
        return self._version(row, with_text) if row else None

    def history(self, device_id, which=None):
        """The device's versions, newest first (no texts)."""
        query = "SELECT * FROM versions WHERE device_id = ?" + (" AND which = ?" if which else "") + " ORDER BY id DESC"
        rows = self.db.execute(query, (device_id, which) if which else (device_id,))
        return [self._version(row, False) for row in rows]

    def upload(self, device_id, which, config, user, source=MANUAL, changed_by="", name="", address="", platform="",
               now=None):
        """Keep a pulled configuration: a new version when it differs (noise aside) from the last one, else only
        when it was checked. {"stored": bool, "version_id", "first": bool, "revision"}."""
        now = time.time() if now is None else now
        if not (config or "").strip():
            raise ArchiveError("There's no configuration to keep.")
        if which not in ("running", "startup"):
            raise ArchiveError(f"Unknown configuration {which!r}.")
        fingerprint = noise.fingerprint(config)
        with self.db:
            self.ensure_device(device_id, name, address, platform, now)
            device = self.device(device_id)
            latest = self.latest(device_id, which)
            if which == "running":
                self.db.execute("DELETE FROM claims WHERE device_id = ?", (device_id,))
                self.db.execute("DELETE FROM failures WHERE device_id = ?", (device_id,))
                due = device["next_due"]
                if source == SCHEDULED or not due:
                    interval = self.interval()
                    due = (due or now) + interval
                    if due <= now:
                        due = now + interval
                self.db.execute("UPDATE devices SET last_ok = ?, last_checked = ?, next_due = ? WHERE id = ?",
                                (now, now, due, device_id))
            if source == SCHEDULED and which == "running":
                same = latest is not None and latest["hash"] == fingerprint
                self.note_result(device_id, user, True, "no change" if same else "first copy" if latest is None
                                 else "changed", now)
            if latest is not None and latest["hash"] == fingerprint:
                revision = self.next_revision()
                self.db.execute("UPDATE devices SET revision = ? WHERE id = ?", (revision, device_id))
                return {"stored": False, "version_id": latest["id"], "first": False, "revision": revision}
            added = removed = 0
            if latest is not None:
                compared = diff.compare(latest["text"], config, diff.NOISE)
                added, removed = compared.counts()
            revision = self.next_revision()
            first = latest is None
            cursor = self.db.execute(
                "INSERT INTO versions (device_id, which, text, hash, pulled_at, pulled_by, source, changed_by, "
                "previous_id, added, removed, first, reviewed_by, reviewed_at, revision) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (device_id, which, pack(config), fingerprint, now, user, source, changed_by,
                 latest["id"] if latest else None, added, removed, 1 if first else 0,
                 user if first else None, now if first else None, revision))
            self.db.execute("UPDATE devices SET revision = ? WHERE id = ?", (revision, device_id))
        return {"stored": True, "version_id": cursor.lastrowid, "first": first, "revision": revision}

    def review(self, version_id, user, now=None):
        """Mark a change seen (it leaves the map's badge)."""
        now = time.time() if now is None else now
        with self.db:
            if self.version(version_id, False) is None:
                raise ArchiveError("That version isn't in the config archive.")
            revision = self.next_revision()
            self.db.execute("UPDATE versions SET reviewed_by = ?, reviewed_at = ?, revision = ? WHERE id = ? AND "
                            "reviewed_by IS NULL", (user, now, revision, int(version_id)))
        return revision

    def recent(self, limit=200):
        """The latest changes (not first copies), newest first, with their devices' names (no texts)."""
        rows = self.db.execute("SELECT v.*, d.name AS device_name FROM versions v LEFT JOIN devices d ON "
                               "d.id = v.device_id WHERE v.first = 0 ORDER BY v.id DESC LIMIT ?", (int(limit),))
        result = []
        for row in rows:
            item = self._version(row, False)
            item["device_name"] = row["device_name"] or row["device_id"]
            result.append(item)
        return result

    def unreviewed(self):
        """{device id: number of changes nobody has reviewed}."""
        rows = self.db.execute("SELECT device_id, count(*) AS n FROM versions WHERE reviewed_by IS NULL AND first = 0 "
                               "GROUP BY device_id")
        return {row["device_id"]: row["n"] for row in rows}

    # ----------------------------------------------------------------- Standards and how devices stand

    def standards(self):
        rows = self.db.execute("SELECT * FROM standards WHERE deleted = 0 ORDER BY lower(name)")
        return [dict(row) for row in rows]

    def standard(self, name):
        row = self.db.execute("SELECT * FROM standards WHERE name = ? AND deleted = 0", (name,)).fetchone()
        return dict(row) if row else None

    def save_standard(self, name, source, user, now=None):
        now = time.time() if now is None else now
        name = (name or "").strip()
        if not name:
            raise ArchiveError("Give the standard a name (its ! STANDARD: line).")
        with self.db:
            revision = self.next_revision()
            self.db.execute("INSERT OR REPLACE INTO standards (name, text, updated_by, updated, deleted, revision) "
                            "VALUES (?, ?, ?, ?, 0, ?)", (name, source, user, now, revision))
        return revision

    def delete_standard(self, name):
        with self.db:
            revision = self.next_revision()
            self.db.execute("UPDATE standards SET deleted = 1, revision = ? WHERE name = ?", (revision, name))
            self.db.execute("DELETE FROM compliance WHERE standard = ?", (name,))
        return revision

    def compliance(self, device_id=None):
        query = "SELECT * FROM compliance" + (" WHERE device_id = ?" if device_id else "") + " ORDER BY device_id"
        rows = self.db.execute(query, (device_id,) if device_id else ())
        return [{**dict(row), "results": json.loads(row["results"] or "[]")} for row in rows]

    def save_compliance(self, device_id, standard_name, results, version_id, now=None, revision=None):
        """How a device stands against a standard (results: [{"status", "rule", "path", "detail", "fix"}])."""
        now = time.time() if now is None else now
        failed = sum(1 for result in results if result.get("status") != "pass")
        with self.db:
            revision = revision or self.next_revision()
            self.db.execute("INSERT OR REPLACE INTO compliance (device_id, standard, failed, total, results, "
                            "version_id, checked, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (device_id, standard_name, failed, len(results), json.dumps(results), version_id, now,
                             revision))
        return revision

    def drop_compliance(self, device_id, standard_name):
        with self.db:
            revision = self.next_revision()
            self.db.execute("DELETE FROM compliance WHERE device_id = ? AND standard = ?", (device_id, standard_name))
        return revision

    def failing(self):
        """{device id: number of standard lines it fails}."""
        rows = self.db.execute("SELECT device_id, sum(failed) AS n FROM compliance GROUP BY device_id")
        return {row["device_id"]: row["n"] for row in rows if row["n"]}

    # ----------------------------------------------------------------- Changes for a copy (a laptop's)

    def changes_since(self, since):
        """Everything changed after revision since (versions without their texts), and the revision now."""
        since = int(since)
        devices = [self._device(row) for row in self.db.execute("SELECT * FROM devices WHERE revision > ?", (since,))]
        versions = [self._version(row, False) for row in
                    self.db.execute("SELECT * FROM versions WHERE revision > ? ORDER BY id", (since,))]
        standards = [dict(row) for row in self.db.execute("SELECT * FROM standards WHERE revision > ?", (since,))]
        compliance = [{**dict(row), "results": json.loads(row["results"] or "[]")} for row in
                      self.db.execute("SELECT * FROM compliance WHERE revision > ?", (since,))]
        settings = {row["name"]: json.loads(row["value"]) for row in
                    self.db.execute("SELECT name, value FROM settings WHERE revision > ?", (since,))}
        # A standard deleted takes its rows with it: the copy is told which devices and standards are still there
        present = [[row["device_id"], row["standard"]] for row in
                   self.db.execute("SELECT device_id, standard FROM compliance")] if standards else None
        return {"devices": devices, "versions": versions, "standards": standards, "compliance": compliance,
                "settings": settings, "compliance_present": present}, self.revision()

    def absorb(self, changes, revision):
        """Take the server's changes into a copy (texts come later, as they're opened)."""
        with self.db:
            for device in changes.get("devices", ()):
                failures = device.pop("failures", [])
                device["names"] = json.dumps(device.get("names") or [])
                device["facts"] = json.dumps(device.get("facts") or {})
                columns = [name for name in device if name in DEVICE_COLUMNS]
                self.db.execute(f"INSERT OR REPLACE INTO devices ({', '.join(columns)}) VALUES "
                                f"({', '.join('?' for _ in columns)})", [device[name] for name in columns])
                self.db.execute("DELETE FROM failures WHERE device_id = ?", (device["id"],))
                for failure in failures:
                    self.db.execute("INSERT OR REPLACE INTO failures (device_id, computer, reason, at) "
                                    "VALUES (?, ?, ?, ?)", (device["id"], failure["computer"], failure["reason"],
                                                            failure["at"]))
            for version in changes.get("versions", ()):
                old = self.db.execute("SELECT text FROM versions WHERE id = ?", (version["id"],)).fetchone()
                values = [version.get(name) for name in VERSION_FIELDS]
                self.db.execute(f"INSERT OR REPLACE INTO versions ({', '.join(VERSION_FIELDS)}, text) VALUES "
                                f"({', '.join('?' for _ in VERSION_FIELDS)}, ?)",
                                values + [old["text"] if old else None])
            for standard in changes.get("standards", ()):
                self.db.execute("INSERT OR REPLACE INTO standards (name, text, updated_by, updated, deleted, revision) "
                                "VALUES (?, ?, ?, ?, ?, ?)", (standard["name"], standard["text"],
                                                              standard["updated_by"], standard["updated"],
                                                              standard["deleted"], standard["revision"]))
            for row in changes.get("compliance", ()):
                self.db.execute("INSERT OR REPLACE INTO compliance (device_id, standard, failed, total, results, "
                                "version_id, checked, revision) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (row["device_id"], row["standard"], row["failed"], row["total"],
                                 json.dumps(row["results"]), row["version_id"], row["checked"], row["revision"]))
            present = changes.get("compliance_present")
            if present is not None:
                keep = {tuple(item) for item in present}
                for row in self.db.execute("SELECT device_id, standard FROM compliance").fetchall():
                    if (row["device_id"], row["standard"]) not in keep:
                        self.db.execute("DELETE FROM compliance WHERE device_id = ? AND standard = ?",
                                        (row["device_id"], row["standard"]))
            for name, value in changes.get("settings", {}).items():
                self.db.execute("INSERT OR REPLACE INTO settings (name, value, revision) VALUES (?, ?, ?)",
                                (name, json.dumps(value), revision))
            self.set_meta("revision", revision)

    def has_text(self, version_id):
        row = self.db.execute("SELECT text IS NOT NULL AS has FROM versions WHERE id = ?", (int(version_id),)).fetchone()
        return bool(row and row["has"])

    def store_text(self, version_id, config):
        with self.db:
            self.db.execute("UPDATE versions SET text = ? WHERE id = ?", (pack(config), int(version_id)))

    # ----------------------------------------------------------------- Uploads waiting for the server (a copy)

    def queue_upload(self, upload):
        with self.db:
            self.db.execute("INSERT INTO outbox (data) VALUES (?)", (json.dumps(upload),))

    def waiting_uploads(self):
        return [(row["id"], json.loads(row["data"])) for row in self.db.execute("SELECT * FROM outbox ORDER BY id")]

    def sent_upload(self, outbox_id):
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE id = ?", (outbox_id,))


DEVICE_COLUMNS = ("id", "name", "address", "names", "platform", "kind", "facts", "in_scope", "excluded", "created",
                  "next_due", "last_ok", "last_checked", "last_try", "revision")
