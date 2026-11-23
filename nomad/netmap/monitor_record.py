"""A monitoring record: each device's status now, its changes of status, and the gaps when nothing was monitoring.

NOMAD's Monitor keeps one for each map on this computer (%LOCALAPPDATA%\\NOMAD\\monitoring, LocalRecord), the Map
Watcher keeps one for the maps it monitors (status.db, watch_monitor.MonitorStore), and the NOMAD Dashboard keeps its
own longer history from the Watcher's (dashboard/history.py). They all work out the same things the same way, here:

- Picking up after a restart: the statuses saved last are taken back (restore), so a device up before is still up
  since the same time, and one that changed while nothing was monitoring has that noted once, with how long it had
  been as it was.
- Gaps: the time from the last check before a restart to the first after it. Uptime leaves gaps out, rather than
  counting them as whatever the device was before.
- When each device's status began: from the record's changes, oldest first, a run of the same status counting as one
  (an older Watcher noted a device down again after each restart). It's exact when the change came from a status
  known before it; otherwise it's only when monitoring first saw the device like that ("up for at least...").
- Uptime over the last 24 hours, 7 days and 30 days: the share of the time it was up, of the time it was known to be
  up or down.

A record's view of a map can be shared as a summary (plain JSON): the Map Watcher writes one for each map it monitors
where anyone on its computer can read it (SHARED_DIR), and sends it to the tribe for everyone else.
"""
import datetime
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import monitor
from .monitor import DOWN, UNKNOWN, UP

UPTIME_SPANS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
UPTIME_NAMES = {"24h": "24 h", "7d": "7 days", "30d": "30 days"}
GAP_SECONDS = 120  # A pause in monitoring shorter than this (or than two checks) isn't a gap: a quick restart
UPTIME_SECONDS = 60  # Uptimes are worked out again at most this often
SUMMARY_VERSION = 1
STALE_SECONDS = 600  # A summary not updated for this long (or five intervals) is from a Map Watcher that stopped
SHARED_DIR_NAME = "monitoring"

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_status (map_id INTEGER, key TEXT, label TEXT, address TEXT, kind TEXT,
    status TEXT, since REAL, checked REAL, rtt INTEGER, via TEXT, problem TEXT, PRIMARY KEY (map_id, key));
CREATE TABLE IF NOT EXISTS changes (id INTEGER PRIMARY KEY AUTOINCREMENT, map_id INTEGER, key TEXT, label TEXT,
    status TEXT, at REAL, lasted REAL, text TEXT);
CREATE INDEX IF NOT EXISTS changes_at ON changes(at);
CREATE INDEX IF NOT EXISTS changes_device ON changes(map_id, key, at);
CREATE TABLE IF NOT EXISTS gaps (id INTEGER PRIMARY KEY AUTOINCREMENT, start_at REAL, end_at REAL);
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT);
"""


# --------------------------------------------------------------------- Working it out

@dataclass(frozen=True)
class Run:
    """A device's current run of one status, as a record's changes have it."""
    status: str
    start: float
    exact: bool  # The change came from a status known before it


def advance_runs(runs, changes):
    """Take changes [(device, status, at, lasted)], oldest first, into runs {device: Run}. Returns runs."""
    for device, status, at, lasted in changes:
        run = runs.get(device)
        if run is not None and run.status == status:
            continue  # The same status noted again: still the same run
        runs[device] = Run(status, float(at), lasted is not None)
    return runs


def since_of(status, since, exact, run):
    """(since, exact) for a device: the record's run when it's of this status and goes back further than what the
    monitoring knows (it started again after the device last changed, so it only knows since then)."""
    if run is not None and run.status == status:
        if not since or run.start < since - 1:
            return run.start, run.exact
        if abs(run.start - since) <= 1:  # The same change: the record may know what came before it
            return since, exact or run.exact
    return since, exact


def missing_changes(runs, states):
    """[(device, status, since)] for devices up or down now that the record's last change has otherwise: a change
    it never got (NOMAD before 2.8 didn't note a device answering the first check after it started again, so a device
    that came back meanwhile stayed down in the record). states: {device: (status, since)}."""
    found = []
    for device, (status, since) in states.items():
        run = runs.get(device)
        if status in (UP, DOWN) and run is not None and run.status != status and since and since > run.start:
            found.append((device, status, since))
    return found


def merge_gaps(gaps):
    """Gaps [(start, end)] in order, with those that overlap made one."""
    merged = []
    for start, end in sorted((float(start), float(end)) for start, end in gaps if end > start):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def gap_overlap(start, end, gaps):
    """How much of start-end falls in gaps (merged)."""
    total = 0.0
    for gap_start, gap_end in gaps:
        low, high = max(start, gap_start), min(end, gap_end)
        if high > low:
            total += high - low
    return total


def fraction_up(status, events, start, end, gaps=()):
    """The share of start-end a device was up, of the time it was known up or down, leaving out gaps. status: what
    it was at start (None: not known); events: [(at, new status)] in order. None if it was never known."""
    clock, up, known = float(start), 0.0, 0.0
    for at, new in [*events, (end, None)]:
        length = max(0.0, at - clock - gap_overlap(clock, at, gaps))
        if status in (UP, DOWN):
            known += length
            up += length if status == UP else 0.0
        clock, status = at, new
    return up / known if known > 0 else None


def uptimes(before, during, start, end, current=None, gaps=()):
    """{device: fraction up} from start to end. before: {device: its status at start (its last change before)};
    during: [(device, at, status)] in order; current: {device: status now}, for devices with no change at all."""
    timelines = {}
    for device, at, status in during:
        timelines.setdefault(device, []).append((at, status))
    gaps = merge_gaps(gaps)
    result = {}
    for device in set(before) | set(timelines) | set(current or {}):
        status = before.get(device)
        events = timelines.get(device, [])
        if status is None and not events:
            status = (current or {}).get(device)
        value = fraction_up(status, events, start, end, gaps)
        if value is not None:
            result[device] = value
    return result


def with_known_start(changes):
    """Changes [(device, status, at, lasted)] in order, as [(device, status, at)] with each device's status before its
    first change put in where that change says how long it had lasted. A device answering the first check isn't
    noted (it isn't news), so a device up for 22 h that then goes down had only the change to down: without this the
    22 h up was unknown and its uptime went straight to 0%."""
    seen, result = set(), []
    for device, status, at, lasted in changes:
        if device not in seen:
            seen.add(device)
            if status in (UP, DOWN) and lasted:
                result.append((device, DOWN if status == UP else UP, float(at) - float(lasted)))
        result.append((device, status, float(at)))
    result.sort(key=lambda change: change[2])  # Stable: changes at the same moment keep their order
    return result


def restore(tracker, rows):
    """Put a record's saved statuses [{key, status, since, checked, rtt, via, problem, exact}] back in a
    monitor.StatusTracker, so monitoring carries on from them. A device down stays down until it answers."""
    for row in rows:
        status = row.get("status")
        if status not in (UP, DOWN, UNKNOWN):
            continue
        tracker.devices[row["key"]] = monitor.DeviceStatus(
            status=status, rtt=row.get("rtt"), since=float(row.get("since") or 0.0),
            fails=tracker.fails_for_down if status == DOWN else 0, checked=float(row.get("checked") or 0.0),
            via=row.get("via") or "", problem=row.get("problem") or "", exact=bool(row.get("exact")))


def short_duration(seconds):
    """3 d 5 h, 5 h 12 min, 12 min, 40 s: for a box on the map, never rounded up (the NOMAD Dashboard's map.js says
    it the same way)."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        hours, minutes = divmod(seconds // 60, 60)
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(seconds // 3600, 24)
    return f"{days} d {hours} h" if hours else f"{days} d"


def percent_text(fraction):
    """99.98% (two places at most, trailing zeros dropped)."""
    return f"{round(100 * fraction, 2):g}%"


def uptime_text(uptime):
    """"99.9% (24 h) · 98% (7 days)" from {"24h": fraction...}, or ""."""
    return " · ".join(f"{percent_text(uptime[name])} ({UPTIME_NAMES[name]})" for name in UPTIME_NAMES
                      if uptime.get(name) is not None)


def duration_since(state, now=None):
    """"for 3 days 2 h" or "for at least 3 days 2 h", or "" without a since."""
    if not state.since:
        return ""
    now = time.time() if now is None else now
    return f"for {'' if state.exact else 'at least '}{monitor.duration_text(now - state.since)}"


def clock_text(when, now=None):
    """"14:02" today, else "2026-11-18 14:02"."""
    now = time.time() if now is None else now
    moment = datetime.datetime.fromtimestamp(when)
    same_day = moment.date() == datetime.datetime.fromtimestamp(now).date()
    return moment.strftime("%H:%M" if same_day else "%Y-%m-%d %H:%M")


def not_checked_text(state, now=None):
    """"Not checked since 14:02" for a device of a Map Watcher that stopped checking, else ""."""
    return f"Not checked since {clock_text(state.stale_at, now)}" if state.stale_at else ""


def stale_at(summary, now=None):
    """When a summary's Map Watcher last checked, if it has stopped checking (nothing for five intervals, and at least
    STALE_SECONDS), else 0.0."""
    now = time.time() if now is None else now
    updated = float(summary.get("updated") or 0)
    return updated if now - updated > max(STALE_SECONDS, 5 * float(summary.get("interval") or 60)) else 0.0


def status_text(state, now=None):
    """"Up for 3 days 2 h, 3 ms (since 2026-11-18 14:02)": a device's status (a DeviceStatus) for the details pane,
    NOMAD's and the NOMAD Dashboard's alike."""
    if state is None:
        return ""
    now = time.time() if now is None else now
    if state.stale_at:  # What it was is all that's known
        was = {UP: "it was up then", DOWN: "it was down then"}.get(
            state.status, "it couldn't be checked then" if state.problem else "it was being checked then")
        return f"{not_checked_text(state, now)} ({was})"
    via = f", checked from {state.via} (IP SLA)" if state.via else ""
    if state.status == UNKNOWN:
        return f"Can't check: {state.problem}" if state.problem else "Being checked" + via
    started = ""
    if state.since:
        when = datetime.datetime.fromtimestamp(state.since)
        today = datetime.datetime.fromtimestamp(now).date()
        started = f" (since {when.strftime('%H:%M:%S' if when.date() == today else '%Y-%m-%d %H:%M')})"
    lasted = duration_since(state, now)
    lasted = f" {lasted}" if lasted else ""
    if state.status == DOWN:
        return f"Down{lasted}{started}{via}"
    rtt = f", {'<1' if state.rtt < 1 else state.rtt} ms" if state.rtt is not None else ""
    return f"Up{lasted}{rtt}{started}{via}"


# --------------------------------------------------------------------- Kept in SQLite

class RecordStore:
    """A monitoring record in SQLite, for one map (map_id 0) or several. Any thread: one connection, behind a lock."""

    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(SCHEMA)
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(device_status)")}
        if "exact" not in columns:  # status.db from before 2.8
            self.db.execute("ALTER TABLE device_status ADD COLUMN exact INTEGER NOT NULL DEFAULT 0")
        self.uptime_cache = {}  # map_id -> (when, {key: {"24h": fraction...}})

    def close(self):
        with self.lock:
            self.db.close()

    def rows(self, sql, parameters=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, parameters).fetchall()]

    # ----------------------------------------------------------------- Meta

    def set_meta(self, name, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES (?, ?)", (name, json.dumps(value)))

    def get_meta(self, name, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM meta WHERE name = ?", (name,)).fetchone()
        try:
            return default if row is None else json.loads(row["value"])
        except ValueError:
            return default

    # ----------------------------------------------------------------- Writing

    def write_statuses(self, map_id, rows):
        """The map's devices as now: [(key, label, address, kind, DeviceStatus)]. Devices no longer on it go."""
        with self.lock, self.db:
            self.db.execute("DELETE FROM device_status WHERE map_id = ?", (int(map_id),))
            self.db.executemany(
                "INSERT INTO device_status (map_id, key, label, address, kind, status, since, checked, rtt, via, "
                "problem, exact) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(int(map_id), key, label, address, kind, state.status, state.since, state.checked, state.rtt,
                  state.via, state.problem, int(bool(state.exact))) for key, label, address, kind, state in rows])
        self.uptime_cache.pop(int(map_id), None)

    def add_changes(self, map_id, changes):
        """[(Change, label, text)]"""
        if changes:
            with self.lock, self.db:
                self.db.executemany("INSERT INTO changes (map_id, key, label, status, at, lasted, text) VALUES "
                                    "(?, ?, ?, ?, ?, ?, ?)",
                                    [(int(map_id), change.key, label, change.status, change.when, change.lasted, text)
                                     for change, label, text in changes])
            self.uptime_cache.pop(int(map_id), None)

    def add_gap(self, start, end):
        """Nothing was monitoring from start to end."""
        with self.lock, self.db:
            self.db.execute("INSERT INTO gaps (start_at, end_at) VALUES (?, ?)", (float(start), float(end)))
        self.uptime_cache.clear()

    def note_restart(self, now, interval):
        """Monitoring is starting (again): the time since the last check before is a gap, if long enough. Returns
        the gap (start, end), or None."""
        last = self.get_meta("checked_at")
        if not last or now - float(last) < max(GAP_SECONDS, 2 * interval):
            return None
        self.add_gap(float(last), now)
        return float(last), now

    def checked(self, now):
        """Monitoring checked the devices just now (where a gap starts if it stops)."""
        self.set_meta("checked_at", now)

    def fill_in(self, map_id, labels, states):
        """Add the changes the record never got (see missing_changes), quietly (no text: they aren't news).
        states: {key: DeviceStatus}."""
        runs = self.runs(map_id)
        missing = missing_changes(runs, {key: (state.status, state.since) for key, state in states.items()})
        if missing:
            self.add_changes(map_id, [(monitor.Change(key, status, since), labels.get(key, key), "")
                                      for key, status, since in missing])

    def prune(self, keep_seconds, now=None):
        now = self.clock() if now is None else now
        with self.lock, self.db:
            self.db.execute("DELETE FROM changes WHERE at < ?", (now - keep_seconds,))
            self.db.execute("DELETE FROM gaps WHERE end_at < ?", (now - keep_seconds,))

    def forget_maps(self, keep):
        """Drop the statuses of maps no longer monitored."""
        keep = [int(map_id) for map_id in keep]
        marks = ", ".join("?" * len(keep)) or "NULL"
        with self.lock, self.db:
            self.db.execute(f"DELETE FROM device_status WHERE map_id NOT IN ({marks})", keep)

    # ----------------------------------------------------------------- Reading

    def saved_statuses(self, map_id):
        return self.rows("SELECT * FROM device_status WHERE map_id = ?", (int(map_id),))

    def runs(self, map_id):
        """{key: Run} from all of the map's changes kept."""
        rows = self.rows("SELECT key, status, at, lasted FROM changes WHERE map_id = ? ORDER BY at, id",
                         (int(map_id),))
        return advance_runs({}, [(row["key"], row["status"], row["at"], row["lasted"]) for row in rows])

    def gaps(self, start=0.0):
        return [(row["start_at"], row["end_at"]) for row in self.rows(
            "SELECT start_at, end_at FROM gaps WHERE end_at > ? ORDER BY start_at", (float(start),))]

    def recent_changes(self, map_id, limit=5000):
        """The map's changes with something to say, oldest first."""
        rows = self.rows("SELECT * FROM changes WHERE map_id = ? AND text != '' ORDER BY at DESC, id DESC LIMIT ?",
                         (int(map_id), int(limit)))
        return rows[::-1]

    def uptimes(self, map_id, now=None, current=None):
        """{key: {"24h": fraction, "7d": ..., "30d": ...}} (worked out at most every UPTIME_SECONDS)."""
        now = self.clock() if now is None else now
        cached = self.uptime_cache.get(int(map_id))
        if cached is not None and now - cached[0] < UPTIME_SECONDS:
            return cached[1]
        longest = max(UPTIME_SPANS.values())
        changes = with_known_start([(row["key"], row["status"], row["at"], row["lasted"]) for row in self.rows(
            "SELECT key, status, at, lasted FROM changes WHERE map_id = ? ORDER BY at, id", (int(map_id),))])
        gaps = self.gaps(now - longest)
        result = {}
        for name, span in UPTIME_SPANS.items():
            start = now - span
            before, during = {}, []
            for key, status, at in changes:
                if at < start:
                    before[key] = status
                else:
                    during.append((key, at, status))
            for key, value in uptimes(before, during, start, now, current, gaps).items():
                result.setdefault(key, {})[name] = value
        self.uptime_cache[int(map_id)] = (now, result)
        return result

    def view(self, map_id, states=None, now=None):
        """{key: DeviceStatus as shown}: since (and whether it's exact) from the record's changes, and the uptimes.
        states: {key: DeviceStatus} as monitoring has them now (default: as saved)."""
        now = self.clock() if now is None else now
        if states is None:
            states = {}
            for row in self.saved_statuses(map_id):
                tracker = monitor.StatusTracker()
                restore(tracker, [row])
                states.update(tracker.devices)
        runs = self.runs(map_id)
        found = self.uptimes(map_id, now, {key: state.status for key, state in states.items()})
        shown = {}
        for key, state in states.items():
            since, exact = since_of(state.status, state.since, state.exact, runs.get(key))
            shown[key] = monitor.DeviceStatus(state.status, state.rtt, since, state.fails, state.checked, state.via,
                                              state.problem, exact, dict(found.get(key, {})), state.source)
        return shown

    def summary(self, map_id, source, interval, states=None, now=None):
        """The map's view as plain JSON, to share (see from_summary)."""
        now = self.clock() if now is None else now
        return make_summary(self.view(map_id, states, now), source, interval, now)


def make_summary(view, source, interval, now):
    return {"version": SUMMARY_VERSION, "source": source, "updated": now, "interval": interval,
            "devices": {key: {"status": state.status, "since": state.since, "exact": state.exact, "rtt": state.rtt,
                              "checked": state.checked, "via": state.via, "problem": state.problem,
                              "uptime": state.uptime} for key, state in view.items()}}


def from_summary(summary, now=None, source=None):
    """{key: DeviceStatus} from a shared summary ({} if it's not one this NOMAD understands). From a Map Watcher that
    has stopped checking, each has stale_at: shown as it was then, as the NOMAD Dashboard shows it."""
    now = time.time() if now is None else now
    if not isinstance(summary, dict) or summary.get("version") != SUMMARY_VERSION:
        return {}
    stopped = stale_at(summary, now)
    shown = {}
    for key, item in (summary.get("devices") or {}).items():
        if not isinstance(item, dict) or item.get("status") not in (UP, DOWN, UNKNOWN):
            continue
        uptime = {name: float(value) for name, value in (item.get("uptime") or {}).items()
                  if name in UPTIME_SPANS and isinstance(value, (int, float))}
        shown[key] = monitor.DeviceStatus(item["status"], item.get("rtt"), float(item.get("since") or 0.0), 0,
                                          float(item.get("checked") or 0.0), item.get("via") or "",
                                          item.get("problem") or "", bool(item.get("exact")), uptime,
                                          source if source is not None else summary.get("source", ""), stopped)
    return shown


# --------------------------------------------------------------------- This computer's record of a map

def records_dir():
    from ..system import log_dir
    path = log_dir() / "monitoring"
    path.mkdir(parents=True, exist_ok=True)
    return path


def record_name(record_id="", server_id="", map_id=None):
    """The name a map's record goes by: tribe-<server>-<map> for a tribe map, map-<its record ID> for one on this
    computer. The Map Watcher's shared summaries are named the same way."""
    if map_id is not None:
        return f"tribe-{_safe(server_id)}-{int(map_id)}"
    return f"map-{_safe(record_id)}"


def _safe(text):
    return "".join(character for character in str(text) if character.isalnum() or character in "-_")[:80] or "x"


def shared_dir():
    """Where the Map Watcher puts the summaries of the maps it monitors, for anyone on its computer to read."""
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / SHARED_DIR_NAME


def read_shared(name, directory=None):
    """The Map Watcher's summary of a map on this computer (record_name's name), or None."""
    path = Path(directory or shared_dir()) / f"{name}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def remove_shared_except(names, directory=None):
    """Delete the shared summaries of maps the Map Watcher no longer monitors (names: those it does)."""
    for path in Path(directory or shared_dir()).glob("*.json"):
        if path.stem not in names:
            try:
                path.unlink()
            except OSError:
                pass


def write_shared(name, summary, directory=None):
    directory = Path(directory or shared_dir())
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / f"{name}.json.tmp"
    temporary.write_text(json.dumps(summary), encoding="utf-8")
    from ..system import replace_file
    replace_file(temporary, directory / f"{name}.json")


class LocalRecord(RecordStore):
    """NOMAD's own record of one map, kept on this computer for a year."""
    KEEP_SECONDS = 366 * 86400

    def import_log(self, entries):
        """Take in a map's status log from before 2.8 ([[ISO time, key, label, status, text]]) the first time,
        with how long each change had lasted where the log shows the change before it."""
        if self.get_meta("imported") or not entries:
            self.set_meta("imported", True)
            return
        last = {}
        changes = []
        for when, key, label, status, text in entries:
            try:
                at = datetime.datetime.fromisoformat(when).timestamp()
            except (TypeError, ValueError):
                continue
            before = last.get(key)
            lasted = at - before[1] if before is not None and before[0] != status and before[0] != UNKNOWN else None
            if before is None or before[0] != status:
                last[key] = (status, at)
            changes.append((monitor.Change(key, status, at, lasted), label, text))
        self.add_changes(0, changes)
        self.set_meta("imported", True)
