"""Where the Syslog Collector keeps messages (SQLite), and the questions asked of them.

Each message is kept as it came (its raw text, who sent it, when, over UDP or TCP) with its severity for filtering;
the rest (facility, host, app, the message itself) is read from the raw text again when it's shown, which keeps the
file about half the size. Messages older than the days to keep are deleted, and the oldest ones too whenever the
messages take more than the size allowed.

SyslogStore is the writer's side (the collector's thread); SyslogQueries reads, from any thread, with a connection of
its own.
"""
import datetime
import logging
import math
import sqlite3
import threading
import time

from ..syslog import parse_message

log = logging.getLogger(__name__)

KEEP_DAYS = 90
MAX_BYTES = 2 * 1024 ** 3
PRUNE_BATCH = 50000  # Rows deleted at a time, so readers aren't kept waiting long
MAX_LIMIT = 20000  # Most messages one question returns

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, received REAL, source TEXT, severity INTEGER,
    protocol TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS messages_received ON messages(received);
CREATE INDEX IF NOT EXISTS messages_source ON messages(source, id);
CREATE TABLE IF NOT EXISTS senders (source TEXT PRIMARY KEY, first_seen REAL, last_seen REAL, messages INTEGER,
    host TEXT) WITHOUT ROWID;
"""


def connect(path, readonly=False):
    if readonly:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10, check_same_thread=False)
    else:
        connection = sqlite3.connect(str(path), timeout=30, check_same_thread=False)
        connection.execute("PRAGMA auto_vacuum=INCREMENTAL")  # Takes effect on a new file only: lets it shrink
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.executescript(SCHEMA)
    return connection


def message_from_row(row):
    """A syslog.SyslogMessage from a stored (id, received, source, severity, protocol, raw)."""
    message_id, received, source, _severity, protocol, raw = row
    message = parse_message(raw, source, datetime.datetime.fromtimestamp(received), protocol or "UDP")
    message.id = message_id
    return message


def message_to_dict(row):
    message_id, received, source, severity, protocol, raw = row
    return {"id": message_id, "received": received, "source": source, "severity": severity, "protocol": protocol,
            "raw": raw}


def message_from_dict(data):
    return message_from_row((data["id"], data["received"], data["source"], data.get("severity", 6),
                             data.get("protocol", "UDP"), data["raw"]))


def like_pattern(word):
    return "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class SyslogStore:
    """Writes messages and keeps the file within its days and size."""

    def __init__(self, path, keep_days=KEEP_DAYS, max_bytes=MAX_BYTES, clock=time.time):
        self.path, self.keep_days, self.max_bytes, self.clock = path, keep_days, max_bytes, clock
        self.connection = connect(path)
        self.lock = threading.Lock()

    def add(self, messages):
        """Keep syslog.SyslogMessages. Returns the ID of the last one."""
        if not messages:
            return None
        rows = [(message.received.timestamp(), message.source, message.severity, message.protocol,
                 message.raw or message.message) for message in messages]
        senders = {}
        for message, row in zip(messages, rows):
            entry = senders.setdefault(message.source, [row[0], row[0], 0, ""])
            entry[1] = row[0]
            entry[2] += 1
            entry[3] = message.host or entry[3]
        with self.lock, self.connection:
            self.connection.executemany(
                "INSERT INTO messages (received, source, severity, protocol, raw) VALUES (?, ?, ?, ?, ?)", rows)
            self.connection.executemany(
                "INSERT INTO senders (source, first_seen, last_seen, messages, host) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(source) DO UPDATE SET last_seen = excluded.last_seen, "
                "messages = messages + excluded.messages, host = CASE WHEN excluded.host != '' THEN excluded.host "
                "ELSE host END",
                [(source, first, last, count, host) for source, (first, last, count, host) in senders.items()])
            return self.connection.execute("SELECT max(id) FROM messages").fetchone()[0]

    def used_bytes(self):
        """What the messages take in the file (pages in use, not the free ones it will reuse)."""
        page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
        pages = self.connection.execute("PRAGMA page_count").fetchone()[0]
        free = self.connection.execute("PRAGMA freelist_count").fetchone()[0]
        return (pages - free) * page_size

    def prune(self):
        """Delete messages past the days to keep, then the oldest while they take more than the size allowed.
        Returns how many were deleted."""
        deleted = 0
        cutoff = self.clock() - self.keep_days * 86400
        with self.lock:
            while True:
                with self.connection:
                    count = self.connection.execute(
                        "DELETE FROM messages WHERE id IN (SELECT id FROM messages WHERE received < ? ORDER BY id "
                        "LIMIT ?)", (cutoff, PRUNE_BATCH)).rowcount
                deleted += count
                if count < PRUNE_BATCH:
                    break
            for _ in range(5):  # Each round removes what should bring it to 90% of the size allowed
                used = self.used_bytes()
                if used <= self.max_bytes:
                    break
                total, oldest = self.connection.execute("SELECT count(*), min(id) FROM messages").fetchone()
                if not total:
                    break
                fraction = 1 - (self.max_bytes * 0.9) / used
                remove = max(1, min(total, math.ceil(total * fraction)))
                with self.connection:
                    deleted += self.connection.execute(
                        "DELETE FROM messages WHERE id < (SELECT id FROM messages ORDER BY id LIMIT 1 OFFSET ?)"
                        if remove < total else "DELETE FROM messages", (remove,) if remove < total else ()).rowcount
            with self.connection:
                self.connection.execute("DELETE FROM senders WHERE last_seen < ?", (cutoff,))
            if deleted:
                self.connection.execute("PRAGMA incremental_vacuum")  # Give the space back
                self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        if deleted:
            log.info("Deleted %s old syslog messages", f"{deleted:,}")
        return deleted

    def close(self):
        with self.lock:
            self.connection.close()


class SyslogQueries:
    """What NOMAD asks of the kept messages (read only, any thread)."""

    def __init__(self, path):
        self.path = path
        self.connection = connect(path, readonly=True)
        self.lock = threading.Lock()

    def query(self, sql, parameters=()):
        with self.lock:
            return self.connection.execute(sql, parameters).fetchall()

    def latest_id(self):
        return self.query("SELECT max(id) FROM messages")[0][0] or 0

    def since(self, after, limit=1000):
        """Messages after the ID `after`, oldest first (dicts, as the API sends them)."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        rows = self.query("SELECT id, received, source, severity, protocol, raw FROM messages WHERE id > ? "
                          "ORDER BY id LIMIT ?", (int(after), limit))
        return [message_to_dict(row) for row in rows]

    def search(self, text="", severity=7, source="", start=None, end=None, before=None, limit=2000):
        """The newest messages matching every word of text (in the sender's address or the raw message, any case),
        at severity or worse, from source, received between start and end (epoch seconds) and before the ID
        `before`; oldest first."""
        conditions, parameters = ["severity <= ?"], [int(severity)]
        for word in text.split():
            conditions.append("(source || ' ' || raw) LIKE ? ESCAPE '\\'")
            parameters.append(like_pattern(word))
        if source:
            conditions.append("source = ?")
            parameters.append(source)
        if start:
            conditions.append("received >= ?")
            parameters.append(float(start))
        if end:
            conditions.append("received <= ?")
            parameters.append(float(end))
        if before:
            conditions.append("id < ?")
            parameters.append(int(before))
        limit = max(1, min(int(limit), MAX_LIMIT))
        rows = self.query("SELECT id, received, source, severity, protocol, raw FROM messages WHERE "
                          + " AND ".join(conditions) + " ORDER BY id DESC LIMIT ?", parameters + [limit])
        return [message_to_dict(row) for row in reversed(rows)]

    def senders(self):
        rows = self.query("SELECT source, first_seen, last_seen, messages, host FROM senders ORDER BY last_seen DESC")
        return [{"source": source, "first_seen": first, "last_seen": last, "messages": count, "host": host}
                for source, first, last, count, host in rows]

    def summary(self):
        count, oldest, newest = self.query("SELECT count(*), min(received), max(received) FROM messages")[0]
        return {"messages": count, "oldest": oldest, "newest": newest, "latest_id": self.latest_id()}

    def close(self):
        with self.lock:
            self.connection.close()
