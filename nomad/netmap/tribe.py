"""This computer's copy of the tribe's maps, and the changes made here that the server hasn't got yet.

The copy keeps each map as the server last had it (base) plus this computer's changes not sent yet (pending, the
latest of each item). A map is read as base with pending on top, so it opens and changes offline; sync() sends the
pending changes, then fetches everyone else's, which land in base under any pending change to the same item (the
pending one is sent afterwards, so it wins: the last change made to an item is the one kept).

Each map's SNMP credentials (its secrets) are kept on the server too, encrypted, so everyone in the tribe crawls and
watches it with the same ones. The copy keeps them (encrypted for this Windows account, or this computer in the
service) for offline use, fetches them again whenever the server says the map changed, and holds a change made
offline until it can be sent, like the map's own changes.

Thread-safe: the map page syncs on a worker thread while it reads and saves on the UI thread, and the Map Watcher
service uses it from its own.
"""
import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from ..ipam.client import LOCK_API
from ..system import log_dir
from . import shared

log = logging.getLogger(__name__)

COPY_FILE = "maps-team.db"
SCHEMA = """
CREATE TABLE IF NOT EXISTS maps (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_by TEXT, created TEXT,
                                 deleted INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS base (map_id INTEGER NOT NULL, section TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL,
                                 PRIMARY KEY (map_id, section, key));
CREATE TABLE IF NOT EXISTS pending (map_id INTEGER NOT NULL, section TEXT NOT NULL, key TEXT NOT NULL, data TEXT,
                                    seq INTEGER NOT NULL, PRIMARY KEY (map_id, section, key));
CREATE TABLE IF NOT EXISTS secrets (map_id INTEGER PRIMARY KEY, data TEXT NOT NULL, pending INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS stale_secrets (map_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS collapsed (map_id INTEGER PRIMARY KEY, groups TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT);
"""


SECRETS = ("secrets", "")  # Among the items sync() says changed on a map: its credentials did
TABLES = ("maps", "base", "pending", "secrets", "stale_secrets", "collapsed")  # Emptied when the copy starts again


def copy_path():
    return log_dir() / COPY_FILE  # %LOCALAPPDATA%: a cache of the server's maps, so it needn't roam


class TribeMaps:
    def __init__(self, server_id, client, path=None, protect=None, unprotect=None):
        """client: a TeamClient (or anything with its map methods). protect/unprotect: how community strings are
        kept in the copy (DPAPI for this Windows account in NOMAD, for this computer in the service)."""
        self.server_id, self.client = server_id, client
        self.path = Path(path or copy_path())
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()
        self.protect = protect or (lambda text: text)
        self.unprotect = unprotect or (lambda text: text)
        self.leases = {}  # Map id -> lease, from the last sync
        self.online, self.last_error = False, ""
        self._upgrade()
        if self._meta("server_id") not in ("", server_id):  # Another server's maps: start again
            with self._transaction():
                for table in TABLES:
                    self.db.execute(f"DELETE FROM {table}")
                self._set_meta("revision", 0)
        self._set_meta("server_id", server_id)

    def _upgrade(self):
        """Bring a copy made by an older NOMAD up to date."""
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(secrets)")}
        if "pending" not in columns:
            with self._transaction():
                self.db.execute("ALTER TABLE secrets ADD COLUMN pending INTEGER NOT NULL DEFAULT 0")
                # Older copies never fetched credentials again once they had some: fetch them all on the next sync
                self.db.execute("INSERT OR IGNORE INTO stale_secrets (map_id) SELECT id FROM maps WHERE deleted = 0")

    def close(self):
        with self.lock:
            self.db.close()

    def clear(self):
        """Forget the copy (leaving the tribe): maps, changes not sent and community strings."""
        with self._transaction():
            for table in TABLES:
                self.db.execute(f"DELETE FROM {table}")
            self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES ('revision', '0')")

    @contextmanager
    def _transaction(self):
        with self.lock, self.db:
            yield

    def _meta(self, name, default=""):
        row = self.db.execute("SELECT value FROM meta WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else default

    def _set_meta(self, name, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES (?, ?)", (name, str(value)))

    def asked(self, map_id, question):
        """Whether this computer has asked a question about a map before (such as which IPAM network it's of)."""
        with self.lock:
            return self._meta(f"asked/{question}/{int(map_id)}") == "1"

    def note_asked(self, map_id, question):
        self._set_meta(f"asked/{question}/{int(map_id)}", "1")

    @property
    def revision(self):
        with self.lock:
            return int(self._meta("revision", "0") or 0)

    # ----------------------------------------------------------------- Reading

    def maps(self):
        """[{"id", "name", ...}] of the tribe's maps, by name."""
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM maps WHERE deleted = 0 ORDER BY name")]

    def map_info(self, map_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM maps WHERE id = ?", (int(map_id),)).fetchone()
            return dict(row) if row else None

    def _base(self, map_id):
        rows = self.db.execute("SELECT section, key, data FROM base WHERE map_id = ?", (int(map_id),))
        return {(row["section"], row["key"]): json.loads(row["data"]) for row in rows}

    def _pending(self, map_id):
        rows = self.db.execute("SELECT section, key, data FROM pending WHERE map_id = ? ORDER BY seq", (int(map_id),))
        return {(row["section"], row["key"]): None if row["data"] is None else json.loads(row["data"])
                for row in rows}

    def items(self, map_id, raw=False):
        """{(section, key): data} of a map as this computer has it: the server's, with changes not sent on top.
        raw: as the server has them (groups shared by older NOMADs say whether they're collapsed)."""
        with self.lock:
            items = self._base(map_id)
            for key, data in self._pending(map_id).items():
                if data is None:
                    items.pop(key, None)
                else:
                    items[key] = data
            return items if raw else {key: shared.shared_part(key[0], data) for key, data in items.items()}

    def load(self, map_id):
        """(NetworkMap, settings) of a map, with the groups collapsed that were collapsed on this computer."""
        network_map, settings, _ = self.snapshot(map_id)
        return network_map, settings

    def snapshot(self, map_id):
        """(NetworkMap, settings, seen) of a map: as load, with the items it was built from, to save it with (so
        only what's changed on it from then is sent)."""
        with self.lock:
            raw = self.items(map_id, raw=True)
            collapsed = self.collapsed(map_id)
        network_map = shared.build(raw)
        if collapsed is None:  # Never opened here since groups stopped being collapsed for everyone: as shared
            collapsed = {key for (section, key), data in raw.items()
                         if section == shared.GROUP and isinstance(data, dict) and data.get("collapsed")}
        for group in network_map.groups:
            group.collapsed = group.key in collapsed
        return network_map, shared.settings_of(raw), {key: shared.shared_part(key[0], data)
                                                      for key, data in raw.items()}

    def collapsed(self, map_id):
        """The keys of the map's groups collapsed on this computer (None if none were ever kept for it)."""
        with self.lock:
            row = self.db.execute("SELECT groups FROM collapsed WHERE map_id = ?", (int(map_id),)).fetchone()
        return None if row is None else set(json.loads(row["groups"]))

    def keep_collapsed(self, map_id, network_map):
        """Note which groups are collapsed here: each person's own, never sent."""
        with self._transaction():
            self._keep_collapsed(map_id, network_map)

    def _keep_collapsed(self, map_id, network_map):
        groups = sorted(group.key for group in network_map.groups if group.collapsed)
        self.db.execute("INSERT OR REPLACE INTO collapsed (map_id, groups) VALUES (?, ?)",
                        (int(map_id), json.dumps(groups)))

    @property
    def server_api(self):
        """The server's API level, as of the last sync (0 before one)."""
        with self.lock:
            return int(self._meta("server_api", "0") or 0)

    @property
    def sends_locks(self):
        """Whether the server is known to keep icons locked in place. Until it is, they stay among the changes not
        sent, so they work on this computer and go when the server's updated."""
        return self.server_api >= LOCK_API

    @property
    def too_old_for_locks(self):
        return 0 < self.server_api < LOCK_API

    def note_server_api(self):
        """Ask the server's API level (network), for sends_locks."""
        status = getattr(self.client, "status", None)
        api = status().get("api") if status is not None else None
        if api:
            self._set_meta("server_api", api)

    def held_sections(self):
        """The sections the server can't take yet (it refuses a whole push with one of them in it)."""
        return () if self.sends_locks else shared.LOCK_SECTIONS

    def pending_count(self, map_id=None):
        """How many changes are waiting to be sent (a change to a map's credentials counts as one)."""
        where, values = ("", ()) if map_id is None else (" AND map_id = ?", (int(map_id),))
        held = self.held_sections()
        where_held = f" AND section NOT IN ({', '.join('?' * len(held))})" if held else ""
        with self.lock:
            items = self.db.execute("SELECT COUNT(*) FROM pending WHERE 1" + where + where_held,
                                    values + held).fetchone()[0]
            secrets = self.db.execute("SELECT COUNT(*) FROM secrets WHERE pending = 1" + where, values).fetchone()[0]
        return items + secrets

    # ----------------------------------------------------------------- Changing

    def save(self, map_id, network_map, settings=None, seen=None):
        """Note what changed on a map here, to send (and which groups are collapsed, kept here only). Returns how
        many items changed.

        seen: the items the map was loaded as (snapshot's), for a copy kept open while others' changes arrive. Only
        what changed on it since is sent, so their changes that arrived meanwhile (and aren't on it yet) aren't
        undone; seen is then updated to the map as saved. Without it, the whole map is saved as it is."""
        with self._transaction():
            self._keep_collapsed(map_id, network_map)
            items = self.items(map_id)
            current = shared.flatten(network_map, settings if settings is not None else shared.settings_of(items))
            changes = shared.diff(items if seen is None else seen, current)
            if seen is not None:
                seen.clear()
                seen.update(current)
                changes = [change for change in changes
                           if items.get((change["section"], change["key"])) != change["data"]]
            if not changes:
                return 0
            base = self._base(map_id)
            seq = (self.db.execute("SELECT MAX(seq) FROM pending").fetchone()[0] or 0) + 1
            for change in changes:
                key = (change["section"], change["key"])
                if base.get(key) == change["data"]:  # Back to the server's: nothing to send
                    self.db.execute("DELETE FROM pending WHERE map_id = ? AND section = ? AND key = ?",
                                    (int(map_id), *key))
                    continue
                self.db.execute("INSERT OR REPLACE INTO pending (map_id, section, key, data, seq) VALUES "
                                "(?, ?, ?, ?, ?)", (int(map_id), *key,
                                                    None if change["data"] is None else json.dumps(change["data"]),
                                                    seq))
                seq += 1
            return len(changes)

    def create(self, name, network_map, settings, secrets):
        """Share a map with the tribe (needs the server). Returns its id."""
        items = shared.flatten(network_map, settings)
        self.note_server_api()
        held = self.held_sections()
        changes = [change for change in shared.diff({}, items) if change["section"] not in held]
        reply = self.client.map_request("create", name=name, changes=changes, secrets=secrets)
        map_id = reply["map_id"]
        with self._transaction():
            self.db.execute("INSERT OR REPLACE INTO maps (id, name, revision) VALUES (?, ?, ?)",
                            (map_id, name.strip(), reply["revision"]))
            self.db.executemany("INSERT OR REPLACE INTO base (map_id, section, key, data) VALUES (?, ?, ?, ?)",
                                [(map_id, section, key, json.dumps(data)) for (section, key), data in items.items()
                                 if section not in held])
            seq = (self.db.execute("SELECT MAX(seq) FROM pending").fetchone()[0] or 0) + 1
            self.db.executemany("INSERT OR REPLACE INTO pending (map_id, section, key, data, seq) VALUES "
                                "(?, ?, ?, ?, ?)", [(map_id, section, key, json.dumps(data), seq)
                                                    for (section, key), data in items.items() if section in held])
            self._keep_collapsed(map_id, network_map)
            self._cache_secrets(map_id, secrets)
        return map_id

    def rename(self, map_id, name):
        self.client.map_request("rename", map_id=int(map_id), name=name)
        with self._transaction():
            self.db.execute("UPDATE maps SET name = ? WHERE id = ?", (name.strip(), int(map_id)))

    def delete(self, map_id):
        self.client.map_request("delete", map_id=int(map_id))
        self._forget(map_id)

    def _forget(self, map_id):
        with self._transaction():
            for table in ("base", "pending", "secrets", "stale_secrets", "collapsed"):
                self.db.execute(f"DELETE FROM {table} WHERE map_id = ?", (int(map_id),))
            self.db.execute("UPDATE maps SET deleted = 1 WHERE id = ?", (int(map_id),))

    # ----------------------------------------------------------------- Community strings (SNMP credentials)

    def _cache_secrets(self, map_id, secrets, pending=False):
        """Keep a map's credentials here. pending: changed here, to send. Returns whether they were kept."""
        try:
            data = self.protect(json.dumps(secrets or {}))
        except Exception as error:  # DPAPI unavailable: they'll be fetched again next time
            log.warning("Couldn't keep a map's community strings: %s", error)
            return False
        with self._transaction():
            self.db.execute("INSERT OR REPLACE INTO secrets (map_id, data, pending) VALUES (?, ?, ?)",
                            (int(map_id), data, int(pending)))
        return True

    def _decrypt(self, data):
        try:
            return json.loads(self.unprotect(data))
        except Exception as error:
            log.warning("Couldn't read a map's community strings: %s", error)
            return {}

    def secrets(self, map_id):
        """The map's community strings and SNMPv3 users as last fetched, or as changed here ({} if never)."""
        with self.lock:
            row = self.db.execute("SELECT data FROM secrets WHERE map_id = ?", (int(map_id),)).fetchone()
        return {} if row is None else self._decrypt(row["data"])

    def fetch_secrets(self, map_id):
        """Fetch a map's credentials from the server (network) and keep them here. If they were changed here and
        not sent yet, those are kept and returned instead: they're sent next, so they win."""
        secrets = self.client.map_secrets(map_id)
        with self._transaction():
            self.db.execute("DELETE FROM stale_secrets WHERE map_id = ?", (int(map_id),))
            row = self.db.execute("SELECT data FROM secrets WHERE map_id = ? AND pending = 1",
                                  (int(map_id),)).fetchone()
        if row is not None:
            return self._decrypt(row["data"])
        self._cache_secrets(map_id, secrets)
        return secrets

    def set_secrets(self, map_id, secrets):
        """Change a map's credentials for everyone in the tribe. They're kept here at once and sent now if the
        server can be reached, else with the next sync. Returns whether they reached the server."""
        if not self._cache_secrets(map_id, secrets, pending=True):
            self.client.map_request("secrets", map_id=int(map_id), secrets=secrets)  # Can't be kept: send or fail
            return True
        try:
            self._send_secrets(map_id)
        except Exception as error:
            log.info("Couldn't send a tribe map's credentials yet: %s", error)
            return False
        return True

    def _send_secrets(self, map_id):
        """Send a map's credentials changed here (network)."""
        with self.lock:
            row = self.db.execute("SELECT data FROM secrets WHERE map_id = ? AND pending = 1",
                                  (int(map_id),)).fetchone()
        if row is None:
            return
        self.client.map_request("secrets", map_id=int(map_id), secrets=self._decrypt(row["data"]))
        with self._transaction():  # Unless they were changed again meanwhile
            self.db.execute("UPDATE secrets SET pending = 0 WHERE map_id = ? AND data = ?", (int(map_id), row["data"]))

    def refresh_secrets(self):
        """Fetch the credentials of the maps the server changed since theirs were last fetched (network: on a
        worker thread). Returns the ids of the maps whose credentials are now different here."""
        with self.lock:
            stale = [row["map_id"] for row in self.db.execute("SELECT map_id FROM stale_secrets")]
        changed = []
        for map_id in stale:
            before = self.secrets(map_id)
            try:
                after = self.fetch_secrets(map_id)
            except Exception as error:
                if "isn't on the server any more" in str(error):
                    with self._transaction():
                        self.db.execute("DELETE FROM stale_secrets WHERE map_id = ?", (int(map_id),))
                else:  # Tried again on the next sync
                    log.info("Couldn't fetch the credentials of tribe map %s: %s", map_id, error)
                continue
            if after != before:
                changed.append(map_id)
        return changed

    # ----------------------------------------------------------------- Syncing

    def send_pending(self):
        """Send the changes made here (network: call on a worker thread). Returns how many were sent."""
        with self.lock:
            changed_secrets = [row["map_id"] for row in self.db.execute("SELECT map_id FROM secrets WHERE pending = 1")]
        for map_id in changed_secrets:
            try:
                self._send_secrets(map_id)
            except Exception as error:
                if "isn't on the server any more" in str(error):
                    self._forget(map_id)
                    continue
                raise
        held = self.held_sections()
        with self.lock:
            outgoing = {}
            for row in self.db.execute("SELECT * FROM pending ORDER BY seq"):
                if row["section"] in held:
                    continue
                outgoing.setdefault(row["map_id"], []).append(
                    {"section": row["section"], "key": row["key"],
                     "data": None if row["data"] is None else json.loads(row["data"])})
        sent = 0
        for map_id, changes in outgoing.items():
            try:
                self.client.map_request("push", map_id=map_id, changes=changes)
            except Exception as error:
                if "isn't on the server any more" in str(error):  # Deleted by someone: nothing to send it to
                    log.info("Dropping changes to a deleted tribe map: %s", error)
                    self._forget(map_id)
                    continue
                raise
            with self._transaction():
                for change in changes:
                    key = (map_id, change["section"], change["key"])
                    row = self.db.execute("SELECT data FROM pending WHERE map_id = ? AND section = ? AND key = ?",
                                          key).fetchone()
                    sent_data = None if change["data"] is None else json.dumps(change["data"])
                    if row is not None and row["data"] == sent_data:  # Not changed again meanwhile
                        self.db.execute("DELETE FROM pending WHERE map_id = ? AND section = ? AND key = ?", key)
                    if change["data"] is None:
                        self.db.execute("DELETE FROM base WHERE map_id = ? AND section = ? AND key = ?", key)
                    else:
                        self.db.execute("INSERT OR REPLACE INTO base VALUES (?, ?, ?, ?)", key + (sent_data,))
            sent += len(changes)
        return sent

    def apply_changes(self, payload, revision):
        """Take what map_changes brought. Returns {map id: (section, key) items changed} for the maps touched."""
        touched = {}
        with self._transaction():
            for item in payload.get("maps", []):
                self.db.execute("INSERT OR REPLACE INTO maps (id, name, created_by, created, deleted, revision) "
                                "VALUES (:id, :name, :created_by, :created, :deleted, :revision)", item)
                if item["deleted"]:
                    for table in ("base", "pending", "secrets", "stale_secrets"):
                        self.db.execute(f"DELETE FROM {table} WHERE map_id = ?", (item["id"],))
                else:  # Shared, renamed or its credentials changed: fetch them again (refresh_secrets)
                    self.db.execute("INSERT OR IGNORE INTO stale_secrets (map_id) VALUES (?)", (item["id"],))
                touched.setdefault(item["id"], set())
            for item in payload.get("items", []):
                key = (item["map_id"], item["section"], item["key"])
                if item["data"] is None:
                    self.db.execute("DELETE FROM base WHERE map_id = ? AND section = ? AND key = ?", key)
                else:
                    self.db.execute("INSERT OR REPLACE INTO base VALUES (?, ?, ?, ?)",
                                    key + (json.dumps(item["data"]),))
                touched.setdefault(item["map_id"], set()).add((item["section"], item["key"]))
            self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES ('revision', ?)", (str(revision),))
        self.leases = {int(map_id): lease for map_id, lease in payload.get("leases", {}).items()}
        return touched

    def sync(self):
        """Send what's pending, then fetch everyone's changes (network: call on a worker thread). Returns
        {map id: items changed} as apply_changes does, with SECRETS among a map's items when its credentials
        changed."""
        try:
            self.note_server_api()
            self.send_pending()
            payload, revision = self.client.map_changes(self.revision)
        except Exception as error:
            self.online, self.last_error = False, str(error)
            raise
        self.online, self.last_error = True, ""
        touched = self.apply_changes(payload, revision)
        for map_id in self.refresh_secrets():
            touched.setdefault(map_id, set()).add(SECRETS)
        return touched

    # ----------------------------------------------------------------- Watching

    def lease(self, map_id, holder, kind="gui", release=False, take=False):
        """Claim (renew, or release) the watching of a map. Returns the lease ({"yours": ...})."""
        reply = self.client.map_request("lease", map_id=int(map_id), holder=holder, kind=kind, release=release,
                                        take=take)
        lease = reply.get("lease") or {}
        with self.lock:
            if lease:
                self.leases[int(map_id)] = lease
            else:
                self.leases.pop(int(map_id), None)
        return lease
