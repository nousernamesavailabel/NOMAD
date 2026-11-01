"""Tribe maps: network maps kept on the tribe (IPAM) server and shared by every NOMAD that has the tribe key.

A map is kept as items, one per device, link, host, group, position and so on, so two people changing different
things on the same map don't undo each other: each change is sent as the items it touched, and the server keeps the
latest of each (the last one sent wins when two people change the same item). Laptops keep a copy with the changes
they haven't sent yet, so maps can be looked at and changed offline and sent when the server is back.

MapStore is the server's database of them (maps.db beside the IPAM database). flatten, build, diff and merge turn
a NetworkMap into items and back.
"""
import datetime
import json
import sqlite3
import threading
from dataclasses import asdict

from .model import Device, Group, Host, Link, NetworkMap, Trace, _build, port_key

DEVICE, LINK, HOST, GROUP, GROUP_OF, POSITION, L3_POSITION, DELETED, TRACE, NEWS, HOST_SEEN, META = (
    "device", "link", "host", "group", "group_of", "position", "l3_position", "deleted", "trace", "news",
    "host_seen", "meta")
LOCKED, L3_LOCKED = "locked", "l3_locked"
LOCK_SECTIONS = (LOCKED, L3_LOCKED)  # Servers below client.LOCK_API refuse these: they wait here until it's updated
SECTIONS = (DEVICE, LINK, HOST, GROUP, GROUP_OF, POSITION, L3_POSITION, DELETED, TRACE, NEWS, HOST_SEEN, META,
            LOCKED, L3_LOCKED)
# The meta items: the map's own fields, how to crawl it (not secret), and the IPAM network it's of (an item of its
# own, so setting it doesn't touch the others)
MAP_META, SETTINGS, IPAM = "map", "settings", "ipam"
PAGE_ITEMS = 5000
LEASE_SECONDS = 180  # A watcher's claim on a map lasts this long unless renewed


class MapError(Exception):
    """A problem worth showing (no such map, a name already used...)."""


def link_id(link):
    ends = sorted(f"{device}#{port_key(port)}" for device, port in ((link.a, link.a_port), (link.b, link.b_port)))
    return "|".join(ends)


def host_id(host):
    return host.mac or f"{host.device}|{port_key(host.port)}|{host.ip}"


def _plain(value):
    """As it comes back from JSON (tuples as lists), so items compare equal before and after a round trip."""
    return json.loads(json.dumps(value))


def shared_part(section, data):
    """An item as the tribe shares it: a group without whether it's collapsed, which is each person's own (kept on
    their computer, so collapsing a group doesn't collapse it for everyone)."""
    if section == GROUP and isinstance(data, dict):
        return {name: value for name, value in data.items() if name != "collapsed"}
    return data


def flatten(network_map, settings=None):
    """{(section, key): data} for a map. settings: how it's crawled (scope, hops...), kept with it."""
    items = {(DEVICE, key): asdict(device) for key, device in network_map.devices.items()}
    items.update({(LINK, link_id(link)): asdict(link) for link in network_map.links})
    items.update({(HOST, host_id(host)): asdict(host) for host in network_map.hosts})
    items.update({(GROUP, group.key): asdict(group) for group in network_map.groups})
    items.update({(GROUP_OF, key): group for key, group in network_map.group_of.items()})
    items.update({(POSITION, key): list(position) for key, position in network_map.positions.items()})
    items.update({(L3_POSITION, key): list(position) for key, position in network_map.l3_positions.items()})
    items.update({(LOCKED, key): True for key in network_map.locked})
    items.update({(L3_LOCKED, key): True for key in network_map.l3_locked})
    items.update({(DELETED, key): list(value) for key, value in network_map.deleted.items()})
    items.update({(TRACE, trace.target): asdict(trace) for trace in network_map.traces})
    items.update({(NEWS, ref): dict(value) for ref, value in network_map.news.items()})
    items.update({(HOST_SEEN, mac): day for mac, day in network_map.host_seen.items()})
    items[(META, MAP_META)] = {"seeds": list(network_map.seeds), "started": network_map.started,
                               "finished": network_map.finished, "stopped": network_map.stopped,
                               "root": network_map.root}
    if network_map.ipam_network:
        items[(META, IPAM)] = {"network": network_map.ipam_network}
    if settings is not None:
        items[(META, SETTINGS)] = dict(settings)
    return {key: shared_part(key[0], _plain(value)) for key, value in items.items()}


def build(items):
    """A NetworkMap from {(section, key): data}. Items it can't make sense of are left out."""
    sections = {section: {} for section in SECTIONS}
    for (section, key), data in items.items():
        if section in sections and data is not None:
            sections[section][key] = data
    meta = sections[META].get(MAP_META, {})
    network_map = NetworkMap(seeds=list(meta.get("seeds", [])), started=meta.get("started", ""),
                             finished=meta.get("finished", ""), stopped=bool(meta.get("stopped")),
                             root=meta.get("root", ""),
                             ipam_network=str((sections[META].get(IPAM) or {}).get("network", "")))
    network_map.devices = {key: _build(Device, data) for key, data in sorted(sections[DEVICE].items())}
    devices = network_map.devices
    network_map.links = [_build(Link, data) for _, data in sorted(sections[LINK].items())
                         if data.get("a") in devices and data.get("b") in devices]
    hosts = [_build(Host, data) for data in sections[HOST].values() if data.get("device") in devices]
    from .model import port_sort_key
    hosts.sort(key=lambda host: (devices[host.device].label.lower(), port_sort_key(host.port), host.mac))
    network_map.hosts = hosts
    network_map.groups = [_build(Group, shared_part(GROUP, data)) for _, data in sorted(sections[GROUP].items())]
    network_map.group_of = dict(sections[GROUP_OF])
    network_map.positions = {key: tuple(value) for key, value in sections[POSITION].items() if key in devices}
    network_map.l3_positions = {key: tuple(value) for key, value in sections[L3_POSITION].items()}
    network_map.locked = sorted(key for key in sections[LOCKED] if key in devices)
    network_map.l3_locked = sorted(sections[L3_LOCKED])
    network_map.deleted ={key: [value[0], list(value[1])] for key, value in sections[DELETED].items()}
    network_map.traces = [_build(Trace, data) for _, data in sorted(sections[TRACE].items())]
    network_map.news = {ref: dict(value) for ref, value in sections[NEWS].items()}
    network_map.host_seen = dict(sections[HOST_SEEN])
    if network_map.root not in devices:
        network_map.root = ""
    network_map.prune_groups()
    return network_map


def settings_of(items):
    return dict(items.get((META, SETTINGS)) or {})


def diff(base, current):
    """What changed from base to current, as changes to send: [{"section", "key", "data"}], with "data": None for
    an item that's gone."""
    changes = [{"section": section, "key": key, "data": data} for (section, key), data in current.items()
               if base.get((section, key)) != data]
    changes += [{"section": section, "key": key, "data": None} for (section, key) in base
                if (section, key) not in current]
    return changes


def merge(local, base, incoming):
    """Bring others' changes (incoming: {(section, key): data or None}) into this copy. Items changed here since
    base keep this copy's change (it's sent afterwards and wins, being the later one). Returns (merged, new base)."""
    mine = {(change["section"], change["key"]) for change in diff(base, local)}
    merged, new_base = dict(local), dict(base)
    for key, data in incoming.items():
        if data is None:
            new_base.pop(key, None)
        else:
            new_base[key] = data
        if key in mine:
            continue
        if data is None:
            merged.pop(key, None)
        else:
            merged[key] = data
    return merged, new_base


def now_text():
    return datetime.datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------- The server's store

SCHEMA = """
CREATE TABLE IF NOT EXISTS maps (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_by TEXT, created TEXT,
                                 deleted INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS items (map_id INTEGER NOT NULL, section TEXT NOT NULL, key TEXT NOT NULL, data TEXT,
                                  revision INTEGER NOT NULL, updated_by TEXT, updated TEXT,
                                  PRIMARY KEY (map_id, section, key));
CREATE INDEX IF NOT EXISTS items_revision ON items (revision);
CREATE TABLE IF NOT EXISTS secrets (map_id INTEGER PRIMARY KEY, data TEXT NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS leases (map_id INTEGER PRIMARY KEY, holder TEXT NOT NULL, computer TEXT, kind TEXT,
                                   expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS meta (name TEXT PRIMARY KEY, value TEXT);
"""


class MapStore:
    """The tribe's maps. Use under self.lock from the server's request threads."""

    def __init__(self, path, protect=None, unprotect=None):
        """protect/unprotect: how community strings are kept at rest (Windows DPAPI on the server)."""
        self.path = str(path)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()
        self.protect = protect or (lambda text: text)
        self.unprotect = unprotect or (lambda text: text)

    def close(self):
        self.db.close()

    def revision(self):
        row = self.db.execute("SELECT value FROM meta WHERE name = 'revision'").fetchone()
        return int(row["value"]) if row else 0

    def _next_revision(self):
        revision = self.revision() + 1
        self.db.execute("INSERT OR REPLACE INTO meta (name, value) VALUES ('revision', ?)", (str(revision),))
        return revision

    def maps(self, deleted=False):
        rows = self.db.execute("SELECT * FROM maps" + ("" if deleted else " WHERE deleted = 0") + " ORDER BY name")
        return [dict(row) for row in rows]

    def _map(self, map_id):
        row = self.db.execute("SELECT * FROM maps WHERE id = ? AND deleted = 0", (int(map_id),)).fetchone()
        if row is None:
            raise MapError("That map isn't on the server any more (someone deleted it).")
        return dict(row)

    def _name_free(self, name, map_id=None):
        name = name.strip()
        if not name:
            raise MapError("Give the map a name.")
        for item in self.maps():
            if item["name"].lower() == name.lower() and item["id"] != map_id:
                raise MapError(f"There's already a tribe map called {item['name']}.")
        return name

    def create(self, name, user, items=(), secrets=None):
        """A new map, with its first items ([{"section", "key", "data"}]). Returns (map id, revision)."""
        with self.db:
            name = self._name_free(name)
            revision = self._next_revision()
            cursor = self.db.execute("INSERT INTO maps (name, created_by, created, revision) VALUES (?, ?, ?, ?)",
                                     (name, user, now_text(), revision))
            map_id = cursor.lastrowid
            self._write(map_id, items, user, revision)
            if secrets is not None:
                self._set_secrets(map_id, secrets, revision)
        return map_id, revision

    def rename(self, map_id, name):
        with self.db:
            self._map(map_id)
            name = self._name_free(name, int(map_id))
            revision = self._next_revision()
            self.db.execute("UPDATE maps SET name = ?, revision = ? WHERE id = ?", (name, revision, int(map_id)))
        return revision

    def delete(self, map_id):
        with self.db:
            self._map(map_id)
            revision = self._next_revision()
            self.db.execute("UPDATE maps SET deleted = 1, revision = ? WHERE id = ?", (revision, int(map_id)))
            self.db.execute("DELETE FROM items WHERE map_id = ?", (int(map_id),))
            self.db.execute("DELETE FROM secrets WHERE map_id = ?", (int(map_id),))
            self.db.execute("DELETE FROM leases WHERE map_id = ?", (int(map_id),))
        return revision

    def push(self, map_id, changes, user):
        """Keep a laptop's changes ([{"section", "key", "data" (None: gone)}]), the latest of each item winning.
        Returns the revision they're in."""
        with self.db:
            self._map(map_id)
            if not changes:
                return self.revision()
            revision = self._next_revision()
            self._write(int(map_id), changes, user, revision)
        return revision

    def _write(self, map_id, changes, user, revision):
        when = now_text()
        rows = []
        for change in changes:
            section, key = change["section"], str(change["key"])
            if section not in SECTIONS:
                raise MapError(f"Unknown part of a map: {section!r}.")
            data = change.get("data")
            rows.append((map_id, section, key, None if data is None else json.dumps(data), revision, user, when))
        self.db.executemany("INSERT OR REPLACE INTO items (map_id, section, key, data, revision, updated_by, updated) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

    def changes_since(self, since, limit=PAGE_ITEMS):
        """Maps and items changed after revision since: ({"maps": [...], "items": [...]}, revision, more). A page
        never splits one revision's items, so the next page can start from the revision returned."""
        since = int(since)
        maps = [dict(row) for row in self.db.execute("SELECT * FROM maps WHERE revision > ? ORDER BY revision",
                                                      (since,))]
        rows = self.db.execute("SELECT * FROM items WHERE revision > ? ORDER BY revision LIMIT ?",
                               (since, limit + 1)).fetchall()
        more = len(rows) > limit
        if more:
            last = rows[limit]["revision"]
            if rows[0]["revision"] == last:  # One revision bigger than a page: send it all
                rows = self.db.execute("SELECT * FROM items WHERE revision = ?", (last,)).fetchall()
                more = self.db.execute("SELECT 1 FROM items WHERE revision > ? LIMIT 1", (last,)).fetchone() is not None
            else:
                rows = [row for row in rows[:limit] if row["revision"] < last]
        revision = rows[-1]["revision"] if more else self.revision()
        maps = [item for item in maps if item["revision"] <= revision]
        items = [{"map_id": row["map_id"], "section": row["section"], "key": row["key"],
                  "data": None if row["data"] is None else json.loads(row["data"]), "revision": row["revision"],
                  "updated_by": row["updated_by"]} for row in rows]
        return {"maps": maps, "items": items}, revision, more

    def items(self, map_id):
        """{(section, key): data} of one map, as it is now."""
        rows = self.db.execute("SELECT section, key, data FROM items WHERE map_id = ? AND data IS NOT NULL",
                               (int(map_id),))
        return {(row["section"], row["key"]): json.loads(row["data"]) for row in rows}

    # ----------------------------------------------------------------- Community strings

    def _set_secrets(self, map_id, secrets, revision):
        self.db.execute("INSERT OR REPLACE INTO secrets (map_id, data, revision) VALUES (?, ?, ?)",
                        (int(map_id), self.protect(json.dumps(secrets)), revision))

    def set_secrets(self, map_id, secrets):
        """The map's community strings ({"communities": [...], "overrides": [[subnet, community]]})."""
        with self.db:
            self._map(map_id)
            revision = self._next_revision()
            self._set_secrets(map_id, secrets, revision)
            self.db.execute("UPDATE maps SET revision = ? WHERE id = ?", (revision, int(map_id)))
        return revision

    def secrets(self, map_id):
        self._map(map_id)
        row = self.db.execute("SELECT data FROM secrets WHERE map_id = ?", (int(map_id),)).fetchone()
        return json.loads(self.unprotect(row["data"])) if row else {}

    # ----------------------------------------------------------------- Who's watching

    def lease(self, map_id, holder, computer, kind, now, release=False, take=False):
        """Claim (or renew, or with release give up) the watching of a map. A claim held by someone else is kept
        until it runs out, unless take (a service takes over from NOMAD left open somewhere). Returns the lease
        as it is now: {"holder", "computer", "kind", "expires", "yours"} or {} when nobody holds it."""
        with self.db:
            self._map(map_id)
            row = self.db.execute("SELECT * FROM leases WHERE map_id = ?", (int(map_id),)).fetchone()
            current = dict(row) if row and row["expires"] > now else None
            mine = current is not None and current["holder"] == holder
            if release:
                if mine:
                    self.db.execute("DELETE FROM leases WHERE map_id = ?", (int(map_id),))
                return {}
            if current is None or mine or (take and current.get("kind") != "service"):
                current = {"map_id": int(map_id), "holder": holder, "computer": computer, "kind": kind,
                           "expires": now + LEASE_SECONDS}
                self.db.execute("INSERT OR REPLACE INTO leases (map_id, holder, computer, kind, expires) "
                                "VALUES (:map_id, :holder, :computer, :kind, :expires)", current)
            return {"holder": current["holder"], "computer": current["computer"], "kind": current["kind"],
                    "expires": current["expires"], "yours": current["holder"] == holder}

    def leases(self, now):
        rows = self.db.execute("SELECT * FROM leases WHERE expires > ?", (now,))
        return {row["map_id"]: {"holder": row["holder"], "computer": row["computer"], "kind": row["kind"],
                                "expires": row["expires"]} for row in rows}

    def backup(self, path):
        target = sqlite3.connect(str(path))
        try:
            self.db.backup(target)
        finally:
            target.close()
