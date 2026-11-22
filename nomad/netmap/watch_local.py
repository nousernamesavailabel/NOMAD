"""Maps on this computer that the Map Watcher monitors: maps not shared with the tribe.

An administrator gives one to the Watcher in Tools > Map Watcher Service. A copy of the map goes in the Watcher's
folder (local-maps\\<its record ID>.nomadmap), with the SNMP credentials NOMAD uses for it encrypted for this computer
in the Watcher's config, and Update Copies there copies them again after the map changes. The Watcher monitors them
like the tribe's maps (for the NOMAD Dashboard, and for NOMAD's own map on this computer), without the tribe: it
doesn't watch them for new devices, which would change a file it can't write back to.

They go by negative map IDs (-1, -2...) wherever the tribe's maps go by theirs, so the two never mix.
"""
import json
import logging
import uuid
from pathlib import Path

from . import store

log = logging.getLogger(__name__)

FOLDER = "local-maps"


def ensure_record_id(network_map):
    """The map's record ID (what its monitoring record goes by), made the first time it's asked for. Returns
    (record ID, whether it was just made, so the map wants saving)."""
    if network_map.record_id:
        return network_map.record_id, False
    network_map.record_id = uuid.uuid4().hex
    return network_map.record_id, True


def entries(config):
    """The config's local maps: [{"id", "record_id", "name", "path", "secrets"}]."""
    return [dict(entry) for entry in (config or {}).get("local_maps", []) if isinstance(entry, dict)
            and entry.get("record_id") and isinstance(entry.get("id"), int) and entry["id"] < 0]


def add(config, directory, network_map, name, path, secrets, protect):
    """Give the Watcher a copy of a map (or a newer copy of one it has): into its folder, and into config (changed
    here; the caller saves it). secrets: the SNMP credentials as NOMAD keeps them for maps (credentials JSON).
    Returns the map's entry."""
    record_id = network_map.record_id
    if not record_id:
        raise ValueError("The map has no record ID yet: save it in NOMAD first.")
    folder = Path(directory) / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    store.save(network_map, folder / f"{record_id}{store.EXTENSION}")
    local = config.setdefault("local_maps", [])
    entry = next((item for item in local if item.get("record_id") == record_id), None)
    if entry is None:
        entry = {"id": min([-1] + [item["id"] - 1 for item in local if isinstance(item.get("id"), int)]),
                 "record_id": record_id}
        local.append(entry)
    entry.update(name=name, path=str(path or ""), secrets=protect(json.dumps(secrets or {})))
    return entry


def remove_others(config, directory):
    """Delete the copies of maps the config no longer has."""
    keep = {entry["record_id"] for entry in entries(config)}
    for path in (Path(directory) / FOLDER).glob(f"*{store.EXTENSION}"):
        if path.stem not in keep:
            try:
                path.unlink()
            except OSError:
                pass


class LocalMaps:
    """The local maps the Watcher monitors, read from its folder (again when the copy changes)."""

    def __init__(self, directory, config, unprotect=None):
        self.directory = Path(directory)
        self.entries = {entry["id"]: entry for entry in entries(config)}
        self.unprotect = unprotect
        self.cache = {}  # id -> (file's modified time, NetworkMap)

    def ids(self):
        return list(self.entries)

    def path(self, map_id):
        return self.directory / FOLDER / f"{self.entries[map_id]['record_id']}{store.EXTENSION}"

    def map_info(self, map_id):
        entry = self.entries.get(map_id)
        if entry is None or not self.path(map_id).exists():
            return None
        return {"id": map_id, "name": entry.get("name") or "Map", "record_id": entry["record_id"]}

    def load(self, map_id):
        path = self.path(map_id)
        modified = path.stat().st_mtime
        cached = self.cache.get(map_id)
        if cached is None or cached[0] != modified:
            cached = (modified, store.load(path))
            self.cache[map_id] = cached
        return cached[1], {}

    def secrets(self, map_id):
        text = self.entries.get(map_id, {}).get("secrets") or ""
        if not text:
            return {}
        try:
            unprotect = self.unprotect
            if unprotect is None:
                from ..terminal.credentials import unprotect
            return json.loads(unprotect(text))
        except Exception as error:  # Encrypted on another computer, or damaged
            log.warning("Couldn't read the SNMP credentials of %s: %s", self.entries[map_id].get("name"), error)
            return {}


class CombinedMaps:
    """The tribe's maps (TribeMaps, or None without a tribe) and the local ones, as one, for the monitoring."""

    def __init__(self, tribe, local):
        self.tribe, self.local = tribe, local

    def sync(self):
        if self.tribe is not None:
            self.tribe.sync()

    def map_info(self, map_id):
        if map_id < 0:
            return self.local.map_info(map_id)
        return self.tribe.map_info(map_id) if self.tribe is not None else None

    def load(self, map_id):
        return self.local.load(map_id) if map_id < 0 else self.tribe.load(map_id)

    def secrets(self, map_id):
        return self.local.secrets(map_id) if map_id < 0 else self.tribe.secrets(map_id)

    def fetch_secrets(self, map_id):
        return self.local.secrets(map_id) if map_id < 0 else self.tribe.fetch_secrets(map_id)

    def __getattr__(self, name):  # Everything else (save, lease, send_pending...) is the tribe's
        if self.tribe is None:
            raise AttributeError(name)
        return getattr(self.tribe, name)
