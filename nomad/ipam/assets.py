"""Assets: the hardware on the network (switch, router and firewall chassis, access points, phones, servers, and the
modules, power supplies, fans and transceivers in them), kept in the IPAM database beside the networks and VLANs.

An asset is known by its serial number, which never changes: its hostname, address and software version are what it
has now, and the history (the store's change log) says what they were. One whose serial can't be read (a phone, or a
lab image) is known by its MAC address, or by the network map device it is. Nothing here touches the networks,
subnets or addresses.

AssetStore works on an IpamStore: this computer's database, the server's, or a laptop's copy of the server's. On a
laptop, TeamAssetStore (asset_team.py) sends changes to the server, or keeps changes made offline as pending, as
VLANs are.
"""
import datetime
import json
import re
import uuid

from ..oui import format_mac, normalize_mac
from .store import Asset, IpamError, _from_row, serial_key

IN_SERVICE, SPARE, REPAIR, REPLACED, RETIRED = "in_service", "spare", "repair", "replaced", "retired"
STATUSES = {IN_SERVICE: "In service", SPARE: "Spare", REPAIR: "In repair (RMA)", REPLACED: "Replaced",
            RETIRED: "Retired"}
OUT_OF_SERVICE = {SPARE, REPAIR, REPLACED, RETIRED}  # Not expected on the network
# Kinds: the map's for whole devices, and parts' (netmap.hardware's part classes)
SWITCH, ROUTER, FIREWALL, AP, PHONE, SERVER, HOST, UNKNOWN = "switch", "router", "firewall", "ap", "phone", \
    "server", "host", "unknown"
WLC = "wlc"  # A wireless controller (tribe servers below client.WLC_API don't know it: sent to them as UNKNOWN)
MODULE, POWER, FAN, TRANSCEIVER = "module", "power supply", "fan", "transceiver"
DEVICE_KINDS = {SWITCH: "Switch", ROUTER: "Router", FIREWALL: "Firewall", WLC: "Wireless controller",
                AP: "Access point", PHONE: "Phone", SERVER: "Server", HOST: "Computer", UNKNOWN: "Other"}
PART_KINDS = {MODULE: "Module", POWER: "Power supply", FAN: "Fan", TRANSCEIVER: "Transceiver"}
KINDS = dict(DEVICE_KINDS, **PART_KINDS)
TEXT_FIELDS = ("serial", "kind", "model", "maker", "hostname", "software", "mgmt_ip", "mac", "parent_id", "slot",
               "map_device", "location", "status", "asset_tag", "owner", "purchased", "warranty_end", "eol",
               "replaced_by", "first_seen", "last_seen", "seen_by", "description")
SEEN_FIELDS = {"first_seen", "last_seen", "seen_by"}  # Noted on every import: not history worth showing alone
SET_ASSET, DELETE_ASSET = "set_asset", "delete_asset"
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ASSET_PENDING_SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_pending (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL, action TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}', expected_version INTEGER, original TEXT, made TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending', error TEXT NOT NULL DEFAULT '');
"""


def is_part(kind):
    return kind in PART_KINDS


def today():
    return datetime.date.today().isoformat()


def clean_values(values):
    """Values for an asset as kept: text trimmed, the serial in capitals without spaces, the MAC written as NOMAD
    writes MACs, dates checked. Raises IpamError naming a bad one."""
    cleaned = {}
    for name, value in values.items():
        if name == "fields":
            cleaned[name] = dict(value or {})
            continue
        if name not in TEXT_FIELDS:
            raise IpamError(f"An asset has no {name}.")
        value = str(value if value is not None else "").strip()
        if name == "serial":
            value = serial_key(value)
        elif name == "mac" and value:
            normalized = normalize_mac(value)
            if len(normalized) != 12:
                raise IpamError(f"{value!r} isn't a MAC address.")
            value = format_mac(normalized)
        elif name == "status" and value not in STATUSES:
            raise IpamError(f"Unknown asset status {value!r}.")
        elif name == "kind" and value not in KINDS:
            raise IpamError(f"Unknown kind of asset {value!r}.")
        elif name in ("purchased", "warranty_end", "eol") and value and not DATE.match(value):
            raise IpamError(f"Write dates like {today()} ({value!r} isn't one).")
        cleaned[name] = value
    return cleaned


def label(asset):
    """How an asset is named in messages: its hostname (and slot), else its model and serial."""
    if asset.hostname:
        return asset.hostname + (f" {asset.slot}" if asset.slot else "")
    return " ".join(part for part in (asset.model, asset.serial or asset.mac) if part) or "an asset"


class AssetStore:
    """Assets in an IpamStore. Changes go through the store's change log (so they sync and have history like
    everything else in it)."""

    def __init__(self, store):
        self.store = store

    @property
    def db(self):
        return self.store.db

    @property
    def user(self):
        return self.store.user

    @staticmethod
    def _asset(row):
        return _from_row(Asset, row)

    def assets(self):
        rows = self.db.execute("SELECT * FROM assets WHERE deleted = 0 ORDER BY hostname COLLATE NOCASE, slot, "
                               "sort_key")
        return [self._asset(row) for row in rows]

    def asset(self, asset_id):
        return self.store._get("assets", asset_id)

    def find(self, asset_id):
        """The asset, or None (deleted, or never here)."""
        row = self.db.execute("SELECT * FROM assets WHERE id = ? AND deleted = 0", (asset_id,)).fetchone()
        return None if row is None else self._asset(row)

    def by_serial(self, serial):
        key = serial_key(serial)
        if not key:
            return None
        row = self.db.execute("SELECT * FROM assets WHERE sort_key = ? AND deleted = 0", (key,)).fetchone()
        return None if row is None else self._asset(row)

    def parts_of(self, asset_id):
        rows = self.db.execute("SELECT * FROM assets WHERE parent_id = ? AND deleted = 0 ORDER BY kind, slot, sort_key",
                               (asset_id,))
        return [self._asset(row) for row in rows]

    def count(self):
        return self.db.execute("SELECT COUNT(*) FROM assets WHERE deleted = 0").fetchone()[0]

    def _check_serial(self, serial, asset_id):
        if not serial:
            return
        other = self.by_serial(serial)
        if other is not None and other.id != asset_id:
            raise IpamError(f"Serial number {serial} is already recorded, as {label(other)}.")

    def set_asset(self, asset_id=None, **values):
        """Record an asset: a new one (asset_id None, or an id not used yet, as one made offline has), or changes to
        one (only the values given change). Returns the Asset."""
        values = clean_values(values)
        with self.store.transaction():
            existing = self.find(asset_id) if asset_id else None
            if existing is None:
                if asset_id and self.db.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone():
                    raise IpamError("That asset was deleted (perhaps by someone else).")
                self._check_serial(values.get("serial", ""), None)
                item = Asset(asset_id or uuid.uuid4().hex, **values)
                return self.store._insert("assets", item)
            self._check_serial(values.get("serial", existing.serial), existing.id)
            return self.store._update("assets", existing, values)

    def set_assets(self, items):
        """Record several at once ([{"id" (or None), **values}]), all or none. Returns the Assets."""
        with self.store.transaction():
            return [self.set_asset(item.get("id"), **{name: value for name, value in item.items()
                                                      if name not in ("id", "expected_version")})
                    for item in items]

    def delete_asset(self, asset_id):
        with self.store.transaction():
            existing = self.find(asset_id)
            if existing is not None:
                self.store._delete("assets", existing)

    def deleted_serials(self):
        """Serial numbers of assets deleted (and not recorded again): removed on purpose, so bringing in a network map
        doesn't offer them as though they were new without saying so."""
        rows = self.db.execute("SELECT sort_key FROM assets AS old WHERE deleted = 1 AND sort_key != '' AND NOT EXISTS "
                               "(SELECT 1 FROM assets WHERE sort_key = old.sort_key AND deleted = 0)")
        return {row[0] for row in rows}

    def search(self, text, limit=500):
        """Assets with the text in any of their columns."""
        like = f"%{text.strip().lower()}%"
        columns = " OR ".join(f"lower({name}) LIKE ?" for name in TEXT_FIELDS + ("fields",))
        rows = self.db.execute(f"SELECT * FROM assets WHERE deleted = 0 AND ({columns}) LIMIT ?",
                               [like] * (len(TEXT_FIELDS) + 1) + [limit])
        return [self._asset(row) for row in rows]


# --------------------------------------------------------------------- What needs looking at

NOT_SEEN_DAYS = 30  # In service and not on a map for longer than this: gone?


def problems(assets, when=None, not_seen_days=NOT_SEEN_DAYS, targets=()):
    """{asset id: [what's wrong, in words]} for the assets with something wrong: no serial number, not seen on a map
    for a while, software off its model's target (targets: SoftwareTargets) or, for a model without one, other
    software than most of its model run, a warranty or support life that has ended."""
    from .targets import compliance, describe
    when = when or today()
    try:
        cutoff = (datetime.date.fromisoformat(when) - datetime.timedelta(days=not_seen_days)).isoformat()
    except ValueError:
        cutoff = ""
    usual = {}  # Model -> {software: how many in service run it}
    for asset in assets:
        if asset.status == IN_SERVICE and asset.model and asset.software and not is_part(asset.kind):
            counts = usual.setdefault(asset.model, {})
            counts[asset.software] = counts.get(asset.software, 0) + 1
    found = {}
    for asset in assets:
        listed = []
        if not asset.serial and not is_part(asset.kind):
            listed.append("No serial number")
        if asset.status == IN_SERVICE:
            if asset.last_seen and cutoff and asset.last_seen < cutoff:
                listed.append(f"Not on a map since {asset.last_seen}")
            state, target = compliance(asset, targets)
            if target is not None:
                line = describe(state, asset.software, target)
                if line:
                    listed.append(line)
            counts = usual.get(asset.model, {})
            if target is None and asset.software and len(counts) > 1 and not is_part(asset.kind):
                common = max(counts, key=lambda version: (counts[version], version))
                if asset.software != common and counts[common] > counts.get(asset.software, 0):
                    listed.append(f"Runs {asset.software}; most {asset.model} run {common}")
            if asset.warranty_end and asset.warranty_end < when:
                listed.append(f"Warranty ended {asset.warranty_end}")
            if asset.eol and asset.eol <= when:
                listed.append(f"Past its end of life ({asset.eol})")
        if listed:
            found[asset.id] = listed
    return found


# --------------------------------------------------------------------- Pending asset changes on a laptop's copy

def keep_pending_on_top(copy, items):
    """The server's rows just replaced some assets that have changes waiting (in the copy's asset_pending): remember
    the server's row as what to go back to if the change is refused, and show the waiting change on top again."""
    arrived = {item["row"]["id"]: item["row"] for item in items if item["entity"] == "assets"}
    if not arrived:
        return
    store = AssetStore(copy)
    for entry in copy.db.execute("SELECT * FROM asset_pending WHERE state = 'pending'").fetchall():
        row = arrived.get(entry["asset_id"])
        if row is None:
            continue
        with copy.transaction():
            copy.db.execute("UPDATE asset_pending SET original = ? WHERE seq = ?",
                            (None if row["deleted"] else json.dumps(row), entry["seq"]))
            try:
                if entry["action"] == SET_ASSET and not row["deleted"]:
                    store.set_asset(entry["asset_id"], **json.loads(entry["data"]))
                elif entry["action"] == DELETE_ASSET:
                    store.delete_asset(entry["asset_id"])
            except IpamError:
                pass  # Its serial is someone else's asset now: the server will refuse it


# --------------------------------------------------------------------- History

def asset_history(store, asset_id, include_seen=False):
    """Everything that happened to an asset, newest first, as history.Events. Changes that only noted when a map saw
    it are left out unless include_seen. store: an IpamStore, or a TeamStore (whose copy keeps the history)."""
    from .history import _events_for, source_of
    db, table = source_of(store)
    events = _events_for(db, table, [asset_id])
    if not include_seen:
        events = [event for event in events if event.op != "update" or set(changed_fields(event)) - SEEN_FIELDS]
    return list(reversed(events))


def changed_fields(event):
    return [name for name in event.after if event.after.get(name) != event.before.get(name)]


def all_asset_history(store, since=None):
    """Every change to any asset (and to the software targets), newest first (seen-only changes left out): the Assets
    page's Changes view."""
    from .history import replay, source_of
    db, table = source_of(store)
    rows = db.execute(f"SELECT seq, entity, entity_id, op, data, modified, modified_by FROM {table} WHERE entity IN "
                      "('assets', 'software_targets') ORDER BY seq").fetchall()
    events = [event for event in replay(rows) if event.op != "update" or set(changed_fields(event)) - SEEN_FIELDS]
    if since:
        events = [event for event in events if event.when >= since]
    return list(reversed(events))
