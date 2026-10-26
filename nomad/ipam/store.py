"""The IPAM database: networks, subnets and addresses in SQLite.

Each network is separate (such as an air-gapped network), so the same ranges can appear in more than one. Within a
network a subnet's CIDR is unique; an address written with a mask stands for the subnet holding it (172.28.101.0/16
is 172.28.0.0/16). A loopback subnet is a pool of host routes (loopback addresses, each a /32 of its own), so it
has no network, broadcast or gateway address. Subnets may nest (a /20 block holding /24s), and an address belongs to the most specific subnet
containing it. Only addresses in use or reserved are stored; the rest of a subnet is free.

Sweeps are remembered too (when each address last answered, and which ranges were swept when), in tables of their
own: they aren't changes to the records, so they stay out of the change log and history, and sync by their own
sequence numbers (sightings_since).

VLANs are kept here too (vlan_domains and vlans, see vlans.py), beside the networks rather than in them: they use
the same change log, sync and backups, but nothing about a network, subnet or address changes when VLANs do. A VLAN
names the subnets it carries by CIDR, in its domain's network. So are assets (the hardware on the network, see
assets.py): one row per chassis, phone, server or part, unique by serial number; and the software each model
should run (software targets, see targets.py), unique by model.

Rows are never removed: deleting marks them deleted (a tombstone) and every change bumps the row's version and is
written to the change log. On the NOMAD server, the change log's sequence numbers are the revisions clients sync by
(changes_since); a client's copy of the team's data is an IpamStore filled by apply_rows, without a change log of
its own.
"""
import contextlib
import datetime
import getpass
import ipaddress
import json
import logging
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field

from ..system import app_data_dir

log = logging.getLogger(__name__)

FILE_NAME = "ipam.db"
SCHEMA_VERSION = 7  # 2 added subnets.loopbacks, 3 the VLAN tables, 4 subnet placement (overrides and moves),
# 5 subnet roles, 6 assets, 7 software targets
USED, RESERVED = "used", "reserved"
ANYWHERE, VALUE, NAME, DESCRIPTION, MAC = "anywhere", "value", "name", "description", "mac"  # Where search looks
STATUSES = {USED: "Used", RESERVED: "Reserved"}
MAX_NEXT_FREE_SCAN = 1 << 20  # Stop looking for a free address after this many (a /12's worth)
TABLES = ("networks", "subnets", "addresses", "vlan_domains", "vlans", "placements", "subnet_moves", "subnet_roles",
          "assets", "software_targets")
# Unique by sort_key within
PARENTS = {"subnets": "network_id", "addresses": "network_id", "vlans": "domain_id", "placements": "network_id",
           "subnet_roles": "network_id"}
# Unique by sort_key across the whole table (when it has one): an asset's serial number, a software target's model
UNIQUE_KEYS = ("assets", "software_targets")
JSON_COLUMNS = ("fields", "subnets", "ranges")

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS networks (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS subnets (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL, sort_key TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '', gateway TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
    fields TEXT NOT NULL DEFAULT '{}', loopbacks INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS subnets_unique ON subnets (network_id, sort_key) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS addresses (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, ip TEXT NOT NULL, sort_key TEXT NOT NULL,
    status TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', mac TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS addresses_unique ON addresses (network_id, sort_key) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS changes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT NOT NULL, entity_id TEXT NOT NULL, version INTEGER NOT NULL,
    op TEXT NOT NULL, data TEXT NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL,
    pushed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sightings (
    network_id TEXT NOT NULL, sort_key TEXT NOT NULL, ip TEXT NOT NULL, seen REAL NOT NULL, rtt INTEGER,
    mac TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', seen_by TEXT NOT NULL DEFAULT '',
    seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (network_id, sort_key));
CREATE TABLE IF NOT EXISTS sweeps (
    network_id TEXT NOT NULL, cidr TEXT NOT NULL, started REAL NOT NULL, finished REAL NOT NULL,
    swept_by TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (network_id, cidr));
CREATE TABLE IF NOT EXISTS vlan_domains (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, network_id TEXT NOT NULL DEFAULT '', vtp_domain TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '', ranges TEXT NOT NULL DEFAULT '[]', fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS vlans (
    id TEXT PRIMARY KEY, domain_id TEXT NOT NULL, vlan INTEGER NOT NULL, sort_key TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, subnets TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS vlans_unique ON vlans (domain_id, sort_key) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS placements (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL, sort_key TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'auto', one_segment INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS placements_unique ON placements (network_id, sort_key) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS subnet_moves (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL, sort_key TEXT NOT NULL,
    from_domain_id TEXT NOT NULL DEFAULT '', from_vlan INTEGER NOT NULL DEFAULT 0,
    from_device TEXT NOT NULL DEFAULT '', to_domain_id TEXT NOT NULL DEFAULT '',
    to_vlan INTEGER NOT NULL DEFAULT 0, to_device TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
    planned_for TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', finished TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS subnet_roles (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL, sort_key TEXT NOT NULL, role TEXT NOT NULL,
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS subnet_roles_unique ON subnet_roles (network_id, sort_key) WHERE deleted = 0;
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY, sort_key TEXT NOT NULL DEFAULT '', serial TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'unknown', model TEXT NOT NULL DEFAULT '', maker TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '', software TEXT NOT NULL DEFAULT '', mgmt_ip TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '', parent_id TEXT NOT NULL DEFAULT '', slot TEXT NOT NULL DEFAULT '',
    map_device TEXT NOT NULL DEFAULT '', location TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'in_service',
    asset_tag TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', purchased TEXT NOT NULL DEFAULT '',
    warranty_end TEXT NOT NULL DEFAULT '', eol TEXT NOT NULL DEFAULT '', replaced_by TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL DEFAULT '', last_seen TEXT NOT NULL DEFAULT '', seen_by TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '', fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS assets_unique ON assets (sort_key) WHERE deleted = 0 AND sort_key != '';
CREATE TABLE IF NOT EXISTS software_targets (
    id TEXT PRIMARY KEY, sort_key TEXT NOT NULL, model TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
    allowed TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS software_targets_unique ON software_targets (sort_key) WHERE deleted = 0;
CREATE INDEX IF NOT EXISTS sightings_seq ON sightings (seq);
CREATE INDEX IF NOT EXISTS sweeps_seq ON sweeps (seq);
"""


class IpamError(Exception):
    """A change that can't be made, with a message for the user."""


def vlan_key(number):
    """Sort key for a VLAN number."""
    return f"{int(number):04d}"


def model_key(model):
    """Sort key (and what makes it unique) for a software target's model: in capitals, spaces made single."""
    return " ".join(str(model or "").split()).upper()


def serial_key(serial):
    """Sort key (and what makes it unique) for an asset's serial number: without case or spaces; "" for none."""
    return "".join(str(serial or "").split()).upper()


def ip_key(address):
    """Text that sorts addresses numerically, IPv4 before IPv6, so ranges can be found with BETWEEN."""
    return f"{address.version}{int(address):032x}"


def subnet_key(network):
    """Sort key for a subnet: its first address, then its prefix length (a /20 before the /24s inside it)."""
    return f"{ip_key(network.network_address)}/{network.prefixlen:03d}"


class Block:
    """A subnet: ipaddress's network plus its first and last address and a sort key, which the IPAM code uses."""

    def __init__(self, network):
        self.first, self.last = network.network_address, network.broadcast_address
        self.prefixlen, self.version, self.num_addresses = network.prefixlen, network.version, network.num_addresses
        self.netmask = network.netmask

    network_address = property(lambda self: self.first)
    broadcast_address = property(lambda self: self.last)

    @property
    def sort_key(self):
        return self.version, int(self.first), self.prefixlen

    def __contains__(self, address):
        return address.version == self.version and self.first <= address <= self.last

    def subnet_of(self, other):
        return other.version == self.version and other.first <= self.first and self.last <= other.last

    def __eq__(self, other):
        return isinstance(other, Block) and (self.first, self.prefixlen) == (other.first, other.prefixlen)

    def __hash__(self):
        return hash((self.first, self.prefixlen))

    def __lt__(self, other):
        return self.sort_key < other.sort_key

    def __str__(self):
        return f"{self.first}/{self.prefixlen}"

    def __repr__(self):
        return f"Block({self})"


def _address(value, version):
    return ipaddress.IPv4Address(value) if version == 4 else ipaddress.IPv6Address(value)


def parse_address(text):
    try:
        return ipaddress.ip_address(str(text).strip())
    except ValueError:
        raise IpamError(f"{text!r} isn't an IP address.") from None


def parse_subnet(text):
    """A Block from "10.1.2.0/24", "10.1.2.0 255.255.255.0" or "10.1.2.0/255.255.255.0". An address inside the
    subnet stands for the subnet ("172.28.101.0/16" is 172.28.0.0/16)."""
    text = " ".join(str(text).split())
    if " " in text:
        text = text.replace(" ", "/", 1)
    address_text, _, mask = text.partition("/")
    try:
        address = ipaddress.ip_address(address_text)
        return Block(ipaddress.ip_network(f"{address}/{mask or address.max_prefixlen}", strict=False))
    except ValueError:
        raise IpamError(f"{text!r} isn't a subnet (use CIDR like 10.1.2.0/24).") from None


def _json_path(key):
    """The JSON path of a detail (json_extract), quoted so any name works."""
    return '$."' + key.replace('"', '\\"') + '"'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def current_user():
    try:
        return getpass.getuser()
    except Exception:  # No user name in the environment
        return "unknown"


@dataclass
class Network:
    id: str
    name: str
    description: str = ""
    fields: dict = field(default_factory=dict)
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class Subnet:
    id: str
    network_id: str
    cidr: str
    name: str = ""
    gateway: str = ""
    description: str = ""
    fields: dict = field(default_factory=dict)
    loopbacks: bool = False  # A pool of loopback addresses: each is a /32 (or /128) of its own
    version: int = 1
    modified: str = ""
    modified_by: str = ""

    @property
    def network(self):
        return parse_subnet(self.cidr)

    def special_addresses(self):
        """Addresses in the subnet that can't be handed out: {address: label}."""
        network = self.network
        special = {}
        if self.loopbacks:
            return special  # Every address is a host route of its own, including the first and last
        if network.version == 4 and network.num_addresses > 2:
            special[network.network_address] = "Network"
            special[network.broadcast_address] = "Broadcast"
        elif network.version == 6 and network.num_addresses > 2:
            special[network.network_address] = "Subnet router anycast"
        if self.gateway:
            with contextlib.suppress(ValueError):
                gateway = ipaddress.ip_address(self.gateway)
                if gateway in network:
                    special[gateway] = "Gateway"
        return special


@dataclass
class Address:
    id: str
    network_id: str
    ip: str
    status: str = USED
    name: str = ""
    mac: str = ""
    description: str = ""
    fields: dict = field(default_factory=dict)
    version: int = 1
    modified: str = ""
    modified_by: str = ""

    @property
    def address(self):
        return ipaddress.ip_address(self.ip)


@dataclass
class VlanDomain:
    """Where VLAN numbers are unique (a VTP domain, or a site's switches), optionally for one IPAM network: the
    network whose subnets its VLANs carry."""
    id: str
    name: str
    network_id: str = ""
    vtp_domain: str = ""  # The VTP domain its switches are in, for matching what a network map found
    description: str = ""
    ranges: list = field(default_factory=list)  # [{"first", "last", "name"}]: blocks set aside for a purpose
    fields: dict = field(default_factory=dict)
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class Vlan:
    id: str
    domain_id: str
    vlan: int
    name: str = ""
    status: str = "active"
    subnets: list = field(default_factory=list)  # CIDRs of the subnets it carries, in its domain's network
    description: str = ""
    fields: dict = field(default_factory=dict)
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class Placement:
    """How the Subnet Placement page treats one subnet of a network, where someone said so: advertised or local
    (over what the map's routing tables suggest), or its places one L2 segment the map can't see."""
    id: str
    network_id: str
    cidr: str
    scope: str = "auto"  # auto, advertised or local
    one_segment: bool = False
    note: str = ""
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class SubnetMove:
    """A subnet moving from one VLAN (and device) to another: planned, in progress, done or cancelled."""
    id: str
    network_id: str
    cidr: str
    from_domain_id: str = ""
    from_vlan: int = 0
    from_device: str = ""  # Network map device key, when it matters which device
    to_domain_id: str = ""
    to_vlan: int = 0
    to_device: str = ""
    status: str = "planned"
    planned_for: str = ""  # When it's to happen (free text, such as a date or change window)
    note: str = ""
    finished: str = ""  # When it was done or cancelled
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class SubnetRole:
    """What a subnet of a network is for (a VLAN, a point-to-point link, loopbacks...), where someone said so over
    what the map and IPAM suggest. Kept beside the placements, never on the subnet."""
    id: str
    network_id: str
    cidr: str
    role: str
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class Asset:
    """A piece of hardware on the network: a switch, router or firewall chassis (one per stack member), an access
    point, phone or server, or a part of one (a module, power supply, fan or transceiver, whose parent_id is the
    chassis it's in). Unique by serial number; one without (not readable, or not known yet) by its id."""
    id: str
    serial: str = ""
    kind: str = "unknown"  # The map's kinds (switch, router...), or a part's (module, power supply, fan, transceiver)
    model: str = ""
    maker: str = ""
    hostname: str = ""
    software: str = ""  # The version it runs
    mgmt_ip: str = ""
    mac: str = ""  # A phone's or server's (how one without a serial number is known again)
    parent_id: str = ""  # A part's chassis
    slot: str = ""  # Where it is in its stack or chassis ("Switch 2", "Power supply A")
    map_device: str = ""  # The network map's key of the device it is (or is in)
    location: str = ""
    status: str = "in_service"
    asset_tag: str = ""
    owner: str = ""
    purchased: str = ""  # Dates as written (YYYY-MM-DD from the dialogs)
    warranty_end: str = ""
    eol: str = ""
    replaced_by: str = ""  # The id of the asset that took its place
    first_seen: str = ""  # Dates (YYYY-MM-DD) a network map found it first and last
    last_seen: str = ""
    seen_by: str = ""  # Who brought in the map that found it last
    description: str = ""
    fields: dict = field(default_factory=dict)
    version: int = 1
    modified: str = ""
    modified_by: str = ""


@dataclass
class SoftwareTarget:
    """The software a model of hardware should run: its target version, and others that are fine too. model may have
    wildcards (C9300-*): the most exact target for a model is the one that counts."""
    id: str
    model: str
    target: str
    allowed: str = ""  # Other versions that are fine, separated by commas
    note: str = ""
    version: int = 1
    modified: str = ""
    modified_by: str = ""


ENTITIES = {"networks": Network, "subnets": Subnet, "addresses": Address, "vlan_domains": VlanDomain, "vlans": Vlan,
            "placements": Placement, "subnet_moves": SubnetMove, "subnet_roles": SubnetRole, "assets": Asset,
            "software_targets": SoftwareTarget}
EDITABLE = {
    "networks": {"name", "description", "fields"},
    "subnets": {"name", "gateway", "description", "fields", "loopbacks"},
    "addresses": {"status", "name", "mac", "description", "fields"},
    "vlan_domains": {"name", "network_id", "vtp_domain", "description", "ranges", "fields"},
    "vlans": {"name", "status", "subnets", "description", "fields"},
    "placements": {"scope", "one_segment", "note"},
    "subnet_moves": {"from_domain_id", "from_vlan", "from_device", "to_domain_id", "to_vlan", "to_device", "status",
                     "planned_for", "note", "finished"},
    "subnet_roles": {"role"},
    "assets": {"serial", "kind", "model", "maker", "hostname", "software", "mgmt_ip", "mac", "parent_id", "slot",
               "map_device", "location", "status", "asset_tag", "owner", "purchased", "warranty_end", "eol",
               "replaced_by", "first_seen", "last_seen", "seen_by", "description", "fields"},
    "software_targets": {"model", "target", "allowed", "note"},
}


def _from_row(cls, row):
    values = {name: row[name] for name in row.keys() if name in cls.__dataclass_fields__}
    for name in JSON_COLUMNS:
        if name in values:
            values[name] = json.loads(values[name] or ("{}" if name == "fields" else "[]"))
    for name in ("loopbacks", "one_segment"):
        if name in values:
            values[name] = bool(values[name])
    return cls(**values)


def default_path():
    return str(app_data_dir() / FILE_NAME)


class IpamStore:
    """An IPAM database. Use one per thread (SQLite connections aren't shared between threads), unless `shared`:
    then callers take `lock` around each use (the server does, handling requests on several threads)."""

    def __init__(self, path=None, user=None, shared=False):
        self.path = path or default_path()
        self.user = user or current_user()
        self.lock = threading.RLock()
        # Transactions are begun and ended explicitly
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=not shared)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self._depth = 0
        self.db.executescript(SCHEMA)
        self._upgrade()
        with self.transaction():
            self.db.execute("INSERT OR IGNORE INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            self.db.execute("INSERT OR IGNORE INTO meta VALUES ('replica_id', ?)", (uuid.uuid4().hex,))

    def _upgrade(self):
        """Add the columns newer versions brought to a database made by an older one."""
        columns = {row["name"] for row in self.db.execute("PRAGMA table_info(subnets)")}
        if "loopbacks" not in columns:
            self.db.execute("ALTER TABLE subnets ADD COLUMN loopbacks INTEGER NOT NULL DEFAULT 0")
        self.db.execute("UPDATE meta SET value = ? WHERE key = 'schema' AND CAST(value AS INTEGER) < ?",
                        (str(SCHEMA_VERSION), SCHEMA_VERSION))

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        """Group changes so they all happen or none do (nested uses join the outer one)."""
        if self._depth == 0:
            self.db.execute("BEGIN IMMEDIATE")
        self._depth += 1
        try:
            yield
        except BaseException:
            self._depth -= 1
            if self._depth == 0:
                self.db.execute("ROLLBACK")
            raise
        self._depth -= 1
        if self._depth == 0:
            self.db.execute("COMMIT")

    # ----------------------------------------------------------------- Writing, with the change log

    def _insert(self, table, item):
        item.version, item.modified, item.modified_by = 1, now(), self.user
        data = {name: getattr(item, name) for name in item.__dataclass_fields__}
        row = dict(data)  # Details keep the order they were given in
        for name in JSON_COLUMNS:
            if name in row:
                row[name] = json.dumps(row[name])
        if table == "subnets":
            row["sort_key"] = subnet_key(item.network)
        elif table == "addresses":
            row["sort_key"] = ip_key(item.address)
        elif table == "vlans":
            row["sort_key"] = vlan_key(item.vlan)
        elif table in ("placements", "subnet_moves", "subnet_roles"):
            row["sort_key"] = subnet_key(parse_subnet(item.cidr))
        elif table == "assets":
            row["sort_key"] = serial_key(item.serial)
        elif table == "software_targets":
            row["sort_key"] = model_key(item.model)
        names = ", ".join(row)
        self.db.execute(f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
        self._log(table, item.id, item.version, "create", data)
        return item

    def _update(self, table, item, changes):
        unknown = set(changes) - EDITABLE[table]
        if unknown:
            raise ValueError(f"Can't change {', '.join(sorted(unknown))} of {table}")
        changes = {name: value for name, value in changes.items() if getattr(item, name) != value}
        if not changes:
            return item
        for name, value in changes.items():
            setattr(item, name, value)
        item.version, item.modified, item.modified_by = item.version + 1, now(), self.user
        row = dict(changes, version=item.version, modified=item.modified, modified_by=item.modified_by)
        for name in JSON_COLUMNS:
            if name in row:
                row[name] = json.dumps(row[name])
        if table == "assets" and "serial" in changes:
            row["sort_key"] = serial_key(item.serial)
        if table == "software_targets" and "model" in changes:
            row["sort_key"] = model_key(item.model)
        assignments = ", ".join(f"{name} = ?" for name in row)
        self.db.execute(f"UPDATE {table} SET {assignments} WHERE id = ?", list(row.values()) + [item.id])
        self._log(table, item.id, item.version, "update", changes)
        return item

    def _delete(self, table, item):
        item.version, item.modified, item.modified_by = item.version + 1, now(), self.user
        self.db.execute(f"UPDATE {table} SET deleted = 1, version = ?, modified = ?, modified_by = ? WHERE id = ?",
                        (item.version, item.modified, item.modified_by, item.id))
        self._log(table, item.id, item.version, "delete", {})

    def _log(self, table, entity_id, version, op, data):
        self.db.execute("INSERT INTO changes (entity, entity_id, version, op, data, modified, modified_by) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (table, entity_id, version, op, json.dumps(data, sort_keys=True), now(), self.user))

    def _get(self, table, item_id):
        row = self.db.execute(f"SELECT * FROM {table} WHERE id = ? AND deleted = 0", (item_id,)).fetchone()
        if row is None:
            raise IpamError("It was deleted (perhaps by someone else).")
        return _from_row(ENTITIES[table], row)

    def pending_changes(self):
        """Changes made here that haven't been sent to a server yet."""
        return self.db.execute("SELECT COUNT(*) FROM changes WHERE pushed = 0").fetchone()[0]

    # ----------------------------------------------------------------- Sync

    def get_meta(self, key, default=""):
        row = self.db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return default if row is None else row[0]

    def set_meta(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, str(value)))

    def revision(self):
        """The latest change's number (0 before any change): what a fully synced copy has seen."""
        return self.db.execute("SELECT COALESCE(MAX(seq), 0) FROM changes").fetchone()[0]

    def log_since(self, revision, limit=5000):
        """The change log after `revision` (who changed what, when), oldest first, for copies to keep as history.
        Returns ([entries], the revision they reach, whether there's more)."""
        rows = self.db.execute("SELECT seq, entity, entity_id, version, op, data, modified, modified_by FROM changes "
                               "WHERE seq > ? ORDER BY seq LIMIT ?", (revision, limit + 1)).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        return [dict(row) for row in rows], (rows[-1]["seq"] if rows else revision), more

    def changes_since(self, revision, limit=5000):
        """Everything changed after `revision`, as each row's current state (deleted rows included, so copies
        remove them). Returns ([{"entity": table, "row": {column: value}}], the revision they bring a copy up to,
        whether there's more after that)."""
        changed = self.db.execute("SELECT entity, entity_id, MAX(seq) AS seq FROM changes WHERE seq > ? "
                                  "GROUP BY entity, entity_id ORDER BY seq LIMIT ?", (revision, limit + 1)).fetchall()
        more = len(changed) > limit
        changed = changed[:limit]
        items = []
        for change in changed:
            row = self.db.execute(f"SELECT * FROM {change['entity']} WHERE id = ?", (change["entity_id"],)).fetchone()
            if row is not None and change["entity"] in TABLES:
                items.append({"entity": change["entity"], "row": dict(row)})
        return items, (changed[-1]["seq"] if changed else revision), more

    def apply_rows(self, items):
        """Bring a copy of the server's data up to date with rows from changes_since (in the order given)."""
        with self.transaction():
            for item in items:
                table, row = item["entity"], item["row"]
                if table not in TABLES:
                    continue
                parent = PARENTS.get(table)
                if parent is not None and not row.get("deleted"):
                    # An older row here may still hold the same address, subnet or VLAN: the server's word wins
                    self.db.execute(f"UPDATE {table} SET deleted = 1 WHERE {parent} = ? AND sort_key = ? AND "
                                    "deleted = 0 AND id != ?", (row[parent], row["sort_key"], row["id"]))
                elif table in UNIQUE_KEYS and row.get("sort_key") and not row.get("deleted"):
                    self.db.execute(f"UPDATE {table} SET deleted = 1 WHERE sort_key = ? AND deleted = 0 AND id != ?",
                                    (row["sort_key"], row["id"]))
                names = ", ".join(row)
                self.db.execute(f"INSERT OR REPLACE INTO {table} ({names}) VALUES ({', '.join('?' * len(row))})",
                                list(row.values()))

    def row_of(self, table, item_id):
        """A row as changes_since sends it, for replying to an edit."""
        row = self.db.execute(f"SELECT * FROM {table} WHERE id = ?", (item_id,)).fetchone()
        return None if row is None else {"entity": table, "row": dict(row)}

    def import_networks(self, plans):
        """Import prepared networks (spreadsheet.import_plan) all at once. Returns the networks."""
        imported = []
        with self.transaction():
            for plan in plans:
                fields = dict(plan["fields"])
                existing = self.network_named(plan["name"])
                if existing is not None and plan.get("replace"):
                    self.clear_network(existing.id)
                    network = self.update_network(existing.id, fields=fields)
                else:
                    network = self.add_network(plan["name"], fields=fields)
                for subnet in plan["subnets"]:
                    self.add_subnet(network.id, subnet["cidr"], subnet["name"], subnet["gateway"],
                                    subnet["description"], subnet["fields"], subnet.get("loopbacks", False))
                for address in plan["addresses"]:
                    self.set_address(network.id, address["ip"], address["status"], address["name"])
                imported.append(network)
        return imported

    # ----------------------------------------------------------------- Networks

    def networks(self):
        rows = self.db.execute("SELECT * FROM networks WHERE deleted = 0 ORDER BY name COLLATE NOCASE")
        return [_from_row(Network, row) for row in rows]

    def network(self, network_id):
        return self._get("networks", network_id)

    def network_named(self, name):
        row = self.db.execute("SELECT * FROM networks WHERE deleted = 0 AND name = ? COLLATE NOCASE",
                              (name.strip(),)).fetchone()
        return None if row is None else _from_row(Network, row)

    def _check_network_name(self, name, network_id=None):
        name = name.strip()
        if not name:
            raise IpamError("Give the network a name.")
        existing = self.network_named(name)
        if existing is not None and existing.id != network_id:
            raise IpamError(f"There's already a network called {existing.name}.")
        return name

    def add_network(self, name, description="", fields=None):
        name = self._check_network_name(name)
        with self.transaction():
            return self._insert("networks", Network(uuid.uuid4().hex, name, description, dict(fields or {})))

    def update_network(self, network_id, **changes):
        with self.transaction():
            network = self.network(network_id)
            if "name" in changes:
                changes["name"] = self._check_network_name(changes["name"], network_id)
            return self._update("networks", network, changes)

    def delete_network(self, network_id):
        """Delete a network with all its subnets and addresses."""
        with self.transaction():
            network = self.network(network_id)
            self.clear_network(network_id)
            self._delete("networks", network)

    def clear_network(self, network_id):
        """Delete every subnet and address in a network, keeping the network (before importing over it)."""
        with self.transaction():
            for subnet in self.subnets(network_id):
                self._delete("subnets", subnet)
            for address in self.addresses(network_id):
                self._delete("addresses", address)

    # ----------------------------------------------------------------- Subnets

    def subnets(self, network_id):
        """The network's subnets, in address order (a containing block before the subnets inside it)."""
        rows = self.db.execute("SELECT * FROM subnets WHERE network_id = ? AND deleted = 0 ORDER BY sort_key",
                               (network_id,))
        return [_from_row(Subnet, row) for row in rows]

    def subnet(self, subnet_id):
        return self._get("subnets", subnet_id)

    def add_subnet(self, network_id, cidr, name="", gateway="", description="", fields=None, loopbacks=False):
        network = parse_subnet(cidr)
        gateway = self._check_gateway(gateway, network, loopbacks)
        with self.transaction():
            self.network(network_id)
            existing = self.db.execute("SELECT name FROM subnets WHERE network_id = ? AND sort_key = ? AND deleted = 0",
                                       (network_id, subnet_key(network))).fetchone()
            if existing is not None:
                raise IpamError(f"{network} is already in this network ({existing['name'] or 'no name'}).")
            return self._insert("subnets", Subnet(uuid.uuid4().hex, network_id, str(network), name.strip(), gateway,
                                                  description, dict(fields or {}), bool(loopbacks)))

    def update_subnet(self, subnet_id, **changes):
        with self.transaction():
            subnet = self.subnet(subnet_id)
            if "loopbacks" in changes:
                changes["loopbacks"] = bool(changes["loopbacks"])
                if changes["loopbacks"]:
                    changes.setdefault("gateway", "")  # A pool of loopbacks has no gateway
            loopbacks = changes.get("loopbacks", subnet.loopbacks)
            if "gateway" in changes or loopbacks:
                changes["gateway"] = self._check_gateway(changes.get("gateway", subnet.gateway), subnet.network,
                                                         loopbacks)
            if "name" in changes:
                changes["name"] = changes["name"].strip()
            return self._update("subnets", subnet, changes)

    def delete_subnet(self, subnet_id, with_addresses=False):
        """Delete a subnet; its addresses stay (under any containing subnet) unless with_addresses."""
        with self.transaction():
            subnet = self.subnet(subnet_id)
            if with_addresses:
                for address in self.addresses(subnet.network_id, subnet.network):
                    self._delete("addresses", address)
            self._delete("subnets", subnet)

    @staticmethod
    def _check_gateway(gateway, network, loopbacks=False):
        gateway = (gateway or "").strip()
        if not gateway:
            return ""
        if loopbacks:
            raise IpamError("A loopback subnet has no gateway: each address is a host route of its own.")
        address = parse_address(gateway)
        if address not in network:
            raise IpamError(f"The gateway {address} isn't in {network}.")
        return str(address)

    def subnet_for(self, network_id, address):
        """The most specific subnet holding an address, or None."""
        address = ipaddress.ip_address(address)
        best = None
        for subnet in self.subnets(network_id):
            if address in subnet.network and (best is None or (subnet.network.prefixlen, subnet.network.first) >
                                              (best.network.prefixlen, best.network.first)):
                best = subnet
        return best

    # ----------------------------------------------------------------- Addresses

    def addresses(self, network_id, within=None):
        """Addresses in use or reserved in a network, or in one range of it, in address order."""
        if within is None:
            rows = self.db.execute("SELECT * FROM addresses WHERE network_id = ? AND deleted = 0 ORDER BY sort_key",
                                   (network_id,))
        else:
            rows = self.db.execute("SELECT * FROM addresses WHERE network_id = ? AND deleted = 0 AND sort_key "
                                   "BETWEEN ? AND ? ORDER BY sort_key",
                                   (network_id, ip_key(within.network_address), ip_key(within.broadcast_address)))
        return [_from_row(Address, row) for row in rows]

    def address(self, network_id, ip):
        row = self.db.execute("SELECT * FROM addresses WHERE network_id = ? AND sort_key = ? AND deleted = 0",
                              (network_id, ip_key(parse_address(ip)))).fetchone()
        return None if row is None else _from_row(Address, row)

    def count_addresses(self, network_id, within):
        return self.db.execute("SELECT COUNT(*) FROM addresses WHERE network_id = ? AND deleted = 0 AND sort_key "
                               "BETWEEN ? AND ?", (network_id, ip_key(within.network_address),
                                                   ip_key(within.broadcast_address))).fetchone()[0]

    def set_address(self, network_id, ip, status=USED, name="", mac="", description="", fields=None):
        """Record an address as used or reserved, adding it or changing what's recorded."""
        if status not in STATUSES:
            raise ValueError(f"Unknown status {status!r}")
        ip = parse_address(ip)
        values = dict(status=status, name=name.strip(), mac=mac.strip(), description=description,
                      fields=dict(fields or {}))
        with self.transaction():
            self.network(network_id)
            existing = self.address(network_id, ip)
            if existing is not None:
                return self._update("addresses", existing, values)
            return self._insert("addresses", Address(uuid.uuid4().hex, network_id, str(ip), **values))

    def free_address(self, network_id, ip):
        """Mark an address free again (forgetting what was recorded for it)."""
        with self.transaction():
            existing = self.address(network_id, ip)
            if existing is not None:
                self._delete("addresses", existing)

    def next_free(self, subnet):
        """The lowest address in a subnet that isn't recorded, the gateway, or the network or broadcast address."""
        network = subnet.network
        taken = {address.address for address in self.addresses(subnet.network_id, network)}
        taken.update(subnet.special_addresses())
        # Addresses in a nested subnet belong to that subnet, so don't hand them out here
        nested = [other.network for other in self.subnets(subnet.network_id)
                  if other.id != subnet.id and other.network.subnet_of(network) and other.network != network]
        candidate = int(network.network_address)
        for _ in range(min(network.num_addresses, MAX_NEXT_FREE_SCAN)):
            address = _address(candidate, network.version)
            if address not in taken and not any(address in block for block in nested):
                return address
            candidate += 1
        return None

    def free_blocks(self, subnet, prefix=None, limit=500):
        """Unused space in a subnet: blocks holding no other subnet, recorded address or the gateway.

        With a prefix, every free aligned block of that size (such as each free /28); without, the free space as the
        fewest blocks, largest first. Returns ([Block], free address count).
        """
        parent = subnet.network
        first, last = int(parent.first), int(parent.last)
        taken = []  # [(first, last)] as integers
        for other in self.subnets(subnet.network_id):
            block = other.network
            if other.id != subnet.id and block.version == parent.version and block.subnet_of(parent) and \
                    block != parent:
                taken.append((int(block.first), int(block.last)))
        for address in self.addresses(subnet.network_id, parent):
            taken.append((int(address.address), int(address.address)))
        if subnet.gateway:
            with contextlib.suppress(ValueError):
                gateway = ipaddress.ip_address(subnet.gateway)
                if gateway in parent:
                    taken.append((int(gateway), int(gateway)))
        gaps, start = [], first
        for low, high in sorted(taken):
            if low > start:
                gaps.append((start, low - 1))
            start = max(start, high + 1)
        if start <= last:
            gaps.append((start, last))
        free_count = sum(high - low + 1 for low, high in gaps)
        blocks = []
        if prefix is None:
            for low, high in gaps:
                blocks += ipaddress.summarize_address_range(_address(low, parent.version),
                                                            _address(high, parent.version))
            blocks.sort(key=lambda block: (block.prefixlen, int(block.network_address)))
        else:
            size = 1 << (parent.first.max_prefixlen - prefix)
            for low, high in gaps:
                aligned = -(-low // size) * size
                while aligned + size - 1 <= high and len(blocks) < limit:
                    blocks.append(ipaddress.ip_network(f"{_address(aligned, parent.version)}/{prefix}"))
                    aligned += size
        return [Block(block) for block in blocks[:limit]], free_count

    def deleted_since(self, network_id):
        """({subnet CIDR}, {address}) deleted in a network (and not recorded again): what someone removed on
        purpose, so a comparison doesn't offer to put it back as though it were new."""
        subnets = {row[0] for row in self.db.execute(
            "SELECT cidr FROM subnets AS old WHERE network_id = ? AND deleted = 1 AND NOT EXISTS (SELECT 1 FROM "
            "subnets WHERE network_id = old.network_id AND sort_key = old.sort_key AND deleted = 0)", (network_id,))}
        addresses = {row[0] for row in self.db.execute(
            "SELECT ip FROM addresses AS old WHERE network_id = ? AND deleted = 1 AND NOT EXISTS (SELECT 1 FROM "
            "addresses WHERE network_id = old.network_id AND sort_key = old.sort_key AND deleted = 0)",
            (network_id,))}
        return subnets, addresses

    # ----------------------------------------------------------------- Sweeps (last seen)

    def record_sightings(self, network_id, hosts=(), ranges=(), by=None):
        """Remember what a sweep found: hosts [{"ip", "seen", "rtt", "mac", "name"}] that answered, and ranges
        [{"cidr", "started", "finished"}] swept in full. Only newer news replaces older (a MAC or name missing from
        a newer sighting is kept from the older). Returns how many were new."""
        by = by or self.user
        changed = 0
        with self.transaction():
            seq = int(self.get_meta("sighting_seq", "0") or 0)
            for host in hosts:
                ip = parse_address(host["ip"])
                seen = float(host["seen"])
                old = self.db.execute("SELECT * FROM sightings WHERE network_id = ? AND sort_key = ?",
                                      (network_id, ip_key(ip))).fetchone()
                if old is not None and old["seen"] >= seen:
                    continue
                seq += 1
                self.db.execute(
                    "INSERT OR REPLACE INTO sightings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (network_id, ip_key(ip), str(ip), seen, host.get("rtt"),
                     host.get("mac") or (old["mac"] if old else ""), host.get("name") or (old["name"] if old else ""),
                     host.get("seen_by") or by, seq))
                changed += 1
            for swept in ranges:
                block = parse_subnet(swept["cidr"])
                old = self.db.execute("SELECT started FROM sweeps WHERE network_id = ? AND cidr = ?",
                                      (network_id, str(block))).fetchone()
                if old is not None and old["started"] >= float(swept["started"]):
                    continue
                seq += 1
                self.db.execute("INSERT OR REPLACE INTO sweeps VALUES (?, ?, ?, ?, ?, ?)",
                                (network_id, str(block), float(swept["started"]), float(swept["finished"]),
                                 swept.get("swept_by") or by, seq))
                changed += 1
            self.set_meta("sighting_seq", seq)
        return changed

    def sighting_seq(self):
        return int(self.get_meta("sighting_seq", "0") or 0)

    def sightings_since(self, seq, limit=5000):
        """Sightings and swept ranges recorded after `seq`, for copies: ({"hosts": [...], "ranges": [...]}, the
        seq they reach, whether there's more)."""
        hosts = [dict(row) for row in self.db.execute(
            "SELECT network_id, ip, seen, rtt, mac, name, seen_by, seq FROM sightings WHERE seq > ? ORDER BY seq "
            "LIMIT ?", (seq, limit + 1))]
        ranges = [dict(row) for row in self.db.execute(
            "SELECT network_id, cidr, started, finished, swept_by, seq FROM sweeps WHERE seq > ? ORDER BY seq "
            "LIMIT ?", (seq, limit + 1))]
        items = sorted([("hosts", row) for row in hosts] + [("ranges", row) for row in ranges],
                       key=lambda item: item[1]["seq"])
        more = len(items) > limit
        items = items[:limit]
        reached = items[-1][1]["seq"] if items else seq
        return ({"hosts": [row for kind, row in items if kind == "hosts"],
                 "ranges": [row for kind, row in items if kind == "ranges"]}, reached, more)

    def apply_sightings(self, payload):
        """Take in sightings_since's rows from the server (on a copy of its data)."""
        networks = {row["network_id"] for row in payload.get("hosts", []) + payload.get("ranges", [])}
        with self.transaction():
            for network_id in networks:
                self.record_sightings(
                    network_id,
                    [row for row in payload.get("hosts", []) if row["network_id"] == network_id],
                    [row for row in payload.get("ranges", []) if row["network_id"] == network_id])

    def sightings(self, network_id, within=None):
        """What sweeps found in a network: ({address: row}, [(Block, started, finished, swept_by)]). `within` (a
        Block) keeps to one subnet."""
        query, arguments = "SELECT * FROM sightings WHERE network_id = ?", [network_id]
        if within is not None:
            query += " AND sort_key BETWEEN ? AND ?"
            arguments += [ip_key(within.network_address), ip_key(within.broadcast_address)]
        hosts = {ipaddress.ip_address(row["ip"]): dict(row) for row in self.db.execute(query, arguments)}
        ranges = []
        for row in self.db.execute("SELECT * FROM sweeps WHERE network_id = ?", (network_id,)):
            block = parse_subnet(row["cidr"])
            if within is None or block.version == within.version and \
                    (block.first in within or within.first in block):
                ranges.append((block, row["started"], row["finished"], row["swept_by"]))
        return hosts, ranges

    # ----------------------------------------------------------------- Finding

    def search(self, text, network_id=None, limit=500, subnets=True, addresses=True, status=None, match=ANYWHERE):
        """Subnets and addresses matching text: an address (or subnet) by value, or any name or description.

        network_id limits it to one network; subnets or addresses False leaves those out, and status (USED or
        RESERVED) keeps only addresses recorded as that. match says where the text must be: ANYWHERE, or one of
        VALUE (the address or subnet), NAME, DESCRIPTION, MAC, or a detail's name (such as "Telephony Rng").
        Returns [(network, subnet or None, address or None)]; a subnet match has address None.
        """
        text = text.strip()
        if not text:
            return []
        if status is not None or match == MAC:
            subnets = False  # Only addresses have a status or a MAC
        networks = {network.id: network for network in self.networks()}
        results = []
        like = f"%{text.lower()}%"
        where_network = "" if network_id is None else "AND network_id = ?"
        extra = [] if network_id is None else [network_id]

        address_value = None
        with contextlib.suppress(ValueError):
            address_value = ipaddress.ip_address(text)
        if address_value is not None and match in (ANYWHERE, VALUE):  # Every subnet holding it, and the address
            for current_id in ([network_id] if network_id else list(networks)):
                subnet = self.subnet_for(current_id, address_value)
                address = self.address(current_id, address_value)
                if not addresses:
                    if subnet is not None:
                        results.append((networks[current_id], subnet, None))
                elif status is not None:
                    if address is not None and address.status == status:
                        results.append((networks[current_id], subnet, address))
                elif subnet is not None or address is not None:
                    results.append((networks[current_id], subnet, address or
                                    Address("", current_id, str(address_value), status="")))
            return results

        def matching(value_column, columns):
            """The WHERE test for the match chosen, and its parameters."""
            tests = {VALUE: (f"{value_column} LIKE ?", f"{text}%"), NAME: ("lower(name) LIKE ?", like),
                     DESCRIPTION: ("lower(description) LIKE ?", like), MAC: ("lower(mac) LIKE ?", like)}
            if match == ANYWHERE:
                chosen = [tests[column] for column in columns] + [("lower(fields) LIKE ?", like)]
            elif match in tests:
                chosen = [tests[match]] if match in columns else []
            else:  # One detail, by name
                return "(lower(json_extract(fields, ?)) LIKE ?)", [_json_path(match), like]
            if not chosen:
                return None, []
            return "(" + " OR ".join(test for test, _ in chosen) + ")", [value for _, value in chosen]

        test, values = matching("cidr", (VALUE, NAME, DESCRIPTION))
        rows = self.db.execute(f"SELECT * FROM subnets WHERE deleted = 0 {where_network} AND {test} "
                               "ORDER BY sort_key LIMIT ?", extra + values + [limit]) if subnets and test else []
        for row in rows:
            subnet = _from_row(Subnet, row)
            results.append((networks[subnet.network_id], subnet, None))
        where_status = "" if status is None else "AND status = ?"
        test, values = matching("ip", (VALUE, NAME, MAC, DESCRIPTION))
        rows = self.db.execute(f"SELECT * FROM addresses WHERE deleted = 0 {where_network} {where_status} AND "
                               f"{test} ORDER BY network_id, sort_key LIMIT ?",
                               extra + ([] if status is None else [status]) + values + [limit])             if addresses and test else []
        subnet_cache = {}
        for row in rows:
            address = _from_row(Address, row)
            subnets = subnet_cache.setdefault(address.network_id, self.subnets(address.network_id))
            holding = [subnet for subnet in subnets if address.address in subnet.network]
            subnet = max(holding, key=lambda subnet: (subnet.network.prefixlen, subnet.network.first), default=None)
            results.append((networks[address.network_id], subnet, address))
        return results[:limit]

    def detail_names(self):
        """The names of the details subnets and addresses have (such as "Telephony Rng"), for searching by."""
        rows = self.db.execute("SELECT DISTINCT key FROM subnets, json_each(subnets.fields) WHERE deleted = 0 UNION "
                               "SELECT DISTINCT key FROM addresses, json_each(addresses.fields) WHERE deleted = 0")
        return sorted((row[0] for row in rows), key=str.casefold)
