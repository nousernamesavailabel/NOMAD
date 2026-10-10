"""MAC Finder: which switch and port a MAC address is on, or an IP address's or a name's MAC.

There are two ways to look:
- On the map (search_map): the hosts the Network Map's last crawl put on edge ports. Instant, and works offline,
  but only as of that crawl.
- On the network now (Locator): the map's switches are asked over SNMP, with the map's credentials. A whole MAC is
  asked for directly (a GET for that one MAC in each VLAN's table, not the whole table): first at the switch the map
  last had it on, then along the uplink it was learned on (a link to another switch) until it's on an edge port.
  When that doesn't find it, every switch is asked. Part of a MAC can't be asked for that way, so every switch's MAC
  table is read and searched instead, the way a crawl places hosts (and the same is done once for a long list of
  MACs, rather than asking every switch about each). An IP address is turned into its MAC from this computer's ARP
  table, the ARP tables of the routers with an interface in its subnet, or the map; a name into an IP address by DNS
  (or the map, for phones and other devices that name themselves over CDP or LLDP).
- Over SSH too, when asked (macssh.SshAsker): switches that don't answer SNMP are asked the same at their command
  line, and a MAC learned on a port with a switch beyond it (in CDP or LLDP) is followed there, onto switches the
  map doesn't have. With no map, the search starts at a switch named for it.

Qt-free: the MAC Finder page runs Locator on a worker thread.
"""
import copy
import datetime
import ipaddress
import logging
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..oui import format_mac, normalize_mac, vendor
from ..snmp import SnmpClient, SnmpError, parse_oid
from ..snmpv3 import is_v3
from . import collect, macssh, vlans
from .crawl import VLAN_WORKERS, Crawler
from .model import AP, FIREWALL, HOST, NEIGHBOR, NETWORK_KINDS, PHONE, ROUTER, SERVER, SHARED_PORT_HOSTS, SNMP, \
    SWITCH, Device, Link, NetworkMap, normalize_name, port_key, short_port

log = logging.getLogger(__name__)

MAC_FULL, MAC_PART, IP, NAME = "mac", "part", "ip", "name"  # What a search is for
MIN_PART_DIGITS = 3  # Fewer hex digits than this would match most of the network
MAP, LIVE, HISTORY = "map", "live", "history"  # Where a location came from
SOURCE_NAMES = {MAP: "Map", LIVE: "Live", HISTORY: "History"}
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"  # ifAlias: the port's description
FDB_PORT, FDB_STATUS = 2, 3  # dot1dTpFdbTable's and dot1qTpFdbTable's port and status columns
FDB_SELF = 4  # Status: the switch's own MAC
GET_BATCH = 20  # OIDs asked for in one GET
TABLE_READ_AT = 8  # MACs without a quick answer before every switch's MAC table is read once instead
FDB_KINDS = {SWITCH, ROUTER}  # Devices that can have MAC tables (routers with switch ports); firewalls only ARP
ARP_KINDS = {SWITCH, ROUTER, FIREWALL}
NOT_UPLINK_KINDS = {PHONE, HOST, AP, SERVER}  # A link to one of these is an edge port, not an uplink
UNKNOWN_DEVICE = "?"  # leads_to: a port another switch's MAC was learned on, with no link on the map
DNS_TIMEOUT = 2.0  # Seconds to wait for reverse DNS (names for live results)

GROUP = re.compile(r"[0-9A-Fa-f]+")
SEPARATORS = re.compile(r"[\s:\-.]+")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_\-.]*[A-Za-z0-9_])?\.?$")
LIST_CELLS = re.compile(r"[,\t;|]")


# --------------------------------------------------------------------- What was typed

@dataclass
class Query:
    text: str  # As typed
    kind: str  # MAC_FULL, MAC_PART, IP or NAME
    digits: str = ""  # A MAC's hex digits (all 12, or the part typed), uppercase
    address: str = ""  # An IP address

    @property
    def mac(self):
        return format_mac(self.digits) if self.kind == MAC_FULL else ""

    @property
    def maybe_name(self):
        """Part of a MAC that's also a name (acc1, cafe): the map's names are searched for it as well."""
        return self.kind == MAC_PART and bool(NAME_PATTERN.match(self.text)) and any(
            character.isalpha() for character in self.text)

    def matches(self, mac):
        """Whether a MAC (any format) is the one searched for, or has the part searched for in it."""
        digits = normalize_mac(mac)
        if not digits:
            return False
        if self.kind == MAC_FULL:
            return digits == self.digits
        return self.kind == MAC_PART and self.digits in digits

    def key(self):
        """The same search typed two ways is one search."""
        return self.kind, self.digits or self.address or self.text.casefold()


def mac_digits(groups):
    """The hex digits of a MAC written in groups (aa:bb:cc..., aabb.ccdd.eeff, aabbcc-ddeeff), with the leading zeros
    some tools leave out (0:1a:2b...) put back. Of part of a MAC, the first and last groups are kept as typed (they
    may be part of a group), the ones between them filled out."""
    if len(groups) == 1:
        return groups[0].upper()
    longest = max(len(group) for group in groups)
    width = next((width for width in (2, 4, 6) if longest <= width), 0)
    if width and len(groups) * width == 12:
        return "".join(group.zfill(width) for group in groups).upper()
    if not width:
        return "".join(groups).upper()
    return (groups[0] + "".join(group.zfill(width) for group in groups[1:-1]) + groups[-1]).upper()


def parse_query(text):
    """A search: a MAC address in any format (dashes, colons, dots, spaces or none), part of one, an IP address or a
    name. Raises ValueError with a message worth showing."""
    text = (text or "").strip().strip('"\'')
    if not text:
        raise ValueError("Enter a MAC address (or part of one), an IP address or a name.")
    try:
        return Query(text, IP, address=str(ipaddress.ip_address(text.partition("%")[0])))
    except ValueError:
        pass
    groups = [group for group in SEPARATORS.split(text) if group]
    if groups and all(GROUP.fullmatch(group) for group in groups):
        digits = mac_digits(groups)
        if len(digits) > 12:
            raise ValueError(f"'{text}' has more hex digits than a MAC address has (12).")
        if len(digits) == 12:
            return Query(text, MAC_FULL, digits)
        if len(digits) >= MIN_PART_DIGITS:
            return Query(text, MAC_PART, digits)
        if not NAME_PATTERN.match(text):
            raise ValueError(f"'{text}' is too short: enter at least {MIN_PART_DIGITS} hex digits of a MAC address.")
    if NAME_PATTERN.match(text):
        return Query(text, NAME)
    raise ValueError(f"'{text}' isn't a MAC address, an IP address or a name.")


def unique(queries):
    seen, kept = set(), []
    for query in queries:
        if query.key() not in seen:
            seen.add(query.key())
            kept.append(query)
    return kept


def parse_queries(text):
    """(queries, problems) from the search box: one search, or several separated by commas, semicolons or lines."""
    queries, problems = [], []
    for piece in re.split(r"[,;\r\n]+", text or ""):
        if piece.strip():
            try:
                queries.append(parse_query(piece))
            except ValueError as error:
                problems.append(str(error))
    return unique(queries), problems


def parse_list(text):
    """(queries, problems) from a pasted list or a file: one search per line. A line with several cells (a
    spreadsheet row, CSV) gives its first whole MAC address, else its first IP address (its other cells, and a
    heading row, are names and notes, not searches)."""
    queries, problems = [], []
    for number, line in enumerate((text or "").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        cells = [cell.strip().strip('"\'') for cell in LIST_CELLS.split(line)]
        cells = [cell for cell in cells if cell]
        if len(cells) <= 1:
            try:
                queries.append(parse_query(line))
            except ValueError as error:
                problems.append(f"Line {number}: {error}")
            continue
        parsed = []
        for cell in cells:
            try:
                parsed.append(parse_query(cell))
            except ValueError:
                pass
        best = next((query for kind in (MAC_FULL, IP) for query in parsed if query.kind == kind), None)
        if best is None:
            problems.append(f"Line {number}: no MAC address or IP address in '{line}'.")
        else:
            queries.append(best)
    return unique(queries), problems


# --------------------------------------------------------------------- Where a MAC is

@dataclass
class Location:
    query: str  # What was searched for, as typed
    mac: str
    ip: str = ""
    name: str = ""
    vendor: str = ""
    device: str = ""  # The switch's key on the map
    switch: str = ""  # Its name (or address)
    switch_ip: str = ""
    port: str = ""
    description: str = ""  # The port's description (live only)
    vlan: int = 0
    mode: str = ""  # access or trunk, as the map has the port
    port_macs: int = 0  # MACs on that port
    note: str = ""
    path: list = field(default_factory=list)  # [[switch, port]] from the map's first switch to here
    seen_on: list = field(default_factory=list)  # [[switch, port]]: uplinks it was also learned on (live)
    when: str = ""  # ISO time it was seen there
    source: str = MAP


def snapshot_map(network_map):
    """A copy of what MAC Finder needs of a map (its devices, links and hosts), for a worker thread to search while
    the Network Map page goes on changing the map."""
    copied = NetworkMap(seeds=list(network_map.seeds), started=network_map.started, finished=network_map.finished,
                        root=network_map.root)
    copied.devices = {key: copy.copy(device) for key, device in network_map.devices.items()}
    copied.links = [copy.copy(link) for link in network_map.links]
    copied.hosts = [copy.copy(host) for host in network_map.hosts]
    return copied


def same_ip(one, other):
    try:
        return ipaddress.ip_address((one or "").partition("%")[0]) == ipaddress.ip_address(
            (other or "").partition("%")[0])
    except ValueError:
        return False


def name_matches(wanted, name):
    """A name searched for is in the name (pc-0142 finds pc-0142.corp.example and SEP-pc-0142)."""
    return bool(name) and wanted.casefold().rstrip(".") in name.casefold()


def uplink_ports(network_map, key):
    """{port key: device key} of a device's ports that lead to other network devices: a MAC learned on one of them
    is further along. A port to a phone, access point, server or host is an edge port."""
    found = {}
    for link in network_map.links_of(key):
        other = network_map.devices.get(link.other(key))
        if other is not None and other.kind not in NOT_UPLINK_KINDS:
            found[port_key(link.port_on(key))] = other.key
    return found


def root_key(network_map):
    """Where the map's paths start: the device chosen as its top, else where the crawl started, else the network
    device with the most links."""
    devices = network_map.devices
    if network_map.root in devices:
        return network_map.root
    for seed in network_map.seeds:
        key = next((key for key, device in devices.items() if device.owns(seed)), None)
        if key is not None:
            return key
    counts = {}
    for link in network_map.links:
        for key in (link.a, link.b):
            if key in devices and devices[key].kind in NETWORK_KINDS:
                counts[key] = counts.get(key, 0) + 1
    return max(counts, key=lambda key: (counts[key], key)) if counts else None


def network_paths(network_map):
    """{device key: [(device key, port out of it), ...]}: the way from the root to each network device over the
    map's links between network devices (fewest hops)."""
    start = root_key(network_map)
    if start is None:
        return {}
    devices = network_map.devices
    paths, queue = {start: []}, [start]
    while queue:
        key = queue.pop(0)
        for link in network_map.links_of(key):
            other = link.other(key)
            if other in paths or other not in devices or devices[other].kind in NOT_UPLINK_KINDS:
                continue
            paths[other] = paths[key] + [(key, link.port_on(key))]
            queue.append(other)
    return paths


def path_to(network_map, key, port, paths=None):
    """[[switch, port]] from the root to a host's switch port."""
    paths = network_paths(network_map) if paths is None else paths
    devices = network_map.devices
    steps = [[devices[step].label if step in devices else step, out] for step, out in paths.get(key, [])]
    return steps + [[devices[key].label if key in devices else key, port]]


def end_device_on(network_map, key, port):
    """The access point (or phone) a link from this port goes to, as (kind, label), or None."""
    for link in network_map.links_of(key):
        other = network_map.devices.get(link.other(key))
        if other is not None and other.kind in (AP, PHONE) and port_key(link.port_on(key)) == port_key(port):
            return other.kind, other.label
    return None


def phone_on(network_map, key, port, mac):
    """The name of a phone on the same switch port as a MAC (a PC plugged into the phone), or ""."""
    for host in network_map.hosts:
        if host.device == key and port_key(host.port) == port_key(port) and host.mac != mac and (
                "phone" in host.platform.lower() or host.name.upper().startswith("SEP")):
            return host.name or host.mac
    return ""


def describe(network_map, location, paths=None, port_macs=None):
    """Fill in what the map knows about a location's port: its mode (and VLAN), how many MACs are on it, what's
    plugged into it, and the way to it."""
    device = network_map.devices.get(location.device)
    if device is None or not location.port:
        return location
    entry = vlans.port_info(device, location.port)
    location.mode = entry.get("mode", "")
    if not location.vlan and location.mode == vlans.ACCESS:
        location.vlan = entry.get("vlan", 0)
    if port_macs is None:
        port_macs = sum(1 for host in network_map.hosts
                        if host.device == location.device and port_key(host.port) == port_key(location.port))
    location.port_macs = port_macs
    notes = [location.note] if location.note else []
    end_device = end_device_on(network_map, location.device, location.port)
    phone = phone_on(network_map, location.device, location.port, location.mac)
    if end_device is not None and end_device[0] == AP:
        notes.append(f"Through access point {end_device[1]}: a Wi-Fi client (or the access point itself).")
    elif phone:
        notes.append(f"Shares the port with phone {phone}: probably plugged into the phone.")
    if port_macs > SHARED_PORT_HOSTS:
        notes.append(f"{port_macs} MACs on this port: probably an unmanaged switch, hub or virtual machine host is "
                     "plugged in there.")
    location.note = " ".join(notes)
    location.path = path_to(network_map, location.device, location.port, paths)
    return location


def host_location(network_map, host, query="", source=MAP, when="", paths=None):
    device = network_map.devices.get(host.device)
    location = Location(query=query, mac=host.mac, ip=host.ip, name=host.name, vendor=host.vendor or vendor(host.mac),
                        device=host.device, switch=device.label if device else host.device,
                        switch_ip=device.mgmt_ip if device else "", port=host.port, vlan=host.vlan,
                        when=when or network_map.finished or network_map.started, source=source)
    return describe(network_map, location, paths)


def search_map(network_map, query):
    """Where the map's last crawl had what's searched for: [Location], one per host that matches."""
    if network_map is None:
        return []
    hosts = network_map.hosts
    if query.kind in (MAC_FULL, MAC_PART):
        chosen = [host for host in hosts if query.matches(host.mac)]
        if query.maybe_name:
            chosen += [host for host in hosts if host not in chosen and name_matches(query.text, host.name)]
    elif query.kind == IP:
        chosen = [host for host in hosts if same_ip(host.ip, query.address)]
    else:
        chosen = [host for host in hosts if name_matches(query.text, host.name)]
    paths = network_paths(network_map) if chosen else {}
    return [host_location(network_map, host, query.text, paths=paths) for host in chosen]


# --------------------------------------------------------------------- Asking the network now

ANSWERED, NO_ANSWER = "Answered", "No answer"  # A device's SNMP, in its report
LOGGED_IN, LOGIN_FAILED = "Logged in", "Login failed"  # Its SSH


@dataclass
class DeviceReport:
    """How asking one device went, for the page to show as it happens."""
    key: str
    name: str
    address: str
    snmp: str = ""  # ANSWERED, NO_ANSWER, or "" when it wasn't asked over SNMP
    ssh: str = ""  # LOGGED_IN, LOGIN_FAILED, or "" when it wasn't asked over SSH
    login: str = ""  # What SSH logged in with ("credential TACACS", "saved session sw1")
    note: str = ""  # Why it couldn't be asked

    @property
    def asked(self):
        return self.snmp == ANSWERED or self.ssh == LOGGED_IN

    @property
    def failed(self):
        return not self.asked and bool(self.snmp or self.ssh)


@dataclass
class Hit:
    """A switch has a MAC in its table now."""
    key: str
    port: str  # Short name: the port-channel, for a MAC learned on one
    vlan: int = 0
    description: str = ""
    own: bool = False  # The switch's own MAC
    members: list = field(default_factory=list)  # A port-channel's member ports (short names)


def is_catalyst(device):
    """Catalyst IOS keeps a MAC table per VLAN (community@vlan, or SNMPv3 context vlan-N); NX-OS and others keep one
    with the VLAN in its index (Q-BRIDGE-MIB)."""
    return device.sys_object_id.startswith(collect.CISCO + ".") and "nx-os" not in device.sys_descr.lower()


def vlans_in_use(device):
    """The VLANs the device's ports put hosts in, from the map: access, voice and trunks' native VLANs."""
    found = set()
    for entry in device.port_vlans.values():
        for name in ("vlan", "voice", "native"):
            if entry.get(name):
                found.add(entry[name])
    return found


def resolve_name(name):
    """A name's IPv4 address by DNS (or the hosts file), or "" when it has none."""
    try:
        return socket.gethostbyname(name)
    except (OSError, UnicodeError):
        return ""


def reverse_names(addresses, timeout=DNS_TIMEOUT):
    """{address: name} by reverse DNS, giving up on the ones that take longer than timeout (all at once, each on its
    own thread, so a missing DNS server costs timeout once rather than for each)."""
    found, threads = {}, []

    def ask(address):
        try:
            found[address] = socket.gethostbyaddr(address)[0]
        except (OSError, UnicodeError):
            pass

    for address in dict.fromkeys(addresses):
        thread = threading.Thread(target=ask, args=(address,), daemon=True)
        thread.start()
        threads.append(thread)
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    return dict(found)


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


class Locator:
    def __init__(self, network_map, settings, client_factory=SnmpClient, should_stop=lambda: False,
                 events=lambda kind, *details: None, arp_lookup=None, resolve=resolve_name, workers=16, ssh=None,
                 start=None):
        """network_map: a snapshot_map copy. settings: a CrawlSettings with the map's credentials (communities,
        overrides, version, timeout). events(kind, *details), from this and its worker threads:
            ("step", text)                              what it's doing now
            ("result", index, [Location], problem)      what was found for queries[index] ("" problem if it was)
            ("device", DeviceReport)                    how asking a device went (a copy), each time that changes
        arp_lookup(ip): this computer's ARP for an address on one of its own subnets: the MAC, or None.
        ssh: a macssh.SshAsker, to ask switches that don't answer SNMP over SSH (None: SNMP only). start: the key of
        the switch to start at when the map doesn't say where a MAC was (a search with no map)."""
        self.map = network_map
        self.settings = settings
        self.client_factory = client_factory
        self.should_stop = should_stop
        self.events = events
        self.arp_lookup = arp_lookup
        self.resolve = resolve
        self.workers = max(1, workers)
        self.crawler = Crawler(settings, client_factory=client_factory, should_stop=should_stop)
        self.lock = threading.Lock()
        self.clients = {}  # Device key -> (client, community), or None when it answered none
        self.interface_cache = {}  # Device key -> {ifIndex: name}
        self.no_contexts = set()  # Catalysts whose per-VLAN tables don't answer
        self.tables = None  # Device key -> DeviceTables, once every switch's MAC table has been read
        self.network_ports = {}  # Device key -> port keys another network device's own MAC was learned on
        self.port_counts = {}  # (device key, port key) -> MACs learned on that port, from the tables
        self.paths = network_paths(network_map)
        self.fan_outs = 0  # MACs every switch was asked about
        self.ssh = ssh
        self.start = start
        self.ssh_read = set()  # Devices answered over SSH
        self.over_ssh = False  # Asking again over SSH what SNMP didn't find: every device at its command line
        self.ssh_tables_read = False  # Every switch's MAC table read over SSH too (searching for part of a MAC)
        self.reports = {}  # Device key -> DeviceReport, for each device asked
        if ssh is not None:
            ssh.listener = self.on_ssh_login

    # ----------------------------------------------------------------- Devices

    def readable(self, key, kinds=FDB_KINDS):
        """Whether a device can be asked: one that answered SNMP, or any with an address when SSH may be used."""
        device = self.map.devices.get(key)
        return device is not None and (device.source == SNMP or self.ssh is not None) and bool(device.mgmt_ip) \
            and device.kind in kinds

    def by_snmp(self, key):
        """Whether to ask a device over SNMP: it answered when the map was made, and does now (and this isn't the
        second look, over SSH)."""
        if self.over_ssh:
            return False
        return self.map.devices[key].source == SNMP and self.client_for(key) is not None

    def names(self, key):
        """A device's name and addresses, for finding its saved SSH session."""
        device = self.map.devices[key]
        return [name for name in (device.name, *device.addresses) if name]

    def switches(self, kinds=FDB_KINDS):
        return [key for key in self.map.devices if self.readable(key, kinds)]

    def label(self, key):
        device = self.map.devices.get(key)
        return device.label if device is not None else key

    def client_for(self, key):
        """(client, community) for a device of the map, found once (the community strings tried in turn), or None
        when it answers none of them."""
        with self.lock:
            if key in self.clients:
                return self.clients[key]
        device = self.map.devices[key]
        client, _, community = self.crawler.connect(device.mgmt_ip)
        entry = (client, community) if client is not None else None
        if entry is None and not self.should_stop():
            log.info("MAC Finder: %s (%s) didn't answer SNMP", device.label, device.mgmt_ip)
        with self.lock:
            self.clients[key] = entry
        if not self.should_stop():
            self.report(key, snmp=ANSWERED if entry is not None else NO_ANSWER,
                        note="" if entry is not None else "Didn't answer SNMP with the map's credentials.")
        return entry

    def report(self, key, **changes):
        """Note how asking a device went, and say so."""
        device = self.map.devices.get(key)
        with self.lock:
            report = self.reports.get(key)
            if report is None:
                report = self.reports[key] = DeviceReport(key, device.label if device else key,
                                                          device.mgmt_ip if device else key)
            for name, value in changes.items():
                setattr(report, name, value)
            if report.asked and "note" not in changes:
                report.note = ""
            shown = copy.copy(report)
        self.events("device", shown)

    def on_ssh_login(self, address, ok, login, problem):
        """From the SshAsker: a switch logged into, or not."""
        key = next((key for key, device in list(self.map.devices.items()) if device.mgmt_ip == address), address)
        label = self.label(key)
        if ok:
            self.report(key, ssh=LOGGED_IN, login=login, note="")
            self.events("step", f"Logged in to {label} over SSH ({login})")
        else:
            self.report(key, ssh=LOGIN_FAILED, login=login, note=problem)
            self.events("step", f"{label}: couldn't ask over SSH: {problem}")

    def vlan_client(self, key, vlan):
        client, community = self.clients[key]
        options = {"timeout": self.settings.timeout, "retries": self.settings.retries}
        if is_v3(community):
            return self.client_factory(client.host, community, self.settings.version, context=f"vlan-{vlan}",
                                       **options)
        return self.client_factory(client.host, f"{community}@{vlan}", self.settings.version, **options)

    def device_vlans(self, key, client):
        """The device's VLANs: from the map, or (a map made before NOMAD read VLANs) read now."""
        device = self.map.devices[key]
        names = set(vlans.vlan_names(device))
        if not names:
            tables = collect.DeviceTables(info=collect.SystemInfo(device.name, device.sys_descr,
                                                                  device.sys_object_id))
            self.crawler.read_vlans(client, tables)
            names = set(tables.vlan_names)
            device.vlans = [[vlan, name] for vlan, name in sorted(tables.vlan_names.items())]
        return names - set(collect.RESERVED_VLANS)

    def vlans_to_ask(self, key, client, hints=()):
        """The VLANs to look for a MAC in on a switch, the likeliest first (the one it was last in). On a Catalyst,
        where each VLAN is a request of its own, only the VLANs its ports use (as a crawl reads them); elsewhere they
        all go in a few requests."""
        device = self.map.devices[key]
        names = self.device_vlans(key, client)
        in_use = vlans_in_use(device) if is_catalyst(device) else set()
        chosen = sorted(names & in_use) if names & in_use else sorted(names or in_use)
        first = [vlan for vlan in hints if vlan and (vlan in chosen or not chosen)]
        return list(dict.fromkeys(first + chosen))

    @staticmethod
    def get(client, oids):
        """[(oid, Value)] for OIDs that have values; a device that refuses an OID it hasn't (SNMPv1's noSuchName)
        is asked for the rest one at a time. Raises SnmpError when it doesn't answer."""
        found = []
        for start in range(0, len(oids), GET_BATCH):
            batch = oids[start:start + GET_BATCH]
            try:
                found += client.get(batch)
            except SnmpError as error:
                if "refused" not in str(error):
                    raise
                for oid in batch:
                    try:
                        found += client.get([oid])
                    except SnmpError as single:
                        if "refused" not in str(single):
                            raise
        return [(oid, value) for oid, value in found if not value.is_exception and value.value is not None]

    def interface_names(self, key, client, if_indexes):
        """{ifIndex: (name, description)} for some interfaces."""
        oids = [parse_oid(f"{root}.{if_index}") for if_index in if_indexes for root in (collect.IF_NAME,
                                                                                         collect.IF_DESCR, IF_ALIAS)]
        values = {}
        try:
            for oid, value in self.get(client, oids):
                values[oid] = collect.text(value)
        except (SnmpError, OSError):
            pass
        found = {}
        for if_index in if_indexes:
            name = values.get(parse_oid(f"{collect.IF_NAME}.{if_index}")) or values.get(
                parse_oid(f"{collect.IF_DESCR}.{if_index}")) or str(if_index)
            found[if_index] = (name, values.get(parse_oid(f"{IF_ALIAS}.{if_index}"), ""))
        return found

    def channel_members(self, client, if_index):
        """A port-channel's members' ifIndexes (ifStackTable)."""
        try:
            rows = list(client.walk(parse_oid(f"{collect.IF_STACK_STATUS}.{if_index}"),
                                    should_stop=self.should_stop))
        except (SnmpError, OSError):
            return []
        root = len(parse_oid(collect.IF_STACK_STATUS)) + 1
        return [oid[root] for oid, value in rows if len(oid) == root + 1 and oid[root] and value.value == 1]

    def make_hit(self, key, client, if_index, vlan, status):
        names = self.interface_names(key, client, [if_index])
        name, description = names[if_index]
        port = short_port(name)
        members = []
        if port_key(port).startswith("po") or "channel" in name.lower():
            member_indexes = self.channel_members(client, if_index)
            if member_indexes:
                members = [short_port(name) for name, _ in self.interface_names(key, client,
                                                                                 member_indexes).values()]
        return Hit(key, port, vlan, description, own=status == FDB_SELF, members=members)

    # ----------------------------------------------------------------- One MAC, asked for directly

    def ask_vlan(self, key, vlan, index):
        """Ask a Catalyst's table for one VLAN about a MAC. (answered, (bridge port's ifIndex, vlan, status) or
        None)."""
        if self.should_stop():
            return False, None
        try:
            client = self.vlan_client(key, vlan)
            values = dict(self.get(client, [parse_oid(f"{collect.FDB_ENTRY}.{FDB_PORT}.{index}"),
                                            parse_oid(f"{collect.FDB_ENTRY}.{FDB_STATUS}.{index}")]))
            port = values.get(parse_oid(f"{collect.FDB_ENTRY}.{FDB_PORT}.{index}"))
            if port is None or not port.value:
                return True, None
            status = values.get(parse_oid(f"{collect.FDB_ENTRY}.{FDB_STATUS}.{index}"))
            if_index = dict(self.get(client, [parse_oid(f"{collect.BASE_PORT_IFINDEX}.{port.value}")])).get(
                parse_oid(f"{collect.BASE_PORT_IFINDEX}.{port.value}"))
        except (SnmpError, OSError):
            return False, None  # Some models don't answer for a VLAN with no ports on them
        if if_index is None or not if_index.value:
            return True, None
        return True, (if_index.value, vlan, status.value if status is not None else 0)

    def ask_default(self, client, index, vlan_list):
        """Ask a switch's one MAC table (Q-BRIDGE-MIB, VLAN in the index, then BRIDGE-MIB) about a MAC. Returns
        [(ifIndex, vlan, status)]."""
        oids = [parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_PORT}.{vlan}.{index}") for vlan in vlan_list]
        oids.append(parse_oid(f"{collect.FDB_ENTRY}.{FDB_PORT}.{index}"))
        ports = {}  # (vlan, bridge port) in the order found
        q_root = len(parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_PORT}"))
        for oid, value in self.get(client, oids):
            if value.value and oid[:q_root] == parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_PORT}"):
                ports[(oid[q_root], value.value)] = parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_STATUS}") + oid[q_root:]
            elif value.value:
                ports[(0, value.value)] = parse_oid(f"{collect.FDB_ENTRY}.{FDB_STATUS}.{index}")
        if not ports and not vlan_list:
            # Nothing says which VLANs it has: read its Q-BRIDGE port column, looking for the MAC in the index
            root = parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_PORT}")
            wanted = tuple(int(part) for part in index.split("."))
            for oid, value in client.walk(root, should_stop=self.should_stop):
                if oid[len(root) + 1:] == wanted and value.value:
                    ports[(oid[len(root)], value.value)] = parse_oid(f"{collect.Q_FDB_ENTRY}.{FDB_STATUS}") + \
                        oid[len(root):]
        if not ports:
            return []
        statuses = dict(self.get(client, list(dict.fromkeys(ports.values()))))
        bases = dict(self.get(client, [parse_oid(f"{collect.BASE_PORT_IFINDEX}.{port}") for _, port in ports]))
        found = []
        for (vlan, port), status_oid in ports.items():
            if_index = bases.get(parse_oid(f"{collect.BASE_PORT_IFINDEX}.{port}"))
            status = statuses.get(status_oid)
            if if_index is not None and if_index.value:
                found.append((if_index.value, vlan, status.value if status is not None else 0))
        return found

    def ask(self, key, digits, hints=()):
        """Whether a switch has a MAC in its table now: [Hit] (one per VLAN it's in, usually one), or None when
        the switch couldn't be asked."""
        if self.should_stop():
            return None
        if not self.by_snmp(key):
            return self.ask_ssh(key, digits)
        client, _ = self.clients[key]
        device = self.map.devices[key]
        index = ".".join(str(byte) for byte in bytes.fromhex(digits))
        found = []
        try:
            vlan_list = self.vlans_to_ask(key, client, hints)
            if is_catalyst(device) and vlan_list and key not in self.no_contexts:
                answered = False
                first, rest = vlan_list[:1], vlan_list[1:]
                for batch in (first, rest):  # The VLAN it was last in, alone: usually where it still is
                    if not batch or self.should_stop():
                        continue
                    with ThreadPoolExecutor(max_workers=VLAN_WORKERS) as executor:
                        for said, result in executor.map(lambda vlan: self.ask_vlan(key, vlan, index), batch):
                            answered = answered or said
                            if result is not None:
                                found.append(result)
                    if found:
                        break
                if not answered:
                    self.no_contexts.add(key)
            if not found and (not is_catalyst(device) or key in self.no_contexts or not vlan_list):
                found = self.ask_default(client, index, [] if is_catalyst(device) else vlan_list)
        except (SnmpError, OSError) as error:
            log.info("MAC Finder: asking %s: %s", device.label, error)
            return None
        return [self.make_hit(key, client, if_index, vlan, status) for if_index, vlan, status in found]

    def ask_ssh(self, key, digits):
        """ask(), at the switch's command line: [Hit], or None when it can't be asked (or SSH isn't to be used)."""
        if self.ssh is None:
            return None
        device = self.map.devices[key]
        entries = self.ssh.mac_entries(device.mgmt_ip, digits, self.names(key))
        if entries is None:
            return None
        with self.lock:
            self.ssh_read.add(key)
        hits = []
        for entry in entries:
            if entry.own:
                hits.append(Hit(key, "", entry.vlan, own=True))
                continue
            description = self.ssh.description(device.mgmt_ip, entry.port, self.names(key)) \
                if entry.port != macssh.PEER_LINK else ""
            hits.append(Hit(key, entry.port, entry.vlan, description, members=self.ssh_members(key, entry.port)))
        return hits

    def ssh_members(self, key, port):
        """A port-channel's members: as the map has them, else as the switch says."""
        if not port_key(port).startswith("po"):
            return []
        device = self.map.devices[key]
        members = [member for member, channel in device.port_channels.items() if port_key(channel) == port_key(port)]
        if members:
            return members
        channels = self.ssh.channels(device.mgmt_ip, self.names(key))
        return next((found for channel, found in channels.items() if port_key(channel) == port_key(port)), [])

    def ssh_neighbor(self, key, hit):
        """For a MAC a switch answered about over SSH: the network device its CDP or LLDP has on that port (added to
        the map, linked, when the map doesn't have it), or None."""
        device = self.map.devices[key]
        ports = {port_key(port) for port in [hit.port] + hit.members}
        for neighbor in self.ssh.neighbors(device.mgmt_ip, self.names(key)):
            if port_key(neighbor.local_port) not in ports:
                continue
            kind = collect.classify(capabilities=neighbor.capabilities, platform=neighbor.platform)
            if kind in NETWORK_KINDS:
                return self.neighbor_device(key, neighbor, kind)
        return None

    def neighbor_device(self, key, neighbor, kind):
        devices = self.map.devices
        with self.lock:
            name = normalize_name(neighbor.name)
            other = next((other for other, device in devices.items() if other != key and (
                (neighbor.address and device.owns(neighbor.address)) or
                (name and normalize_name(device.name) == name))), None)
            if other is None:
                other = f"ssh:{neighbor.address or name}"
                devices[other] = Device(other, name=neighbor.name, mgmt_ip=neighbor.address, kind=kind,
                                        platform=neighbor.platform, source=NEIGHBOR)
            elif not devices[other].mgmt_ip and neighbor.address:
                devices[other].mgmt_ip = neighbor.address
            self.map.add_link(Link(key, neighbor.local_port, other, neighbor.port, protocols=[neighbor.protocol]))
            self.paths = network_paths(self.map)
        return other

    def leads_to(self, key, hit):
        """The device a hit's port leads to (an uplink): its key, UNKNOWN_DEVICE for a port another switch's MAC
        was learned on (a link the map hasn't), or None for an edge port."""
        uplinks = uplink_ports(self.map, key)
        for port in [hit.port] + hit.members:
            if port_key(port) in uplinks:
                return uplinks[port_key(port)]
        if key in self.ssh_read and hit.port and not hit.own and hit.port != macssh.PEER_LINK:
            found = self.ssh_neighbor(key, hit)
            if found is not None:
                return found
        if port_key(hit.port) in self.network_ports.get(key, ()) or hit.port == macssh.PEER_LINK:
            return UNKNOWN_DEVICE
        return None

    def depth(self, key):
        return len(self.paths.get(key, []))

    def choose_edge(self, hits):
        """Of the switches that have a MAC, the one it's plugged into: (key, Hit, note) or None. An edge port wins
        (an access port first, then the port with fewest MACs); failing that, an uplink to something that couldn't
        be asked; failing that, the uplink furthest from the root."""
        if not hits:
            return None
        edges = [(key, hit) for key, hit in hits.items() if not hit.own and self.leads_to(key, hit) is None]
        if edges:
            def preference(item):
                key, hit = item
                mode = vlans.port_info(self.map.devices[key], hit.port).get("mode", "")
                count = self.port_counts.get((key, port_key(hit.port)), 0)
                return mode != vlans.ACCESS, count, -self.depth(key), key
            key, hit = min(edges, key=preference)
            others = [f"{self.label(other)} {other_hit.port}" for other, other_hit in edges if other != key]
            note = f"Also on {', '.join(others)}, which the map doesn't link to another switch." if others else ""
            return key, hit, note
        own = [(key, hit) for key, hit in hits.items() if hit.own]
        if own:
            key, hit = own[0]
            return key, hit, f"This is {self.label(key)}'s own MAC address."
        beyond = []
        for key, hit in hits.items():
            other = self.leads_to(key, hit)
            if other == UNKNOWN_DEVICE or other not in hits:
                beyond.append((key, hit, other))
        if beyond:
            key, hit, other = max(beyond, key=lambda item: (self.depth(item[0]), item[0]))
            if other == UNKNOWN_DEVICE:
                what = "another switch (not linked on the map)"
            elif self.ssh is not None and self.map.devices[other].mgmt_ip in self.ssh.problems:
                what = f"{self.label(other)}, which NOMAD couldn't ask over SSH"
            elif self.readable(other):
                what = f"{self.label(other)}, which doesn't have it in its table now"
            else:
                what = f"{self.label(other)}, which NOMAD can't read over SNMP"
            return key, hit, f"{hit.port} leads to {what}: the device is beyond it."
        key, hit = max(hits.items(), key=lambda item: (self.depth(item[0]), item[0]))
        return key, hit, ""

    def live_location(self, query, mac, choice, hits, ip=""):
        key, hit, note = choice
        device = self.map.devices[key]
        known = next((host for host in self.map.hosts if host.mac == mac), None)
        location = Location(query=query, mac=mac, ip=ip or (known.ip if known else ""),
                            name=known.name if known else "", vendor=vendor(mac), device=key, switch=device.label,
                            switch_ip=device.mgmt_ip, port=hit.port, description=hit.description, vlan=hit.vlan,
                            note=note, when=now(), source=LIVE)
        if hit.own:
            location.port = ""
            location.path = path_to(self.map, key, "", self.paths)
            return location
        counts = self.port_counts.get((key, port_key(hit.port))) if self.tables is not None else None
        if counts is None and key in self.ssh_read and hit.port != macssh.PEER_LINK:
            counts = self.ssh.port_macs(device.mgmt_ip, hit.port, self.names(key))
        describe(self.map, location, self.paths, port_macs=counts if counts is not None else 0)
        location.seen_on = [[self.label(other), other_hit.port] for other, other_hit in
                            sorted(hits.items(), key=lambda item: (self.depth(item[0]), item[0])) if other != key]
        return location

    def locate_mac(self, query, digits, hint=None, ip=""):
        """Where a whole MAC is now: [Location], or [] when no switch has it in its table. hint: where the map last
        had it (a Location), asked first and followed along uplinks; then every switch is asked. With SSH, what SNMP
        doesn't find is looked for again at the switches' command lines (SNMP can miss what show mac address-table
        has: a VLAN whose table it can't read, say)."""
        found = self.find_mac(query, digits, hint, ip)
        if found or self.ssh is None or self.over_ssh or self.ssh_tables_read or self.should_stop():
            return found
        self.events("step", f"{format_mac(digits)}: not found over SNMP; asking the switches over SSH")
        self.over_ssh, tables = True, self.tables
        self.tables = None  # Ask each switch for it, rather than search the tables SNMP read
        try:
            return self.find_mac(query, digits, hint, ip)
        finally:
            self.over_ssh, self.tables = False, tables

    def find_mac(self, query, digits, hint=None, ip=""):
        mac = format_mac(digits)
        if self.tables is not None:
            return self.from_tables(query, digits, ip)
        hits, asked = {}, set()
        hints = (hint.vlan,) if hint is not None and hint.vlan else ()
        key = hint.device if hint is not None and self.readable(hint.device) else None
        if key is None and self.start is not None and self.readable(self.start):
            key = self.start  # No idea where it was: start at the switch chosen for it
        while key is not None and key not in asked and not self.should_stop():
            asked.add(key)
            self.events("step", f"{mac}: asking {self.label(key)}")
            found = self.ask(key, digits, hints)
            if not found:
                break
            hit = found[0]
            hits[key] = hit
            other = self.leads_to(key, hit)
            if hit.own or other is None or other == UNKNOWN_DEVICE or not self.readable(other):
                return [self.live_location(query, mac, self.choose_edge(hits), hits, ip)]
            key = other
            hints = (hit.vlan,) if hit.vlan else hints
        others = [key for key in self.switches() if key not in asked]
        if others and not self.should_stop():
            self.fan_outs += 1
            self.events("step", f"{mac}: asking every switch ({len(others)})")
            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                for key, found in zip(others, executor.map(lambda key: self.ask(key, digits, hints), others)):
                    if found:
                        hits[key] = found[0]
        choice = self.choose_edge(hits)
        if choice is None and hint is not None and self.readable(hint.device) and not self.should_stop():
            # Not in the VLANs asked about: read the whole MAC table of the switch the map had it on
            self.events("step", f"{mac}: reading {self.label(hint.device)}'s whole MAC table")
            tables = self.read_device(hint.device)
            for entry_mac, if_index, vlan in (tables.fdb if tables is not None else []):
                if entry_mac == mac:
                    port, members = self.fdb_port(tables, if_index)
                    hits[hint.device] = Hit(hint.device, port, vlan, members=members)
                    choice = self.choose_edge(hits)
                    break
        return [self.live_location(query, mac, choice, hits, ip)] if choice is not None else []

    # ----------------------------------------------------------------- Every switch's MAC table

    def read_device(self, key):
        """A device's MAC table (switches and routers) and ARP table, as a crawl reads them. DeviceTables or None."""
        if self.should_stop():
            return None
        if not self.by_snmp(key):
            return self.read_device_ssh(key)
        client, community = self.clients[key]
        device = self.map.devices[key]
        tables = collect.DeviceTables(info=collect.SystemInfo(device.name, device.sys_descr, device.sys_object_id))
        walk = self.crawler.walk
        tables.arp = collect.arp(walk(client, collect.ARP_PHYS_ADDRESS, tables, "ARP"))
        if device.kind not in FDB_KINDS:
            return tables
        tables.interfaces = collect.interface_names(walk(client, collect.IF_NAME, tables, "Interface names"),
                                                    walk(client, collect.IF_DESCR, tables, "Interfaces"))
        tables.own_macs = collect.own_macs(walk(client, collect.IF_PHYS_ADDRESS, tables, "Interfaces"))
        tables.lag_parents = collect.lag_parents(walk(client, collect.IF_STACK_STATUS, tables, "Port-channels"),
                                                 walk(client, collect.LAG_ATTACHED, tables, "Port-channels"))
        tables.vlan_names = {vlan: "" for vlan in self.device_vlans(key, client)}
        tables.vlans_in_use = sorted(vlans_in_use(device))
        if is_catalyst(device) and tables.vlan_names:
            if self.crawler.read_vlan_tables(client, tables, community, sorted(tables.vlan_names)):
                return tables
        self.crawler.read_mac_table(client, tables)
        return tables

    def read_device_ssh(self, key):
        """read_device(), at the command line: the ports get made-up ifIndexes. DeviceTables or None."""
        if self.ssh is None:
            return None
        device = self.map.devices[key]
        names = self.names(key)
        tables = collect.DeviceTables(info=collect.SystemInfo(device.name, device.sys_descr, device.sys_object_id))
        routes = device.kind != SWITCH or bool(device.interfaces_l3) or key == self.start
        arp = self.ssh.arp(device.mgmt_ip, names=names) if routes else {}
        if arp is None:
            return None
        tables.arp = arp
        if device.kind not in FDB_KINDS:
            return tables
        entries = self.ssh.mac_table(device.mgmt_ip, names)
        if entries is None:
            return None
        with self.lock:
            self.ssh_read.add(key)
        indexes = {}

        def index(port):
            if port_key(port) not in indexes:
                indexes[port_key(port)] = len(indexes) + 1
                tables.interfaces[indexes[port_key(port)]] = port
            return indexes[port_key(port)]

        for entry in entries:
            if entry.own:
                tables.own_macs.add(entry.mac)
            else:
                tables.fdb.append((entry.mac, index(entry.port), entry.vlan))
        channels = {}
        for member, channel in device.port_channels.items():
            channels.setdefault(channel, []).append(member)
        if not channels and any(port_key(entry.port).startswith("po") for entry in entries):
            channels = self.ssh.channels(device.mgmt_ip, names)
        for channel, members in channels.items():
            for member in members:
                tables.lag_parents[index(member)] = index(channel)
        return tables

    def read_all_tables(self):
        """Read every switch's MAC table (and every router's and firewall's ARP table) once. Over SSH (the second
        look), what's read is added to the tables SNMP read, in place of the same device's."""
        keys = self.switches(ARP_KINDS)
        tables, done = {}, [0]

        def read(key):
            result = self.read_device(key)
            with self.lock:
                done[0] += 1
                self.events("step", f"Reading MAC and ARP tables: {done[0]} of {len(keys)} devices "
                                    f"({self.label(key)})")
            return result

        self.events("step", f"Reading MAC and ARP tables of {len(keys)} devices")
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for key, result in zip(keys, executor.map(read, keys)):
                if result is not None:
                    tables[key] = result
        if self.over_ssh and self.tables is not None:
            tables = {**self.tables, **tables}
        network_macs = set()
        for key, result in tables.items():
            if self.map.devices[key].kind in NETWORK_KINDS:
                network_macs |= result.own_macs
        self.network_ports, self.port_counts = {}, {}
        for key, result in tables.items():
            for mac, if_index, _ in result.fdb:
                port = port_key(self.fdb_port(result, if_index)[0])
                self.port_counts[(key, port)] = self.port_counts.get((key, port), 0) + 1
                if mac in network_macs and mac not in result.own_macs:
                    self.network_ports.setdefault(key, set()).add(port)
        self.tables = tables

    def read_tables_over_ssh(self):
        """The second look for part of a MAC: every switch's MAC table read again at its command line."""
        self.over_ssh = True
        try:
            self.read_all_tables()
        finally:
            self.over_ssh = False
        self.ssh_tables_read = True

    @staticmethod
    def fdb_port(tables, if_index):
        """(short port name, its port-channel's members' short names) for an ifIndex in a MAC table."""
        parent = tables.lag_parents.get(if_index, if_index)
        members = [short_port(tables.interfaces.get(member, str(member)))
                   for member, owner in tables.lag_parents.items() if owner == parent]
        return short_port(tables.interfaces.get(parent, str(parent))), members

    def table_hits(self, digits):
        mac, hits = format_mac(digits), {}
        for key, tables in self.tables.items():
            for entry_mac, if_index, vlan in tables.fdb:
                if entry_mac == mac:
                    port, members = self.fdb_port(tables, if_index)
                    hits[key] = Hit(key, port, vlan, members=members)
                    break
            else:
                if mac in tables.own_macs and self.map.devices[key].kind in NETWORK_KINDS:
                    hits.setdefault(key, Hit(key, "", own=True))
        return hits

    def arp_ip(self, mac):
        for key in sorted(self.tables, key=lambda key: (self.map.devices[key].kind != ROUTER, key)):
            addresses = self.tables[key].arp.get(mac)
            if addresses:
                return addresses[0]
        return ""

    def from_tables(self, query, digits, ip=""):
        mac = format_mac(digits)
        hits = self.table_hits(digits)
        choice = self.choose_edge(hits)
        if choice is None:
            return []
        return [self.live_location(query, mac, choice, hits, ip or self.arp_ip(mac))]

    def search_tables(self, query):
        """Every MAC in the tables read that matches part of a MAC: [Location]."""
        macs = sorted({mac for tables in self.tables.values() for mac, _, _ in tables.fdb if query.matches(mac)})
        found = []
        for mac in macs:
            found += self.from_tables(query.text, normalize_mac(mac))
        return found

    # ----------------------------------------------------------------- An IP address or a name

    def router_arp(self, address):
        """The MAC an IP address has in the ARP table of a router (or layer 3 switch or firewall) with an interface
        in its subnet: asked for directly, else read whole. "" when none has it."""
        ip = ipaddress.ip_address(address)
        holders = []
        for key in self.switches(ARP_KINDS):
            for interface in self.map.devices[key].interfaces_l3:
                try:
                    network = ipaddress.ip_network(f"{interface[0]}/{interface[1]}", strict=False)
                except (ValueError, IndexError, TypeError):
                    continue
                if ip.version == network.version and ip in network and network.prefixlen < network.max_prefixlen:
                    holders.append((key, interface[2] if len(interface) > 2 else ""))
                    break
        octets = ".".join(str(number) for number in ip.packed)
        if self.ssh is not None and self.start is not None and self.start not in [key for key, _ in holders] \
                and self.readable(self.start, ARP_KINDS):
            holders.append((self.start, ""))  # With no map, the switch chosen to start at may route the subnet
        for key, port in holders:
            if self.should_stop():
                continue
            if not self.by_snmp(key):
                if self.ssh is not None:
                    self.events("step", f"{address}: asking {self.label(key)} for its MAC (ARP, over SSH)")
                    found = self.ssh.arp(self.map.devices[key].mgmt_ip, address, self.names(key)) or {}
                    mac = next((mac for mac, addresses in found.items() if address in addresses), "")
                    if mac:
                        return mac
                continue
            client, _ = self.clients[key]
            self.events("step", f"{address}: asking {self.label(key)} for its MAC (ARP)")
            try:
                names = self.interface_cache.get(key)
                if names is None:
                    names = collect.interface_names(list(client.walk(parse_oid(collect.IF_NAME),
                                                                     should_stop=self.should_stop)))
                    self.interface_cache[key] = names
                if_index = next((index for index, name in names.items() if port_key(name) == port_key(port)), None)
                if if_index is not None:
                    values = self.get(client, [parse_oid(f"{collect.ARP_PHYS_ADDRESS}.{if_index}.{octets}")])
                    mac = collect.mac_text(values[0][1].value) if values else ""
                    if mac:
                        return mac
                rows = list(client.walk(parse_oid(collect.ARP_PHYS_ADDRESS), should_stop=self.should_stop))
                for mac, addresses in collect.arp(rows).items():
                    if address in addresses:
                        return mac
            except (SnmpError, OSError) as error:
                log.info("MAC Finder: ARP of %s: %s", self.label(key), error)
        return ""

    def mac_for_ip(self, address, hints=()):
        """(MAC, how it was found) for an IP address, or ("", "")."""
        if self.tables is not None:
            for tables in self.tables.values():
                for mac, addresses in tables.arp.items():
                    if address in addresses:
                        return mac, "ARP"
        if self.arp_lookup is not None:
            try:
                mac = self.arp_lookup(address)
            except OSError:
                mac = None
            if mac:
                return format_mac(mac), "this computer's ARP"
        mac = self.router_arp(address)
        if not mac and self.ssh is not None and not self.over_ssh and not self.should_stop():
            self.over_ssh = True  # Not in an ARP table SNMP read: ask the routers at their command line
            try:
                mac = self.router_arp(address)
            finally:
                self.over_ssh = False
        if mac:
            return mac, "ARP"
        known = next((location for location in hints if location.mac), None)
        if known is not None:
            return known.mac, "the map"
        return "", ""

    # ----------------------------------------------------------------- Searches

    def run(self, queries, hints=None):
        """Look for each query (parse_query's) on the network now. hints: {index: [Location]} where the map has each.
        Returns {index: ([Location], problem)}, and says each as it's found ("result" events)."""
        hints = hints or {}
        results = {}
        quick = [query for index, query in enumerate(queries) if query.kind != MAC_PART and not hints.get(index)]
        if any(query.kind == MAC_PART for query in queries) or len(quick) >= TABLE_READ_AT:
            self.read_all_tables()
        for index, query in enumerate(queries):
            if self.should_stop():
                break
            if self.tables is None and self.fan_outs >= TABLE_READ_AT:
                self.read_all_tables()  # Many MACs that weren't where the map had them: read everything once
            try:
                found, problem = self.run_one(query, hints.get(index) or [])
            except (SnmpError, OSError) as error:
                found, problem = [], str(error)
            if self.should_stop() and not found:
                break
            results[index] = (found, problem)
            self.events("result", index, found, problem)
        return results

    def run_one(self, query, hints):
        if query.kind == MAC_PART:
            found = self.search_tables(query)
            if not found and self.ssh is not None and not self.ssh_tables_read and not self.should_stop():
                self.events("step", f"Nothing with {query.digits} in the MAC tables read over SNMP: reading them "
                                    "over SSH")
                self.read_tables_over_ssh()
                found = self.search_tables(query)
            return found, ""
        if query.kind == MAC_FULL:
            hint = next((location for location in hints if location.mac == query.mac), None)
            return self.locate_mac(query.text, query.digits, hint), ""
        address, how = query.address, ""
        if query.kind == NAME:
            named = next((location for location in hints if location.mac), None)
            if named is not None:
                return self.locate_mac(query.text, normalize_mac(named.mac), named), ""
            self.events("step", f"{query.text}: looking up its address (DNS)")
            address = self.resolve(query.text)
            if not address:
                return [], f"{query.text} isn't a name DNS knows (or the map has)."
        mac, how = self.mac_for_ip(address, hints)
        if not mac:
            return [], (f"No ARP table NOMAD could read has {address}" +
                        (f" ({query.text})" if query.kind == NAME else "") +
                        ": it may be off, or on a subnet whose router isn't on the map.")
        hint = next((location for location in hints if location.mac == mac), None)
        found = self.locate_mac(query.text, normalize_mac(mac), hint, ip=address)
        for location in found:
            location.ip = address
            if how == "the map":
                location.note = " ".join(filter(None, [location.note, "Its MAC is the one the map had for that "
                                                                      "address (no ARP table had it now)."]))
        return found, ""
