"""What a network map holds: devices, the links between them, and the hosts on switch ports. Saved as JSON."""
import json
import re
from dataclasses import asdict, dataclass, field, fields, replace

FORMAT_VERSION = 1

# Kinds of device
SWITCH, ROUTER, FIREWALL, AP, PHONE, HOST, UNKNOWN = "switch", "router", "firewall", "ap", "phone", "host", "unknown"
SERVER = "server"  # Only set by hand: the crawl shows servers as hosts on their switch port
NETWORK_KINDS = {SWITCH, ROUTER, FIREWALL}  # Worth asking over SNMP, and whose links carry other devices' traffic
KIND_NAMES = {SWITCH: "Switch", ROUTER: "Router", FIREWALL: "Firewall", AP: "Access point", PHONE: "Phone",
              HOST: "Host", SERVER: "Server", UNKNOWN: "Unknown"}

# How a device was found
SNMP = "snmp"  # Answered SNMP: its neighbors, MAC and ARP tables were read
NEIGHBOR = "neighbor"  # Only in another device's CDP/LLDP (not asked: out of scope, too far, or not a network device)
NO_SNMP = "no-snmp"  # Answers ping but not SNMP (wrong community or an ACL)
UNREACHABLE = "unreachable"  # Answered neither SNMP nor ping
UNCHECKED = "unchecked"  # Added by hand and not asked yet (or it has no address to ask)
SOURCE_NAMES = {SNMP: "SNMP", NEIGHBOR: "Seen as a neighbor", NO_SNMP: "Pings, no SNMP", UNREACHABLE: "Unreachable",
                UNCHECKED: "Not checked"}
MANUAL_SOURCE_NAMES = {SNMP: "Added by hand, answers SNMP", NO_SNMP: "Added by hand, pings, no SNMP",
                       UNREACHABLE: "Added by hand, unreachable", UNCHECKED: "Added by hand"}

# Groups of devices on the map: sites, which can hold buildings, which can hold rooms (or workspaces)
SITE, BUILDING, ROOM = "site", "building", "room"
GROUP_KINDS = {SITE: "Site", BUILDING: "Building", ROOM: "Room"}
PARENT_KIND = {BUILDING: SITE, ROOM: BUILDING}  # The kind of group each kind can be in

CORRECTABLE = ("name", "mgmt_ip", "kind", "platform", "note")  # What can be corrected by hand on a device found
CORRECTED_NAMES = {"name": "Name", "mgmt_ip": "IP address", "kind": "Kind", "platform": "Model", "note": "Note"}

SHARED_PORT_HOSTS = 8  # More MACs than this on a port with no neighbor: probably an unmanaged switch or a hypervisor

PORT_PREFIXES = [  # Longest first, so TenGigabitEthernet isn't taken for GigabitEthernet
    ("hundredgigabitethernet", "Hu"), ("hundredgige", "Hu"), ("fortygigabitethernet", "Fo"),
    ("twentyfivegigabitethernet", "Twe"), ("twentyfivegige", "Twe"), ("tengigabitethernet", "Te"),
    ("fivegigabitethernet", "Fi"), ("twogigabitethernet", "Tw"), ("appgigabitethernet", "Ap"),
    ("gigabitethernet", "Gi"), ("fastethernet", "Fa"), ("port-channel", "Po"), ("ethernet", "Eth"),
    ("management", "Mgmt"), ("vlan", "Vl"),
]


def short_port(name):
    """Cisco's short interface names: GigabitEthernet1/0/1 -> Gi1/0/1, Ethernet1/1 -> Eth1/1. Others unchanged."""
    name = (name or "").strip()
    lower = name.lower()
    for prefix, short in PORT_PREFIXES:
        if lower.startswith(prefix) and len(name) > len(prefix) and (name[len(prefix)].isdigit()
                                                                    or name[len(prefix)] == " "):
            return short + name[len(prefix):].strip()
    return name


def port_key(name):
    """For matching the same port written two ways (Gi1/0/1, GigabitEthernet1/0/1, gi1/0/1; Et0/0, as IOS names an
    Ethernet port itself, and Eth0/0, from Ethernet0/0 as CDP gives it)."""
    key = short_port(name).lower().replace(" ", "")
    return "eth" + key[2:] if re.match(r"et\d", key) else key


def display_name(name):
    """A device name as CDP gives it, without the serial number some devices add: "sw1(FOC1234X0YZ)" -> "sw1"."""
    return re.sub(r"\(.*\)\s*$", "", (name or "").strip()).strip()


def normalize_name(name):
    """A device's name as a key: CDP's "core-sw1.corp.example(FOC1234X0YZ)" and LLDP's "core-sw1" are the same."""
    name = display_name(name)
    if re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", name):
        return name.lower()  # An address, not a host name
    return name.split(".")[0].lower()


@dataclass
class Device:
    key: str
    name: str = ""
    mgmt_ip: str = ""
    addresses: list = field(default_factory=list)
    kind: str = UNKNOWN
    platform: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    source: str = NEIGHBOR
    hops: int = 0
    error: str = ""
    interfaces_l3: list = field(default_factory=list)  # [[ip, prefix length, port]]
    routes: list = field(default_factory=list)  # [[destination, next hop ("" if connected), port, protocol]]
    routes_truncated: bool = False
    manual: bool = False  # Added by hand (an unmanaged switch, or one the crawl can't reach), kept when mapping again
    note: str = ""
    # On a device the crawl found: what was corrected by hand (a wrong address, kind or name), kept over what later
    # crawls find. {attribute: [what the crawl found, what it was corrected to]}
    corrected: dict = field(default_factory=dict)
    vtp_domain: str = ""
    vtp_mode: str = ""  # server, client, transparent or off
    vlans: list = field(default_factory=list)  # [[VLAN, name]]: the VLANs a switch has
    # Switch port (short name) -> {"mode": "access" or "trunk", "vlan": an access port's, "voice", "native",
    # "allowed": a trunk's VLANs as text, such as "1-10,20"} (numbers that are 0 are left out)
    port_vlans: dict = field(default_factory=dict)
    port_vrfs: dict = field(default_factory=dict)  # Port (short name) -> VRF, for the ports in one (else global)
    port_channels: dict = field(default_factory=dict)  # Port-channel member (short name) -> its port-channel's
    stp_mode: str = ""  # The spanning tree it runs: pvst, rapid-pvst, mst... ("" if unknown)
    # Port (short name) -> {"oper": "up", "down"..., "speed": Mb/s, "duplex": "full" or "half"}, for the ports not
    # shut down, as last read
    port_status: dict = field(default_factory=dict)
    # VRF -> [[destination, next hop, port, protocol]], like routes (which are the global table's). Only VRFs whose
    # routes could be read are here
    vrf_routes: dict = field(default_factory=dict)

    @property
    def label(self):
        return self.name or self.mgmt_ip or self.key

    def correct(self, attribute, value):
        """Correct what the crawl found; putting it back to what was found forgets the correction."""
        found = self.corrected[attribute][0] if attribute in self.corrected else getattr(self, attribute)
        if value == found:
            self.corrected.pop(attribute, None)
        else:
            self.corrected[attribute] = [found, value]
        setattr(self, attribute, value)

    def apply_corrections(self, corrections):
        """Corrections ({attribute: value}) made by hand on an earlier map, over what this crawl found."""
        for attribute, value in corrections.items():
            if attribute in CORRECTABLE:
                self.correct(attribute, value)

    def corrections(self):
        """{attribute: value} corrected by hand, for the next crawl."""
        return {attribute: value for attribute, (_, value) in self.corrected.items()}

    def forget_corrections(self):
        """Back to what the crawl found."""
        for attribute, (found, _) in self.corrected.items():
            setattr(self, attribute, found)
        self.corrected = {}

    @property
    def found_by(self):
        """For the Devices table and the details: how it got on the map, and whether it answers SNMP."""
        names = MANUAL_SOURCE_NAMES if self.manual else SOURCE_NAMES
        return names.get(self.source, self.source)

    def owns(self, address):
        """Whether the address is one of the device's."""
        return bool(address) and (address == self.mgmt_ip or address in self.addresses
                                  or any(item[0] == address for item in self.interfaces_l3))


@dataclass
class Link:
    a: str
    a_port: str
    b: str
    b_port: str
    protocols: list = field(default_factory=list)  # ["cdp"], ["lldp"] or both
    manual: bool = False  # Drawn by hand, kept when mapping again (until the crawl finds it)

    @property
    def key(self):
        return frozenset([(self.a, port_key(self.a_port)), (self.b, port_key(self.b_port))])

    def port_on(self, device):
        return self.a_port if device == self.a else self.b_port

    def other(self, device):
        return self.b if device == self.a else self.a


@dataclass
class Host:
    mac: str
    device: str  # The switch it was learned on
    port: str
    ip: str = ""
    vendor: str = ""
    vlan: int = 0
    name: str = ""  # From CDP/LLDP for phones and other end devices that announce themselves
    platform: str = ""
    manual: bool = False  # Added by hand (a device that's off or unplugged while mapping), kept when mapping again
    note: str = ""

    def same_as(self, other):
        """The same machine: by MAC, or by IP when either has no MAC."""
        if self.mac and other.mac:
            return self.mac == other.mac
        return bool(self.ip) and self.ip == other.ip


@dataclass
class Trace:
    """A traceroute from this computer: the address that answered at each hop ("" where none did)."""
    target: str
    hops: list = field(default_factory=list)
    reached: bool = False
    reason: str = ""  # Why it was traced: an unreachable device, a next hop, a static route


@dataclass
class Group:
    """A site, building or room drawn as a box round its devices. A room can be in a building and a building in
    a site; a site can't be in anything."""
    key: str
    name: str
    kind: str = SITE
    parent: str = ""  # A building's site or a room's building ("" if it isn't in one)
    # Drawn as one box, with its links to the rest of the map. On a tribe map, each person's own (not shared)
    collapsed: bool = False


@dataclass
class NetworkMap:
    devices: dict = field(default_factory=dict)  # key -> Device
    links: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    seeds: list = field(default_factory=list)
    started: str = ""
    finished: str = ""
    stopped: bool = False
    positions: dict = field(default_factory=dict)  # Device key -> [x, y] where the user left it
    root: str = ""  # Device laid out at the top, when the user chose one
    traces: list = field(default_factory=list)  # [Trace]
    l3_positions: dict = field(default_factory=dict)  # Node key -> [x, y] on the logical (L3) view
    status_log: list = field(default_factory=list)  # Monitoring: [[time, device key, label, up/down, text]]
    groups: list = field(default_factory=list)  # [Group]
    group_of: dict = field(default_factory=dict)  # Device key -> key of the group it's directly in
    # Devices the crawl found that were deleted by hand: left off (and not crawled through) when mapping again.
    # Device key -> [label, [its addresses]]
    deleted: dict = field(default_factory=dict)
    # Found by watching for new devices and not looked at yet: "device:<key>" or "host:<MAC>" ->
    # {"when": ISO time, "where": "SW1 Gi1/0/5", "by": who found it}
    news: dict = field(default_factory=dict)
    host_seen: dict = field(default_factory=dict)  # MAC -> date (ISO) last on the map, so a host back isn't "new"
    # The IPAM network the map is of, as the IP Addresses page names it: "team:<id>" (the tribe's) or "local:<id>"
    # (this computer's), or "" when nobody has said
    ipam_network: str = ""

    def add_link(self, link):
        """Add a link, merging it with the same link seen from the other end (or by the other protocol)."""
        for existing in self.links:
            if existing.key == link.key:
                for protocol in link.protocols:
                    if protocol not in existing.protocols:
                        existing.protocols.append(protocol)
                existing.manual = existing.manual and link.manual  # Drawn by hand, and now found for real
                return existing
        self.links.append(link)
        return link

    def merge_crawl(self, newer, hosts=True):
        """Add a crawl from part of the network (Crawl from Here) to this map. Devices it read replace what this map
        had for them; ones it only saw as neighbors don't replace devices this map read. Its links are added, and
        the switches it read get its hosts (hand-added ones stay, or give their name and note to the host found).
        Returns (new device keys, keys of devices it read)."""
        added = [key for key in newer.devices if key not in self.devices]
        read = {key for key, device in newer.devices.items() if device.source == SNMP}
        for key, device in newer.devices.items():
            old = self.devices.get(key)
            if old is None or device.source == SNMP or (old.source != SNMP and device.source != NEIGHBOR):
                if old is not None and old.corrected and not device.corrected:  # Corrected by hand: still is
                    device.apply_corrections(old.corrections())
                self.devices[key] = device
        for link in newer.links:
            self.add_link(Link(link.a, link.a_port, link.b, link.b_port, list(link.protocols)))
        if hosts:
            found_macs = {host.mac for host in newer.hosts if host.mac}
            kept = [host for host in self.hosts
                    if host.manual or (host.device not in read and host.mac not in found_macs)]
            new_hosts = list(newer.hosts)
            for manual in [host for host in kept if host.manual]:
                found = next((host for host in new_hosts if host.same_as(manual)), None)
                if found is not None:
                    found.name, found.note = found.name or manual.name, found.note or manual.note
                    kept.remove(manual)
            self.hosts = [host for host in kept + new_hosts if host.device in self.devices]
            self.hosts.sort(key=lambda host: (self.devices[host.device].label.lower(), port_key(host.port), host.mac))
            traces = {item.target: item for item in self.traces}
            traces.update({item.target: item for item in newer.traces})
            self.traces = list(traces.values())
            self.finished, self.stopped = newer.finished, newer.stopped
        self.fold_unread_devices(read, new=set(added))
        return [key for key in added if key in self.devices], read

    def preview_with(self, newer, positions=None):
        """This map with a crawl's devices and links so far added (for drawing Crawl from Here as it goes), leaving
        this map as it was. Devices added by hand that it has found are folded in, so the found one is drawn in their
        place (positions: where devices are drawn now, if not this map's)."""
        preview = NetworkMap(seeds=self.seeds, started=self.started, root=self.root,
                             positions=dict(self.positions if positions is None else positions))
        preview.devices = dict(self.devices)
        preview.links = [replace(link, protocols=list(link.protocols)) for link in self.links]
        preview.hosts = [replace(host) for host in self.hosts]
        preview.groups, preview.group_of = [replace(group) for group in self.groups], dict(self.group_of)
        added, _ = preview.merge_crawl(newer, hosts=False)
        preview.devices = {key: replace(device) for key, device in preview.devices.items()}  # Folding fills some in
        preview.fold_manual_devices(new=set(added))
        return preview

    # ----------------------------------------------------------------- Devices and links added by hand

    def new_device_key(self):
        number = 1
        while f"manual:{number}" in self.devices:
            number += 1
        return f"manual:{number}"

    def remove_devices(self, keys, remember=False):
        """Take devices off the map, with their links and hosts. remember: the ones the crawl found stay off it when
        mapping again (deleted), until brought back."""
        keys = set(keys)
        for key in keys:
            device = self.devices.get(key)
            if remember and device is not None and not device.manual:
                addresses = [device.mgmt_ip] + [address for address in device.addresses if address != device.mgmt_ip]
                self.deleted[key] = [device.label, [address for address in addresses if address]]
            self.devices.pop(key, None)
            self.positions.pop(key, None)
            self.l3_positions.pop(key, None)
        self.links = [link for link in self.links if link.a not in keys and link.b not in keys]
        self.hosts = [host for host in self.hosts if host.device not in keys]
        self.news = {ref: item for ref, item in self.news.items() if ref.partition(":")[2] not in keys
                     or not ref.startswith("device:")}
        if self.root in keys:
            self.root = ""
        self.prune_groups()

    def bring_back(self, keys):
        """Forget that devices were deleted, so the next crawl puts them back on the map."""
        for key in keys:
            self.deleted.pop(key, None)

    def carry_deleted(self, older):
        """Keep an earlier map's deleted devices off this one too (the crawl was told to leave them out). One the
        crawl was started from is on it again, so it isn't deleted any more."""
        self.deleted = {key: value for key, value in older.deleted.items() if key not in self.devices}

    def carry_manual(self, older):
        """Bring the devices and links added by hand to an earlier map of the network over to this one; a device the
        crawl has now found takes over its links (fold_manual_devices). Returns (the [(hand-added Device, found
        Device)] folded together, how many links drawn by hand were left out because an end isn't on this map)."""
        keys = {}
        for key, device in older.devices.items():
            if device.manual:
                keys[key] = key if key not in self.devices else self.new_device_key()
                self.devices[keys[key]] = replace(device, key=keys[key], addresses=list(device.addresses))
        left_out = 0
        for link in older.links:
            if not link.manual:
                continue
            a, b = keys.get(link.a, link.a), keys.get(link.b, link.b)
            if a in self.devices and b in self.devices:
                self.add_link(replace(link, a=a, b=b, protocols=list(link.protocols)))
            else:
                left_out += 1
        for host in (host for host in older.hosts if host.device in keys):  # Hosts added by hand on them
            found = next((item for item in self.hosts if not item.manual and item.same_as(host)), None)
            if found is not None:  # Found by the crawl elsewhere: it gets the name and note
                found.name, found.note = found.name or host.name, found.note or host.note
            else:
                self.hosts.append(replace(host, device=keys[host.device]))
        return self.fold_manual_devices(), left_out

    def found_for(self, manual):
        """The device a crawl found that a device added by hand is (by address, or by name), or None."""
        name = normalize_name(manual.name) if manual.name else ""
        for device in self.devices.values():
            if device.manual:
                continue
            if manual.mgmt_ip and device.owns(manual.mgmt_ip):
                return device
            if name and (normalize_name(device.name) == name or device.key == name):
                return device
        return None

    def fold_manual_devices(self, new=()):
        """Devices added by hand that a crawl has now found for real become the found ones: their links, hosts, place
        and group move over, and what the found one doesn't know (an address, a model, a note) is filled in. A link
        drawn by hand is dropped when the crawl found one between the same two devices. A found device in new (just
        added to the map, by Crawl from Here) takes the hand-added one's place rather than where the crawl drew it.
        Returns [(hand-added Device, found Device)]."""
        folded = []
        for key, manual in list(self.devices.items()):
            found = self.found_for(manual) if manual.manual else None
            if found is None:
                continue
            self.fold_device(key, found, new)
            folded.append((manual, found))
        return folded

    def fold_unread_devices(self, read, new=()):
        """Devices that didn't answer SNMP that a crawl has now read under another key become the read ones (as
        fold_manual_devices does): a seed that didn't answer is keyed by its address, and the same device seen as
        a neighbor by its name, and only reading it shows they're one. read: keys of the devices the crawl read.
        Returns [(Device folded in, read Device)]."""
        folded = []
        readers = [self.devices[key] for key in read if key in self.devices]
        for key, device in list(self.devices.items()):
            if device.manual or device.source == SNMP or key in read or not device.mgmt_ip:
                continue
            found = next((other for other in readers if other.key != key and other.owns(device.mgmt_ip)), None)
            if found is not None:
                self.fold_device(key, found, new)
                folded.append((device, found))
        return folded

    def fold_device(self, key, found, new=()):
        """Fold device key into found, the same device: its links, hosts, place and group move over, and what found
        doesn't know (a name, an address, a model, a note) is filled in. A link drawn by hand is dropped when there's
        a crawled one between the same two devices. A found device in new (just added to the map) takes key's
        place rather than where the crawl drew it."""
        old = self.devices[key]
        for attribute in ("name", "mgmt_ip", "platform", "note"):
            if not getattr(found, attribute):
                setattr(found, attribute, getattr(old, attribute))
        if found.kind == UNKNOWN:
            found.kind = old.kind
        crawled_pairs = {frozenset((link.a, link.b)) for link in self.links if not link.manual}
        links, self.links = self.links, []
        for link in links:
            if key in (link.a, link.b):
                link.a, link.b = (found.key if link.a == key else link.a), (found.key if link.b == key else link.b)
                if link.a == link.b or (link.manual and frozenset((link.a, link.b)) in crawled_pairs):
                    continue
            self.add_link(link)
        for host in self.hosts:
            if host.device == key:
                host.device = found.key
        for positions in (self.positions, self.l3_positions):
            if key in positions and (found.key in new or found.key not in positions):
                positions[found.key] = positions[key]
        if key in self.group_of:
            self.group_of.setdefault(found.key, self.group_of[key])
        if self.root == key:
            self.root = found.key
        self.remove_devices([key])

    def carry_manual_hosts(self, older):
        """Bring the hosts added by hand to an earlier map of the network over to this one. One that has since
        been found for real is left to the crawl, which gets its name and note. Returns the ones left out because
        their switch isn't on this map."""
        dropped = []
        for manual in (host for host in older.hosts if host.manual):
            if host_device_manual(older, manual):
                continue  # Came over with its device (carry_manual)
            found = next((host for host in self.hosts if not host.manual and host.same_as(manual)), None)
            if found is not None:
                found.name = found.name or manual.name
                found.note = found.note or manual.note
            elif manual.device in self.devices:
                self.hosts.append(manual)
            else:
                dropped.append(manual)
        self.hosts.sort(key=lambda host: (self.devices[host.device].label.lower(), port_key(host.port), host.mac))
        return dropped

    # ----------------------------------------------------------------- Groups

    def group(self, key):
        return next((group for group in self.groups if group.key == key), None)

    def new_group(self, name, kind=SITE, parent=""):
        used = {group.key for group in self.groups}
        number = 1
        while f"g{number}" in used:
            number += 1
        outer = self.group(parent)
        fits = outer is not None and outer.kind == PARENT_KIND.get(kind)  # A building in a site, a room in a building
        group = Group(f"g{number}", name, kind, parent if fits else "")
        self.groups.append(group)
        return group

    def subgroups(self, key):
        return [group for group in self.groups if group.parent == key]

    def group_chain(self, group):
        """The group and the groups it's in, outermost first: [site, building, room], or as much as there is."""
        chain = []
        while group is not None and group not in chain:
            chain.insert(0, group)
            group = self.group(group.parent)
        return chain

    def group_path(self, device_key):
        """The groups a device is in, outermost first, such as [], [site], [building] or [site, building, room]."""
        return self.group_chain(self.group(self.group_of.get(device_key, "")))

    def group_label(self, group):
        """"Site / Building / Room", or as much of that as the group is in."""
        return " / ".join(item.name for item in self.group_chain(group))

    def device_group_label(self, device_key):
        path = self.group_path(device_key)
        return self.group_label(path[-1]) if path else ""

    def members(self, key, deep=True):
        """Keys of the devices in a group (and, deep, in its buildings and their rooms)."""
        keys = {key}
        if deep:
            inner = [key]
            while inner:
                inner = [group.key for parent in inner for group in self.subgroups(parent) if group.key not in keys]
                keys.update(inner)
        return [device for device, group in self.group_of.items() if group in keys]

    def set_group(self, device_keys, key):
        """Put devices in a group, or take them out of theirs with key "". Empty groups are removed."""
        for device in device_keys:
            if key:
                self.group_of[device] = key
            else:
                self.group_of.pop(device, None)
        self.prune_groups()

    def remove_group(self, key):
        """Ungroup: a room's devices go to its building and a building's to its site; the groups that were in it
        stand on their own, and devices in a group that wasn't in anything are left in no group."""
        group = self.group(key)
        if group is None:
            return
        for inner in self.subgroups(key):
            inner.parent = ""
        for device in self.members(key, deep=False):
            if group.parent:
                self.group_of[device] = group.parent
            else:
                del self.group_of[device]
        self.groups.remove(group)
        self.prune_groups()

    def prune_groups(self):
        """Forget devices no longer on the map and groups with nothing in them."""
        kinds = {group.key: group.kind for group in self.groups}
        self.group_of = {device: group for device, group in self.group_of.items()
                         if device in self.devices and group in kinds}
        for group in self.groups:
            if group.kind not in PARENT_KIND or kinds.get(group.parent) != PARENT_KIND[group.kind]:
                group.parent = ""
        used = set(self.group_of.values())
        for kind in (ROOM, BUILDING):  # Innermost first, so a site holding only a building of rooms stays
            used |= {group.parent for group in self.groups if group.kind == kind and group.key in used}
        used.discard("")
        self.groups = [group for group in self.groups if group.key in used]

    def carry_groups(self, older, folded=()):
        """Bring an earlier map's sites, buildings and rooms over, with the devices still on this map in them.
        folded: carry_manual's [(hand-added Device, found Device)], whose found ones take the hand-added ones'
        place in them (unless the earlier map had them in one already)."""
        self.groups = [Group(**asdict(group)) for group in older.groups]
        self.group_of = dict(older.group_of)
        for manual, found in folded:
            if manual.key in self.group_of:
                self.group_of.setdefault(found.key, self.group_of[manual.key])
        self.prune_groups()

    def links_of(self, key):
        return [link for link in self.links if key in (link.a, link.b)]

    def hosts_by_port(self, key):
        """{port: [Host]} for one switch, in port order."""
        ports = {}
        for host in self.hosts:
            if host.device == key:
                ports.setdefault(host.port, []).append(host)
        return dict(sorted(ports.items(), key=lambda item: port_sort_key(item[0])))

    def to_json(self):
        data = asdict(self)
        data["devices"] = list(data["devices"].values())
        data["format"] = FORMAT_VERSION
        return json.dumps(data, indent=1)

    @classmethod
    def from_json(cls, text):
        data = json.loads(text)
        if not isinstance(data, dict) or "devices" not in data:
            raise ValueError("This isn't a NOMAD network map.")
        if data.get("format", 1) > FORMAT_VERSION:
            raise ValueError("This map was saved by a newer version of NOMAD.")
        network_map = cls(**{name: data[name] for name in ("seeds", "started", "finished", "stopped", "root",
                                                          "ipam_network") if name in data})
        network_map.devices = {item["key"]: _build(Device, item) for item in data["devices"]}
        network_map.links = [_build(Link, item) for item in data.get("links", [])]
        network_map.hosts = [_build(Host, item) for item in data.get("hosts", [])]
        network_map.positions = {key: tuple(value) for key, value in data.get("positions", {}).items()
                                 if key in network_map.devices}
        network_map.traces = [_build(Trace, item) for item in data.get("traces", [])]
        network_map.l3_positions = {key: tuple(value) for key, value in data.get("l3_positions", {}).items()}
        network_map.status_log = [list(entry) for entry in data.get("status_log", [])]
        network_map.groups = [_build(Group, item) for item in data.get("groups", [])]
        network_map.group_of = dict(data.get("group_of", {}))
        network_map.deleted = {key: [value[0], list(value[1])] for key, value in data.get("deleted", {}).items()}
        network_map.news = {ref: dict(value) for ref, value in data.get("news", {}).items()}
        network_map.host_seen = dict(data.get("host_seen", {}))
        network_map.prune_groups()
        return network_map


def host_device_manual(network_map, host):
    device = network_map.devices.get(host.device)
    return device is not None and device.manual


def _build(cls, data):
    """A dataclass from saved fields, ignoring any it doesn't have (from a later version)."""
    names = {item.name for item in fields(cls)}
    return cls(**{key: value for key, value in data.items() if key in names})


def port_sort_key(name):
    """Gi1/0/2 before Gi1/0/10."""
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", name or "")]


def normalize_vtp_domain(domain):
    """Treat IOS placeholders for an unset VTP domain as the empty domain."""
    domain = (domain or "").strip()
    return "" if domain.casefold() in {"(no vtp domain)", "null", "local-transparent"} else domain
