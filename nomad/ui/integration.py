"""The IP Addresses, VLANs and Subnet Placement pages and the Network Map, working as one.

Integration (one, on the main window) keeps:
- the network being worked on: choosing a network on one of the pages (or opening a map of it) chooses it on the
  others, so they all show the same network;
- which IPAM network each map is of (the map remembers it: NetworkMap.ipam_network), so the pages only check a
  network against a map of it;
- what's known about each subnet of a network (its role, the VLANs it's linked to, where the map has it, what's
  wrong: Subnet Placement's rows), worked out once and shared until something it's made from changes;
- links between the pages: nomad://... addresses in their details, opened by open_link.

Nothing here writes to IPAM's networks, subnets or addresses.
"""
import html
import ipaddress
import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QComboBox, QLabel

from ..ipam.map_compare import DEVICE, HOST, short_name, usable
from ..ipam.placement import SEVERITY_LABELS, PlacementStore, evaluate
from ..ipam.placement_team import TeamPlacementStore
from ..ipam.store import IpamError
from ..ipam.vlan_team import TeamVlanStore
from ..ipam.vlans import VlanStore
from ..netmap.l3 import owned_addresses
from ..netmap.placement import GLOBAL, places
from .ipam_dialogs import _EditDialog

log = logging.getLogger(__name__)

TEAM, LOCAL = "team", "local"  # Where networks come from, as the IP Addresses page names them
SCHEME = "nomad"
IPAM, VLAN, PLACEMENT, MAP_SUBNET, MAP_DEVICE = "ipam", "vlan", "placement", "map-subnet", "map-device"
MAP_PLACES = "map-places"  # Integration.cache key, with the network's


def network_key(source, network_id):
    return f"{source}:{network_id}" if network_id else ""


def split_key(key):
    """("team" or "local", network id) from "source:id"."""
    source, _, network_id = (key or "").partition(":")
    return source, network_id


def link(target, **params):
    """A nomad:// address that open_link goes to: target is IPAM, VLAN, PLACEMENT, MAP_SUBNET or MAP_DEVICE."""
    return f"{SCHEME}://{target}?" + urlencode({name: value for name, value in params.items() if value not in
                                                (None, "")})


def anchor(text, target, **params):
    """An HTML link to another page (for the pages' details)."""
    return f"<a href='{html.escape(link(target, **params), quote=True)}'>{html.escape(text)}</a>"


def hub(window):
    """The window's Integration, or None (a page on its own, as in a test)."""
    found = getattr(window, "__dict__", {}).get("integration") if window is not None else None
    return found if isinstance(found, Integration) else None


def map_subnets(network_map):
    """The subnets a map has addresses in."""
    return {cidr for _, cidr in places(network_map)} if network_map is not None else set()


def held_by(network_map, subnets):
    """How many of a map's subnets are an IPAM network's subnets (or inside one)."""
    blocks = [subnet.network for subnet in subnets]
    count = 0
    for cidr in map_subnets(network_map):
        network = ipaddress.ip_network(cidr)
        if any(network.version == block.version and network.subnet_of(block) for block in blocks):
            count += 1
    return count


@dataclass
class MapPlace:
    """Where an address is on a map: the devices with it (each "R1 Gi0/3"), or the switch ports a host with it is
    seen on."""
    device: str  # The map's device key to show: the first device with it, or the switch the host is on
    kind: str  # DEVICE or HOST
    where: list = field(default_factory=list)

    def text(self):
        places = ", ".join(self.where)
        return places if self.kind == DEVICE else f"Host on {places}" if places else "Host"


def map_places(network_map):
    """{address text: MapPlace} of every address a device on the map has (its interfaces', the one it's managed by)
    and of the hosts the switches see. A device's address is its own even when a host entry has it too."""
    found = {}
    for key, device in sorted(network_map.devices.items(), key=lambda item: item[1].label.lower()):
        name = short_name(device.label)
        ports = {}
        for address, _, port in device.interfaces_l3:
            ports.setdefault(address, port)
        for address in dict.fromkeys([device.mgmt_ip] + list(device.addresses) + list(ports)):  # Each once
            if address and usable(address):
                found.setdefault(address, MapPlace(key, DEVICE)).where.append(
                    f"{name} {ports[address]}" if address in ports else name)
    for host in network_map.hosts:
        if not host.ip or not usable(host.ip) or found.get(host.ip, MapPlace("", HOST)).kind == DEVICE:
            continue
        place = found.setdefault(host.ip, MapPlace(host.device, HOST))
        switch = network_map.devices.get(host.device)
        where = " ".join(part for part in (short_name(switch.label) if switch else host.device, host.port) if part)
        if where and where not in place.where:
            place.where.append(where)
    return found


class Facts:
    """What's known about a network's subnets: Subnet Placement's rows (role, VLANs linked, where the map has it,
    findings) by CIDR, the global routing table's first."""

    def __init__(self, rows, network_map):
        self.rows = rows
        self.network_map = network_map  # The map they were worked out with (of the network), or None
        self.with_map = network_map is not None
        self.by_cidr = {}
        for row in rows:
            if row.cidr not in self.by_cidr or row.vrf == GLOBAL:
                self.by_cidr[row.cidr] = row

    def row(self, cidr):
        return self.by_cidr.get(cidr)


class Integration(QObject):
    network_changed = pyqtSignal(str)  # The network now worked on: "source:id"
    facts_changed = pyqtSignal()  # Something the subnets' facts are made from changed (synced, the map, an edit)

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.network = ""
        self.origin = None  # The page that chose the network last
        self.cache = {}
        self.map_identity = None  # The map (and its network) the pages were last pointed at
        self.waiting_network = ""  # The open map's network, to show once IPAM's databases are open (at start)

    def connect_pages(self):
        """Once every page exists: hear what changes the facts."""
        window = self.window
        window.ipam_tab.tribe_synced.connect(self.invalidate)
        page = window.netmap_tab
        page.map_shown.connect(self.on_map_shown)
        page.routes_read.connect(self.on_routes_read)
        page.ipam_network_changed.connect(self.on_map_shown)
        self.network_changed.connect(self.tell_network)
        self.facts_changed.connect(self.tell_facts)

    def tell_network(self, key):
        """Each page shows the network chosen. A mistake on one page is logged, not let through: from a signal it
        would end NOMAD."""
        window = self.window
        for method in (window.ipam_tab.follow_network, window.vlan_tab.follow_network,
                       window.placement_tab.follow_network, window.netmap_tab.update_network_bar,
                       window.netmap_tab.on_facts_changed):
            try:
                method(key)
            except Exception:
                log.exception("Showing the network chosen on another page")

    def tell_facts(self):
        window = self.window
        for method in (window.ipam_tab.on_facts_changed, window.vlan_tab.on_facts_changed,
                       window.netmap_tab.on_facts_changed):
            try:
                method()
            except Exception:
                log.exception("Showing what changed about the subnets")

    # ----------------------------------------------------------------- The network worked on

    def choose_network(self, key, origin=None):
        """A page (origin) chose a network: the others follow."""
        if not key or key == self.network:
            return
        self.network, self.origin = key, origin
        self.network_changed.emit(key)

    def follows(self, page):
        """Whether a page should follow the network just chosen (not the page that chose it)."""
        return self.origin is not page

    def on_map_shown(self):
        """The map was drawn again: facts change. Another map opened (or the map's network was set): the pages
        show its network (not each time it's redrawn, by watching say, which would pull them back to it)."""
        self.invalidate()
        page, key = self.window.netmap_tab, self.map_network()
        network_map = page.network_map
        identity = (page.tribe_map_id, str(page.map_path), network_map.started if network_map else "", key)
        if identity == self.map_identity:
            return
        self.map_identity = identity
        if key and self.store_for(split_key(key)[0]) is not None:
            self.waiting_network = ""
            self.choose_network(key, page)
        else:
            self.waiting_network = key  # Reopened at start, before IPAM's databases are: shown when they are

    def stores_opened(self):
        """The IP Addresses page opened its databases (or connected to the tribe): show the network of the map that
        was opened before they were."""
        key, page = self.waiting_network, self.window.netmap_tab
        if key and self.store_for(split_key(key)[0]) is not None and page.network_map is not None and \
                page.network_map.ipam_network == key:
            self.waiting_network = ""
            log.info("Showing the network of the map opened at start: %s", key)
            self.choose_network(key, page)

    def on_routes_read(self, *_):
        self.invalidate()

    # ----------------------------------------------------------------- Stores

    def store_for(self, source):
        page = self.window.ipam_tab
        return page.team if source == TEAM else page.local_store

    def stores(self, source):
        """(IPAM store, VlanStore-like, PlacementStore-like, whether placement can be changed now), or Nones."""
        page = self.window.ipam_tab
        if source == TEAM and page.team is not None:
            placements = TeamPlacementStore(page.team)
            return page.team, TeamVlanStore(page.team), placements, placements.can_change
        if source == LOCAL and page.local_store is not None:
            store = page.local_store
            return store, VlanStore(store), PlacementStore(store), True
        return None, None, None, False

    def networks(self):
        """[(key, label, store, network)] of every network: the tribe's, then this computer's."""
        page = self.window.ipam_tab
        found = []
        for source, label, store in ((TEAM, "Tribe", page.team), (LOCAL, "Local", page.local_store)):
            if store is not None:
                found += [(network_key(source, network.id), f"{network.name}  ({label})", store, network)
                          for network in store.networks()]
        return found

    def network_name(self, key):
        store = self.store_for(split_key(key)[0])
        try:
            return store.network(split_key(key)[1]).name if store is not None and key else ""
        except IpamError:
            return ""

    # ----------------------------------------------------------------- The map

    def open_map(self):
        return getattr(getattr(self.window, "netmap_tab", None), "network_map", None)

    def map_network(self):
        """The IPAM network the open map is of ("source:id"), or ""."""
        network_map = self.open_map()
        return network_map.ipam_network if network_map is not None else ""

    def map_for(self, key):
        """The open map, if it's of this network (or nobody has said which network it's of), else None."""
        network_map = self.open_map()
        if network_map is None or (network_map.ipam_network and network_map.ipam_network != key):
            return None
        return network_map

    def suggested_network(self, network_map=None):
        """The network holding most of the map's subnets ("source:id"), or ""."""
        network_map = network_map or self.open_map()
        best, best_count = "", 0
        for key, _, store, network in self.networks():
            count = held_by(network_map, store.subnets(network.id))
            if count > best_count:
                best, best_count = key, count
        return best

    # ----------------------------------------------------------------- What's known about subnets

    def invalidate(self, *_):
        """Something the facts come from changed: work them out again when next asked, and tell the pages."""
        self.cache.clear()
        self.facts_changed.emit()

    def forget(self):
        """As invalidate, without telling the pages (the page that made the change shows it itself)."""
        self.cache.clear()

    def facts(self, key):
        """Facts for a network ("source:id"), or None when its store isn't open."""
        if not key:
            return None
        network_map = self.map_for(key)
        source, network_id = split_key(key)
        ipam, vlans, placements, _ = self.stores(source)
        if ipam is None:
            return None
        try:
            # Kept while the map and the network's subnets are the same (address changes don't matter here)
            subnets = tuple((subnet.id, subnet.version) for subnet in ipam.subnets(network_id))
            cached = self.cache.get(key)
            if cached is not None and cached[0] is network_map and cached[1] == subnets:
                return cached[2]
            facts = Facts(evaluate(network_map, ipam, vlans, placements, network_id), network_map)
        except IpamError:
            return None
        self.cache[key] = (network_map, subnets, facts)
        return facts

    # ----------------------------------------------------------------- Going to things on the pages

    def open_link(self, url):
        """Go to what a nomad:// link names. Returns whether it was one."""
        url = url.toString() if hasattr(url, "toString") else str(url)
        parts = urlsplit(url)
        if parts.scheme != SCHEME:
            return False
        params = dict(parse_qsl(parts.query))
        target, window = parts.netloc, self.window
        if target == IPAM:
            if params.get("ip"):
                window.ipam_tab.show_address(params.get("src"), params.get("net"), params["ip"])
            else:
                window.ipam_tab.go_to_subnet(params.get("src"), params.get("net"), params.get("cidr"))
        elif target == VLAN:  # A domain's VLAN, or a VLAN number found in a VTP domain or a network's domains
            window.vlan_tab.go_to_vlan(params.get("src"), params.get("domain"), int(params.get("vlan", 0) or 0),
                                       vtp=params.get("vtp", ""), network=params.get("net", ""))
        elif target == PLACEMENT:
            window.placement_tab.go_to_subnet(params.get("src"), params.get("net"), params.get("cidr"),
                                              params.get("vrf"), find=params.get("find", ""))
        elif target == MAP_SUBNET:
            window.netmap_tab.show_subnet(params.get("cidr"))
        elif target == MAP_DEVICE:
            window.netmap_tab.show_device(params.get("key"))
        return True

    def subnet_summary(self, key, cidr):
        """What the other pages know about a subnet, as HTML parts with links: its role, VLANs, placement, and where
        the map has it (for the IP Addresses page's subnet line)."""
        facts = self.facts(key)
        row = facts.row(cidr) if facts is not None else None
        if row is None:
            return []
        source, network_id = split_key(key)
        parts = [f"role: {html.escape(row.role.text.lower())}"]
        if row.planned:
            parts.append(", ".join(anchor(f"VLAN {vlan.vlan}" + (f" {vlan.name}" if vlan.name else ""), VLAN,
                                          src=source, domain=domain.id, vlan=vlan.vlan)
                                   for domain, vlan in row.planned))
        elif row.role.role == "vlan":
            parts.append("no VLAN linked")
        status = SEVERITY_LABELS.get(row.severity, "OK") if row.severity in ("problem", "warning") else "OK"
        parts.append(anchor(f"placement: {status}", PLACEMENT, src=source, net=network_id, cidr=cidr, vrf=row.vrf))
        if row.found is not None:
            count = len(row.found.segments)
            parts.append(anchor(f"on the map: {count} place{'s' if count != 1 else ''}", MAP_SUBNET, cidr=cidr))
        elif facts.with_map:
            parts.append("not on the map")
        return parts

    def map_device_for(self, key, address):
        """The device on the open map (of this network) with this address, or the switch a host with it is on."""
        network_map = self.map_for(key)
        if network_map is None or not address:
            return None
        owner = owned_addresses(network_map).get(address)
        if owner is not None:
            return owner
        host = next((host for host in network_map.hosts if host.ip == address), None)
        return host.device if host is not None else None

    def map_places(self, key):
        """{address text: MapPlace} of every device and host address on the open map (of this network), or None
        when there's no such map. Worked out once per map (until it's redrawn)."""
        network_map = self.map_for(key)
        if network_map is None:
            return None
        cached = self.cache.get((MAP_PLACES, key))
        if cached is not None and cached[0] is network_map:
            return cached[1]
        found = map_places(network_map)
        self.cache[(MAP_PLACES, key)] = (network_map, found)
        return found

    def subnet_links(self, key, cidr, row=None, skip=()):
        """HTML links to a subnet on the other pages: IP Addresses, its VLANs, Subnet Placement, the map."""
        source, network_id = split_key(key)
        row = row if row is not None else (self.facts(key) or Facts([], None)).row(cidr)
        parts = []
        if IPAM not in skip and row is not None and row.subnet is not None:
            parts.append(anchor("IP Addresses", IPAM, src=source, net=network_id, cidr=cidr))
        if VLAN not in skip and row is not None:
            parts += [anchor(f"VLAN {vlan.vlan}" + (f" {vlan.name}" if vlan.name else ""), VLAN, src=source,
                             domain=domain.id, vlan=vlan.vlan) for domain, vlan in row.planned]
        if PLACEMENT not in skip:
            parts.append(anchor("Subnet Placement", PLACEMENT, src=source, net=network_id, cidr=cidr,
                                vrf=row.vrf if row is not None else ""))
        if MAP_SUBNET not in skip and row is not None and row.found is not None:
            parts.append(anchor("Network Map", MAP_SUBNET, cidr=cidr))
        return parts


class MapNetworkDialog(_EditDialog):
    """Which IPAM network a map is of: the pages check that network against it (and only that one)."""

    def __init__(self, parent, integration, network_map, map_name):
        super().__init__(parent, "IPAM Network of the Map")
        self.network_map = network_map
        self.combo = QComboBox()
        self.combo.addItem("(none chosen: the pages use it with any network)", "")
        suggested = integration.suggested_network(network_map)
        for key, label, store, network in integration.networks():
            held = held_by(network_map, store.subnets(network.id))
            text = label + (f"  ({held} of the map's subnets)" if held else "")
            self.combo.addItem(text + ("  (suggested)" if key == suggested else ""), key)
        self.combo.setCurrentIndex(max(self.combo.findData(network_map.ipam_network or suggested), 0))
        intro = QLabel(f"The network {map_name} is of. The VLANs and Subnet Placement pages check this network's "
                       "subnets against the map, and choosing it on one of the pages opens it on the others. A map "
                       "is of one network (with any number of its subnets).")
        intro.setWordWrap(True)
        self.form.addRow(intro)
        self.form.addRow("IPAM network:", self.combo)
        self.finish_layout()

    def apply(self):
        return self.combo.currentData()
