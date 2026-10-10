"""Where each subnet lives on a network map, and whether it's advertised: what the Subnet Placement page checks.

A subnet is *connected* where a device has an address in it (an SVI, a routed port, a subinterface). Places that are
one L2 segment count as one place: two switches with SVIs in the same VLAN carried between them (HSRP or VRRP), the
two ends of a point-to-point link, a router's port and the switch VLAN it's plugged into.

A subnet is *advertised* when devices other than where it's connected have a route to exactly it (learned by a routing
protocol, or a static route): then it must be in one place only. One no other device has a route to is *local*, and
may be reused in several places. One only covered by a summary (a shorter route, not the default) is local too, with
the summary noted. Each route to it is followed hop by hop to where it leads (its origin), so routers reaching it in
two different places show up, and the devices the routes end at are the ones advertising it. The others with an
address in it are only attached to it (a switch's management SVI, say). Addresses in it that no device on the map
has, but that routes use as next hops, are routers on it the map couldn't read (they may advertise it too), and so
may be devices that didn't answer SNMP linked to it.

Everything is per VRF: the same subnet in two VRFs is two subnets. "" is the global routing table.
"""
import ipaddress
from dataclasses import dataclass, field

from .model import port_key
from .vlans import ACCESS, ONE_END, bdi_vlan, carries, focus, port_info, subinterface_vlan, svi_vlan

GLOBAL = ""  # The global routing table, as a VRF name
MAX_HOPS = 16
CONNECTED_PROTOCOLS = {"connected", "local"}


def vrf_text(vrf):
    return vrf or "global"


@dataclass
class Place:
    """A device's address in a subnet."""
    device: str  # Device key
    port: str
    address: str
    prefix: int
    vrf: str = GLOBAL
    vlan: int = 0  # The VLAN of an SVI, bridge-domain interface or subinterface (guessed from the latter two's
    # names), else 0


@dataclass
class Learned:
    """A device's route to a subnet."""
    device: str
    next_hop: str
    port: str
    protocol: str
    origin: object = None  # Index of the segment it leads to, or None (beyond the map, or a loop)
    beyond: str = ""  # Where it leaves the map: the next hop no device on it has
    origin_device: str = ""  # The device it leads to (which has the subnet connected): one advertising it


@dataclass
class MapSubnet:
    vrf: str
    cidr: str
    segments: list = field(default_factory=list)  # [[Place]]: the places, one list per L2 segment
    learned: list = field(default_factory=list)  # [Learned]: other devices' routes to exactly this subnet
    summaries: list = field(default_factory=list)  # [(summary CIDR, [device keys])] covering it, when not learned
    routes_unknown: list = field(default_factory=list)  # Device keys in this VRF whose routes couldn't be read
    # Addresses in it no device on the map has, that routes use as next hops: {address: [device keys whose routes]}
    unseen: dict = field(default_factory=dict)
    # Devices that didn't answer SNMP linked to it: [(their key, the device on it, its port they're on)]
    unread: list = field(default_factory=list)

    @property
    def network(self):
        return ipaddress.ip_network(self.cidr)

    @property
    def advertised(self):
        """Whether other devices have a route to exactly it: None when nobody does but some routes couldn't be read
        (so it may be)."""
        if self.learned:
            return True
        return None if self.routes_unknown else False

    @property
    def protocols(self):
        return sorted({route.protocol for route in self.learned})

    @property
    def origins(self):
        """Segments the routes to it lead to."""
        return sorted({route.origin for route in self.learned if route.origin is not None})

    @property
    def advertisers(self):
        """Devices on the map the routes to it lead to: the ones advertising it (as far as the map shows)."""
        return sorted({route.origin_device for route in self.learned if route.origin_device})

    def role(self, network_map, device_key):
        """What a device with an address in it does with it: advertises it, routes (but no route here leads through
        it), or has an address only (no routing table)."""
        if device_key in self.advertisers:
            return "advertises it"
        device = network_map.devices.get(device_key)
        if device is not None and not device.routes and not device.vrf_routes:
            return "address only (it doesn't route)"
        return "has it connected"


def port_vrf(device, port):
    """The VRF a device's port is in ("" for the global table)."""
    if not device.port_vrfs:
        return GLOBAL
    if port in device.port_vrfs:
        return device.port_vrfs[port]
    wanted = port_key(port)
    return next((vrf for name, vrf in device.port_vrfs.items() if port_key(name) == wanted), GLOBAL)


def places(network_map):
    """Every place a device has an address: {(VRF, CIDR): [Place]}."""
    found = {}
    for key, device in network_map.devices.items():
        for address, prefix, port in device.interfaces_l3:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.network_address.is_unspecified and network.prefixlen == 0:
                continue  # 0.0.0.0/0: a placeholder some devices list (pfSense, for an interface's unset address)
            vrf = port_vrf(device, port)
            vlan = svi_vlan(port) or bdi_vlan(port) or subinterface_vlan(port)
            found.setdefault((vrf, str(network)), []).append(Place(key, port, address, int(prefix), vrf, vlan))
    return found


class _Segments:
    """Union-find over where addresses attach to L2: (device, VLAN) for SVIs and subinterfaces, (device, port) for
    routed ports, joined by the links carrying a VLAN and by links between routed and access ports."""

    def __init__(self, network_map):
        self.network_map = network_map
        self.parent = {}
        self.vlans_done = set()

    def find(self, node):
        self.parent.setdefault(node, node)
        while self.parent[node] != node:
            self.parent[node] = self.parent[self.parent[node]]
            node = self.parent[node]
        return node

    def join(self, one, other):
        self.parent[self.find(one)] = self.find(other)

    @staticmethod
    def node(place):
        if place.vlan:
            return place.device, "vlan", place.vlan
        return place.device, "port", port_key(place.port.split(".")[0])

    def add_vlan(self, vlan):
        """Join the devices the links carrying a VLAN connect (once per VLAN)."""
        if vlan in self.vlans_done:
            return
        self.vlans_done.add(vlan)
        carried = focus(self.network_map, vlan).links
        for link in self.network_map.links:
            if carried.get(id(link)) not in (None, ONE_END):
                self.join((link.a, "vlan", vlan), (link.b, "vlan", vlan))

    def add_routed_links(self):
        """A routed port joins whatever's at the other end of its link: another routed port, or the access VLAN of
        a switch port."""
        devices = self.network_map.devices
        for link in self.network_map.links:
            ends = []
            for key, port in ((link.a, link.a_port), (link.b, link.b_port)):
                info = port_info(devices[key], port) if key in devices else {}
                if info.get("mode") == ACCESS and info.get("vlan"):
                    ends.append((key, "vlan", info["vlan"]))
                else:
                    ends.append((key, "port", port_key(port)))
            self.join(*ends)

    def add_shared_links(self, place_list):
        """Two devices linked directly, each with an address in the subnet, are on one segment when each end of the
        link can carry it: the addressed port itself (or the port a subinterface is on), or a switch port carrying the
        SVI's VLAN (or one whose VLANs aren't known). Such as two routers on a transit subnet, OSPF neighbors over it,
        reaching each other through something the map can't see (a hypervisor's bridge tagging the VLAN)."""
        by_device = {}
        for place in place_list:
            by_device.setdefault(place.device, []).append(place)
        if len(by_device) < 2:
            return
        devices = self.network_map.devices
        for link in self.network_map.links:
            if link.a == link.b or link.a not in by_device or link.b not in by_device:
                continue
            ends = []
            for key, port in ((link.a, link.a_port), (link.b, link.b_port)):
                place = next((place for place in by_device[key] if self.carries(devices.get(key), place, port)), None)
                if place is None:
                    break
                ends.append(self.node(place))
            if len(ends) == 2:
                self.join(*ends)

    @staticmethod
    def carries(device, place, port):
        """Whether a device's port (a link's end) can carry its address in place."""
        if port_key(place.port.split(".")[0]) == port_key(port):
            return True  # The addressed port, or the one a subinterface is on
        if not place.vlan or device is None:
            return False
        info = port_info(device, port)
        if info:
            return bool(carries(info, place.vlan))
        # Its VLANs weren't read: it may carry the VLAN, unless it's a routed port (one with an address of its own)
        return not any(port_key(item[2].split(".")[0]) == port_key(port) for item in device.interfaces_l3)

    def group(self, place_list):
        self.add_shared_links(place_list)
        for place in place_list:
            if place.vlan:
                self.add_vlan(place.vlan)
        roots = {}
        for place in place_list:
            roots.setdefault(self.find(self.node(place)), []).append(place)
        return list(roots.values())


def _routing_tables(network_map):
    """{(device key, VRF): {destination: [(next hop, port, protocol)]}} for the tables that were read."""
    tables = {}
    for key, device in network_map.devices.items():
        for vrf, routes in [(GLOBAL, device.routes)] + list(device.vrf_routes.items()):
            if vrf == GLOBAL and not routes and device.source != "snmp":
                continue
            table = tables.setdefault((key, vrf), {})
            for destination, next_hop, port, protocol in routes:
                table.setdefault(destination, []).append((next_hop, port, protocol))
    return tables


def analyze(network_map):
    """Every subnet a device on the map has an address in, per VRF: [MapSubnet] by VRF then address."""
    found = places(network_map)
    segments = _Segments(network_map)
    segments.add_routed_links()
    tables = _routing_tables(network_map)
    owners = {}  # Address -> device key
    for key, device in network_map.devices.items():
        for address in [device.mgmt_ip] + list(device.addresses) + [item[0] for item in device.interfaces_l3]:
            if address:
                owners.setdefault(address, key)
    vrfs_unread = {}  # VRF -> devices with ports in it whose routes in it weren't read
    for key, device in network_map.devices.items():
        for vrf in set(device.port_vrfs.values()):
            if vrf not in device.vrf_routes:
                vrfs_unread.setdefault(vrf, []).append(key)
    learned_by_vrf = {}  # VRF -> [(network, device, next hop, port, protocol)] of every learned route
    for (key, vrf), table in tables.items():
        for destination, entries in table.items():
            for next_hop, port, protocol in entries:
                if next_hop or protocol not in CONNECTED_PROTOCOLS:
                    learned_by_vrf.setdefault(vrf, []).append((destination, key, next_hop, port, protocol))

    results = []
    for (vrf, cidr), place_list in sorted(found.items(), key=lambda item: (item[0][0],
                                                                            ipaddress.ip_network(item[0][1]))):
        network = ipaddress.ip_network(cidr)
        subnet = MapSubnet(vrf, cidr, segments.group(place_list), routes_unknown=sorted(vrfs_unread.get(vrf, [])))
        here = {place.device for place in place_list}
        segment_of = {place.device: number for number, group in enumerate(subnet.segments) for place in group}
        covering = {}
        for destination, key, next_hop, port, protocol in learned_by_vrf.get(vrf, []):
            if key in here:
                continue  # Connected there: its own routes to it don't make it advertised
            if destination == cidr:
                subnet.learned.append(Learned(key, next_hop, port, protocol))
            else:
                other = ipaddress.ip_network(destination)
                if 0 < other.prefixlen < network.prefixlen and other.version == network.version and \
                        network.subnet_of(other):
                    covering.setdefault(destination, set()).add(key)
        if not subnet.learned:
            subnet.summaries = [(destination, sorted(keys)) for destination, keys in
                                sorted(covering.items(), key=lambda item: ipaddress.ip_network(item[0]).prefixlen,
                                       reverse=True)]
        for route in subnet.learned:
            route.origin, route.beyond, route.origin_device = _follow(route, vrf, cidr, tables, owners, here,
                                                                      segment_of)
        for (key, table_vrf), table in tables.items():
            if table_vrf != vrf:
                continue
            for entries in table.values():
                for next_hop, _, _ in entries:
                    if next_hop and next_hop not in owners and _in(next_hop, network):
                        subnet.unseen.setdefault(next_hop, set()).add(key)
        subnet.unseen = {address: sorted(keys) for address, keys in
                         sorted(subnet.unseen.items(), key=lambda item: ipaddress.ip_address(item[0]))}
        subnet.unread = _unread_neighbors(network_map, place_list)
        results.append(subnet)
    return results


def _in(address, network):
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def _unread_neighbors(network_map, place_list):
    """Devices that didn't answer SNMP linked to a device with an address in the subnet, on a port that can carry
    it: they may be on it too."""
    devices = network_map.devices
    found = []
    for place in place_list:
        for link in network_map.links_of(place.device):
            other = devices.get(link.other(place.device))
            port = link.port_on(place.device)
            if other is None or other.source == "snmp" or other.key == place.device:
                continue
            if _Segments.carries(devices.get(place.device), place, port) and \
                    (other.key, place.device, port) not in found:
                found.append((other.key, place.device, port))
    return found


def _follow(route, vrf, cidr, tables, owners, here, segment_of):
    """Follow a route hop by hop to where it leads: (the segment it reaches, or None; the next hop where it leaves
    the map; the device it ends at, which has the subnet connected)."""
    next_hop, seen = route.next_hop, {route.device}
    for _ in range(MAX_HOPS):
        if not next_hop:
            return None, "", ""
        device = owners.get(next_hop)
        if device is None:
            return None, next_hop, ""
        if device in here:
            return segment_of.get(device), "", device
        if device in seen:
            return None, "", ""  # A loop
        seen.add(device)
        entries = tables.get((device, vrf), {}).get(cidr)
        if not entries:
            return None, "", ""
        next_hop = entries[0][0]
    return None, "", ""


def place_text(network_map, place):
    device = network_map.devices.get(place.device)
    label = device.label if device is not None else place.device
    return f"{label} {place.port}"


def segment_text(network_map, segment):
    """"sw1 Vl102 + sw2 Vl102 (VLAN 102)"."""
    names = " + ".join(place_text(network_map, place) for place in segment)
    vlans = sorted({place.vlan for place in segment if place.vlan})
    return names + (f" (VLAN {', '.join(str(vlan) for vlan in vlans)})" if vlans else "")
