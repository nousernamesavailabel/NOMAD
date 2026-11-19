"""What each subnet is for, its role: a VLAN's subnet, a point-to-point link, loopbacks, a tunnel, a routed port's
subnet, a container (a block holding other subnets), or other (its purpose isn't known yet). Not every subnet is in
a VLAN, so the VLANs and Subnet Placement pages only expect VLAN things of VLAN subnets, and the placement checks
know a tunnel's or a point-to-point link's ends are one place, however far apart they are on the map.

A role is worked out (detect) from what the network map shows (the interfaces with addresses in it: a tunnel or
loopback interface, an SVI or subinterface, a routed port plugged into a switch's access VLAN, the two ends of a
link), then from IPAM (a loopback subnet, a /32, a /30 or /31, subnets inside it, a name such as Vlan 6) and the
VLANs page (linked to a VLAN). Anyone can set it instead (SubnetRole, kept beside the placements in the IPAM
database, never on the subnet), Other included.
"""
import ipaddress
import re
from dataclasses import dataclass

from ..netmap.model import port_key
from ..netmap.placement import places as map_places
from ..netmap.vlans import ACCESS, port_info
from .vlans import vlan_named_in

AUTO = "auto"
VLAN, POINT_TO_POINT, LOOPBACK, TUNNEL, ROUTED, CONTAINER, OTHER = \
    "vlan", "point-to-point", "loopback", "tunnel", "routed", "container", "other"
ROLE_NAMES = {VLAN: "VLAN", POINT_TO_POINT: "Point-to-point", LOOPBACK: "Loopbacks", TUNNEL: "Tunnel",
              ROUTED: "Routed port", CONTAINER: "Container", OTHER: "Other"}
ROLE_HELP = {
    VLAN: "a LAN in a VLAN (an SVI, a router's subinterface, or a port in a switch's access VLAN)",
    POINT_TO_POINT: "a link between two devices (a /30 or /31, a WAN circuit): its two ends are one place",
    LOOPBACK: "loopback addresses (each a /32 or /128 of its own, on one device)",
    TUNNEL: "a GRE, DMVPN or IPsec tunnel: every end of it is one place",
    ROUTED: "on a routed port that isn't in a VLAN (a firewall's or router's interface)",
    CONTAINER: "a block holding other subnets, not on an interface itself",
    OTHER: "its purpose isn't known yet: nothing is expected of it",
}
NOT_IN_VLANS = (POINT_TO_POINT, LOOPBACK, TUNNEL, ROUTED, CONTAINER)  # Not offered for linking to VLANs at first
ONE_PLACE = (POINT_TO_POINT, TUNNEL)  # All their places are one, wherever the map has them
# Interfaces that make a role plain whatever else is said: what a subnet on them is set to be is checked against it
LOOPBACK_PORT = re.compile(r"^(lo|loopback)[\d./:]*$", re.IGNORECASE)
TUNNEL_PORT = re.compile(r"^(tu|tunnel)[\d./:]*$", re.IGNORECASE)


def port_role(port):
    """LOOPBACK or TUNNEL for a loopback or tunnel interface (Loopback0, loopback.1, Tunnel10, tunnel.5), else ""."""
    port = (port or "").strip()
    if LOOPBACK_PORT.match(port):
        return LOOPBACK
    if TUNNEL_PORT.match(port):
        return TUNNEL
    return ""


def two_device_prefix(network):
    """A /30 or /31 (/126 or /127): room for the two ends of a link only."""
    return network.prefixlen >= network.max_prefixlen - 2 and network.prefixlen < network.max_prefixlen


def single_address(network):
    return network.prefixlen == network.max_prefixlen


def _label(network_map, key):
    device = network_map.devices.get(key) if network_map is not None else None
    return device.label if device is not None else key


def _where(network_map, places, limit=3):
    text = ", ".join(f"{_label(network_map, place.device)} {place.port}" for place in places[:limit])
    return text + (f" and {len(places) - limit} more" if len(places) > limit else "")


def access_vlan(network_map, place):
    """The access VLAN of the switch port a routed port is plugged into, as (VLAN, switch key, switch port), or
    None: a router's or firewall's port in a switch's VLAN puts its subnet in that VLAN."""
    if network_map is None or place.vlan:
        return None
    wanted = port_key(place.port)
    for link in network_map.links_of(place.device):
        if port_key(link.port_on(place.device)) != wanted:
            continue
        other = network_map.devices.get(link.other(place.device))
        if other is None:
            continue
        info = port_info(other, link.port_on(other.key))
        if info.get("mode") == ACCESS and info.get("vlan"):
            return info["vlan"], other.key, link.port_on(other.key)
    return None


def _link_ends(network_map, places):
    """Whether two places on two devices are the two ends of one link on the map."""
    if network_map is None or len(places) != 2 or places[0].device == places[1].device:
        return False
    one, other = places
    for link in network_map.links_of(one.device):
        if link.other(one.device) == other.device and \
                port_key(link.port_on(one.device)) == port_key(one.port.split(".")[0]) and \
                port_key(link.port_on(other.device)) == port_key(other.port.split(".")[0]):
            return True
    return False


def map_role(network, places, network_map):
    """(role, why) from where the map has addresses in the subnet (netmap.placement.Place), or ("", "") when it has
    none."""
    if not places:
        return "", ""
    tunnels = [place for place in places if port_role(place.port) == TUNNEL]
    if tunnels:
        return TUNNEL, f"on tunnel interfaces on the map: {_where(network_map, tunnels)}"
    loopbacks = [place for place in places if port_role(place.port) == LOOPBACK]
    if loopbacks:
        return LOOPBACK, f"on loopback interfaces on the map: {_where(network_map, loopbacks)}"
    in_vlans = [place for place in places if place.vlan]
    if in_vlans:
        numbers = ", ".join(str(number) for number in sorted({place.vlan for place in in_vlans}))
        return VLAN, f"in VLAN {numbers} on the map: {_where(network_map, in_vlans)}"
    for place in places:
        attached = access_vlan(network_map, place)
        if attached is not None:
            vlan, switch, port = attached
            return VLAN, (f"{_label(network_map, place.device)} {place.port} is plugged into VLAN {vlan} on "
                          f"{_label(network_map, switch)} {port}")
    if two_device_prefix(network):
        return POINT_TO_POINT, f"a /{network.prefixlen} on routed ports on the map: {_where(network_map, places)}"
    if _link_ends(network_map, places):
        return POINT_TO_POINT, f"the two ends of a link on the map: {_where(network_map, places)}"
    return ROUTED, f"on routed ports on the map: {_where(network_map, places)}"


def detect(cidr, subnet=None, places=(), network_map=None, linked=(), inner=(), pool=None):
    """(role, why) for a subnet, worked out from the map and IPAM.

    subnet: the IPAM Subnet, if it's one; places: the map's netmap.placement.Places in it; linked: the VLANs (numbers)
    it's linked to on the VLANs page; inner: IPAM subnets inside it; pool: IPAM's loopback subnet holding it (for a
    single address)."""
    network = ipaddress.ip_network(cidr)
    if subnet is not None and subnet.loopbacks:
        return LOOPBACK, "IPAM has it as a loopback subnet"
    if pool is not None:
        return LOOPBACK, f"in IPAM's loopback subnet {pool.cidr}" + (f" ({pool.name})" if pool.name else "")
    role, why = map_role(network, list(places), network_map)
    if role:
        return role, why
    if linked:
        return VLAN, f"linked to VLAN {', '.join(str(number) for number in sorted(set(linked)))} on the VLANs page"
    if subnet is not None:
        number = vlan_named_in(subnet.name)
        if number:
            return VLAN, f"its name is {subnet.name}"
        for key, value in subnet.fields.items():
            number = vlan_named_in(str(value))
            if number:
                return VLAN, f"its {key} says {value}"
    if single_address(network):
        return LOOPBACK, f"a /{network.prefixlen} is a single address"
    if two_device_prefix(network):
        return POINT_TO_POINT, f"a /{network.prefixlen} has room for the two ends of a link only"
    if inner:
        return CONTAINER, f"{len(inner)} IPAM subnet{'s are' if len(inner) != 1 else ' is'} inside it"
    return OTHER, "nothing on the map or in IPAM says what it's for yet"


@dataclass
class RoleInfo:
    role: str  # What it's treated as: the one set, else the one detected
    why: str
    detected: str  # What the map and IPAM suggest
    detected_why: str
    set: object = None  # The SubnetRole someone set, or None
    on_map: str = ""  # What the map alone shows ("" when it doesn't have it)
    on_map_why: str = ""

    @property
    def name(self):
        return ROLE_NAMES.get(self.role, self.role)

    @property
    def text(self):
        """"Tunnel", or "Tunnel (set)" when someone set it."""
        return self.name + (" (set)" if self.set is not None else "")

    def mismatch(self):
        """Why the role set doesn't fit what the map shows (a tunnel, a loopback, or neither), or ""."""
        if self.set is None or not self.on_map or self.role in (OTHER, CONTAINER):
            return ""

        def kind(role):
            return role if role in (TUNNEL, LOOPBACK) else "lan"

        if kind(self.role) == kind(self.on_map):
            return ""
        return f"Set as {ROLE_NAMES[self.role].lower()}, but it's {self.on_map_why}."


def role_info(cidr, set_role=None, **evidence):
    """RoleInfo for a subnet: the role set (SubnetRole, or None) over the one detect() works out from evidence."""
    detected, detected_why = detect(cidr, **evidence)
    on_map, on_map_why = map_role(ipaddress.ip_network(cidr), list(evidence.get("places", ())),
                                  evidence.get("network_map"))
    if set_role is not None:
        why = f"set by {set_role.modified_by}; the map and IPAM suggest {ROLE_NAMES[detected].lower()} ({detected_why})"
        return RoleInfo(set_role.role, why, detected, detected_why, set_role, on_map, on_map_why)
    return RoleInfo(detected, detected_why, detected, detected_why, None, on_map, on_map_why)


def loopback_pool(subnets, network):
    """The IPAM loopback subnet holding a single address (a /32 or /128 on the map), or None."""
    if not single_address(network):
        return None
    holding = [subnet for subnet in subnets if subnet.loopbacks and subnet.network.version == network.version
               and network.subnet_of(subnet.network)]
    return max(holding, key=lambda subnet: subnet.network.prefixlen, default=None)


def inside(subnet, subnets):
    """The other IPAM subnets inside one."""
    network = subnet.network
    return [other for other in subnets if other.id != subnet.id and other.network.version == network.version
            and other.network != network and other.network.subnet_of(network)]


def inside_all(subnets):
    """inside() for every subnet at once: {subnet id: [the other IPAM subnets inside it]}, in the order given. Each
    subnet looks up the ones around it rather than going through them all."""
    subnets = list(subnets)
    by_network, lengths = {}, {}
    for subnet in subnets:
        network = subnet.network
        by_network.setdefault(_block_key(network, network.prefixlen), []).append(subnet)
        lengths.setdefault(network.version, set()).add(network.prefixlen)
    lengths = {version: sorted(found) for version, found in lengths.items()}
    found = {}
    for subnet in subnets:  # In order, so each list keeps it
        network = subnet.network
        for prefix in lengths[network.version]:
            if prefix >= network.prefixlen:
                break
            for other in by_network.get(_block_key(network, prefix), []):
                found.setdefault(other.id, []).append(subnet)
    return found


def _block_key(block, prefix):
    """What identifies the subnet of a prefix length holding a Block: (IP version, its leading bits, the length)."""
    bits = 32 if block.version == 4 else 128
    return block.version, int(block.first) >> (bits - prefix), prefix


def subnet_roles(ipam_store, placement_store, vlan_store, network_id, network_map=None):
    """{CIDR: RoleInfo} for an IPAM network's subnets, from the map (or None) and what's set."""
    subnets = ipam_store.subnets(network_id)
    found = {}
    for (_, cidr), place_list in (map_places(network_map).items() if network_map is not None else []):
        found.setdefault(cidr, []).extend(place_list)
    linked = {}
    for domain in vlan_store.domains():
        if domain.network_id == network_id:
            for vlan in vlan_store.vlans(domain.id):
                for cidr in vlan.subnets:
                    linked.setdefault(cidr, []).append(vlan.vlan)
    roles = placement_store.roles(network_id)
    inner = inside_all(subnets)
    return {subnet.cidr: role_info(subnet.cidr, roles.get(subnet.cidr), subnet=subnet,
                                   places=found.get(subnet.cidr, []), network_map=network_map,
                                   linked=linked.get(subnet.cidr, []), inner=inner.get(subnet.id, []))
            for subnet in subnets}
