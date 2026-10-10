"""The logical (L3) view: routers, L3 switches and firewalls joined through the subnets they have addresses in,
the next hops their routes point to, and the paths traceroute found to what SNMP couldn't show.

Traceroute (ICMP) fills in what SNMP can't: routers that don't answer SNMP, next hops outside the crawl, and the
way to static routes' destinations.
"""
import ipaddress
from dataclasses import dataclass

from .model import NETWORK_KINDS, NO_SNMP, SNMP, UNREACHABLE, Link, short_port

TRACE_HOPS = 20
TRACE_TIMEOUT_MS = 1000
GIVE_UP_AFTER = 4  # Silent hops in a row before a trace stops (a firewall dropping it)
MAX_TRACES = 64
SELF = "self"  # This computer, where traces start

# Node kinds
DEVICE, SUBNET, HOP, STAR = "device", "subnet", "hop", "star"


@dataclass
class L3Node:
    key: str
    kind: str
    label: str
    detail: str = ""
    device: object = None  # The Device, for device nodes
    tone: str = ""  # A theme color for a subnet's outline (what Subnet Placement found), or "" for the usual


def owned_addresses(network_map):
    """Address -> device key, for every address a device on the map is known to have."""
    owned = {}
    for key, device in network_map.devices.items():
        for address in [device.mgmt_ip] + list(device.addresses) + [item[0] for item in device.interfaces_l3]:
            if address:
                owned.setdefault(address, key)
    return owned


def _address(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


# ----------------------------------------------------------------- Traceroute

def trace(address, echo, max_hops=TRACE_HOPS, should_stop=lambda: False):
    """Traceroute with one probe per hop. echo(address, ttl) returns an icmp.EchoReply. Returns (hops, reached),
    hops being the address that answered at each TTL, or "" where nothing did."""
    from ..icmp import TTL_EXPIRED_STATUSES
    hops, silent = [], 0
    for ttl in range(1, max_hops + 1):
        if should_stop():
            break
        reply = echo(address, ttl)
        if reply.ok:
            hops.append(reply.address or address)
            return hops, True
        if reply.address and reply.status in TTL_EXPIRED_STATUSES:
            hops.append(reply.address)
            silent = 0
        elif reply.address:  # A router saying the destination can't be reached: the path ends there
            hops.append(reply.address)
            break
        else:
            hops.append("")
            silent += 1
            if silent >= GIVE_UP_AFTER:
                break
    while hops and not hops[-1]:
        hops.pop()
    return hops, False


def icmp_echo(address, ttl):
    """One echo request with a TTL, from this computer (Windows' ICMP API)."""
    from ..icmp import IcmpClient
    with IcmpClient(4) as client:
        return client.echo(address, timeout=TRACE_TIMEOUT_MS, ttl=ttl)


def trace_targets(network_map, in_scope=lambda address: True, limit=MAX_TRACES):
    """What to trace, most useful first, as [(address, reason)]: devices that didn't answer SNMP, next hops that
    aren't on the map, and the first address of each static route's destination."""
    owned = owned_addresses(network_map)
    targets = {}
    devices = sorted(network_map.devices.values(), key=lambda device: device.label.lower())
    for device in devices:
        if device.source in (NO_SNMP, UNREACHABLE) and device.mgmt_ip:
            targets.setdefault(device.mgmt_ip, f"{device.label} didn't answer SNMP")
    for device in devices:
        for destination, next_hop, _, _ in device.routes:
            if next_hop and next_hop not in owned:
                targets.setdefault(next_hop, f"Next hop in {device.label}'s routes")
    for device in devices:
        for destination, next_hop, _, protocol in device.routes:
            network = ipaddress.ip_network(destination)
            if protocol == "static" and next_hop and network.version == 4 and 8 <= network.prefixlen <= 30:
                first = str(network.network_address + 1)
                if first not in owned:
                    targets.setdefault(first, f"Static route {destination} on {device.label}")
    return [(address, reason) for address, reason in targets.items() if in_scope(address)][:limit]


# ----------------------------------------------------------------- The graph

def subnet_key(network):
    return f"net:{network}"


def l3_graph(network_map):
    """The nodes and links of the logical view: ({key: L3Node}, [Link])."""
    nodes, links = {}, []
    subnets = {}  # ip_network -> [(device key, port, address)]
    for key, device in network_map.devices.items():
        for address, prefix, port in device.interfaces_l3:
            ip = _address(address)
            if ip is None or ip.is_loopback or ip.is_link_local or ip.is_unspecified or prefix >= ip.max_prefixlen:
                continue  # Loopbacks and /32s don't join anything; 0.0.0.0 is a placeholder (pfSense lists one)
            network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            subnets.setdefault(network, []).append((key, port, address))

    def add_device(key):
        device = network_map.devices[key]
        nodes.setdefault(key, L3Node(key, DEVICE, device.label, device.mgmt_ip, device))

    def containing(address):
        ip = _address(address)
        matches = [network for network in subnets if ip is not None and ip.version == network.version
                   and ip in network]
        return max(matches, key=lambda network: network.prefixlen) if matches else None

    for network, members in sorted(subnets.items(), key=lambda item: (item[0].version, item[0])):
        key = subnet_key(network)
        nodes[key] = L3Node(key, SUBNET, str(network))
        for device_key, port, address in members:
            add_device(device_key)
            links.append(Link(device_key, f"{short_port(port)} {address}".strip(), key, "", ["l3"]))

    # Routers and firewalls that weren't read, on the subnet their address is in
    for key, device in network_map.devices.items():
        if key in nodes or device.source == SNMP or device.kind not in NETWORK_KINDS or not device.mgmt_ip:
            continue
        network = containing(device.mgmt_ip)
        if network is not None:
            add_device(key)
            links.append(Link(key, device.mgmt_ip, subnet_key(network), "", ["l3"]))

    owned = owned_addresses(network_map)
    next_hops = {}  # Next hops that aren't a device on the map -> [(device label, destination)]
    for device in network_map.devices.values():
        for destination, next_hop, _, _ in device.routes:
            if next_hop and next_hop not in owned:
                next_hops.setdefault(next_hop, []).append((device.label, destination))
    for address, routes in sorted(next_hops.items(), key=lambda item: ipaddress.ip_address(item[0])):
        network = containing(address)
        if network is None:
            continue  # Not on any subnet we know: shown if a trace reaches it
        key = f"hop:{address}"
        nodes[key] = L3Node(key, HOP, address, f"Next hop for {len(routes)} route{'' if len(routes) == 1 else 's'}")
        links.append(Link(key, "", subnet_key(network), "", ["l3"]))

    if network_map.traces:
        nodes[SELF] = L3Node(SELF, HOP, "This computer", "Where the traceroutes started")
    for trace_result in network_map.traces:
        previous = SELF
        for number, address in enumerate(trace_result.hops, start=1):
            if not address:
                key = f"star:{trace_result.target}:{number}"
                nodes[key] = L3Node(key, STAR, "*", f"No answer at hop {number} toward {trace_result.target}")
            elif address in owned:
                key = owned[address]
                add_device(key)
            else:
                key = f"hop:{address}"
                if key not in nodes:
                    nodes[key] = L3Node(key, HOP, address, "Found by traceroute")
            if key != previous:
                links.append(Link(previous, "", key, "", ["icmp"]))
            previous = key

    on_subnets = {}  # Node -> the subnets it's on
    for link in links:
        if link.protocols == ["l3"]:
            on_subnets.setdefault(link.a, set()).add(link.b)
    unique = {}
    for link in links:
        if link.protocols == ["icmp"] and on_subnets.get(link.a, set()) & on_subnets.get(link.b, set()):
            continue  # A hop between two routers on the same subnet: the subnet already shows it
        unique.setdefault(link.key, link)
    return nodes, list(unique.values())


def subnet_details(network_map, network_text):
    """(devices on it as [(label, port, address)], hosts on the map with addresses in it)."""
    network = ipaddress.ip_network(network_text)
    members = []
    for device in network_map.devices.values():
        for address, prefix, port in device.interfaces_l3:
            ip = _address(address)
            if ip is not None and ip.version == network.version and ip in network and prefix < ip.max_prefixlen:
                members.append((device.label, short_port(port), address))
    hosts = [host for host in network_map.hosts
             if host.ip and _address(host.ip) is not None and _address(host.ip).version == network.version
             and _address(host.ip) in network]
    return sorted(members), hosts
