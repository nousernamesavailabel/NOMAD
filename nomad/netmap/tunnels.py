"""The tunnels between the map's devices, from what the crawl read over SNMP: each device's tunnel interfaces with
their two ends (TUNNEL-MIB) and, on Cisco, its IKE sessions that are up (CISCO-IPSEC-FLOW-MONITOR-MIB).

A point-to-point tunnel (GRE, IPsec VTI) names its far end: the device that has that address is at the other end. A
multipoint tunnel (DMVPN's mGRE) names none: its peers are the IKE sessions from its address (a hub's spokes, a
spoke's hubs and the spokes it has a shortcut to now), unless a point-to-point tunnel from the same address to the
same peer (not down) explains the session. A far end that isn't on the map (or is only known by an address NAT
changes) isn't drawn. IOS XE doesn't fill in the NHRP tables over SNMP, so a router in a DMVPN cloud with no session
to its hub is found by its tunnel subnet instead (the hub: the one with the most sessions in it).

Whether each is up: both tunnel interfaces up, and when it's protected, an IKE session up between the two ends. While
monitoring, each poll reads the routers' tunnel interfaces' status and IKE sessions again (poll), and what it read
(live) is used over what the crawl read.

Qt-free.
"""
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from types import SimpleNamespace

from ..snmp import SnmpError, parse_oid
from . import collect
from .model import SNMP, port_key

UP, DOWN, NEGOTIATING, UNKNOWN = "up", "down", "negotiating", "unknown"  # As vpnstatus says them
STATE_TEXT = {UP: "up", DOWN: "down", NEGOTIATING: "up, but IPsec isn't", UNKNOWN: "not known (an end wasn't read)"}


@dataclass
class Tunnel:
    a: str  # Device key
    a_port: str  # Its tunnel interface (short name)
    b: str
    b_port: str = ""  # "" when the far end's tunnels weren't read
    a_address: str = ""  # The ends' addresses (each one's tunnel source)
    b_address: str = ""
    multipoint: bool = False
    ipsec: bool = False
    state: str = UNKNOWN

    def text(self, network_map):
        a, b = network_map.devices[self.a], network_map.devices[self.b]
        kind = "multipoint (DMVPN)" if self.multipoint else "point-to-point"
        protection = " over IPsec" if self.ipsec else ""
        far = f"{b.label} {self.b_port}".strip()
        return f"Tunnel {a.label} {self.a_port} to {far}: {kind}{protection}, {STATE_TEXT[self.state]}"


def tunnel_key(name):
    """For matching a tunnel interface however it's written (Tu100, Tunnel100)."""
    key = port_key(name)
    return "tu" + key[len("tunnel"):] if key.startswith("tunnel") else key


def owners(network_map):
    """{address: device key} of every address the map's devices have."""
    found = {}
    for key, device in network_map.devices.items():
        for address in [device.mgmt_ip] + list(device.addresses) + [item[0] for item in device.interfaces_l3]:
            if address:
                found.setdefault(address, key)
    return found


def far_port(device, address, toward):
    """The far device's tunnel from address: the one pointing back at toward, else a multipoint one there."""
    multipoint = ""
    for port, end in device.tunnels.items():
        if end.get("local") != address:
            continue
        if end.get("remote") == toward:
            return port
        if not end.get("remote"):
            multipoint = multipoint or port
    return multipoint


def oper(device, port):
    """A tunnel interface's status as read: "up", "down", or "" when its status wasn't read."""
    if not device.port_status:
        return ""
    entry = device.port_status.get(port)
    return "down" if entry is None else ("up" if entry.get("oper") == "up" else "down")  # Absent: shut down


def ike_up(device, local, remote):
    """True or False when the device's IKE sessions were read, None otherwise."""
    if not device.ike_read:
        return None
    return [local, remote] in device.ike_sessions


def state_of(network_map, tunnel):
    a, b = network_map.devices[tunnel.a], network_map.devices[tunnel.b]
    ends = [oper(a, tunnel.a_port), oper(b, tunnel.b_port) if tunnel.b_port else ""]
    if "down" in ends:
        return DOWN
    sessions = [ike_up(a, tunnel.a_address, tunnel.b_address), ike_up(b, tunnel.b_address, tunnel.a_address)]
    if tunnel.ipsec and True in sessions:
        return UP
    if tunnel.ipsec and False in sessions:
        return NEGOTIATING if "up" in ends else UNKNOWN
    if ends == ["up", "up"] and not tunnel.ipsec:
        return UP
    return UNKNOWN


def find(network_map, live=None):
    """[Tunnel] between the map's devices, each once. live: what monitoring read last (see poll), over the crawl's."""
    if network_map is None:
        return []
    network_map = with_live(network_map, live)
    owner = owners(network_map)
    found, seen = [], set()
    for key, device in sorted(network_map.devices.items()):  # (Each the same way round, whatever the order read)
        for port, end in device.tunnels.items():
            local, remote = end.get("local", ""), end.get("remote", "")
            if not local:
                continue
            if remote:
                peers = [remote]
            else:
                explained = {item.get("remote") for other, item in device.tunnels.items()  # (Not one that's down)
                             if other != port and item.get("local") == local and item.get("remote") and
                             oper(device, other) != "down"}
                peers = [far for near, far in device.ike_sessions if near == local and far not in explained]
            for address in peers:
                other = owner.get(address)
                if other is None or other == key:
                    continue
                other_port = far_port(network_map.devices[other], address, local)
                pair = frozenset([(key, port, local), (other, other_port, address)])
                if pair in seen:
                    continue
                seen.add(pair)
                far = network_map.devices[other].tunnels.get(other_port, {})
                tunnel = Tunnel(key, port, other, other_port, local, address,
                                multipoint=not remote or (bool(far) and not far.get("remote")),  # (Phase 1 spoke)
                                ipsec=bool(end.get("ipsec") or far.get("ipsec")))
                tunnel.state = state_of(network_map, tunnel)
                found.append(tunnel)
    return found + silent_spokes(network_map, found)


def silent_spokes(network_map, found):
    """[Tunnel] from a DMVPN hub to the routers in its cloud that have no IKE session with it (down, or IPsec not
    up), which the sessions alone wouldn't show. A cloud is the multipoint tunnels in one tunnel subnet; its hubs
    are the ones with the most sessions in it, at least two (fewer can't tell a hub from a spoke); with just two in
    it, they're each other's."""
    clouds = {}
    for key, device in sorted(network_map.devices.items()):
        ports = {tunnel_key(port): port for port in device.tunnels}
        for address, length, port in device.interfaces_l3:
            port = ports.get(tunnel_key(port), "")
            end = device.tunnels.get(port)
            if end is not None and not end.get("remote") and end.get("local"):
                try:
                    subnet = ipaddress.IPv4Interface(f"{address}/{length}").network
                except ValueError:
                    continue
                clouds.setdefault(subnet, []).append((key, port))
    added = []
    for members in clouds.values():
        if len(members) < 2:
            continue
        joined = {(tunnel.a, tunnel.a_port, tunnel.b, tunnel.b_port) for tunnel in found if tunnel.multipoint}
        joined |= {(b, b_port, a, a_port) for a, a_port, b, b_port in joined}
        counts = {member: sum(1 for other in members if member + other in joined) for member in members}
        most = max(counts.values())
        hubs = members if len(members) == 2 else [
            member for member in members if most >= 2 and counts[member] == most]
        for hub in hubs:
            device = network_map.devices[hub[0]]
            if not device.ike_read:
                continue  # Its sessions unknown: who's missing isn't
            for member in members:
                if member == hub or member + hub in joined or (len(members) == 2 and member < hub):
                    continue
                far = network_map.devices[member[0]]
                tunnel = Tunnel(hub[0], hub[1], member[0], member[1], device.tunnels[hub[1]]["local"],
                                far.tunnels[member[1]]["local"], multipoint=True,
                                ipsec=bool(device.tunnels[hub[1]].get("ipsec")))
                tunnel.state = state_of(network_map, tunnel)
                added.append(tunnel)
    return added


def lines(network_map, live=None):
    """[(device key, device key, state, what to say)] of the map's tunnels (as the VPN Tunnels overlay takes them)."""
    return [(tunnel.a, tunnel.b, tunnel.state, tunnel.text(network_map)) for tunnel in find(network_map, live)]


def with_live(network_map, live):
    """The map's devices with what monitoring read last over what the crawl read (the map itself left as it is)."""
    if not live:
        return network_map
    devices = dict(network_map.devices)
    for key, reading in live.items():
        device = devices.get(key)
        if device is None:
            continue
        status = dict(device.port_status)
        for port, state in reading.get("status", {}).items():
            status[port] = dict(status.get(port, {}), oper=state)
        changes = {"port_status": status}
        if reading.get("ike") is not None:
            changes.update(ike_sessions=reading["ike"], ike_read=True)
        devices[key] = replace(device, **changes)
    return SimpleNamespace(devices=devices)


# ----------------------------------------------------------------- While monitoring

def tunnel_routers(network_map):
    """{device key: [tunnel interface]} of the devices with tunnels that answered SNMP."""
    return {key: list(device.tunnels) for key, device in network_map.devices.items()
            if device.tunnels and device.source == SNMP and device.mgmt_ip}


def read_ike(client):
    """[[local, remote]] of a router's IKE sessions up, or None when it hasn't CISCO-IPSEC-FLOW-MONITOR-MIB (or
    didn't say)."""
    if not list(client.walk(parse_oid(collect.IKE_ACTIVE_COUNT))):
        return None
    rows = []
    for number in collect.IKE_TUNNEL_COLUMNS:
        rows += list(client.walk(parse_oid(f"{collect.IKE_TUNNEL_ENTRY}.{number}")))
    entry = parse_oid(collect.IKE_TUNNEL_ENTRY)
    indexes = sorted({oid[len(entry) + 1:] for oid, _ in rows if oid[:len(entry)] == entry})
    for at in range(0, len(indexes), 20):  # Each session's status, by GET (see collect.IKE_TUNNEL_ENTRY)
        rows += client.get([entry + (collect.IKE_STATUS,) + index for index in indexes[at:at + 20]])
    return [list(item) for item in collect.ike_sessions(rows)]


def read_live(client, ports, index):
    """{"status": {tunnel interface: "up" or "down"}, "ike": read_ike's} of a router now. index: {port key:
    ifIndex}."""
    by_name = {tunnel_key(name): if_index for name, if_index in index.items()}
    wanted = {port: by_name[tunnel_key(port)] for port in ports if tunnel_key(port) in by_name}
    status = {}
    items = list(wanted.items())
    for at in range(0, len(items), 20):
        values = dict(client.get([parse_oid(f"{collect.IF_OPER_STATUS}.{if_index}")
                                  for _, if_index in items[at:at + 20]]))
        for port, if_index in items[at:at + 20]:
            value = values.get(parse_oid(f"{collect.IF_OPER_STATUS}.{if_index}"))
            if value is not None and isinstance(value.value, int):
                status[port] = "up" if value.value == 1 else "down"
    return {"status": status, "ike": read_ike(client)}


def poll(targets, indexes, client_factory, interface_index, workers=16):
    """Read every target's tunnels now: targets [(device key, address, credential, version, timeout, [tunnel
    interface])]; indexes {device key: interface index} read before (else read with interface_index(client)).
    Returns {device key: (its interface index, read_live's)}, leaving out devices that didn't answer."""
    def read(target):
        key, address, credential, version, timeout, ports = target
        try:
            client = client_factory(address, credential, version, timeout=timeout, retries=0)
            index = indexes.get(key)
            if index is None:
                index = interface_index(client)
            return key, index, read_live(client, ports, index)
        except (SnmpError, OSError, ValueError):
            return key, None, None

    if not targets:
        return {}
    found = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as executor:
        for key, index, reading in executor.map(read, targets):
            if index is not None:
                found[key] = (index, reading)
    return found


def by_ends(found):
    """{its two ends: Tunnel} (the same whichever end it was found from)."""
    return {frozenset([(tunnel.a, tunnel.a_port), (tunnel.b, tunnel.b_port)]): tunnel for tunnel in found}


def changes(network_map, before, after):
    """[what to say] of the tunnels whose state changed between two polls (before, after: by_ends's): one first seen
    is said when it isn't up, one no longer seen (a DMVPN peer whose session went) is said too."""
    said = []
    for name, tunnel in after.items():
        old = before.get(name)
        if (old is None and tunnel.state != UP) or (old is not None and old.state != tunnel.state):
            said.append(tunnel.text(network_map))
    for name, tunnel in before.items():
        if name not in after and all(key in network_map.devices for key in (tunnel.a, tunnel.b)):
            said.append(f"{tunnel.text(network_map).rsplit(', ', 1)[0]}: no longer seen (its IKE session went)")
    return said
