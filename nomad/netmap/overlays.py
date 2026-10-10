"""Overlays on the network map's physical view, beside Highlight VLAN: what one failure would cut off (and the
single points of failure), links whose two ends are set up differently, a VRF, a subnet, and coloring devices by
what they run or where they are.

Each is an Overlay worked out from the map alone: marks for devices (by key) and links (by id(Link), as the view
draws the map's own Link objects), the rest fading when it fades, and a legend.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from . import vlans as vlan_info
from .collect import BLOCKING, DISABLED, FORWARDING
from .model import AP, FIREWALL, KIND_NAMES, NETWORK_KINDS, ROUTER, SOURCE_NAMES, SWITCH, port_key

# Kinds of overlay
IMPACT, SPOF, TRUNKS, VRF, SUBNET, COLOR = "impact", "spof", "trunks", "vrf", "subnet", "color"
SPEED, STP, UTIL = "speed", "stp", "util"  # From what's read over SNMP: ports' status, a VLAN's tree, counters
# How a link's drawn
SOLID, DASH, DOT = "solid", "dash", "dot"
# Color By: what devices can be colored by, and what each is called
COLOR_BY = [("kind", "Kind"), ("platform", "Model"), ("version", "Software Version"), ("site", "Site"),
             ("vtp_domain", "VTP Domain"), ("vtp_mode", "VTP Mode"), ("stp_mode", "Spanning Tree"),
             ("source", "How It Was Found")]
COLOR_NAMES = dict(COLOR_BY)
# Distinct colors for Color By's values, most devices first; the rest share OTHER
PALETTE = ["#58a6ff", "#35f28b", "#f0b429", "#c792ea", "#ff6b6b", "#4ecdc4", "#ff9f43", "#f78fb3", "#a3e635",
           "#e6edf3"]
OTHER = "muted"
NONE_TEXT = "(not known)"
VERSION_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in (
    r"\bVersion\s+([\w.()\-]+[\w)])",  # Cisco IOS, IOS XE, NX-OS: "Version 15.2(4)E10, RELEASE SOFTWARE"
    r"\bPAN-OS\s+([\d.\-\w]+)",
    r"\bsw[_ ]?version[:=\s]+([\w.\-]+)",
    r"\b(?:firmware|software)[:\s]+v?(\d[\w.\-]+)",
)]
# Link Speed: (fastest speed in Mb/s, color, what it's called, line width), slowest first
SPEED_TIERS = [(100, "#ff9f43", "100 Mb/s or less", 2), (1000, "#58a6ff", "1 Gb/s", 3),
               (10000, "#4ecdc4", "2.5 to 10 Gb/s", 4.5), (40000, "#c792ea", "25 to 40 Gb/s", 5.5),
               (float("inf"), "#e6edf3", "100 Gb/s and up", 6.5)]
BUSY, FULL = 0.3, 0.7  # Utilization: a link this busy is amber, this busy red


@dataclass
class Mark:
    """How one device or link is shown: a color (a theme color's name, such as "error", or "#rrggbb"), what the
    tooltip says, and for a link how its line is drawn."""
    color: str
    note: str = ""
    style: str = SOLID
    width: float = 0  # A link's line width (0: as usual for an overlay)


@dataclass
class Overlay:
    kind: str
    title: str  # What the bar over the map says first, such as "If SW1 fails"
    devices: dict = field(default_factory=dict)  # Device key -> Mark
    links: dict = field(default_factory=dict)  # id(Link) -> Mark
    fade: bool = True  # What isn't marked fades
    summary: list = field(default_factory=list)  # Parts of what the bar says after the title
    legend: list = field(default_factory=list)  # [(color, what it means)]
    tone: str = ""  # "warning" or "error" when the overlay found something wrong ("" otherwise)


def count_text(count, noun):
    return f"{count} {noun}{'' if count == 1 else 's'}"


# ----------------------------------------------------------------- Failures

def adjacency(network_map, skip=()):
    """{device key: set of the device keys it's linked to}, leaving out the links in skip (ids of Links)."""
    devices = network_map.devices
    found = {key: set() for key in devices}
    for link in network_map.links:
        if id(link) in skip or link.a == link.b or link.a not in devices or link.b not in devices:
            continue
        found[link.a].add(link.b)
        found[link.b].add(link.a)
    return found


def reachable(graph, start, removed=frozenset()):
    """The devices start can reach in graph without going through any in removed."""
    if start in removed or start not in graph:
        return set()
    seen, todo = {start}, [start]
    while todo:
        for other in graph[todo.pop()]:
            if other not in seen and other not in removed:
                seen.add(other)
                todo.append(other)
    return seen


def pieces(graph, keys, removed=frozenset()):
    """keys split into the groups that can still reach each other, without the devices in removed."""
    left, found = set(keys) - set(removed), []
    while left:
        piece = reachable(graph, min(left), removed) & left
        found.append(piece)
        left -= piece
    return found


def anchors(network_map):
    """Where "cut off" is measured from, best first: the device put at the top, then the ones the map was started
    from."""
    found = [network_map.root] if network_map.root in network_map.devices else []
    seeds = set(network_map.seeds)
    for key, device in network_map.devices.items():
        if key not in found and seeds & ({device.mgmt_ip} | set(device.addresses)):
            found.append(key)
    return found


def main_piece(network_map, split, preferred=()):
    """Of the pieces a network is split into, the one still "connected": the one with the first of preferred (the
    anchors) in it, else the biggest (the one with the most network devices, if as big)."""
    for key in preferred:
        for piece in split:
            if key in piece:
                return piece
    devices = network_map.devices

    def size(piece):
        return (len(piece), sum(1 for key in piece if devices[key].kind in NETWORK_KINDS), -len(min(piece)))
    return max(split, key=size, default=set())


def cut_off(network_map, graph=None, device=None, links=(), anchor_keys=None):
    """The devices that would be cut off if a device (a key) or some links failed: those that could reach the main
    part of their network before and can't after. Returns (set of device keys, the key of the device the main part is
    known by, or "")."""
    skip = {id(link) for link in links}
    before = graph if graph is not None else adjacency(network_map)
    after = adjacency(network_map, skip) if skip else before
    removed = {device} if device is not None else set()
    start = device if device is not None else next((link.a for link in links if link.a in before), None)
    if start is None:
        return set(), ""
    whole = reachable(before, start)
    split = pieces(after, whole, removed)
    if len(split) <= 1:
        return set(), ""
    anchor_keys = anchors(network_map) if anchor_keys is None else anchor_keys
    usable = [key for key in anchor_keys if key in whole and key not in removed]
    main = main_piece(network_map, split, usable)
    known_by = next((key for key in usable if key in main), "")
    return set().union(*(piece for piece in split if piece is not main)), known_by


def host_counts(network_map):
    counts = {}
    for host in network_map.hosts:
        counts[host.device] = counts.get(host.device, 0) + 1
    return counts


def impact(network_map, device=None, links=()):
    """If a device (key) or a connection (the links between two devices) fails: what's cut off."""
    devices = network_map.devices
    lost, known_by = cut_off(network_map, device=device, links=links)
    hosts = host_counts(network_map)
    if device is not None:
        title = f"If {devices[device].label} fails"
        failed_links = {id(link) for link in network_map.links_of(device)}
    else:
        ends = sorted({end for link in links for end in (link.a, link.b) if end in devices})
        names = " and ".join(devices[key].label for key in ends)
        title = (f"If the link between {names} fails" if len(links) == 1
                 else f"If the {len(links)} links between {names} fail")
        failed_links = {id(link) for link in links}
    overlay = Overlay(IMPACT, title)
    if device is not None:
        overlay.devices[device] = Mark("error", "Fails")
    for link in network_map.links:
        if id(link) in failed_links:
            overlay.links[id(link)] = Mark("error", "Fails" if device is None else "Goes down with it", DASH)
            for end in (link.a, link.b):
                if end in devices and end != device and end not in lost:
                    overlay.devices.setdefault(end, Mark("muted", "Still connected"))
        elif link.a in lost or link.b in lost:
            overlay.links[id(link)] = Mark("error", "Cut off from the rest")
    for key in lost:
        overlay.devices[key] = Mark("error", f"Cut off{f' ({count_text(hosts[key], 'host')})' if key in hosts else ''}")
    if known_by and known_by not in lost:
        overlay.devices[known_by] = Mark("success", "Still connected: where the rest of the network is measured from")
    lost_hosts = sum(hosts.get(key, 0) for key in lost) + (hosts.get(device, 0) if device is not None else 0)
    if lost:
        kinds = sorted({devices[key].kind for key in lost}, key=lambda kind: (kind not in NETWORK_KINDS, kind))
        overlay.summary.append(f"{count_text(len(lost), 'device')} cut off "
                               f"({', '.join(KIND_NAMES.get(kind, kind).lower() for kind in kinds)})")
        overlay.tone = "error"
    else:
        overlay.summary.append("nothing else is cut off: every other device still has a way round")
    if lost_hosts:
        overlay.summary.append(f"{count_text(lost_hosts, 'host')} lose{'s' if lost_hosts == 1 else ''} the network")
    if lost and known_by:
        overlay.summary.append(f"measured from {devices[known_by].label}")
    overlay.summary.append("on the links the map knows (CDP, LLDP, drawn by hand)")
    overlay.legend = [("error", "fails, or is cut off"), ("success", "where the rest is measured from")]
    return overlay


def single_points(network_map):
    """Every device and connection whose failure alone would cut other devices off. Returns ({device key: [cut off
    keys]}, {(a, b) sorted pair: ([Link], [cut off keys])})."""
    graph = adjacency(network_map)
    anchor_keys = anchors(network_map)
    found_devices, found_links = {}, {}
    for key in network_map.devices:
        if len(graph[key]) < 2:
            continue  # At the edge: nothing hangs off it
        lost, _ = cut_off(network_map, graph, device=key, anchor_keys=anchor_keys)
        if lost:
            found_devices[key] = sorted(lost)
    pairs = {}
    for link in network_map.links:
        if link.a in graph and link.b in graph and link.a != link.b:
            pairs.setdefault(tuple(sorted((link.a, link.b))), []).append(link)
    for pair, links in pairs.items():
        lost, _ = cut_off(network_map, graph, links=links, anchor_keys=anchor_keys)
        if lost:
            found_links[pair] = (links, sorted(lost))
    return found_devices, found_links


def spof(network_map):
    """Single points of failure: the devices and connections that are the only way to part of the network."""
    devices = network_map.devices
    found_devices, found_links = single_points(network_map)
    hosts = host_counts(network_map)
    overlay = Overlay(SPOF, "Single points of failure")
    for key, lost in found_devices.items():
        lost_hosts = sum(hosts.get(other, 0) for other in lost)
        note = f"If it fails, {count_text(len(lost), 'device')} {'is' if len(lost) == 1 else 'are'} cut off"
        overlay.devices[key] = Mark("error" if any(devices[other].kind in NETWORK_KINDS for other in lost)
                                    else "warning", note + (f" ({count_text(lost_hosts, 'host')})" if lost_hosts
                                                            else ""))
    for (a, b), (links, lost) in found_links.items():
        bundle = f"all {len(links)} links of it, " if len(links) > 1 else ""
        note = f"The only way to {count_text(len(lost), 'device')} ({bundle}one path)"
        for link in links:
            overlay.links[id(link)] = Mark("warning", note)
        for end in (a, b):
            overlay.devices.setdefault(end, Mark("muted", "At the end of a single link"))
    network_devices = [key for key in found_devices if devices[key].kind in NETWORK_KINDS]
    if found_devices or found_links:
        overlay.summary.append(f"{count_text(len(found_devices), 'device')} "
                               f"({len(network_devices)} switches, routers or firewalls) and "
                               f"{count_text(len(found_links), 'connection')} "
                               f"{'is' if len(found_devices) + len(found_links) == 1 else 'are'} the only way to part "
                               "of the network")
        overlay.tone = "warning"
    else:
        overlay.summary.append("none: every device has more than one way to the rest of the network")
    anchor_keys = anchors(network_map)
    if anchor_keys:
        overlay.summary.append(f"measured from {devices[anchor_keys[0]].label}")
    overlay.summary.append("right-click a device or link > What If It Fails? for one")
    overlay.legend = [("error", "cuts off switches, routers or firewalls"), ("warning", "cuts off other devices, or "
                                                                                       "the only link")]
    return overlay


# ----------------------------------------------------------------- Trunks

def find_link(network_map, a, a_port, b, b_port):
    wanted = {(a, port_key(a_port)), (b, port_key(b_port))}
    return next((link for link in network_map.links if link.key == frozenset(wanted)), None)


def trunk_problems(network_map):
    """Links whose ends are set up differently (trunk at one end and access at the other, native VLANs or access
    VLANs that differ, VLANs allowed at one end only), and ports in VLANs their switch doesn't have."""
    overlay = Overlay(TRUNKS, "Trunk and port problems")
    findings = vlan_info.check_map(network_map)
    errors = warnings = 0
    for finding in findings:
        if finding.severity == vlan_info.INFO:
            continue
        color = "error" if finding.severity == vlan_info.ERROR else "warning"
        errors += color == "error"
        warnings += color == "warning"
        link = find_link(network_map, finding.device, finding.port, finding.other, finding.other_port) \
            if finding.other else None
        if link is not None:
            mark = overlay.links.get(id(link))
            if mark is None or (mark.color == "warning" and color == "error"):
                overlay.links[id(link)] = Mark(color, finding.text, DASH if color == "warning" else SOLID)
            elif finding.text not in mark.note:
                mark.note += "\n" + finding.text
            ends = (finding.device, finding.other)
        else:
            ends = (finding.device,)
        for key in ends:
            if key not in network_map.devices:
                continue
            mark = overlay.devices.get(key)
            if mark is None:
                overlay.devices[key] = Mark(color, finding.text)
            else:
                if color == "error":
                    mark.color = "error"
                if finding.text not in mark.note:
                    mark.note += "\n" + finding.text
    if errors or warnings:
        overlay.summary.append(", ".join(part for part in (count_text(errors, "problem") if errors else "",
                                                           count_text(warnings, "warning") if warnings else "")
                                         if part))
        overlay.summary.append("hover over a link or switch for what's wrong (all are on the VLANs tab)")
        overlay.tone = "error" if errors else "warning"
    else:
        known = sum(1 for device in network_map.devices.values() if device.port_vlans)
        overlay.summary.append("none found" if known else
                               "none found, but no switch's ports have been read (VLANs tab > Read VLANs Again)")
    overlay.legend = [("error", "trunk/access, native VLAN mismatch"), ("warning", "VLANs at one end only, others")]
    return overlay


# ----------------------------------------------------------------- VRFs and subnets

def map_vrfs(network_map):
    """The VRFs on the map: {name: number of devices with it}, by name."""
    found = {}
    for device in network_map.devices.values():
        for name in set(device.port_vrfs.values()) | set(device.vrf_routes):
            if name:
                found[name] = found.get(name, 0) + 1
    return dict(sorted(found.items(), key=lambda item: item[0].lower()))


def vrf(network_map, name):
    """A VRF: the devices with ports in it (or routes in it), and the links whose ports are in it."""
    overlay = Overlay(VRF, f"VRF {name}")
    devices = network_map.devices
    for key, device in devices.items():
        ports = sorted(port for port, vrf_name in device.port_vrfs.items() if vrf_name == name)
        routes = len(device.vrf_routes.get(name, []))
        if ports or name in device.vrf_routes:
            parts = [f"{count_text(len(ports), 'port')} in VRF {name}" + (f": {', '.join(ports[:8])}"
                                                                          f"{'...' if len(ports) > 8 else ''}"
                                                                          if ports else "")]
            if routes:
                parts.append(count_text(routes, "route"))
            overlay.devices[key] = Mark("accent", "; ".join(parts))
    in_vrf = {(key, port_key(port)) for key, device in devices.items()
              for port, vrf_name in device.port_vrfs.items() if vrf_name == name}
    for link in network_map.links:
        ends = [(link.a, port_key(link.a_port)) in in_vrf, (link.b, port_key(link.b_port)) in in_vrf]
        if all(ends):
            overlay.links[id(link)] = Mark("accent", f"In VRF {name} at both ends")
        elif any(ends):
            overlay.links[id(link)] = Mark("warning", f"In VRF {name} at one end only", DASH)
    addresses = sum(1 for device in devices.values() for _, _, port in device.interfaces_l3
                    if device.port_vrfs.get(port) == name)
    overlay.summary.append(f"{count_text(len(overlay.devices), 'device')}, {count_text(addresses, 'address')}"
                           f", {count_text(len(overlay.links), 'link')} in it")
    if any(mark.color == "warning" for mark in overlay.links.values()):
        overlay.tone = "warning"
    overlay.legend = [("accent", "in the VRF"), ("warning", "in it at one end only (dashed)")]
    return overlay


def map_subnets(network_map):
    """The subnets of the devices' interfaces on the map, in order."""
    found = set()
    for device in network_map.devices.values():
        for address, prefix, _ in device.interfaces_l3:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.prefixlen < network.max_prefixlen:
                found.add(network)
    return [str(network) for network in sorted(found, key=lambda network: (network.version, network))]


def parse_network(text):
    """A subnet typed (10.1.2.0/24, or an address alone: its /32). Raises ValueError."""
    return ipaddress.ip_network(text.strip(), strict=False)


def in_network(address, network):
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def subnet(network_map, text):
    """A subnet: its gateways (the interfaces with an address in it), the switches carrying their VLANs, the devices
    managed from it, and the switches with hosts in it."""
    network = parse_network(text)
    overlay = Overlay(SUBNET, f"Subnet {network}")
    devices = network_map.devices
    vlans_found = set()
    gateways = 0
    for key, device in devices.items():
        notes = []
        for address, prefix, port in device.interfaces_l3:
            if in_network(address, network):
                gateways += 1
                notes.append(f"{address}/{prefix} on {port}")
                number = vlan_info.svi_vlan(port) or vlan_info.bdi_vlan(port) or vlan_info.subinterface_vlan(port)
                if number:
                    vlans_found.add((number, vlan_info.domain_of(device) if device.vlans else None))
        if notes:
            overlay.devices[key] = Mark("accent", "Has an address in it: " + "; ".join(notes))
        elif in_network(device.mgmt_ip, network):
            overlay.devices[key] = Mark("link", f"Managed at {device.mgmt_ip}")
    host_counts_in = {}
    for host in network_map.hosts:
        if host.ip and in_network(host.ip, network) and host.device in devices:
            host_counts_in[host.device] = host_counts_in.get(host.device, 0) + 1
            if host.vlan:
                device = devices[host.device]
                vlans_found.add((host.vlan, vlan_info.domain_of(device) if device.vlans else None))
    for number, domain in sorted(vlans_found, key=lambda item: (item[0], item[1] or "")):
        focus = vlan_info.focus(network_map, number, domain)
        for link_id in focus.links:
            if focus.links[link_id] == vlan_info.ONE_END:
                overlay.links.setdefault(link_id, Mark("warning", f"VLAN {number} allowed at one end only", DASH))
            else:
                overlay.links[link_id] = Mark("link", f"Carries VLAN {number}")
        for key, role in focus.devices.items():
            overlay.devices.setdefault(key, Mark("link", f"VLAN {number}: {role}"))
    for key, count in host_counts_in.items():
        mark = overlay.devices.setdefault(key, Mark("link", ""))
        mark.note = "; ".join(part for part in (mark.note, f"{count_text(count, 'host')} in it") if part)
    hosts = sum(host_counts_in.values())
    numbers = sorted({number for number, _ in vlans_found})
    overlay.summary.append(f"{count_text(gateways, 'address')} on the devices' interfaces"
                           if gateways else "no device on the map has an interface in it")
    if numbers:
        overlay.summary.append(f"VLAN{'s' if len(numbers) > 1 else ''} {vlan_info.vlan_text(numbers)} "
                               f"({count_text(len(overlay.links), 'link')} carrying it)")
    if hosts:
        overlay.summary.append(f"{count_text(hosts, 'host')} in it")
    if not overlay.devices:
        overlay.tone = "warning"
    overlay.legend = [("accent", "address in it (gateway)"), ("link", "carries its VLAN, managed from it or has "
                                                                      "hosts in it")]
    return overlay


# ----------------------------------------------------------------- Color By

def software_version(device):
    """The software version in a device's description (sysDescr), or ""."""
    for pattern in VERSION_PATTERNS:
        match = pattern.search(device.sys_descr or "")
        if match:
            return match.group(1).rstrip(".,")
    return ""


def attribute_value(network_map, device, attribute):
    """What a device is, for Color By (attribute from COLOR_BY), as text ("" when not known)."""
    if attribute == "kind":
        return KIND_NAMES.get(device.kind, device.kind)
    if attribute == "platform":
        return device.platform
    if attribute == "version":
        return software_version(device)
    if attribute == "site":
        path = network_map.group_path(device.key)
        return path[0].name if path else ""
    if attribute == "source":
        return SOURCE_NAMES.get(device.source, device.source)
    if attribute == "vtp_domain":
        return vlan_info.domain_of(device) or ("(none)" if device.vtp_mode else "")
    return str(getattr(device, attribute, "") or "")


def color_by(network_map, attribute):
    """Color each device by what it is (COLOR_BY), one color per value (the most common first)."""
    name = COLOR_NAMES.get(attribute, attribute)
    overlay = Overlay(COLOR, f"Color by {name.lower()}", fade=False)
    values = {key: attribute_value(network_map, device, attribute) for key, device in network_map.devices.items()}
    if attribute in ("vtp_domain", "vtp_mode", "stp_mode", "version"):  # Only means something for switches etc.
        values = {key: value for key, value in values.items()
                  if value or network_map.devices[key].kind in (SWITCH, ROUTER, FIREWALL, AP)}
    counts = {}
    for value in values.values():
        if value:
            counts[value] = counts.get(value, 0) + 1
    ordered = sorted(counts, key=lambda value: (-counts[value], value.lower()))
    colors = {value: PALETTE[position] for position, value in enumerate(ordered[:len(PALETTE) - 1])}
    others = ordered[len(PALETTE) - 1:]
    for key, value in values.items():
        color = colors.get(value, OTHER)
        overlay.devices[key] = Mark(color, f"{name}: {value or NONE_TEXT}")
    overlay.legend = [(colors[value], f"{value} ({counts[value]})") for value in colors]
    if others:
        overlay.legend.append((OTHER, f"{count_text(len(others), 'other')} ({sum(counts[v] for v in others)})"))
    unknown = sum(1 for value in values.values() if not value)
    if unknown:
        overlay.legend.append((OTHER, f"{NONE_TEXT} ({unknown})"))
    overlay.summary.append(f"{count_text(len(counts), 'value')} across {count_text(len(values), 'device')}"
                           if counts else f"not known for any device{' (read over SNMP)' if values else ''}")
    return overlay


# ----------------------------------------------------------------- Link speed and status

def speed_text(mbps):
    """Mb/s as people say it: "100 Mb/s", "1 Gb/s", "2.5 Gb/s"."""
    if not mbps:
        return "speed not known"
    if mbps >= 1000:
        value = mbps / 1000
        return f"{value:g} Gb/s"
    return f"{mbps:g} Mb/s"


def port_state(device, port):
    """A device's Device.port_status entry for a port (written any way), or {}."""
    if not device.port_status or not port:
        return {}
    entry = device.port_status.get(port)
    if entry is not None:
        return entry
    wanted = port_key(port)
    return next((entry for name, entry in device.port_status.items() if port_key(name) == wanted), {})


def state_text(device, port, state):
    parts = [state.get("oper", "unknown"), speed_text(state.get("speed"))]
    if state.get("duplex"):
        parts.append(f"{state['duplex']} duplex")
    return f"{device.label} {port}: {', '.join(parts)}"


def speed_tier(mbps):
    return next(tier for tier in SPEED_TIERS if mbps <= tier[0])


def link_speed(network_map):
    """Each link's speed (the slower end's), as color and thickness; links down at an end, whose ends' speeds or
    duplex differ, or running half duplex, marked as problems."""
    overlay = Overlay(SPEED, "Link speed and status", fade=False)
    devices = network_map.devices
    tiers, down, mismatched, unknown = {}, 0, 0, 0
    for link in network_map.links:
        a, b = devices.get(link.a), devices.get(link.b)
        if a is None or b is None:
            continue
        ends = [(device, port, port_state(device, port)) for device, port in ((a, link.a_port), (b, link.b_port))]
        known = [(device, port, state) for device, port, state in ends if state]
        if not known:
            unknown += 1
            continue
        note = "\n".join(state_text(*end) for end in known)
        speeds = {state["speed"] for _, _, state in known if state.get("speed")}
        duplexes = {state["duplex"] for _, _, state in known if state.get("duplex")}
        if any(state.get("oper") != "up" for _, _, state in known):
            overlay.links[id(link)] = Mark("error", "Down at an end\n" + note, DASH, 3)
            down += 1
        elif len(speeds) > 1:
            overlay.links[id(link)] = Mark("warning", "The ends' speeds differ\n" + note, SOLID, 4)
            mismatched += 1
        elif len(duplexes) > 1 or "half" in duplexes:
            what = "Duplex mismatch" if len(duplexes) > 1 else "Half duplex"
            overlay.links[id(link)] = Mark("error", f"{what} (expect errors and slowness)\n" + note, SOLID, 4)
            mismatched += 1
        elif speeds:
            limit, color, name, width = speed_tier(min(speeds))
            overlay.links[id(link)] = Mark(color, note, SOLID, width)
            tiers[name] = tiers.get(name, 0) + 1
        else:
            unknown += 1
    names = [name for _, _, name, _ in SPEED_TIERS]
    parts = [f"{tiers[name]} at {name}" for name in names if name in tiers]
    if down:
        parts.append(f"{count_text(down, 'link')} down at an end")
    if mismatched:
        parts.append(f"{count_text(mismatched, 'link')} whose ends' speed or duplex differ (or half duplex)")
    if unknown:
        parts.append(f"{unknown} not read")
    if not tiers and not down and not mismatched:
        parts = ["ports' speed and status not read yet: map again, or VLANs tab > Read VLANs Again (it reads "
                 "them too)"]
    overlay.summary = [", ".join(parts)]
    overlay.tone = "error" if down or mismatched else ""
    overlay.legend = [(color, name) for _, color, name, _ in SPEED_TIERS if name in tiers]
    overlay.legend += [("error", "down (dashed), duplex mismatch"), ("warning", "speeds differ")]
    return overlay


# ----------------------------------------------------------------- Spanning tree

def spanning_tree(network_map, vlan, views, unread=()):
    """One VLAN's spanning tree as read from its switches (views: {device key: vlan_path.StpView}): which links
    block (the redundant ones STP keeps shut), which forward, and the root bridge. unread: device keys that didn't
    answer."""
    overlay = Overlay(STP, f"Spanning tree of VLAN {vlan}")
    devices = network_map.devices
    focus = vlan_info.focus(network_map, vlan)
    roots = [key for key, view in views.items() if key in devices and view.root]
    for key in set(focus.devices) | set(views):
        if key not in devices:
            continue
        view = views.get(key)
        if view is None:
            note = "Didn't answer" if key in unread else "Spanning tree not read (not a switch read over SNMP)"
            overlay.devices[key] = Mark("muted", note)
            continue
        mode = view.mode or "spanning tree"
        instance = f", MST instance {view.instance}" if view.mode == "mst" and view.instance >= 0 else ""
        if view.root:
            overlay.devices[key] = Mark("accent", f"Root bridge of VLAN {vlan} ({mode}{instance})")
        else:
            blocked = sorted(port for port, (state, _) in view.ports.items() if state == BLOCKING)
            note = f"{mode}{instance}" + (f"; blocking on {', '.join(blocked[:6])}" if blocked else "")
            overlay.devices[key] = Mark("link", note[0].upper() + note[1:])
    blocking = forwarding = 0
    for link in network_map.links:
        a, b = devices.get(link.a), devices.get(link.b)
        if a is None or b is None:
            continue
        ends = []
        for device, port in ((a, link.a_port), (b, link.b_port)):
            view = views.get(device.key)
            if view is not None:
                state, role = view.state(port)
                if state:
                    ends.append((device, port, state, role))
        notes = [f"{device.label} {port}: {role or state}" for device, port, state, role in ends]
        if any(state == BLOCKING for _, _, state, _ in ends):
            overlay.links[id(link)] = Mark("error", f"Blocked by spanning tree in VLAN {vlan}\n" + "\n".join(notes),
                                           DASH, 4)
            blocking += 1
        elif ends and all(state == FORWARDING for _, _, state, _ in ends):
            overlay.links[id(link)] = Mark("link", f"Forwarding in VLAN {vlan}\n" + "\n".join(notes))
            forwarding += 1
        elif any(state == DISABLED for _, _, state, _ in ends):
            overlay.links[id(link)] = Mark("muted", "\n".join(notes), DOT)
        elif id(link) in focus.links:
            overlay.links[id(link)] = Mark("link", f"Carries VLAN {vlan} (spanning tree not read at its ends)")
    root_text = (f"root bridge {', '.join(devices[key].label for key in roots)}" if roots
                 else "the root bridge isn't one of the switches read")
    overlay.summary = [root_text, f"{count_text(blocking, 'link')} blocking, {forwarding} forwarding",
                       f"{len(views)} switch{'' if len(views) == 1 else 'es'} read"]
    if unread:
        overlay.summary.append(f"{len(unread)} didn't answer")
    if not views:
        overlay.tone = "warning"
    overlay.legend = [("accent", "root bridge"), ("link", "forwarding"), ("error", "blocking (dashed)")]
    return overlay


# ----------------------------------------------------------------- Utilization and errors

def bps_text(bps):
    for limit, unit in ((1e9, "Gb/s"), (1e6, "Mb/s"), (1e3, "kb/s")):
        if bps >= limit:
            return f"{bps / limit:.3g} {unit}"
    return f"{bps:.0f} b/s"


def utilization(network_map, rates, monitoring=True):
    """How busy each link is (the busier direction at the busier end, as a share of its speed) and whether it's
    seeing errors, from the counters monitoring polls: rates {(device key, port_key): netmap.counters.Rate}."""
    overlay = Overlay(UTIL, "Utilization and errors", fade=False)
    devices = network_map.devices
    busy = full = with_errors = measured = 0
    for link in network_map.links:
        a, b = devices.get(link.a), devices.get(link.b)
        if a is None or b is None:
            continue
        ends = [(device, port, rates.get((device.key, port_key(port))))
                for device, port in ((a, link.a_port), (b, link.b_port))]
        ends = [end for end in ends if end[2] is not None]
        if not ends:
            continue
        measured += 1
        shares, notes, errors, discards = [], [], 0, 0
        for device, port, rate in ends:
            share = max(rate.in_bps, rate.out_bps) / (rate.speed * 1e6) if rate.speed else None
            if share is not None:
                shares.append(share)
            of = f" ({share:.0%} of {speed_text(rate.speed)})" if share is not None else ""
            notes.append(f"{device.label} {port}: in {bps_text(rate.in_bps)}, out {bps_text(rate.out_bps)}{of}; "
                         f"{rate.errors} errors, {rate.discards} discards in the last {rate.seconds:.0f} s"
                         + (f" ({rate.total_errors} errors since monitoring started)" if rate.total_errors else ""))
            errors += rate.errors
            discards += rate.discards
        peak = max(shares, default=0.0)
        note = "\n".join(notes)
        if errors:
            overlay.links[id(link)] = Mark("error", f"Errors\n{note}", DASH, 5)
            with_errors += 1
        elif peak >= FULL:
            overlay.links[id(link)] = Mark("error", f"{peak:.0%} busy\n{note}", SOLID, 6)
            full += 1
        elif peak >= BUSY or discards:
            overlay.links[id(link)] = Mark("warning", f"{peak:.0%} busy" + (", discarding" if discards else "")
                                           + f"\n{note}", SOLID, 4.5)
            busy += 1
        else:
            overlay.links[id(link)] = Mark("success", f"{peak:.0%} busy\n{note}", SOLID, 3)
    if not monitoring:
        overlay.summary = ["turn Monitor on: each poll also reads the counters of the switches' and routers' "
                           "linked ports"]
        overlay.tone = "warning"
    elif not measured:
        overlay.summary = ["measuring: rates show from Monitor's second poll (on devices that answer SNMP)"]
    else:
        overlay.summary = [f"{count_text(measured, 'link')} measured",
                           f"{full} over {FULL:.0%} busy, {busy} over {BUSY:.0%} (or discarding)",
                           f"{count_text(with_errors, 'link')} with errors"]
        overlay.tone = "error" if with_errors or full else "warning" if busy else ""
    overlay.legend = [("success", f"under {BUSY:.0%}"), ("warning", f"{BUSY:.0%} to {FULL:.0%}, or discards"),
                      ("error", f"over {FULL:.0%}, or errors (dashed)")]
    return overlay


# ----------------------------------------------------------------- What a menu offers

def build(network_map, kind, argument=None, rates=None, monitoring=False):
    """The overlay of a kind for the map, or None if it can't be made (a VRF or device no longer there, a subnet
    that isn't one). argument: the device key, or the Link.keys of the links, for IMPACT; the VRF, the subnet, or the
    attribute; for STP (VLAN, {device key: StpView}, [keys that didn't answer]). rates and monitoring: UTIL's."""
    if network_map is None:
        return None
    try:
        if kind == SPEED:
            return link_speed(network_map)
        if kind == STP:
            vlan, views, unread = argument
            return spanning_tree(network_map, vlan, views, unread)
        if kind == UTIL:
            return utilization(network_map, rates or {}, monitoring)
        if kind == IMPACT:
            if isinstance(argument, str):
                return impact(network_map, device=argument) if argument in network_map.devices else None
            wanted = set(argument or [])
            links = [link for link in network_map.links if link.key in wanted]
            return impact(network_map, links=links) if links else None
        if kind == SPOF:
            return spof(network_map)
        if kind == TRUNKS:
            return trunk_problems(network_map)
        if kind == VRF:
            return vrf(network_map, argument) if argument in map_vrfs(network_map) else None
        if kind == SUBNET:
            return subnet(network_map, argument)
        if kind == COLOR:
            return color_by(network_map, argument) if argument in COLOR_NAMES else None
    except ValueError:
        return None
    return None

