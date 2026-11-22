"""What a device's details say: the Network Map's details pane and the NOMAD Dashboard's both show this, each in its
own way (HTML in the app, elements on the web page), so they show the same things. No Qt here: the dashboard service
imports it.

device_details gives {"title", "sections": [{"title", "blocks"}]}, where each block is one of
    {"p": text}                         a paragraph (its new lines kept)
    {"label": text}                     a bold line, over the rows after it
    {"rows": [[left, right]], "bold"}   a two-column table; bold: the left column's are labels
The first section has no title. Nothing here is a credential or a config.
"""
from . import hardware, l3, tunnels as tunnel_module
from . import vlans as vlan_info
from .model import AP_DOWN, AP_UP, CORRECTED_NAMES, KIND_NAMES, short_port

ROUTES_SHOWN = 50
VLANS_LISTED = 40  # A device's details name this many of its VLANs


def format_size(size):
    """Bytes for display, such as "12.3 MB"."""
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024


def shown_value(attribute, value):
    """How a value the crawl found reads: a kind's name, or "nothing"."""
    if attribute == "kind":
        return KIND_NAMES.get(value, value)
    return value or "nothing"


def wireless_rows(network_map, key):
    """[(label, value)] for a device's details: an access point's controller, AP group and status, or a wireless
    controller's access points and Wi-Fi clients."""
    device = network_map.devices[key]
    rows = []
    if device.ap_status:
        controller = network_map.devices.get(device.controller)
        rows += [("Access point", f"{'Up' if device.ap_status == AP_UP else 'Down'}, as its controller says"),
                 ("Controller", controller.label if controller is not None else device.controller),
                 ("AP group", device.ap_group)]
    aps = network_map.access_points_of(key)
    if aps:
        down = sum(1 for other in aps if network_map.devices[other].ap_status == AP_DOWN)
        clients = sum(1 for host in network_map.hosts if host.controller == key)
        rows += [("Access points", f"{len(aps)}" + (f" ({down} down)" if down else "")),
                 ("Wi-Fi clients", str(clients))]
    return rows


def disk_rows(device):
    """[(label, value)] for a device's details: how full each of a pfSense firewall's disks was when last read."""
    rows = []
    for disk in device.disks:
        label = "Disk" if len(device.disks) == 1 else f"Disk {disk['name']}"
        percent = 100 * disk["used"] / disk["total"] if disk["total"] else 0
        rows.append((label, f"{format_size(disk['used'])} of {format_size(disk['total'])} used ({percent:.1f}%), "
                            f"{format_size(disk['free'])} free, read {device.disks_read[:16].replace('T', ' ')}"))
    return rows


def vlan_port_text(info):
    """A port's VLANs in a few words: "trunk, native 1, VLANs 1-10,20" or "access VLAN 10, voice 20"."""
    if not info:
        return ""
    if info.get("mode") == vlan_info.TRUNK:
        allowed = info.get("allowed", "")
        return f"trunk, native {info.get('native', 1)}, " + (f"VLANs {allowed}" if allowed != "1-4094" else "all VLANs")
    text = f"access VLAN {info['vlan']}" if info.get("vlan") else ""
    if info.get("voice"):
        text += f"{', ' if text else ''}voice VLAN {info['voice']}"
    return text


def _rows(rows, bold=False):
    return {"rows": [[str(left), str(right)] for left, right in rows], "bold": bold}


def device_details(network_map, key, status="", status_rows=(), live=None):
    """A device's details (see the module's docstring), or None if it isn't on the map. status: what monitoring says
    of it; status_rows: more (label, value) rows to show after it (the dashboard's uptime); live: the tunnels as
    monitoring last read them."""
    device = network_map.devices.get(key)
    if device is None:
        return None
    kind = KIND_NAMES.get(device.kind, device.kind)
    rows = [("Status", status), *status_rows, *disk_rows(device), *wireless_rows(network_map, key),
            ("Management IP", device.mgmt_ip), ("Group", network_map.device_group_label(key)),
            ("Found by", device.found_by), ("Hops from start", "" if device.manual else str(device.hops)),
            ("Addresses", ", ".join(device.addresses)), ("Problem", device.error), ("Note", device.note),
            ("Corrected", "; ".join(f"{CORRECTED_NAMES[attribute]} (the crawl found {shown_value(attribute, found)})"
                                    for attribute, (found, _) in device.corrected.items()))]
    top = [{"p": kind + (f" · {device.platform}" if device.platform else "")},
           _rows([(label, value) for label, value in rows if value], bold=True)]
    sections = [{"title": "", "blocks": top}]

    def section(title, *blocks):
        sections.append({"title": title, "blocks": [block for block in blocks if block]})

    links = network_map.links_of(key)
    if links:
        lines = []
        for link in sorted(links, key=lambda link: link.port_on(key)):
            other = network_map.devices[link.other(key)]
            port = vlan_port_text(vlan_info.port_info(device, link.port_on(key)))
            lines.append((link.port_on(key), f"→ {other.label} {link.port_on(other.key)}"
                          + (f" · {port}" if port else "")))
        section("Links", _rows(lines))
    if device.tunnels:
        found = [tunnel for tunnel in tunnel_module.find(network_map, live) if key in (tunnel.a, tunnel.b)]
        lines = []
        for port, end in device.tunnels.items():
            ends = f"{end.get('local') or '?'} to {end.get('remote') or 'any (multipoint)'}"
            ends += " over IPsec" if end.get("ipsec") else ""
            lines.append((port, ends))
            for tunnel in found:
                mine, other, other_port = (tunnel.a_port, tunnel.b, tunnel.b_port) if tunnel.a == key else \
                    (tunnel.b_port, tunnel.a, tunnel.a_port)
                if mine == port:
                    far = f"{network_map.devices[other].label} {other_port}".strip()
                    lines.append(("", f"→ {far}: {tunnel_module.STATE_TEXT[tunnel.state]}"))
        section(f"Tunnels ({len(device.tunnels)})", _rows(lines))
    blocks = hardware_blocks(device)
    if blocks:
        section("Hardware", *blocks)
    vlans = vlan_blocks(device)
    if vlans:
        section(*vlans)
    ports = network_map.hosts_by_port(key)
    if ports:
        count = sum(len(hosts) for hosts in ports.values())
        section(f"Hosts ({count})", _rows(
            (port, ", ".join(host.name or host.ip or host.mac for host in hosts) if len(hosts) <= 3
             else f"{len(hosts)} hosts") for port, hosts in ports.items()))
    if device.interfaces_l3:
        section("IP Interfaces", _rows((short_port(port), f"{address}/{prefix}")
                                       for address, prefix, port in device.interfaces_l3))
    routes = [route for route in device.routes if route[1]]  # Connected ones are the interfaces above
    if routes:
        section(f"Routes ({len(routes)}{'+' if device.routes_truncated else ''})",
                _rows((destination, f"via {next_hop} ({protocol})")
                      for destination, next_hop, port, protocol in routes[:ROUTES_SHOWN]),
                {"p": f"...and {len(routes) - ROUTES_SHOWN} more."} if len(routes) > ROUTES_SHOWN else None)
    if device.sys_descr:
        section("Description", {"p": device.sys_descr})
    if device.manual:
        section("", {"p": "Added by hand: right-click it to edit or delete it, or to draw a link from it. It's kept "
                          "when you map again, until the crawl finds it."})
    return {"title": device.label, "sections": sections}


def subnet_details(network_map, subnet):
    """A subnet's details on the logical view: the devices with an address in it, the routes to it, and its hosts on
    the map. The same shape as device_details."""
    members, hosts = l3.subnet_details(network_map, subnet)
    routed = [(device.label, route) for device in network_map.devices.values() for route in device.routes
              if route[1] and route[0] == subnet]
    blocks = [_rows((label, f"{port} {address}") for label, port, address in members)]
    blocks += [{"p": f"{label} routes it via {next_hop} ({protocol})"}
               for label, (destination, next_hop, port, protocol) in routed[:ROUTES_SHOWN]]
    sections = [{"title": "Devices with an address in it", "blocks": blocks}]
    if hosts:
        rows = []
        for host in hosts[:ROUTES_SHOWN]:
            device = network_map.devices.get(host.device)
            rows.append((host.ip, f"{host.name or host.mac} on {device.label if device else host.device} {host.port}"))
        sections.append({"title": f"Hosts on the map ({len(hosts)})", "blocks": [_rows(rows)]})
    return {"title": subnet, "sections": sections}


def hardware_blocks(device):
    """Its chassis (each stack member's), model, serial number and software, and its parts, as last read."""
    members = hardware.chassis(device.parts)
    others = [part for part in device.parts if part.get("class") != hardware.CHASSIS]
    if not members and not device.software and not device.serial and not device.mac:
        return []
    rows = []
    if device.software:
        rows.append(("Software", device.software))
    for part in members:
        name = part.get("name") if len(members) > 1 else "Chassis"
        mac = part.get("mac", "")
        mac = f"MAC {mac}" + (" (its management interface's)" if part.get("mac_source") == hardware.MANAGEMENT
                              else "") if mac else ""
        what = ", ".join(item for item in (part.get("model"), part.get("serial") or "no serial number", mac) if item)
        rows.append((name or "Chassis", what))
    if not members and device.serial:
        rows.append(("Serial", f"{device.serial} (from a neighbor's CDP)"))
    if device.mac and not any(part.get("mac") for part in members):
        name, said = "MAC", ""
        if len(members) > 1:
            name, said = "Stack MAC", " (the active member's, or one set by hand)"
        elif not device.inventory_read:
            said = " (from its neighbors' LLDP)"
        rows.append((name, f"{device.mac}{said}"))
    if others:
        counts = {}
        for part in others:
            counts[part["class"]] = counts.get(part["class"], 0) + 1
        listed = ", ".join(f"{count} {name}{'s' if count != 1 else ''}" for name, count in counts.items())
        rows.append(("Parts", f"{listed} (on the Assets page)"))
    return [_rows(rows, bold=True)]


def vlan_blocks(device):
    """[title, blocks...] of a switch's VLANs, its VTP domain, and which ports are in which VLAN; [] without any."""
    names = vlan_info.vlan_names(device)
    if not names and not device.port_vlans:
        return []
    vtp = f"VTP domain {device.vtp_domain}" if device.vtp_domain else ""
    if device.vtp_mode:
        vtp = f"{vtp} ({device.vtp_mode})" if vtp else f"VTP {device.vtp_mode}"
    blocks = [f"VLANs ({len(names)})"]
    if vtp:
        blocks.append({"p": vtp})
    if names:
        listed = [f"{vlan} {name}".strip() for vlan, name in sorted(names.items())]
        more = f" ...and {len(listed) - VLANS_LISTED} more" if len(listed) > VLANS_LISTED else ""
        blocks.append({"p": ", ".join(listed[:VLANS_LISTED]) + more})
    trunks = [(port, vlan_port_text(info)) for port, info in device.port_vlans.items()
              if info.get("mode") == vlan_info.TRUNK]
    if trunks:
        blocks.append(_rows(trunks))
    by_vlan = {}
    for port, info in device.port_vlans.items():
        if info.get("mode") != vlan_info.TRUNK and info.get("vlan"):
            by_vlan.setdefault(info["vlan"], []).append(port)
    if by_vlan:
        blocks.append({"label": "Access ports"})
        blocks.append(_rows((f"VLAN {vlan}", ", ".join(ports[:8]) + (f" and {len(ports) - 8} more"
                                                                     if len(ports) > 8 else ""))
                            for vlan, ports in sorted(by_vlan.items())))
    return blocks
