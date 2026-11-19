"""VLANs on a network map: what each switch has and where each VLAN goes (access ports, trunks, VLAN interfaces),
and the mistakes that show up when both ends of a link are known (a native VLAN that differs, a VLAN one end of a
trunk allows and the other doesn't).

A VLAN number means one VLAN within one VTP domain, so VLANs are grouped by the domain their switches are in
(switches without VTP, or not saying, are in the domain "").
"""
import ipaddress
import re
from dataclasses import dataclass, field

from .model import normalize_vtp_domain, port_key, port_sort_key

ACCESS, TRUNK = "access", "trunk"
NATIVE, TAGGED, VOICE = "native", "tagged", "voice"
ONE_END = "one end"  # A link whose ports are known at both ends, only one of which carries the VLAN
ERROR, WARNING, INFO = "error", "warning", "info"
SEVERITY_LABELS = {ERROR: "Problem", WARNING: "Warning", INFO: "Note"}
MAX_VLAN = 4094
SVI_PATTERN = re.compile(r"^(?:vlan|vl)[\s.]*(\d+)$", re.IGNORECASE)  # Vlan10, Vl10, and PAN-OS vlan.10
BDI_PATTERN = re.compile(r"^(?:bdi|bd)(\d+)$", re.IGNORECASE)  # IOS XE bridge-domain interfaces: BDI10, BD10
SUBINTERFACE_PATTERN = re.compile(r"^(?!tunnel|loopback|lo\d|tu\d)[a-z][\w\-/]*\d\.(\d+)$", re.IGNORECASE)


def vlan_text(numbers):
    """VLAN numbers as Cisco writes them: "1-5,10,20-22"."""
    numbers = sorted(set(numbers))
    parts, start = [], None
    for position, number in enumerate(numbers):
        if start is None:
            start = number
        if position + 1 == len(numbers) or numbers[position + 1] != number + 1:
            parts.append(str(start) if start == number else f"{start}-{number}")
            start = None
    return ",".join(parts)


def parse_vlans(text):
    """The VLAN numbers in text such as "1-5, 10 20-22". Raises ValueError naming what isn't one."""
    numbers = set()
    for part in re.split(r"[,\s]+", (text or "").strip()):
        if not part:
            continue
        first, dash, last = part.partition("-")
        try:
            low, high = int(first), int(last) if dash else int(first)
        except ValueError:
            raise ValueError(f"'{part}' isn't a VLAN or a range of them (such as 10 or 100-199).") from None
        if not 1 <= low <= high <= MAX_VLAN:
            raise ValueError(f"'{part}' isn't between 1 and {MAX_VLAN} (lowest first).")
        numbers.update(range(low, high + 1))
    return numbers


def port_entry(port):
    """A collect.PortVlans as a device keeps it (Device.port_vlans)."""
    entry = {"mode": port.mode}
    for name in ("vlan", "voice", "native"):
        if getattr(port, name):
            entry[name] = getattr(port, name)
    if port.mode == TRUNK:
        entry["allowed"] = vlan_text(port.allowed)
    return entry


def device_port_vlans(tables, short_port):
    """A device's Device.port_vlans from what was read (collect.DeviceTables). A port-channel's members, which CDP
    and LLDP name, get its VLANs when the switch gives them none of their own."""
    entries = {}
    for if_index, port in tables.port_vlans.items():
        entries[short_port(tables.interfaces.get(if_index, str(if_index)))] = port_entry(port)
    for member, parent in tables.lag_parents.items():
        name = short_port(tables.interfaces.get(member, str(member)))
        if name not in entries and parent in tables.port_vlans:
            entries[name] = port_entry(tables.port_vlans[parent])
    return dict(sorted(entries.items(), key=lambda item: port_sort_key(item[0])))


def is_port_channel(port):
    """Whether an interface is a port-channel (an aggregate of links), not a subinterface or tunnel over one."""
    key = port_key(port)
    return "." not in key and key.startswith(("po", "port-channel", "ae", "bond", "bridge-aggregation", "trk"))


def device_port_channels(tables, short_port):
    """A device's Device.port_channels from what was read: {member port: its port-channel} (short names). Only real
    port-channels: ifStackTable also stacks a router's subinterfaces on their port."""
    found = {}
    for member, parent in sorted(tables.lag_parents.items()):
        if member in tables.interfaces and parent in tables.interfaces:
            name = short_port(tables.interfaces[parent])
            if is_port_channel(name):
                found[short_port(tables.interfaces[member])] = name
    return found


def port_info(device, port):
    """The device's VLAN entry for a port (written any way: Gi1/0/1 or GigabitEthernet1/0/1), or {}."""
    if not device.port_vlans or not port:
        return {}
    entry = device.port_vlans.get(port)
    if entry is not None:
        return entry
    wanted = port_key(port)
    return next((entry for name, entry in device.port_vlans.items() if port_key(name) == wanted), {})


def allowed(entry):
    """A trunk entry's allowed VLANs."""
    try:
        return parse_vlans(entry.get("allowed", ""))
    except ValueError:
        return set()


def carries(entry, vlan):
    """How a port carries a VLAN: NATIVE (untagged on a trunk), TAGGED, ACCESS, VOICE, or "" when it doesn't."""
    if not entry:
        return ""
    if entry.get("mode") == TRUNK:
        if vlan not in allowed(entry):
            return ""
        return NATIVE if entry.get("native") == vlan else TAGGED
    if entry.get("vlan") == vlan:
        return ACCESS
    return VOICE if entry.get("voice") == vlan else ""


def vlan_names(device):
    """{VLAN: name} the device has."""
    return {int(item[0]): str(item[1]) for item in device.vlans if isinstance(item, (list, tuple)) and len(item) == 2}


def svi_vlan(port):
    """The VLAN of a VLAN interface's name (Vlan10, Vl10, PAN-OS vlan.10), or 0."""
    match = SVI_PATTERN.match((port or "").strip())
    number = int(match.group(1)) if match else 0
    return number if 1 <= number <= MAX_VLAN else 0


def bdi_vlan(port):
    """The VLAN a bridge-domain interface (an IOS XE router's SVI: BDI10, or BD10 as its ifName gives it) is probably
    in: its bridge-domain number, which is usually the VLAN's (but needn't be), or 0."""
    match = BDI_PATTERN.match((port or "").strip())
    number = int(match.group(1)) if match else 0
    return number if 1 <= number <= MAX_VLAN else 0


def subinterface_vlan(port):
    """The VLAN a subinterface is probably tagged with (ethernet1/3.20, Gi0/0/1.100: the number after the dot, which
    is the usual way to name them but not a rule), or 0."""
    match = SUBINTERFACE_PATTERN.match((port or "").strip())
    number = int(match.group(1)) if match else 0
    return number if 1 <= number <= MAX_VLAN else 0


@dataclass
class Gateway:
    """A VLAN interface (SVI) or a subinterface: where a VLAN gets its addresses."""
    device: str  # Device key
    address: str
    prefix: int
    port: str
    guessed: bool = False  # A subinterface or bridge-domain interface: its VLAN is guessed from its name

    @property
    def subnet(self):
        try:
            return str(ipaddress.ip_network(f"{self.address}/{self.prefix}", strict=False))
        except ValueError:
            return ""


def gateways(device):
    """[(VLAN, Gateway)] from a device's interfaces' addresses."""
    found = []
    for address, prefix, port in device.interfaces_l3:
        vlan = svi_vlan(port)
        guessed = False
        if not vlan:
            vlan, guessed = bdi_vlan(port) or subinterface_vlan(port), True
        if vlan:
            found.append((vlan, Gateway(device.key, address, int(prefix), port, guessed)))
    return found


def domain_of(device):
    return normalize_vtp_domain(device.vtp_domain)


@dataclass
class MapVlan:
    """One VLAN seen on the map."""
    vlan: int
    domain: str = ""
    names: dict = field(default_factory=dict)  # Name -> [device keys that call it that]
    switches: list = field(default_factory=list)  # Device keys of the switches that have it
    access_ports: list = field(default_factory=list)  # [(device key, port)]
    voice_ports: list = field(default_factory=list)
    trunk_ports: list = field(default_factory=list)  # [(device key, port, NATIVE or TAGGED)]
    gateways: list = field(default_factory=list)  # [Gateway]
    hosts: int = 0  # Hosts on the map in it (from the switches' MAC tables)

    @property
    def name(self):
        """The name most switches give it."""
        if not self.names:
            return ""
        return max(self.names, key=lambda name: (len(self.names[name]), bool(name), name))

    @property
    def subnets(self):
        return sorted({gateway.subnet for gateway in self.gateways if gateway.subnet},
                      key=lambda text: ipaddress.ip_network(text))


def map_vlans(network_map):
    """Every VLAN on the map, as [MapVlan] by domain then number. A VLAN a switch only has a gateway or ports in
    still counts; a router's subinterface counts in the domain of the switches it's linked to (or "")."""
    found = {}
    devices = network_map.devices

    def entry(domain, vlan):
        return found.setdefault((domain, vlan), MapVlan(vlan, domain))

    for key, device in devices.items():
        domain = domain_of(device)
        for vlan, name in vlan_names(device).items():
            item = entry(domain, vlan)
            item.switches.append(key)
            item.names.setdefault(name, []).append(key)
        for port, info in device.port_vlans.items():
            if info.get("mode") == TRUNK:
                for vlan in allowed(info):
                    if (domain, vlan) in found or vlan in vlan_names(device):
                        entry(domain, vlan).trunk_ports.append(
                            (key, port, NATIVE if info.get("native") == vlan else TAGGED))
            else:
                if info.get("vlan"):
                    entry(domain, info["vlan"]).access_ports.append((key, port))
                if info.get("voice"):
                    entry(domain, info["voice"]).voice_ports.append((key, port))
        gateway_domain = domain or linked_domain(network_map, key)
        for vlan, gateway in gateways(device):
            entry(gateway_domain, vlan).gateways.append(gateway)
    for host in network_map.hosts:
        device = devices.get(host.device)
        if host.vlan and device is not None:
            item = found.get((domain_of(device), host.vlan))
            if item is not None:
                item.hosts += 1
    return [found[key] for key in sorted(found)]


def linked_domain(network_map, key):
    """The VTP domain of the switches a device (a router or firewall) is linked to, when they all agree, or ""."""
    domains = {domain_of(network_map.devices[link.other(key)]) for link in network_map.links_of(key)
               if link.other(key) in network_map.devices and network_map.devices[link.other(key)].vlans}
    return domains.pop() if len(domains) == 1 else ""


def domains(network_map):
    """The VTP domains on the map ("" for switches without one), most switches first."""
    counts = {}
    for device in network_map.devices.values():
        if device.vlans:
            counts[domain_of(device)] = counts.get(domain_of(device), 0) + 1
    return sorted(counts, key=lambda domain: (-counts[domain], domain))


@dataclass
class Focus:
    """Where one VLAN goes on the map, for highlighting it."""
    vlan: int
    domain: str = ""
    devices: dict = field(default_factory=dict)  # Device key -> what it does in the VLAN ("has it", "gateway"...)
    links: dict = field(default_factory=dict)  # id(Link) -> NATIVE, TAGGED, ACCESS (how it's carried) or ONE_END


def focus(network_map, vlan, domain=None):
    """Focus for a VLAN: the devices that have it, its gateways, and the links carrying it (a link carries it when
    either end's port does). domain None: in any domain."""
    domain = normalize_vtp_domain(domain) if domain is not None else None
    result = Focus(vlan, domain or "")
    devices = network_map.devices

    def in_domain(device):
        if domain is None:
            return True  # Any domain: no need to work out the device's (which goes through every link)
        device_domain = domain_of(device)
        if not device.vlans and not device_domain:
            device_domain = linked_domain(network_map, device.key)
        return domain is None or device_domain == domain

    def port_carries(device, info):
        if not in_domain(device):
            return ""
        # An allowed list (often 1-4094) permits a VLAN; it doesn't create it on the switch.
        if info.get("mode") == TRUNK and vlan not in vlan_names(device):
            return ""
        return carries(info, vlan)

    for key, device in devices.items():
        if not in_domain(device):
            continue
        roles = []
        if vlan in vlan_names(device):
            roles.append("has it")
        if any(number == vlan for number, _ in gateways(device)):
            roles.append("gateway")
        ports = [port for port, info in device.port_vlans.items() if info.get("mode") != TRUNK and carries(info, vlan)]
        if ports:
            roles.append(f"{len(ports)} access port{'s' if len(ports) != 1 else ''}")
        if roles:
            result.devices[key] = ", ".join(roles)
    for link in network_map.links:
        a, b = devices.get(link.a), devices.get(link.b)
        if a is None or b is None or not (in_domain(a) or in_domain(b)):
            continue
        infos = [port_info(device, port) for device, port in ((a, link.a_port), (b, link.b_port))]
        ends = [port_carries(device, info) for device, info in zip((a, b), infos)]
        ways = [way for way, info in zip(ends, infos) if info]  # Ends whose ports are known
        if not any(ways):
            continue
        if not all(ways):
            result.links[id(link)] = ONE_END  # Known at both ends, and only one carries it
        else:
            result.links[id(link)] = TAGGED if TAGGED in ways else NATIVE if NATIVE in ways else ACCESS
        for key, way in zip((link.a, link.b), ends):
            if way:
                result.devices.setdefault(key, "carries it")
    return result


@dataclass
class Finding:
    severity: str
    text: str
    device: str = ""  # Device key
    port: str = ""
    vlan: int = 0
    other: str = ""  # The device at the link's other end
    other_port: str = ""


def check_map(network_map):
    """Mistakes in how VLANs are set up that the map can see: [Finding], worst first."""
    devices = network_map.devices
    findings = []
    for link in network_map.links:
        a, b = devices.get(link.a), devices.get(link.b)
        if a is None or b is None:
            continue
        one, other = port_info(a, link.a_port), port_info(b, link.b_port)
        if not one or not other:
            continue
        where = dict(device=link.a, port=link.a_port, other=link.b, other_port=link.b_port)
        ends = f"{a.label} {link.a_port} and {b.label} {link.b_port}"
        modes = {one.get("mode"), other.get("mode")}
        if modes == {TRUNK, ACCESS}:
            findings.append(Finding(ERROR, f"{ends}: one end is a trunk, the other an access port", **where))
        elif modes == {TRUNK}:
            if one.get("native", 1) != other.get("native", 1):
                findings.append(Finding(ERROR, f"{ends}: native VLAN {one.get('native', 1)} on one end, "
                                               f"{other.get('native', 1)} on the other", **where))
            both = set(vlan_names(a)) & set(vlan_names(b))  # Only VLANs both switches have matter
            first_only = (allowed(one) - allowed(other)) & both
            second_only = (allowed(other) - allowed(one)) & both
            for device, port, only in ((a, link.a_port, first_only), (b, link.b_port, second_only)):
                if only:
                    findings.append(Finding(WARNING, f"{ends}: VLAN{'s' if len(only) > 1 else ''} {vlan_text(only)} "
                                                     f"allowed only on {device.label} {port}", **where))
        elif modes == {ACCESS} and one.get("vlan") != other.get("vlan"):
            findings.append(Finding(WARNING, f"{ends}: access VLAN {one.get('vlan')} on one end, {other.get('vlan')} "
                                             f"on the other (traffic crosses between VLANs)", **where))
    for key, device in devices.items():
        names = vlan_names(device)
        if not names:
            continue
        missing = {}
        for port, info in device.port_vlans.items():
            for vlan in (info.get("vlan"), info.get("voice")):
                if vlan and vlan not in names:
                    missing.setdefault(vlan, []).append(port)
        for vlan, ports in sorted(missing.items()):
            ports.sort(key=port_sort_key)
            listed = ", ".join(ports[:6]) + (f" and {len(ports) - 6} more" if len(ports) > 6 else "")
            one = len(ports) == 1
            findings.append(Finding(WARNING, f"{device.label}: {listed} {'is' if one else 'are'} in VLAN {vlan}, which "
                                             f"the switch doesn't have ({'it passes' if one else 'they pass'} no "
                                             "traffic)", key, ports[0], vlan))
        for vlan, gateway in gateways(device):
            if not gateway.guessed and vlan not in names:
                findings.append(Finding(INFO, f"{device.label}: {gateway.port} ({gateway.address}/{gateway.prefix}) is "
                                              f"for VLAN {vlan}, which the switch doesn't have", key, gateway.port, vlan))
    for item in map_vlans(network_map):
        if len(item.names) > 1:
            parts = [f"{name or '(no name)'} on {', '.join(devices[key].label for key in keys[:4])}"
                     f"{f' and {len(keys) - 4} more' if len(keys) > 4 else ''}" for name, keys in item.names.items()]
            domain = f" in VTP domain {item.domain}" if item.domain else ""
            findings.append(Finding(INFO, f"VLAN {item.vlan}{domain} has different names: {'; '.join(parts)}",
                                    item.switches[0], vlan=item.vlan))
    order = {ERROR: 0, WARNING: 1, INFO: 2}
    findings.sort(key=lambda finding: (order[finding.severity], finding.vlan, finding.text))
    return findings
