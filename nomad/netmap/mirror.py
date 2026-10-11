"""Port Mirroring: SPAN, RSPAN and ERSPAN on Cisco IOS / IOS-XE switches, set up and taken down again.

A mirror copies the traffic of some ports (or VLANs) of one switch to a destination:
- a port on the same switch: SPAN (local);
- a port on another switch the map connects to it by switched links: RSPAN, over a VLAN used for nothing else
  (`remote-span`), carried along the way the way Carry VLAN carries one (vlan_path), and taken off again after;
- a port on a switch that's only reached through routers, or an IP address (a capture box, or this PC): ERSPAN
  (IOS-XE: Catalyst 9000, 3650/3850, ISR/ASR, CSR), GRE packets from the source switch to the address.

Before anything is planned the switches' own sessions are read (show monitor session all), so a session number
that's free is used, and a port that's already a destination isn't. A destination port stops being a normal port
while it's one, so a link to another network device, a trunk or a port-channel is never used as one.

Each switch can be told to take its part away itself after a while (an EEM applet with a countdown timer), so a
mirror left behind doesn't stay. Every mirror set up is recorded with exactly what takes it away (MirrorStore).

Qt-free, so it can be tested without a network.
"""
import datetime
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field, fields

from . import vlan_path
from .model import AP, FIREWALL, KIND_NAMES, ROUTER, SHARED_PORT_HOSTS, SWITCH, port_key, short_port
from .vlans import ERROR, INFO, MAX_VLAN, TRUNK, WARNING, Finding, port_info, vlan_names

log = logging.getLogger(__name__)

SPAN, RSPAN, ERSPAN = "span", "rspan", "erspan"
KIND_TITLES = {SPAN: "SPAN", RSPAN: "RSPAN", ERSPAN: "ERSPAN"}
BOTH, RX, TX = "both", "rx", "tx"
DIRECTIONS = [BOTH, RX, TX]
DIRECTION_NAMES = {BOTH: "Both ways", RX: "Received", TX: "Sent"}
TO_PORT, TO_ADDRESS = "port", "address"  # Where a mirror goes: a switch port, or an IP address (ERSPAN only)

MAX_SESSION = 66  # The highest session number IOS takes (most switches allow far fewer at once)
MAX_ERSPAN_ID = 1023
RSPAN_RANGE = range(999, 899, -1)  # Where a free RSPAN VLAN is looked for first (then anywhere below 1006)
RSPAN_NAME = "NOMAD_RSPAN"
APPLET_PREFIX = "NOMAD-MIRROR-"
MAX_MINUTES = 7 * 24 * 60
ERROR_LINE = re.compile(r"^\s*%(?!\s*(?:Warning|Applying|Note|Info))", re.IGNORECASE)

# Roles of the switches in a mirror
SOURCE, DESTINATION, PATH = "source", "destination", "path"
ROLE_NAMES = {SOURCE: "Source", DESTINATION: "Destination", PATH: "On the way"}


# ----------------------------------------------------------------- What to mirror, and where to

@dataclass
class Source:
    """A port (short name) or a VLAN of the source switch, and which of its traffic."""
    port: str = ""
    vlan: int = 0
    direction: str = BOTH

    def text(self):
        what = f"VLAN {self.vlan}" if self.vlan else self.port
        return f"{what} ({DIRECTION_NAMES.get(self.direction, self.direction).lower()})"

    def ios(self):
        """`interface Gi1/0/1 both` / `vlan 10 rx` / `service instance 6 gigabitEthernet 6 both`, after `source`."""
        if self.vlan:
            what = f"vlan {self.vlan}"
        else:
            instance = SERVICE_INSTANCE.match(short_port(self.port))
            what = (f"service instance {instance['number']} {ios_port_type(instance['port'])}" if instance
                    else f"interface {self.port}")
        return f"{what} {self.direction}"


# A service instance (EFP) of a port, as SNMP names it: GigabitEthernet6.SI.6 (Gi6.SI.6 short)
SERVICE_INSTANCE = re.compile(r"^(?P<port>.+?)\.SI\.(?P<number>\d+)$", re.IGNORECASE)
IOS_PORT_TYPES = {  # Short name -> the interface type as IOS's own keyword, for `service instance N <type> <number>`
    "hu": "hundredGigE", "fo": "fortyGigabitEthernet", "twe": "twentyFiveGigE", "te": "tenGigabitEthernet",
    "fi": "fiveGigabitEthernet", "tw": "twoGigabitEthernet", "gi": "gigabitEthernet", "fa": "fastEthernet",
    "po": "port-channel", "eth": "ethernet", "et": "ethernet",
}


def ios_port_type(port):
    """Gi6 -> `gigabitEthernet 6`, Te1/0/1 -> `tenGigabitEthernet 1/0/1` (a type not known kept as it is)."""
    match = re.match(r"^([A-Za-z-]+)\s*(\d.*)$", port)
    if not match:
        return port
    kind, number = match.groups()
    return f"{IOS_PORT_TYPES.get(kind.lower(), kind)} {number}"


@dataclass
class Request:
    """A mirror to plan. kind "" lets the plan choose (SPAN, RSPAN, then ERSPAN)."""
    source_device: str = ""  # The map's key of the switch whose ports (or VLANs) are mirrored
    sources: list = field(default_factory=list)  # [Source]
    to: str = TO_PORT
    dest_device: str = ""  # TO_PORT: the switch and port the copies go out of
    dest_port: str = ""
    dest_ip: str = ""  # TO_ADDRESS: where ERSPAN sends them (a capture box, or this PC)
    kind: str = ""
    name: str = ""
    session: int = 0  # The session number to use on every switch (0: the first free one on each)
    rspan_vlan: int = 0  # 0: a VLAN no switch on the map has
    erspan_id: int = 0  # 0: chosen
    origin_ip: str = ""  # ERSPAN: the source switch's address the GRE packets come from ("" its management one)
    receive_ip: str = ""  # ERSPAN to a switch port: that switch's address they go to ("" its management one)
    vrf: str = ""  # ERSPAN: the VRF the GRE packets go in ("" the global table)
    replicate: bool = False  # Copies keep their VLAN tags, CDP, STP... (encapsulation replicate)
    ingress_vlan: int = 0  # The device on the destination port still gets onto the network in this VLAN
    remove_after: int = 0  # Minutes until each switch takes its part away itself (EEM); 0: never
    to_this_pc: bool = False  # The destination is this computer (to offer a capture once it's set up)
    own_port: bool = False  # The destination port is the one this computer reaches the switches through
    adapter: str = ""  # This computer's adapter the copies go to (This PC)


# ----------------------------------------------------------------- The switches' own sessions

@dataclass
class MonitorSession:
    """A session as show monitor session all lists it."""
    number: int
    type: str = ""  # As the switch says: Local Session, Remote Source Session, ERSPAN Source Session...
    sources: list = field(default_factory=list)  # ["Both: Gi1/0/1", "RX Only: VLAN 10"]
    source_ports: list = field(default_factory=list)  # Short names
    destinations: list = field(default_factory=list)  # Destination ports (short names)
    rspan_vlan: int = 0  # Dest RSPAN VLAN or Source RSPAN VLAN
    erspan_id: int = 0
    dest_ip: str = ""
    origin_ip: str = ""
    status: str = ""
    text: str = ""

    @property
    def kind(self):
        lowered = self.type.lower()
        if "erspan" in lowered:
            return ERSPAN
        if "remote" in lowered or self.rspan_vlan:
            return RSPAN
        return SPAN

    def summary(self):
        parts = [self.type or "Session"]
        if self.sources:
            parts.append("from " + ", ".join(self.sources))
        if self.destinations:
            parts.append("to " + ", ".join(self.destinations))
        if self.rspan_vlan:
            parts.append(f"RSPAN VLAN {self.rspan_vlan}")
        if self.dest_ip:
            parts.append(f"to {self.dest_ip}")
        if self.erspan_id:
            parts.append(f"ERSPAN ID {self.erspan_id}")
        return "; ".join(parts)


def expand_ports(text):
    """Short port names from a list as IOS writes it: "Gi1/0/1-3,Gi1/0/5" -> Gi1/0/1, Gi1/0/2, Gi1/0/3, Gi1/0/5."""
    ports = []
    for part in re.split(r"[,\s]+", (text or "").strip()):
        if not part:
            continue
        match = re.match(r"^(.*?)(\d+)-(\d+)$", part)
        if match and re.search(r"[A-Za-z]", match.group(1)):
            prefix, low, high = match.group(1), int(match.group(2)), int(match.group(3))
            if low <= high <= low + 512:
                ports += [short_port(f"{prefix}{number}") for number in range(low, high + 1)]
                continue
        if re.match(r"^[A-Za-z][A-Za-z\-]*\d", part):
            ports.append(short_port(part))
    return ports


def parse_sessions(text):
    """{session number: MonitorSession} from show monitor session all (or show monitor)."""
    sessions = {}
    chunks = re.split(r"^\s*Session\s+(\d+)\s*$", text or "", flags=re.MULTILINE | re.IGNORECASE)
    for index in range(1, len(chunks) - 1, 2):
        number, body = int(chunks[index]), chunks[index + 1]
        session = MonitorSession(number, text=f"Session {number}{body}".strip())
        heading = ""
        for line in body.splitlines():
            if not line.strip() or re.match(r"^\s*-{3,}\s*$", line):
                continue
            key, colon, value = line.partition(":")
            if not colon:
                continue
            key, value = key.strip().lower(), value.strip()
            indented = line[:1].isspace() and line[:len(line) - len(line.lstrip())].count(" ") >= 2
            if key in ("source ports", "source vlans", "source vlan", "source subinterfaces"):
                heading = "vlan" if "vlan" in key else "port"
                if value:  # "Source VLANs : RX Only: 10" written on one line
                    session.sources.append(value)
                continue
            if heading and indented and key in ("both", "rx only", "tx only", "rx", "tx"):
                what = f"VLAN {value}" if heading == "vlan" else value
                session.sources.append(f"{key.title()}: {what}")
                if heading == "port":
                    session.source_ports += expand_ports(value)
                continue
            heading = ""
            if key == "type":
                session.type = value
            elif key == "status":
                session.status = value
            elif key in ("destination ports", "destination port"):
                session.destinations += expand_ports(value)
            elif key in ("dest rspan vlan", "source rspan vlan", "destination rspan vlan"):
                session.rspan_vlan = int(value) if value.isdigit() else 0
            elif key in ("destination erspan id", "source erspan id", "erspan id"):
                session.erspan_id = int(value) if value.isdigit() else 0
            elif key == "destination ip address":
                session.dest_ip = value
            elif key in ("origin ip address", "source ip address"):
                session.origin_ip = value
        sessions[number] = session
    return sessions


def parse_applets(text):
    """The names of NOMAD's EEM applets from show running-config | include event manager applet."""
    found = re.finditer(r"^\s*event manager applet\s+(\S+)", text or "", re.MULTILINE)  # Not its own "no event..."
    return list(dict.fromkeys(match.group(1) for match in found if match.group(1).upper().startswith(APPLET_PREFIX)))


@dataclass
class SwitchState:
    """What a switch said before planning (or checking): its sessions and NOMAD's applets."""
    read: bool = False
    sessions: dict = field(default_factory=dict)  # number -> MonitorSession
    applets: list = field(default_factory=list)
    problem: str = ""  # Why it couldn't be read

    def free_session(self, avoid=()):
        return next((number for number in range(1, MAX_SESSION + 1)
                     if number not in self.sessions and number not in avoid), 0)

    def destination_ports(self):
        return {port_key(port) for session in self.sessions.values() for port in session.destinations}

    def session_using(self, port):
        wanted = port_key(port)
        return next((session for session in self.sessions.values()
                     if wanted in {port_key(item) for item in session.destinations + session.source_ports}), None)


# ----------------------------------------------------------------- The plan

@dataclass
class Step:
    """What to send to one switch to set its part up, and what takes it away."""
    device: str
    role: str
    session: int = 0
    lines: list = field(default_factory=list)  # Configuration lines (between configure terminal and end)
    undo_lines: list = field(default_factory=list)
    applet: list = field(default_factory=list)  # The EEM applet that takes it away after a while ([] for none)
    applet_name: str = ""
    notes: list = field(default_factory=list)

    @property
    def empty(self):
        return not self.lines


@dataclass
class Plan:
    request: Request
    kind: str = ""
    why: str = ""  # Why that kind ("the destination is on the same switch")
    steps: list = field(default_factory=list)  # [Step] in the order to set up (taken away in reverse)
    findings: list = field(default_factory=list)
    rspan_vlan: int = 0
    erspan_id: int = 0
    origin_ip: str = ""
    dest_ip: str = ""  # ERSPAN: where the GRE packets go
    route: list = field(default_factory=list)  # RSPAN: the switches the VLAN goes through, source first
    hops: list = field(default_factory=list)  # RSPAN: vlan_path.Hop between each two of route
    applet_name: str = ""

    @property
    def ok(self):
        return bool(self.steps) and not any(finding.severity == ERROR for finding in self.findings)

    def step_for(self, device):
        return next((step for step in self.steps if step.device == device), None)


def device_label(network_map, key):
    device = network_map.devices.get(key)
    return device.label if device is not None else key


def is_ios_xe(device):
    """True when the switch says it runs IOS XE, False when it says it's classic IOS, None when it doesn't say."""
    text = f"{device.sys_descr} {device.platform}".lower()
    if re.search(r"ios[ -]?xe|c9[0-9]{3}|cat9k|cat3k_caa|csr1000|c8000|isr4|asr1", text):
        return True
    version = re.search(r"version (\d+)\.", text)
    if version and int(version.group(1)) >= 16:  # IOS XE 16 and 17 often say just "Cisco IOS Software [Everest]"
        return True
    if "ios software" in text or re.search(r"c2960|c3560|c3750|c4500|i86bi|vios", text):
        return False
    return None


def used_vlans(network_map):
    """Every VLAN any device of the map has, or has on a port."""
    numbers = set()
    for device in network_map.devices.values():
        numbers |= set(vlan_names(device))
        for entry in device.port_vlans.values():
            numbers |= {entry.get(name) for name in ("vlan", "voice", "native") if entry.get(name)}
    return numbers


def free_rspan_vlan(network_map):
    used = used_vlans(network_map)
    return next((number for number in [*RSPAN_RANGE, *range(1005, 1, -1)] if number not in used), 0)


def port_speed(device, port):
    """A port's speed in Mb/s as last read (0: unknown)."""
    status = device.port_status.get(port) or next(
        (value for name, value in device.port_status.items() if port_key(name) == port_key(port)), {})
    try:
        return int(status.get("speed") or 0)
    except (TypeError, ValueError):
        return 0


def port_oper(device, port):
    status = device.port_status.get(port) or next(
        (value for name, value in device.port_status.items() if port_key(name) == port_key(port)), {})
    return status.get("oper", "")


LINKED_KINDS = {SWITCH, ROUTER, FIREWALL, AP}  # What a port can't be taken from: an AP takes its clients with it


def linked_to(network_map, key, port):
    """The network device (switch, router, firewall, access point) a port links to on the map, or None."""
    for link in network_map.links_of(key):
        if port_key(link.port_on(key)) != port_key(port):
            continue
        other = network_map.devices.get(link.other(key))
        if other is not None and other.kind in LINKED_KINDS:
            return other
    return None


def shared_port(network_map, key, port):
    """Whether a port has many hosts behind it (an access point, an unmanaged switch or a hypervisor): a MAC learned
    there isn't one machine's own port."""
    hosts = sum(1 for host in network_map.hosts if host.device == key and port_key(host.port) == port_key(port))
    return hosts > SHARED_PORT_HOSTS or linked_to(network_map, key, port) is not None


def in_port_channel(device, port):
    if port_key(port).startswith("po"):
        return True
    return any(port_key(member) == port_key(port) for member in device.port_channels)


def plan(network_map, request, states=None, applet_tag=""):
    """What to send to each switch for request. states: {device key: SwitchState} read just before (their sessions,
    so free numbers are used and a port in use isn't). applet_tag: names the EEM applets (NOMAD-MIRROR-<tag>)."""
    states = states or {}
    result = Plan(request)
    findings = result.findings
    devices = network_map.devices
    source = devices.get(request.source_device)
    if source is None or source.kind not in (SWITCH, ROUTER):
        findings.append(Finding(ERROR, "Choose the switch or router whose ports (or VLANs) to mirror."))
        return finish(result)
    sources = [item for item in request.sources if item.port or item.vlan]
    if not sources:
        findings.append(Finding(ERROR, f"Choose the ports (or VLANs) of {source.label} to mirror."))
        return finish(result)
    if any(item.port for item in sources) and any(item.vlan for item in sources):
        findings.append(Finding(ERROR, "A session mirrors ports or VLANs, not both: choose one or the other."))
    for item in sources:
        if item.direction not in DIRECTIONS:
            findings.append(Finding(ERROR, f"{item.text()}: choose both ways, received or sent."))
        if item.vlan and not 1 <= item.vlan <= MAX_VLAN:
            findings.append(Finding(ERROR, f"{item.vlan} isn't a VLAN (1 to {MAX_VLAN})."))
    dest = devices.get(request.dest_device) if request.to == TO_PORT else None
    if request.to == TO_PORT:
        if dest is None or not request.dest_port:
            findings.append(Finding(ERROR, "Choose the switch port the copies go out of (or an address, for "
                                           "ERSPAN)."))
            return finish(result)
    elif not valid_ipv4(request.dest_ip):
        findings.append(Finding(ERROR, "Enter the IP address the copies go to (ERSPAN)."))
        return finish(result)

    choose_kind(network_map, request, result)
    if not result.kind:
        return finish(result)
    if request.session and not 1 <= request.session <= MAX_SESSION:
        findings.append(Finding(ERROR, f"Session numbers go from 1 to {MAX_SESSION}."))
    check_sources(network_map, request, sources, states, result)
    if dest is not None:
        check_destination(network_map, request, sources, states, result)
    if request.remove_after and not 1 <= request.remove_after <= MAX_MINUTES:
        findings.append(Finding(ERROR, f"Remove after is from 1 minute to {MAX_MINUTES // 1440} days."))
    result.applet_name = f"{APPLET_PREFIX}{applet_tag}" if request.remove_after and applet_tag else ""
    if any(finding.severity == ERROR for finding in findings):
        return finish(result)
    if result.kind == SPAN:
        plan_span(network_map, request, sources, states, result)
    elif result.kind == RSPAN:
        plan_rspan(network_map, request, sources, states, result)
    else:
        plan_erspan(network_map, request, sources, states, result)
    if result.applet_name:
        for step in result.steps:
            step.applet_name = result.applet_name
            step.applet = applet(result.applet_name, step, request.remove_after, request.name)
        findings.append(Finding(INFO, f"Each device takes its part away itself after {minutes_text(request.remove_after)} "
                                      f"(EEM applet {result.applet_name}). A device that refuses the applet has its "
                                      "part taken away by NOMAD when the time's up, while NOMAD is open."))
    return finish(result)


def finish(result):
    order = {ERROR: 0, WARNING: 1, INFO: 2}
    result.findings.sort(key=lambda finding: order[finding.severity])
    return result


def valid_ipv4(text):
    import ipaddress
    try:
        ipaddress.IPv4Address((text or "").strip())
        return True
    except ValueError:
        return False


def minutes_text(minutes):
    if minutes % 1440 == 0:
        days = minutes // 1440
        return f"{days} day{'' if days == 1 else 's'}"
    if minutes % 60 == 0:
        hours = minutes // 60
        return f"{hours} hour{'' if hours == 1 else 's'}"
    return f"{minutes} minute{'' if minutes == 1 else 's'}"


def choose_kind(network_map, request, result):
    """SPAN to the same switch, RSPAN over switched links, else ERSPAN (or the kind asked for, when it can be)."""
    findings = result.findings
    source = network_map.devices[request.source_device]
    if request.to == TO_ADDRESS:
        if request.kind not in ("", ERSPAN):
            findings.append(Finding(ERROR, f"Mirroring to an address is ERSPAN only ({KIND_TITLES[request.kind]} "
                                           "goes to a switch port)."))
            return
        result.kind, result.why = ERSPAN, f"the copies go to an address ({request.dest_ip})"
        return
    same = request.dest_device == request.source_device
    if same:
        if request.kind in ("", SPAN):
            result.kind, result.why = SPAN, "the destination port is on the same device"
        elif request.kind == ERSPAN:
            findings.append(Finding(ERROR, "ERSPAN goes to another device (or an address): the destination port is on "
                                           "the same device, so use SPAN."))
        else:
            findings.append(Finding(ERROR, "RSPAN goes to another switch: the destination port is on the same device, "
                                           "so use SPAN."))
        return
    if request.kind == SPAN:
        findings.append(Finding(ERROR, f"SPAN stays on one device: the destination is on "
                                       f"{device_label(network_map, request.dest_device)}, not {source.label}."))
        return
    if request.kind == ERSPAN:
        result.kind, result.why = ERSPAN, "chosen"
        return
    vlan = request.rspan_vlan or free_rspan_vlan(network_map)
    trial = vlan_path.plan(network_map, vlan, a=request.source_device, b=request.dest_device) if vlan else None
    if trial is not None and trial.route and trial.ok:
        result.kind = RSPAN
        result.why = "chosen" if request.kind == RSPAN else \
            f"the devices are joined by switched links ({len(trial.route) - 1} hop{'' if len(trial.route) == 2 else 's'})"
        return
    if request.kind == RSPAN:
        why = next((finding.text for finding in (trial.findings if trial is not None else [])
                    if finding.severity == ERROR), "there's no free VLAN for it")
        findings.append(Finding(ERROR, f"RSPAN can't reach {device_label(network_map, request.dest_device)}: {why}"))
        return
    result.kind, result.why = ERSPAN, "no switched way between the devices (only through routers)"


def check_sources(network_map, request, sources, states, result):
    findings = result.findings
    key = request.source_device
    device = network_map.devices[key]
    state = states.get(key)
    for item in sources:
        if not item.port:
            continue
        if request.to == TO_PORT and request.dest_device == key and port_key(item.port) == port_key(request.dest_port):
            findings.append(Finding(ERROR, f"{item.port} can't be both mirrored and the destination.", key, item.port))
        if state is not None and port_key(item.port) in state.destination_ports():
            findings.append(Finding(ERROR, f"{device.label} {item.port} is a mirror destination already: it can't be a "
                                           "source.", key, item.port))
        other = linked_to(network_map, key, item.port)
        if other is not None:
            findings.append(Finding(INFO, f"{item.port} goes to {other.label}: everything crossing that link is "
                                          "copied.", key, item.port))
        instance = SERVICE_INSTANCE.match(short_port(item.port))
        if instance:
            findings.append(Finding(WARNING, f"{item.port} is service instance {instance['number']} of "
                                             f"{instance['port']}. Some routers take a service instance as the source "
                                             "but copy nothing: if the capture stays empty, mirror "
                                             f"{instance['port']} instead and filter the capture on the instance's "
                                             "VLAN (vlan.id == its VLAN).", key, item.port))
    if any(item.vlan for item in sources) and any(item.direction != RX for item in sources):
        findings.append(Finding(INFO, "Some devices only mirror a VLAN's received traffic: if one refuses, choose "
                                      "Received."))


def check_destination(network_map, request, sources, states, result):
    """A destination port stops being a normal port: never a link to another network device, a trunk or a
    port-channel; a warning for the devices on it."""
    findings = result.findings
    key, port = request.dest_device, request.dest_port
    device = network_map.devices[key]
    if device.kind != SWITCH:
        findings.append(Finding(ERROR, f"{device.label} is a {KIND_NAMES.get(device.kind, device.kind).lower()}: the "
                                       "destination port has to be on a switch.", key, port))
        return
    other = linked_to(network_map, key, port)
    if other is not None:
        findings.append(Finding(ERROR, f"{device.label} {port} goes to {other.label}. A mirror destination stops "
                                       f"passing normal traffic, which would cut {other.label} off: choose an edge "
                                       "port.", key, port))
    info = port_info(device, port)
    if info.get("mode") == TRUNK:
        findings.append(Finding(ERROR, f"{device.label} {port} is a trunk. A mirror destination stops passing normal "
                                       "traffic: choose an access (edge) port.", key, port))
    if in_port_channel(device, port):
        findings.append(Finding(ERROR, f"{device.label} {port} is in a port-channel, which can't be a mirror "
                                       "destination.", key, port))
    state = states.get(key)
    if state is not None:
        using = state.session_using(port)
        if using is not None:
            findings.append(Finding(ERROR, f"{device.label} {port} is in session {using.number} already "
                                           f"({using.type or 'a mirror'}): remove that first.", key, port))
    hosts = [host for host in network_map.hosts if host.device == key and port_key(host.port) == port_key(port)]
    if request.own_port:
        findings.append(Finding(WARNING, f"This PC reaches the network through {device.label} {port}. While it's a "
                                         "mirror destination it gets the copies but"
                                         + (f" only reaches VLAN {request.ingress_vlan}"
                                            if request.ingress_vlan else " can't reach the network devices")
                                         + ", so NOMAD may not be able to take it away: the device's own timer will.",
                                key, port))
        if not request.remove_after:
            findings.append(Finding(ERROR, "Mirroring to the port this PC is on needs Remove after, so the device "
                                           "takes it away itself. Or plug a second network adapter into a free "
                                           "port and mirror to that.", key, port))
    elif hosts and not request.to_this_pc:
        names = ", ".join(host.name or host.ip or host.mac for host in hosts[:3])
        findings.append(Finding(WARNING, f"{device.label} {port} has {len(hosts)} device"
                                         f"{'' if len(hosts) == 1 else 's'} on it ({names}"
                                         f"{', ...' if len(hosts) > 3 else ''}): "
                                         + ("only VLAN " + str(request.ingress_vlan) + " reaches them"
                                            if request.ingress_vlan else "they lose the network")
                                         + " while it's a mirror destination.", key, port))
    if port_oper(device, port) and port_oper(device, port) != "up":
        findings.append(Finding(INFO, f"{device.label} {port} was {port_oper(device, port)} when last read.", key,
                                port))
    source = network_map.devices[request.source_device]
    speed = port_speed(device, port)
    total = 0
    for item in sources:
        if item.port:
            each = port_speed(source, item.port)
            total += each * (2 if item.direction == BOTH else 1)
    if speed and total > speed:
        findings.append(Finding(WARNING, f"The ports mirrored add up to {total} Mb/s"
                                         f"{' (both ways counted)' if any(i.direction == BOTH for i in sources) else ''}"
                                         f", more than {port} takes ({speed} Mb/s): when they're busy, copies are "
                                         "dropped.", key, port))
    elif any(item.vlan for item in sources):
        findings.append(Finding(INFO, "A VLAN can carry more than one port takes: when it's busy, copies are dropped.",
                                key, port))


def session_for(request, states, key, avoid=()):
    """(number, finding or None): the session number to use on a switch."""
    state = states.get(key)
    if request.session:
        if state is not None and request.session in state.sessions:
            return request.session, Finding(ERROR, f"Session {request.session} is in use on the device "
                                                   f"({state.sessions[request.session].summary()}): choose another "
                                                   "or Auto.", key)
        if state is None or not state.read:
            return request.session, Finding(WARNING, f"The device's sessions weren't read: if session "
                                                     f"{request.session} is in use, these lines change it.", key)
        return request.session, None
    if state is None or not state.read:
        why = f" ({state.problem.rstrip('.')})" if state is not None and state.problem else ""
        return 0, Finding(ERROR, f"The device's mirror sessions couldn't be read{why}, so NOMAD can't tell which "
                                 "session number is free: log in over SSH, or choose a session number.", key)
    number = state.free_session(avoid)
    if not number:
        return 0, Finding(ERROR, "Every session number is in use on the device.", key)
    return number, None


def destination_line(request, session, port, replicate=True):
    line = f"monitor session {session} destination interface {port}"
    if request.replicate and replicate:
        line += " encapsulation replicate"
    if request.ingress_vlan:
        line += f" ingress untagged vlan {request.ingress_vlan}"
    return line


def add_session(result, network_map, request, states, key, role, lines_for):
    """A step for one switch with a session: lines_for(number) gives its lines. Returns the step (or None)."""
    number, finding = session_for(request, states, key)
    if finding is not None:
        finding.text = f"{device_label(network_map, key)}: {finding.text}"
        result.findings.append(finding)
        if not number:
            return None
    step = result.step_for(key)
    if step is None:
        step = Step(key, role)
        result.steps.append(step)
    else:
        step.role = role
    step.session = number
    step.lines += lines_for(number)
    step.undo_lines.insert(0, f"no monitor session {number}")
    return step


def plan_span(network_map, request, sources, states, result):
    def lines(number):
        return [f"monitor session {number} source {item.ios()}" for item in sources] + \
            [destination_line(request, number, request.dest_port)]
    add_session(result, network_map, request, states, request.source_device, SOURCE, lines)


def plan_rspan(network_map, request, sources, states, result):
    findings = result.findings
    used = used_vlans(network_map)
    vlan = request.rspan_vlan or free_rspan_vlan(network_map)
    if not vlan:
        findings.append(Finding(ERROR, "No VLAN is free for RSPAN: choose one."))
        return
    if request.rspan_vlan and vlan in used:
        findings.append(Finding(ERROR, f"VLAN {vlan} is in use on the map: RSPAN needs a VLAN used for nothing "
                                       "else (its traffic is flooded everywhere it goes)."))
        return
    result.rspan_vlan = vlan
    carry = vlan_path.plan(network_map, vlan, RSPAN_NAME, a=request.source_device, b=request.dest_device)
    for finding in carry.findings:
        if finding.severity != INFO:
            findings.append(finding)
    if not carry.ok:
        return
    result.route, result.hops = list(carry.route), list(carry.hops)
    for carried in carry.changes:
        step = Step(carried.device, PATH, notes=list(carried.notes))
        if carried.create_vlan:
            step.lines += [f"vlan {vlan}", " remote-span", f" name {RSPAN_NAME}", " exit"]
        for port in carried.trunks:
            step.lines += [f"interface {port}", f" switchport trunk allowed vlan add {vlan}", " exit"]
            step.undo_lines += [f"interface {port}", f" switchport trunk allowed vlan remove {vlan}", " exit"]
        if carried.create_vlan:
            step.undo_lines.append(f"no vlan {vlan}")
        result.steps.append(step)

    def source_lines(number):
        return [f"monitor session {number} source {item.ios()}" for item in sources] + \
            [f"monitor session {number} destination remote vlan {vlan}"]

    def destination_lines(number):
        return [f"monitor session {number} source remote vlan {vlan}",
                destination_line(request, number, request.dest_port, replicate=False)]
    destination = add_session(result, network_map, request, states, request.dest_device, DESTINATION,
                              destination_lines)
    source = add_session(result, network_map, request, states, request.source_device, SOURCE, source_lines)
    # Set up: the VLAN and trunks first, then the destination, then the source (so copies start once there's
    # somewhere for them); taken away in reverse
    order = [step for step in result.steps if step not in (destination, source)] + \
        [step for step in (destination, source) if step is not None]
    result.steps = order
    if request.replicate:
        findings.append(Finding(INFO, "Copies over RSPAN can't keep their tags: they go out of the destination "
                                      "untagged."))


def plan_erspan(network_map, request, sources, states, result):
    findings = result.findings
    devices = network_map.devices
    source = devices[request.source_device]
    xe = is_ios_xe(source)
    if xe is False:
        findings.append(Finding(WARNING, f"{source.label} looks like classic IOS, which has no ERSPAN (it's IOS XE: "
                                         "Catalyst 9000, 3650/3850, ISR/ASR): it will probably refuse it.",
                                request.source_device))
    elif xe is None:
        findings.append(Finding(INFO, f"NOMAD can't tell whether {source.label} runs IOS XE (ERSPAN needs it).",
                                request.source_device))
    origin = (request.origin_ip or source.mgmt_ip).strip()
    if not valid_ipv4(origin):
        findings.append(Finding(ERROR, f"Choose the address of {source.label} the copies come from (its origin "
                                       "address).", request.source_device))
        return
    result.origin_ip = origin
    erspan_id = request.erspan_id or free_erspan_id(states)
    if not 1 <= erspan_id <= MAX_ERSPAN_ID:
        findings.append(Finding(ERROR, f"ERSPAN IDs go from 1 to {MAX_ERSPAN_ID}."))
        return
    result.erspan_id = erspan_id
    vrf = f"   vrf {request.vrf.strip()}" if request.vrf.strip() else ""
    description = f" description NOMAD {request.name}".rstrip()[:80] if request.name else " description NOMAD"
    if request.to == TO_PORT:
        dest = devices[request.dest_device]
        receive = (request.receive_ip or dest.mgmt_ip).strip()
        if not valid_ipv4(receive):
            findings.append(Finding(ERROR, f"Choose the address of {dest.label} the copies go to.",
                                    request.dest_device))
            return
        if is_ios_xe(dest) is False:
            findings.append(Finding(WARNING, f"{dest.label} looks like classic IOS, which can't receive ERSPAN (an "
                                             "erspan-destination session needs IOS XE).", request.dest_device))
        result.dest_ip = receive

        def destination_lines(number):
            lines = [f"monitor session {number} type erspan-destination", description,
                     f" destination interface {request.dest_port}", " source", f"  erspan-id {erspan_id}",
                     f"  ip address {receive}"]
            if vrf:
                lines.append(vrf)
            return lines + [" exit", " no shutdown", " exit"]
        add_session(result, network_map, request, states, request.dest_device, DESTINATION, destination_lines)
    else:
        result.dest_ip = request.dest_ip.strip()
        if result.dest_ip == origin:
            findings.append(Finding(ERROR, "The copies can't go to the device's own address."))
            return

    def source_lines(number):
        lines = [f"monitor session {number} type erspan-source", description]
        lines += [f" source {item.ios()}" for item in sources]
        lines += [" destination", f"  erspan-id {erspan_id}", f"  ip address {result.dest_ip}",
                  f"  origin ip address {origin}"]
        if vrf:
            lines.append(vrf)
        return lines + [" exit", " no shutdown", " exit"]
    add_session(result, network_map, request, states, request.source_device, SOURCE, source_lines)
    if request.to == TO_ADDRESS and request.to_this_pc:
        findings.append(Finding(INFO, f"The copies reach this PC as GRE packets from {origin}: Capture Here "
                                      "captures them and unwraps them into an ordinary capture."))
    findings.append(Finding(INFO, "ERSPAN adds about 50 bytes to each packet: on links with a 1500-byte MTU, big "
                                  "frames arrive in two pieces (Capture Here puts them back together)."))


def free_erspan_id(states):
    used = {session.erspan_id for state in states.values() for session in state.sessions.values()}
    return next((number for number in range(1, MAX_ERSPAN_ID + 1) if number not in used), 1)


# ----------------------------------------------------------------- What's sent

def config_text(step, applet=True):
    """The lines to type for a step, from the enable (#) prompt."""
    lines = ["configure terminal", *step.lines]
    if applet and step.applet:
        lines += step.applet
    return "\n".join(lines + ["end"])


def undo_text(step, applet=True):
    """The lines that take a step away again (and its applet)."""
    lines = ["configure terminal"]
    if applet and step.applet_name:
        lines.append(f"no event manager applet {step.applet_name}")
    return "\n".join(lines + step.undo_lines + ["end"])


def applet(name, step, minutes, mirror_name=""):
    """An EEM applet that takes the step away after minutes, then deletes itself."""
    actions = ["enable", "configure terminal"]
    actions += [line.strip() for line in step.undo_lines]
    actions.append("end")
    what = f"mirror {mirror_name}" if mirror_name else "mirror"
    lines = [f"event manager applet {name}", f" event timer countdown time {minutes * 60}"]
    number = 1
    for action in actions:
        lines.append(f' action {number:03d} cli command "{action}"')
        number += 1
    lines.append(f' action {number:03d} syslog msg "NOMAD {what} taken away after {minutes_text(minutes)}"')
    number += 1
    lines += [f' action {number:03d} cli command "configure terminal"',
              f' action {number + 1:03d} cli command "no event manager applet {name}"', " exit"]
    return lines


def export_text(network_map, result):
    """Every step's lines and undo, for Copy All / Export."""
    request = result.request
    title = f"! {KIND_TITLES.get(result.kind, 'Mirror')}" + (f" {request.name}" if request.name else "")
    parts = [title, f"! {describe_request(network_map, request)}", "!"]
    for index, step in enumerate(result.steps, start=1):
        device = network_map.devices.get(step.device)
        where = f" ({device.mgmt_ip})" if device is not None and device.mgmt_ip else ""
        parts += [f"! ---- {index}. {device_label(network_map, step.device)}{where} - {ROLE_NAMES[step.role]}",
                  config_text(step), "!", "! To take it away:"]
        parts += ["! " + line for line in undo_text(step).splitlines()]
        parts.append("!")
    return "\n".join(parts) + "\n"


def describe_request(network_map, request):
    source = device_label(network_map, request.source_device)
    what = ", ".join(item.text() for item in request.sources)
    if request.to == TO_ADDRESS:
        where = f"{request.dest_ip}{' (this PC)' if request.to_this_pc else ''}"
    else:
        where = f"{device_label(network_map, request.dest_device)} {request.dest_port}" \
                f"{' (this PC)' if request.to_this_pc else ''}"
    return f"{source} {what} to {where}"


def errors_in(output):
    """The lines of a switch's answer that say it refused something."""
    return [line.strip() for line in (output or "").splitlines() if ERROR_LINE.match(line)]


# ----------------------------------------------------------------- Checking

def check_step(step, kind, state, rspan_vlan=0, erspan_id=0):
    """[what isn't right] about one step's session on a switch read again ([] when it's there as planned)."""
    if state is None or not state.read:
        return [f"Couldn't read it{f': {state.problem}' if state is not None and state.problem else ''}."]
    if not step.session:
        return []
    session = state.sessions.get(step.session)
    if session is None:
        return [f"Session {step.session} isn't there."]
    problems = []
    if kind == ERSPAN and session.kind != ERSPAN:
        problems.append(f"Session {step.session} isn't an ERSPAN session ({session.type}).")
    if kind == RSPAN and rspan_vlan and session.rspan_vlan and session.rspan_vlan != rspan_vlan:
        problems.append(f"Session {step.session} uses RSPAN VLAN {session.rspan_vlan}, not {rspan_vlan}.")
    if erspan_id and session.erspan_id and session.erspan_id != erspan_id:
        problems.append(f"Session {step.session} has ERSPAN ID {session.erspan_id}, not {erspan_id}.")
    if "disabled" in session.status.lower():
        problems.append(f"Session {step.session} is shut down ({session.status}).")
    return problems


# ----------------------------------------------------------------- Mirrors set up (kept on this computer)

ACTIVE, PARTIAL, REMOVED, FAILED, SENT = "active", "partial", "removed", "failed", "sent"
STATE_NAMES = {ACTIVE: "Set up", PARTIAL: "Partly set up", REMOVED: "Taken away", FAILED: "Failed",
               SENT: "Sent to sessions"}
STEP_SET, STEP_SENT, STEP_FAILED, STEP_REMOVED, STEP_PENDING = "set", "sent", "failed", "removed", ""
FILE_NAME = "mirrors.json"
KEEP_REMOVED = 50  # Mirrors taken away that are kept in the list


def now_text():
    return datetime.datetime.now().replace(microsecond=0).isoformat()


@dataclass
class RecordStep:
    device: str
    label: str
    address: str
    role: str
    session: int = 0
    setup: str = ""  # What was sent (config_text)
    undo: str = ""  # What takes it away (undo_text)
    applet_name: str = ""
    applet_ok: object = None  # The switch took the applet (True), refused it (False), or not sent (None)
    state: str = STEP_PENDING
    problem: str = ""
    names: list = field(default_factory=list)  # The switch's name and addresses (to find its saved session)


@dataclass
class MirrorRecord:
    id: str
    name: str = ""
    kind: str = SPAN
    what: str = ""  # describe_request
    created: str = ""
    expires: str = ""  # ISO time the switches take it away themselves ("" never)
    removed: str = ""
    state: str = ACTIVE
    map_name: str = ""
    rspan_vlan: int = 0
    erspan_id: int = 0
    origin_ip: str = ""
    dest_ip: str = ""
    to_this_pc: bool = False
    adapter: str = ""  # This computer's adapter the copies go to (to capture them on)
    nomad_timer: bool = False  # Some switch refused the applet: NOMAD takes it away when it expires
    steps: list = field(default_factory=list)  # [RecordStep], in the order they were set up
    note: str = ""

    @property
    def expired(self):
        return bool(self.expires) and self.expires <= now_text()

    def update_state(self):
        states = {step.state for step in self.steps}
        if not self.steps or (states <= {STEP_REMOVED, STEP_PENDING} and STEP_REMOVED in states):
            self.state = REMOVED
        elif states <= {STEP_SET}:
            self.state = ACTIVE
        elif STEP_SENT in states and states <= {STEP_SENT, STEP_SET}:
            self.state = SENT
        elif states & {STEP_SET, STEP_SENT}:
            self.state = PARTIAL
        else:
            self.state = FAILED
        return self.state


def record_from(network_map, result, record_id=None, map_name=""):
    """A MirrorRecord for a plan about to be set up (its steps pending)."""
    request = result.request
    record = MirrorRecord(record_id or new_id(), name=request.name, kind=result.kind,
                          what=describe_request(network_map, request), created=now_text(), map_name=map_name,
                          rspan_vlan=result.rspan_vlan, erspan_id=result.erspan_id, origin_ip=result.origin_ip,
                          dest_ip=result.dest_ip, to_this_pc=request.to_this_pc, adapter=request.adapter)
    if request.remove_after:
        expires = datetime.datetime.now() + datetime.timedelta(minutes=request.remove_after)
        record.expires = expires.replace(microsecond=0).isoformat()
    for step in result.steps:
        device = network_map.devices.get(step.device)
        names = [name for name in ([device.name, *device.addresses] if device is not None else []) if name]
        record.steps.append(RecordStep(step.device, device_label(network_map, step.device),
                                       device.mgmt_ip if device is not None else "", step.role, step.session,
                                       config_text(step), undo_text(step), step.applet_name, names=names))
    return record


def new_id():
    return uuid.uuid4().hex[:6].upper()


def record_from_dict(data):
    known = {item.name for item in fields(MirrorRecord)}
    record = MirrorRecord(**{key: value for key, value in data.items() if key in known and key != "steps"})
    step_fields = {item.name for item in fields(RecordStep)}
    record.steps = [RecordStep(**{key: value for key, value in step.items() if key in step_fields})
                    for step in data.get("steps", [])]
    return record


class MirrorStore:
    """The mirrors set up from this computer, newest first, in a JSON file in the app's folder."""

    def __init__(self, path=None):
        self.path = path
        self.records = []

    @classmethod
    def default(cls):
        from ..system import app_data_dir
        store = cls(app_data_dir() / FILE_NAME)
        store.load()
        return store

    def load(self):
        self.records = []
        if self.path is None:
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
            self.records = [record_from_dict(item) for item in data.get("mirrors", [])]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as error:
            log.warning("Couldn't read the mirrors from %s: %s", self.path, error)

    def save(self):
        if self.path is None:
            return
        from ..system import replace_file
        removed = [record for record in self.records if record.state == REMOVED]
        if len(removed) > KEEP_REMOVED:
            doomed = {id(record) for record in removed[KEEP_REMOVED:]}
            self.records = [record for record in self.records if id(record) not in doomed]
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump({"version": 1, "mirrors": [asdict(record) for record in self.records]}, file, indent=1)
        replace_file(temporary, self.path)

    def get(self, record_id):
        return next((record for record in self.records if record.id == record_id), None)

    def put(self, record):
        existing = self.get(record.id)
        if existing is not None:
            self.records[self.records.index(existing)] = record
        else:
            self.records.insert(0, record)
        self.save()

    def forget(self, record_id):
        self.records = [record for record in self.records if record.id != record_id]
        self.save()

    def live(self):
        """Mirrors not taken away yet."""
        return [record for record in self.records if record.state != REMOVED]

    def overdue(self):
        """Mirrors past their time that a switch refused to take away itself: NOMAD's to take away."""
        return [record for record in self.live() if record.nomad_timer and record.expired]
