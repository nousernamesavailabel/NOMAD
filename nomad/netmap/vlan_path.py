"""Carry VLAN: what to change on Cisco IOS / IOS-XE switches so a VLAN reaches a switch (B) from where it already
is, or from a switch chosen (A), over the map's links.

The way is the one needing the fewest changes (or one set by hand, switch by switch). Along it, a switch without the
VLAN gets it (on a VTP client, from the domain's VTP server), and a trunk that doesn't allow it gets
`switchport trunk allowed vlan add` (never without "add", which would replace the whole allowed list). Access
ports are never turned into trunks: a link with one in another VLAN can't carry it.

Links that would close a loop once the VLAN is on the way (redundant links) are offered, with what spanning tree
does on them, and only changed when chosen. Whether the VLAN's gateway is reachable from B is checked, never set up.
Qt-free, so it can be tested without a network.
"""
import heapq
from dataclasses import dataclass, field

from .collect import BLOCKING
from .model import FIREWALL, KIND_NAMES, ROUTER, SNMP, SWITCH, port_key, port_sort_key
from .vlans import ACCESS, ERROR, INFO, MAX_VLAN, TRUNK, WARNING, Finding, allowed, domain_of, gateways, port_info, \
    vlan_names

ENDPOINT_KINDS = {SWITCH, ROUTER, FIREWALL}  # A router or firewall can be where the way starts, never on it
CARRIES = "carries"  # The port already carries the VLAN
ADD = "add"  # A trunk that doesn't allow it yet: allowed vlan add
BLOCKED = "blocked"  # An access port in another VLAN, or a router or firewall port without a subinterface for it
UNKNOWN = "unknown"  # Its VLANs weren't read (no SNMP, added by hand, or the port isn't in what was read)
UNKNOWN_COST = 10  # Crossing a port that wasn't read: only when there's no other way
STP_BLOCKED_COST = 20  # A port spanning tree blocks in the VLAN's instance (MST): avoided when there's another way
EXTENDED_VLANS = 1006  # From here up, VTP version 1 and 2 servers and clients can't have them
STP_NAMES = {"pvst": "PVST+", "rapid-pvst": "Rapid-PVST+", "mst": "MST", "mistp": "MISTP", "mistp-pvst": "MISTP-PVST+"}
PER_VLAN_STP = {"pvst", "rapid-pvst"}


@dataclass
class Hop:
    """A link between two network devices as Carry VLAN sees it. The links of a port-channel are one hop, on the
    port-channels (where the configuration goes: changing a member on its own gets it suspended)."""
    a: str
    a_port: str
    b: str
    b_port: str
    links: list = field(default_factory=list)  # The map's Links it stands for

    @property
    def key(self):
        return frozenset([(self.a, port_key(self.a_port)), (self.b, port_key(self.b_port))])

    def port_on(self, device):
        return self.a_port if device == self.a else self.b_port

    def other(self, device):
        return self.b if device == self.a else self.a

    def text(self, network_map=None, start=None):
        """"Gi1/0/49 - SW2 Gi1/0/50" (from start), or with no start "SW1 Gi1/0/49 - SW2 Gi1/0/50"."""
        def label(key):
            device = network_map.devices.get(key) if network_map is not None else None
            return device.label if device is not None else key
        if start is not None:
            return f"{self.port_on(start)} - {label(self.other(start))} {self.port_on(self.other(start))}"
        return f"{label(self.a)} {self.a_port} - {label(self.b)} {self.b_port}"


@dataclass
class StpView:
    """How a switch's spanning tree has its ports for the VLAN being carried (from crawl.read_stp)."""
    mode: str = ""
    instance: int = -1  # The VLAN's instance: the VLAN on PVST+, its MST instance on MST (-1: unknown)
    ports: dict = field(default_factory=dict)  # port_key -> (FORWARDING, BLOCKING or DISABLED, role or state)
    root: object = None  # Whether it's the root bridge of that tree (None: not known)

    def state(self, port):
        return self.ports.get(port_key(port), ("", ""))


def stp_view(tables):
    """A StpView from a read_vlans_of(stp_vlan=...) DeviceTables, or None when no STP was read."""
    if tables is None or not tables.stp_read:
        return None
    ports = {}
    for if_index, state in tables.stp_ports.items():
        name = tables.interfaces.get(if_index)
        if name:
            ports[port_key(name)] = state
    return StpView(tables.stp_mode, tables.stp_instance, ports, tables.stp_root)


@dataclass
class Step:
    """What to send to one switch: one step for the way (and B's edge ports), and one more for the redundant links
    chosen, which go last so a loop can only form once the way works."""
    device: str
    create_vlan: bool = False
    name: str = ""  # Given to the VLAN when it's created
    trunks: list = field(default_factory=list)  # Ports to add the VLAN to (allowed vlan add)
    edge: list = field(default_factory=list)  # [(port, its VLAN entry before)] to put in the VLAN at B
    redundant: bool = False
    notes: list = field(default_factory=list)  # Why it's in the plan (for the dialog), such as "VTP server"

    @property
    def empty(self):
        return not (self.create_vlan or self.trunks or self.edge)


@dataclass
class Redundant:
    """A link that would close a loop once the VLAN is on the way: changed only when chosen."""
    hop: Hop
    severity: str  # INFO when spanning tree will block one of the links, WARNING when that's not sure
    note: str
    parallel: bool = False  # Between the same two switches as a hop of the way, not in a port-channel


@dataclass
class Plan:
    vlan: int
    name: str = ""
    a: str = ""
    b: str = ""
    route: list = field(default_factory=list)  # Device keys, A first and B last
    hops: list = field(default_factory=list)  # Hop between each two of route
    steps: list = field(default_factory=list)  # [Step], in the order to send them
    redundant: list = field(default_factory=list)  # [Redundant] that could be chosen
    chosen: list = field(default_factory=list)  # [Redundant] chosen (they have steps)
    findings: list = field(default_factory=list)  # [Finding], worst first
    gateway: Finding = None  # Whether B can reach the VLAN's gateway
    already: bool = False  # B already had the VLAN reaching it
    by_hand: bool = False  # The route was set by hand

    @property
    def ok(self):
        """Whether it can be sent: nothing in the way (a problem)."""
        return bool(self.route) and not any(finding.severity == ERROR for finding in self.findings)

    @property
    def changes(self):
        return [step for step in self.steps if not step.empty]


class Graph:
    """The map's network devices and the hops between them."""

    def __init__(self, network_map):
        self.map = network_map
        self.devices = network_map.devices
        self.hops = []
        self.adjacent = {}  # Device key -> [Hop]
        grouped = {}
        for link in network_map.links:
            a, b = self.devices.get(link.a), self.devices.get(link.b)
            if a is None or b is None or a.kind not in ENDPOINT_KINDS or b.kind not in ENDPOINT_KINDS or a is b:
                continue
            a_port, b_port = logical_port(a, link.a_port), logical_port(b, link.b_port)
            key = frozenset([(link.a, port_key(a_port)), (link.b, port_key(b_port))])
            if key in grouped:
                grouped[key].links.append(link)
            else:
                grouped[key] = Hop(link.a, a_port, link.b, b_port, [link])
        for hop in grouped.values():
            self.hops.append(hop)
            self.adjacent.setdefault(hop.a, []).append(hop)
            self.adjacent.setdefault(hop.b, []).append(hop)

    def hops_of(self, key):
        return self.adjacent.get(key, [])

    def between(self, one, other):
        """The hops between two devices."""
        return [hop for hop in self.hops_of(one) if hop.other(one) == other]

    def label(self, key):
        device = self.devices.get(key)
        return device.label if device is not None else key


def logical_port(device, port):
    """The port-channel a member port is in (where its configuration goes), or the port itself."""
    if not device.port_channels or not port:
        return port
    parent = device.port_channels.get(port)
    if parent is None:
        wanted = port_key(port)
        parent = next((channel for member, channel in device.port_channels.items() if port_key(member) == wanted), None)
    return parent or port


def is_read(device):
    """Whether its VLANs were read (so its ports' states for a VLAN can be known)."""
    return device.source == SNMP and not device.manual and bool(device.vlans or device.port_vlans)


def has_vlan(device, vlan):
    return vlan in vlan_names(device)


def subinterface_for(device, port, vlan):
    """Whether a router or firewall has a subinterface (or VLAN interface on that port) for the VLAN on a port."""
    wanted = port_key(port)
    for number, gateway in gateways(device):
        if number == vlan and port_key(gateway.port.partition(".")[0]) == wanted:
            return True
    return False


def end_state(device, port, vlan):
    """How one end of a hop stands with the VLAN: CARRIES, ADD, BLOCKED or UNKNOWN."""
    if device.kind != SWITCH:
        return CARRIES if subinterface_for(device, port, vlan) else BLOCKED
    if not is_read(device):
        return UNKNOWN
    info = port_info(device, port)
    if not info:
        return UNKNOWN
    if info.get("mode") == TRUNK:
        return CARRIES if vlan in allowed(info) else ADD
    return CARRIES if info.get("vlan") == vlan else BLOCKED


def hop_states(graph, hop, vlan):
    return end_state(graph.devices[hop.a], hop.a_port, vlan), end_state(graph.devices[hop.b], hop.b_port, vlan)


def carries(graph, hop, vlan):
    """Whether a hop carries the VLAN now: both ends, and the switches have it."""
    if hop_states(graph, hop, vlan) != (CARRIES, CARRIES):
        return False
    return all(device.kind != SWITCH or has_vlan(device, vlan) for device in (graph.devices[hop.a],
                                                                            graph.devices[hop.b]))


def stp_blocked(stp, hop):
    """Whether spanning tree blocks the VLAN's instance on either end of a hop (from the STP read)."""
    for key in (hop.a, hop.b):
        view = (stp or {}).get(key)
        if view is not None and view.state(hop.port_on(key))[0] == BLOCKING:
            return True
    return False


def hop_cost(graph, hop, vlan, stp=None, avoid_blocked=True):
    """What crossing a hop costs (the ends to change, more for ends not read), or None when it can't carry the VLAN."""
    states = hop_states(graph, hop, vlan)
    if BLOCKED in states:
        return None
    cost = sum(1 for state in states if state == ADD) + sum(UNKNOWN_COST for state in states if state == UNKNOWN)
    if avoid_blocked and stp_blocked(stp, hop):
        cost += STP_BLOCKED_COST
    return cost


def device_cost(graph, key, vlan):
    """What going through a device costs: 1 when it needs the VLAN created."""
    device = graph.devices[key]
    if device.kind != SWITCH:
        return 0
    if not is_read(device):
        return UNKNOWN_COST
    return 0 if has_vlan(device, vlan) else 1


def components(graph, vlan):
    """The VLAN's islands now: [set of device keys] joined by hops that carry it. Switches that have it with no hop
    carrying it are islands of one."""
    seen, found = set(), []
    starts = [key for key, device in graph.devices.items()
              if (device.kind == SWITCH and has_vlan(device, vlan))
              or any(number == vlan for number, _ in gateways(device))]
    for start in starts:
        if start in seen:
            continue
        island, queue = {start}, [start]
        while queue:
            key = queue.pop()
            for hop in graph.hops_of(key):
                other = hop.other(key)
                if other not in island and carries(graph, hop, vlan):
                    island.add(other)
                    queue.append(other)
        seen |= island
        found.append(island)
    return found


def gateway_devices(graph, vlan):
    """{device key: [Gateway]} for the VLAN's gateways on the map."""
    found = {}
    for key, device in graph.devices.items():
        for number, gateway in gateways(device):
            if number == vlan:
                found.setdefault(key, []).append(gateway)
    return found


def in_use(graph, island, vlan):
    """Whether an island really has the VLAN in use (a hop carrying it, an access port in it, or a gateway), rather
    than a switch that only lists it (as every VTP client in the domain does)."""
    if len(island) > 1:
        return True
    key = next(iter(island))
    device = graph.devices[key]
    if any(number == vlan for number, _ in gateways(device)):
        return True
    return any(info.get("mode") != TRUNK and (info.get("vlan") == vlan or info.get("voice") == vlan)
               for info in device.port_vlans.values())


def sources_for(graph, vlan):
    """Where the VLAN already is, for finding A: the island with its gateway, else the islands where it's in use,
    else every switch that has it. Returns (set of device keys, a Finding saying which, or None)."""
    islands = components(graph, vlan)
    gateway_keys = set(gateway_devices(graph, vlan))
    with_gateway = [island for island in islands if island & gateway_keys]
    if with_gateway:
        return set().union(*with_gateway), None
    used = [island for island in islands if in_use(graph, island, vlan)]
    if used:
        return set().union(*used), None
    listed = set().union(*islands) if islands else set()
    if listed:
        return listed, Finding(INFO, f"VLAN {vlan} isn't in use on any link or port yet: starting from the switches "
                                     "that have it.")
    return set(), None


def search(graph, vlan, sources, target, stp=None, avoid=frozenset()):
    """The way from any of sources to target needing the fewest changes (then fewest hops), as (route, hops), or
    None. Routers and firewalls can only be where it starts. avoid: devices it mustn't go through."""
    best = {}
    queue = []
    order = 0
    for key in sources:
        if key in graph.devices and key not in avoid:
            best[key] = (0, 0)
            heapq.heappush(queue, (0, 0, order, key, None))
            order += 1
    previous = {}
    while queue:
        cost, hops, _, key, came = heapq.heappop(queue)
        if best.get(key, (cost, hops)) < (cost, hops):
            continue
        if came is not None:
            previous[key] = came
        if key == target:
            break
        device = graph.devices[key]
        if device.kind != SWITCH and key not in sources:
            continue  # A router or firewall is an end, never on the way
        for hop in sorted(graph.hops_of(key), key=lambda item: port_sort_key(item.port_on(key))):
            other = hop.other(key)
            if other in avoid or other in sources:
                continue
            step = hop_cost(graph, hop, vlan, stp)
            if step is None:
                continue
            if graph.devices[other].kind != SWITCH and other != target:
                continue
            total = (cost + step + device_cost(graph, other, vlan), hops + 1)
            if total < best.get(other, (float("inf"), 0)):
                best[other] = total
                heapq.heappush(queue, (*total, order, other, (key, hop)))
                order += 1
    if target not in best:
        return None
    route, hops = [target], []
    key = target
    while key in previous:
        key, hop = previous[key]
        route.append(key)
        hops.append(hop)
    return route[::-1], hops[::-1]


def fill_between(network_map, vlan, one, other, avoid=(), stp=None):
    """Fill In Between: the switches between two of a route set by hand (the way needing the fewest changes, not
    going through avoid), as (route from one to other, hops), or None."""
    graph = Graph(network_map)
    return search(graph, vlan, {one}, other, stp, frozenset(avoid) - {one, other})


def check_route(graph, route, chosen_hops=None):
    """A route set by hand: [device key], A first. chosen_hops: [Hop or None] between each two (None: the only
    one, or the port-channel). Returns ([Hop or None], [Finding]): a None where there's no hop to use."""
    findings, hops = [], []
    chosen_hops = list(chosen_hops or [])
    if len(route) < 2:
        findings.append(Finding(ERROR, "A route needs at least two switches: A and B."))
    seen = set()
    for index, key in enumerate(route):
        device = graph.devices.get(key)
        if device is None:
            findings.append(Finding(ERROR, f"{key} isn't on the map any more.", key))
            continue
        if key in seen:
            findings.append(Finding(ERROR, f"{device.label} is on the route twice (that would be a loop).", key))
        seen.add(key)
        if device.kind not in ENDPOINT_KINDS:
            findings.append(Finding(ERROR, f"{device.label} isn't a switch, router or firewall.", key))
        elif device.kind != SWITCH and index:
            where = "B" if index == len(route) - 1 else "in the middle of the route"
            findings.append(Finding(ERROR, f"{device.label} is a {KIND_NAMES[device.kind].lower()}, which can't pass a "
                                           f"VLAN on: it can only be A, not {where}.", key))
    for index in range(len(route) - 1):
        one, other = route[index], route[index + 1]
        if one not in graph.devices or other not in graph.devices:
            hops.append(None)
            continue
        between = graph.between(one, other)
        wanted = chosen_hops[index] if index < len(chosen_hops) else None
        if wanted is not None:
            hop = next((item for item in between if item.key == wanted.key), None)
        elif len(between) == 1:
            hop = between[0]
        else:
            hop = None
        if not between:
            findings.append(Finding(ERROR, f"No link between {graph.label(one)} and {graph.label(other)} on the map: "
                                           "add the switches between them (Fill In Between).", one, other=other))
        elif hop is None:
            findings.append(Finding(ERROR, f"{graph.label(one)} and {graph.label(other)} have {len(between)} links: "
                                           "choose the one to use.", one, other=other))
        hops.append(hop)
    return hops, findings


def stp_note(graph, hop, vlan, stp):
    """(severity, text) about what spanning tree does if the VLAN is added on a redundant link too."""
    modes = {graph.devices[key].stp_mode or ((stp or {}).get(key) or StpView()).mode for key in (hop.a, hop.b)}
    known = {mode for mode in modes if mode}
    states = []
    for key in (hop.a, hop.b):
        view = (stp or {}).get(key)
        state = view.state(hop.port_on(key)) if view is not None else ("", "")
        if state[0]:
            states.append(f"{graph.label(key)} {hop.port_on(key)} {state[1] or state[0]}")
    now = f" Now: {', '.join(states)}." if states else ""
    if "" in modes or not known:
        return WARNING, ("Spanning tree mode unknown on " + " and ".join(
            graph.label(key) for key in (hop.a, hop.b) if not graph.devices[key].stp_mode) +
            ": if spanning tree doesn't run for this VLAN, this link makes a loop." + now)
    if len(known) > 1:
        names = ", ".join(sorted(STP_NAMES.get(mode, mode) for mode in known))
        return WARNING, f"The switches run different spanning trees ({names}): check which link will block first." + now
    mode = known.pop()
    if mode in PER_VLAN_STP:
        return INFO, (f"{STP_NAMES[mode]}: spanning tree keeps one of the redundant links blocked for VLAN {vlan}, "
                      "so this adds a backup way rather than a loop." + now)
    if mode == "mst":
        instances = {view.instance for view in ((stp or {}).get(key) for key in (hop.a, hop.b))
                     if view is not None and view.instance >= 0}
        which = f"MST instance {instances.pop()}" if len(instances) == 1 else "its MST instance"
        return WARNING, (f"MST: VLAN {vlan} is in {which}, whose topology (not the VLAN's) decides which link blocks. "
                         "If that instance blocks a link of the way instead of this one, the VLAN stops there." + now)
    return WARNING, f"{STP_NAMES.get(mode, mode)}: check which link spanning tree will block before adding this." + now


def plan(network_map, vlan, name="", a=None, b=None, edge_ports=(), stp=None, route=None, route_hops=None,
         chosen=(), vtp_servers=None):
    """What to change so VLAN reaches switch b.

    a None: from wherever the VLAN already is (its gateway's island first). route: a route set by hand ([device
    key], A first, B last; route_hops the hop chosen between each two, or None) instead of searching. edge_ports:
    ports of b to put in the VLAN too. stp: {device key: StpView} from the read before planning. chosen: keys
    (Hop.key) of redundant links to add it to as well. vtp_servers: {VTP domain: device key} chosen where a domain
    has more than one server."""
    result = Plan(vlan, (name or "").strip(), a or "", b or "", by_hand=route is not None)
    findings = result.findings
    if not 1 <= vlan <= MAX_VLAN:
        findings.append(Finding(ERROR, f"{vlan} isn't a VLAN (1 to {MAX_VLAN})."))
        return result
    graph = Graph(network_map)
    if route is not None:
        route = list(route)
        result.a, result.b = (route[0], route[-1]) if route else ("", "")
        hops, problems = check_route(graph, route, route_hops)
        findings.extend(problems)
        if any(finding.severity == ERROR for finding in problems):
            return finish(result)
        result.route, result.hops = route, hops
    else:
        target = graph.devices.get(b)
        if target is None or target.kind != SWITCH:
            findings.append(Finding(ERROR, "Choose a switch for B."))
            return finish(result)
        if a:
            if a not in graph.devices:
                findings.append(Finding(ERROR, "A isn't on the map any more."))
                return finish(result)
            sources = {a}
        else:
            sources, note = sources_for(graph, vlan)
            if note is not None:
                findings.append(note)
            if not sources:
                findings.append(Finding(ERROR, f"No switch on the map has VLAN {vlan}: choose A (where it starts)."))
                return finish(result)
        if b in sources:
            result.route, result.hops = [b], []
            result.a = b
            result.already = True
        else:
            found = search(graph, vlan, sources, b, stp)
            if found is None:
                where = graph.label(a) if a else f"anywhere VLAN {vlan} is"
                findings.append(Finding(ERROR, f"No way from {where} to {graph.label(b)} that can carry VLAN {vlan}: "
                                               "every way has an access port in another VLAN, or goes through a "
                                               "router or firewall. Set the route by hand to see why.", b))
                return finish(result)
            result.route, result.hops = found
            result.a = result.route[0]
    check_way(graph, result, stp)
    add_steps(graph, result, edge_ports, vtp_servers or {})
    find_redundant(graph, result, stp, set(chosen))
    check_gateway(graph, result)
    return finish(result)


def finish(result):
    order = {ERROR: 0, WARNING: 1, INFO: 2}
    result.findings.sort(key=lambda finding: order[finding.severity])
    return result


def check_way(graph, result, stp):
    """Findings about the way itself: ports that block it, that weren't read, and spanning tree blocking it."""
    vlan = result.vlan
    for hop in result.hops:
        for key in (hop.a, hop.b):
            device = graph.devices[key]
            state = end_state(device, hop.port_on(key), vlan)
            port = hop.port_on(key)
            if state == BLOCKED:
                if device.kind == SWITCH:
                    info = port_info(device, port)
                    findings_text = (f"{device.label} {port} is an access port in VLAN {info.get('vlan') or '?'}, so "
                                     f"this link can't carry VLAN {vlan}. Carry VLAN never turns an access port into "
                                     "a trunk: change it by hand, or choose another way.")
                else:
                    findings_text = (f"{device.label} {port} has no subinterface for VLAN {vlan}, so the link to it "
                                     "can't carry the VLAN.")
                result.findings.append(Finding(ERROR, findings_text, key, port, vlan))
            elif state == UNKNOWN:
                why = ("was added by hand or doesn't answer SNMP" if not is_read(device)
                       else f"has no VLAN details for {port}")
                result.findings.append(Finding(WARNING, f"{device.label} {why}, so NOMAD can't tell whether {port} "
                                                        f"carries VLAN {vlan}, or change it: check it by hand.",
                                               key, port, vlan))
        if stp_blocked(stp, hop):
            text = (f"Spanning tree blocks {hop.text(graph.map)} in VLAN {vlan}'s instance now, so the VLAN won't "
                    "pass there unless the topology changes.")
            modes = {graph.devices[key].stp_mode for key in (hop.a, hop.b)}
            if modes <= PER_VLAN_STP and carries(graph, hop, vlan):
                text = (f"Spanning tree blocks VLAN {vlan} on {hop.text(graph.map)}: it already reaches the far side "
                        "another way.")
                result.findings.append(Finding(INFO, text, hop.a, hop.a_port, vlan))
            else:
                result.findings.append(Finding(WARNING, text, hop.a, hop.a_port, vlan))
    for key in result.route:
        device = graph.devices[key]
        if device.kind == SWITCH and device.manual:
            result.findings.append(Finding(WARNING, f"{device.label} was added by hand (an unmanaged switch?): many "
                                                    "drop tagged frames, so check it passes VLAN tags.", key))


def vtp_server_for(graph, device, vlan, vtp_servers, findings):
    """Where a VTP client's VLAN must be created: its domain's server on the map, or None (with a finding)."""
    domain = domain_of(device)
    servers = sorted((key for key, other in graph.devices.items()
                      if other.kind == SWITCH and other.vtp_mode == "server" and domain_of(other) == domain),
                     key=lambda key: graph.label(key).lower())
    if domain in vtp_servers and vtp_servers[domain] in servers:
        return vtp_servers[domain]
    if not servers:
        findings.append(Finding(ERROR, f"{device.label} is a VTP client in domain {domain or '(none)'}, and no VTP "
                                       f"server for it is on the map: create VLAN {vlan} on the domain's server by "
                                       "hand, then Plan again.", device.key, vlan=vlan))
        return None
    if len(servers) > 1:
        findings.append(Finding(INFO, f"VTP domain {domain} has {len(servers)} servers on the map "
                                      f"({', '.join(graph.label(key) for key in servers)}): creating VLAN {vlan} on "
                                      f"{graph.label(servers[0])}. On VTP version 3 only the primary server can.",
                                device.key, vlan=vlan))
    return servers[0]


def add_steps(graph, result, edge_ports, vtp_servers):
    """A step for each switch of the way that needs a change, the VTP server first."""
    vlan, findings = result.vlan, result.findings
    steps = {key: Step(key, name=result.name) for key in result.route if graph.devices[key].kind == SWITCH}
    server_steps = {}
    for key in list(steps):
        device = graph.devices[key]
        if not is_read(device) or has_vlan(device, vlan):
            continue
        if device.vtp_mode == "client":
            server = vtp_server_for(graph, device, vlan, vtp_servers, findings)
            if server is None:
                continue
            server_device = graph.devices[server]
            if has_vlan(server_device, vlan):
                findings.append(Finding(WARNING, f"{device.label} is a VTP client without VLAN {vlan}, though its "
                                                 f"server {server_device.label} has it: check VTP between them (the "
                                                 "domain, password, version, and the trunk to the server).", key,
                                        vlan=vlan))
                continue
            step = server_steps.get(server) or steps.get(server) or Step(server, name=result.name)
            step.create_vlan = True
            note = f"VTP server for {device.label}"
            if note not in step.notes:
                step.notes.append(note)
            if server not in steps:
                server_steps[server] = step
            if vlan >= EXTENDED_VLANS:
                findings.append(Finding(WARNING, f"VLAN {vlan} is an extended VLAN: VTP version 1 and 2 servers and "
                                                 "clients can't have it (only version 3, or transparent mode).", server,
                                        vlan=vlan))
        else:
            steps[key].create_vlan = True
            if vlan >= EXTENDED_VLANS and device.vtp_mode == "server":
                findings.append(Finding(WARNING, f"VLAN {vlan} is an extended VLAN: a VTP version 1 or 2 server "
                                                 "can't have it (only version 3, or transparent mode).", key,
                                        vlan=vlan))
    for hop in result.hops:
        for key in (hop.a, hop.b):
            if key in steps and end_state(graph.devices[key], hop.port_on(key), vlan) == ADD:
                steps[key].trunks.append(hop.port_on(key))
    b = graph.devices.get(result.b)
    for port in edge_ports:
        if b is None or result.b not in steps:
            break
        port = logical_port(b, port)
        info = port_info(b, port)
        uplink = next((hop for hop in graph.hops_of(result.b) if port_key(hop.port_on(result.b)) == port_key(port)),
                      None)
        if uplink is not None:
            findings.append(Finding(WARNING, f"{b.label} {port} goes to {graph.label(uplink.other(result.b))}: it's a "
                                             "link, not an edge port.", result.b, port, vlan))
        if info.get("mode") == TRUNK:
            if vlan not in allowed(info) and port not in steps[result.b].trunks:
                steps[result.b].trunks.append(port)
        elif info.get("mode") == ACCESS and info.get("vlan") == vlan:
            continue
        else:
            if not info:
                findings.append(Finding(INFO, f"NOMAD has no VLAN details for {b.label} {port}: it will be made an "
                                              "access port.", result.b, port, vlan))
            steps[result.b].edge.append((port, dict(info)))
    ordered = list(server_steps.values()) + [steps[key] for key in result.route if key in steps]
    result.steps = ordered


def find_redundant(graph, result, stp, chosen_keys):
    """Links that would close a loop with the way: offered, and added (as last steps) when chosen."""
    vlan = result.vlan
    islands = components(graph, vlan)
    route = set(result.route)
    carrying = set(route)
    for island in islands:
        if island & route:
            carrying |= island
    way_keys = {hop.key for hop in result.hops}
    way_pairs = {frozenset([hop.a, hop.b]) for hop in result.hops}
    seen = set()
    for key in result.route:
        for hop in graph.hops_of(key):
            other = hop.other(key)
            if hop.key in way_keys or hop.key in seen or other not in carrying or carries(graph, hop, vlan):
                continue
            seen.add(hop.key)
            states = hop_states(graph, hop, vlan)
            devices = (graph.devices[hop.a], graph.devices[hop.b])
            if BLOCKED in states or UNKNOWN in states or any(device.kind != SWITCH for device in devices):
                continue
            severity, note = stp_note(graph, hop, vlan, stp)
            parallel = frozenset([hop.a, hop.b]) in way_pairs
            if parallel:
                note = ("Another link between the same two switches, not in a port-channel (a port-channel would use "
                        "both). " + note)
            item = Redundant(hop, severity, note, parallel)
            result.redundant.append(item)
            if hop.key in chosen_keys:
                result.chosen.append(item)
    by_device = {}
    for item in result.chosen:
        for key in (item.hop.a, item.hop.b):
            if end_state(graph.devices[key], item.hop.port_on(key), vlan) != ADD:
                continue
            step = by_device.get(key)
            if step is None:
                step = by_device[key] = Step(key, redundant=True, notes=["Redundant links"])
            step.trunks.append(item.hop.port_on(key))
            device = graph.devices[key]
            if key not in route and not has_vlan(device, vlan) and device.vtp_mode != "client":
                step.create_vlan, step.name = True, result.name
    result.steps += [by_device[key] for key in sorted(by_device, key=lambda key: graph.label(key).lower())]


def check_gateway(graph, result):
    """Whether B reaches the VLAN's gateway once the plan is done (check only: gateways are never set up)."""
    vlan = result.vlan
    found = gateway_devices(graph, vlan)
    if not found:
        result.gateway = Finding(INFO, f"No gateway for VLAN {vlan} on the map (no VLAN interface or subinterface "
                                       f"for it): hosts in it at {graph.label(result.b)} can reach only VLAN {vlan}.",
                                 vlan=vlan)
        return
    planned = {hop.key for hop in result.hops} | {item.hop.key for item in result.chosen}
    island, queue = {result.b}, [result.b]
    while queue:
        key = queue.pop()
        for hop in graph.hops_of(key):
            other = hop.other(key)
            if other in island:
                continue
            if hop.key in planned or carries(graph, hop, vlan):
                island.add(other)
                queue.append(other)
    texts = [f"{gateway.address}/{gateway.prefix} on {graph.label(key)} {gateway.port}"
             for key, items in sorted(found.items()) for gateway in items]
    reached = [key for key in found if key in island]
    if reached:
        reachable = [f"{gateway.address}/{gateway.prefix} on {graph.label(key)} {gateway.port}"
                     for key in sorted(reached) for gateway in found[key]]
        result.gateway = Finding(INFO, f"{', '.join(reachable)}: reachable from {graph.label(result.b)} over "
                                       "this plan.", reached[0], vlan=vlan)
    else:
        result.gateway = Finding(WARNING, f"VLAN {vlan}'s gateway ({'; '.join(texts)}) isn't connected to "
                                          f"{graph.label(result.b)} by this plan: hosts there won't get past VLAN "
                                          f"{vlan}.", next(iter(found)), vlan=vlan)


# ----------------------------------------------------------------- Configuration text


def config(step, vlan, save=False):
    """The IOS / IOS-XE lines for one step."""
    lines = ["configure terminal"]
    if step.create_vlan:
        lines.append(f"vlan {vlan}")
        if step.name:
            lines.append(f" name {vlan_name_text(step.name)}")
        lines.append(" exit")
    for port in step.trunks:
        lines += [f"interface {port}", f" switchport trunk allowed vlan add {vlan}", " exit"]
    for port, before in step.edge:
        lines.append(f"interface {port}")
        if before.get("mode") != ACCESS:
            lines.append(" switchport mode access")
        lines += [f" switchport access vlan {vlan}", " exit"]
    lines.append("end")
    if save:
        lines.append("write memory")
    return "\n".join(lines)


def undo(step, vlan, save=False):
    """The lines that take one step back out."""
    lines = ["configure terminal"]
    for port in step.trunks:
        lines += [f"interface {port}", f" switchport trunk allowed vlan remove {vlan}", " exit"]
    for port, before in step.edge:
        lines.append(f"interface {port}")
        old = before.get("vlan")
        lines.append(f" switchport access vlan {old}" if old else " no switchport access vlan")
        if before.get("mode") == TRUNK:
            lines.append(" switchport mode trunk")
        lines.append(" exit")
    if step.create_vlan:
        lines.append(f"no vlan {vlan}")
    lines.append("end")
    if save:
        lines.append("write memory")
    return "\n".join(lines)


def vlan_name_text(name):
    """A VLAN name IOS takes: at most 32 characters, no spaces (they'd end it)."""
    return "_".join(name.split())[:32]


def export_text(network_map, result, save=False):
    """Every step's configuration and undo, for Export All."""
    parts = [f"! Carry VLAN {result.vlan}{f' ({result.name})' if result.name else ''} to "
             f"{label_of(network_map, result.b)}",
             f"! Route: {' > '.join(label_of(network_map, key) for key in result.route)}", "!"]
    for index, step in enumerate(result.changes, start=1):
        device = network_map.devices.get(step.device)
        where = f" ({device.mgmt_ip})" if device is not None and device.mgmt_ip else ""
        kind = " - redundant links" if step.redundant else ""
        parts += [f"! ---- {index}. {label_of(network_map, step.device)}{where}{kind}",
                  config(step, result.vlan, save), "!", "! Undo:"]
        parts += ["! " + line for line in undo(step, result.vlan, save).splitlines()]
        parts.append("!")
    return "\n".join(parts) + "\n"


def label_of(network_map, key):
    device = network_map.devices.get(key)
    return device.label if device is not None else key


# ----------------------------------------------------------------- Checking it worked


def verify(network_map, result):
    """After sending and reading the switches again: ({step index (in result.changes): [what isn't done yet]} (an
    empty list when the step is done), [what isn't done on switches of the route with no step: VTP clients])."""
    vlan = result.vlan
    outcome, others = {}, []
    for index, step in enumerate(result.changes):
        device = network_map.devices.get(step.device)
        problems = []
        if device is None:
            outcome[index] = ["It isn't on the map any more."]
            continue
        if step.create_vlan and not has_vlan(device, vlan):
            problems.append(f"VLAN {vlan} isn't on {device.label} yet.")
        for port in step.trunks:
            info = port_info(device, port)
            if info.get("mode") != TRUNK or vlan not in allowed(info):
                problems.append(f"{port} doesn't allow VLAN {vlan} yet.")
        for port, _ in step.edge:
            info = port_info(device, port)
            if info.get("mode") == TRUNK:
                if vlan not in allowed(info):
                    problems.append(f"{port} doesn't allow VLAN {vlan} yet.")
            elif info.get("vlan") != vlan:
                problems.append(f"{port} isn't in VLAN {vlan} yet.")
        outcome[index] = problems
    for key in result.route:  # VTP clients get the VLAN from their server
        device = network_map.devices.get(key)
        if device is not None and device.kind == SWITCH and is_read(device) and not has_vlan(device, vlan) and \
                not any(step.device == key and step.create_vlan for step in result.changes):
            others.append(f"VLAN {vlan} hasn't reached {device.label} (VTP {device.vtp_mode or 'client'}) yet: VTP may "
                          "still be passing it on. Verify again in a moment.")
    return outcome, others


def candidates(network_map, a=None, b=None, vlan=None, route=None, depth=1):
    """The switches to read before planning: the route set by hand (or the way on the map as it is now), their
    neighbors (for redundant links), and the VTP servers of their domains. [device key]."""
    graph = Graph(network_map)
    keys = list(route or [])
    if not keys and b in graph.devices and vlan:
        sources = {a} if a else sources_for(graph, vlan)[0]
        found = search(graph, vlan, sources, b) if sources and b not in sources else None
        keys = found[0] if found else [b]
    wanted = dict.fromkeys(keys)
    frontier = list(keys)
    for _ in range(depth):
        nearby = []
        for key in frontier:
            for hop in graph.hops_of(key):
                other = hop.other(key)
                if other not in wanted:
                    wanted[other] = None
                    nearby.append(other)
        frontier = nearby
    domains = {domain_of(graph.devices[key]) for key in wanted if key in graph.devices}
    for key, device in graph.devices.items():
        if device.kind == SWITCH and device.vtp_mode == "server" and domain_of(device) in domains:
            wanted.setdefault(key, None)
    return [key for key in wanted if key in graph.devices and graph.devices[key].kind in ENDPOINT_KINDS]


def edge_port_choices(network_map, key):
    """B's ports that could be edge ports: [(port, its VLAN entry)], port-channel members left out (their
    port-channel is listed) and ports to other network devices last."""
    device = network_map.devices.get(key)
    if device is None:
        return []
    members = {port_key(member) for member in device.port_channels}
    links = {port_key(link.port_on(key)) for link in network_map.links_of(key)}
    ports = [(port, entry) for port, entry in device.port_vlans.items() if port_key(port) not in members]
    return sorted(ports, key=lambda item: (port_key(item[0]) in links, port_sort_key(item[0])))


def describe_entry(entry):
    """"access 10", "trunk 1-10,20", or "?"."""
    if not entry:
        return "?"
    if entry.get("mode") == TRUNK:
        return f"trunk {entry.get('allowed') or '(none)'}"
    return f"access {entry.get('vlan') or '?'}" + (f", voice {entry['voice']}" if entry.get("voice") else "")

