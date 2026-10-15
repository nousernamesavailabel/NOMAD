"""Monitoring devices this computer can't reach (they're behind a VRF, or there's no route back to here) from a router
on the map that can: an IP SLA ICMP echo probe on the router pings the device, and NOMAD reads the probe's latest
result over SNMP (CISCO-RTTMON-MIB, read-only).

The probes are the shared record. NOMAD tags the ones it makes "NOMAD <device>", so every NOMAD with the map (anyone in
the tribe, the Map Watcher service) finds them by reading the tags on the map's routers and matching each probe's
target to a device; nothing about them is kept in the map. A router runs one probe per device however many people are
watching, and a probe tagged NOMAD by hand is used just the same.

Qt-free: the map page reads the routers on a worker thread.
"""
import getpass
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..snmp import SnmpError, parse_oid
from .collect import text
from .model import FIREWALL, NETWORK_KINDS, SNMP, short_port

# CISCO-RTTMON-MIB, each table indexed by the probe's number
RTT_MON = "1.3.6.1.4.1.9.9.42.1.2"
CTRL_OWNER = f"{RTT_MON}.1.1.2"  # rttMonCtrlAdminOwner
CTRL_TAG = f"{RTT_MON}.1.1.3"  # rttMonCtrlAdminTag
CTRL_RTT_TYPE = f"{RTT_MON}.1.1.4"  # rttMonCtrlAdminRttType: 1 echo
CTRL_FREQUENCY = f"{RTT_MON}.1.1.6"  # Seconds
CTRL_TIMEOUT = f"{RTT_MON}.1.1.7"  # Milliseconds
ECHO_PROTOCOL = f"{RTT_MON}.2.1.1"  # rttMonEchoAdminProtocol: 2 ipIcmpEcho
ECHO_TARGET = f"{RTT_MON}.2.1.2"  # rttMonEchoAdminTargetAddress: 4 bytes for IPv4
ECHO_VRF = f"{RTT_MON}.2.1.26"  # rttMonEchoAdminVrfName
OPER_STATE = f"{RTT_MON}.9.1.10"  # rttMonCtrlOperState: 6 active
LATEST_RTT = f"{RTT_MON}.10.1.1"  # rttMonLatestRttOperCompletionTime, ms
LATEST_SENSE = f"{RTT_MON}.10.1.2"  # rttMonLatestRttOperSense: 1 ok
LATEST_TIME = f"{RTT_MON}.10.1.5"  # rttMonLatestRttOperTime: sysUpTime (centiseconds) of the latest result
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"

ECHO, ICMP_ECHO, ACTIVE, OK = 1, 2, 6, 1
SENSES = {0: "other", 1: "OK", 2: "disconnected", 3: "over threshold", 4: "timeout", 5: "busy", 6: "not connected",
          7: "dropped", 8: "sequence error", 9: "verify error", 10: "application specific", 11: "DNS server timeout",
          12: "TCP connect timeout", 13: "HTTP transaction timeout", 14: "DNS query error", 15: "HTTP error",
          16: "error", 17: "MPLS LSP echo transport error", 18: "MPLS LSP unreachable", 19: "MPLS LSP malformed",
          20: "MPLS LSP reached upstream of the target", 21: "MPLS LSP reached downstream of the target",
          22: "MPLS LSP duplicate", 23: "MPLS LSP failure"}
OPER_STATES = {1: "reset", 2: "stopped", 3: "stopped", 4: "pending", 5: "inactive", 6: "active", 7: "restarting"}

TAG_PREFIX = "NOMAD"
TAG_LENGTH = 60  # Kept short: older IOS has a 16-character tag (the rest is in the long tag)
FIRST_ENTRY = 9000  # Clear of the numbers people pick for their own probes
LAST_ENTRY = 2147483647
FREQUENCIES = [10, 15, 30, 60, 120, 300]  # Seconds between a probe's pings, on offer
DEFAULT_FREQUENCY = 30
TIMEOUT_MS = 1000  # Also the threshold: IOS won't schedule a probe whose threshold is over its timeout
STALE_AFTER = 3  # A latest result older than this many of its probe's periods (and a minute): the probe isn't running
PROBES_PER_GET = 8
WORKERS = 16


@dataclass
class Probe:
    """One IP SLA ICMP echo probe NOMAD found on a router."""
    router: str  # The router's device key
    address: str  # Where NOMAD asks the router over SNMP
    entry: int
    target: str
    vrf: str = ""
    tag: str = ""
    owner: str = ""
    frequency: int = 0  # Seconds
    state: str = ""  # active, pending...

    @property
    def device_label(self):
        """What the tag says it's for ("NOMAD core-sw3" -> "core-sw3")."""
        return self.tag[len(TAG_PREFIX):].strip() if is_nomad_tag(self.tag) else self.tag

    def where(self, router_label):
        """"R5 (vrf MGMT-B)": what it's checked from, for the Monitor log and the details."""
        return f"{router_label} (vrf {self.vrf})" if self.vrf else router_label


@dataclass
class Reading:
    """A probe's latest result, as read."""
    sense: int = 0
    rtt: int = 0  # ms
    time: int = 0  # The router's sysUpTime (centiseconds) when it was taken; 0: no result yet
    uptime: int = 0  # The router's sysUpTime when read

    @property
    def ok(self):
        return self.sense == OK

    @property
    def age(self):
        """Seconds since the result, or None if there's none yet."""
        return (self.uptime - self.time) / 100 if self.time and self.uptime >= self.time else None


@dataclass
class Candidate:
    """A router on the map that should reach an address, and in which VRF."""
    router: str
    vrf: str
    why: str  # "Gi0/1 10.20.5.1/24", "route 10.20.0.0/16 via 10.0.0.2 (ospf)"
    connected: bool
    prefix_length: int


@dataclass
class Discovery:
    """What the routers' probes were, from one look at every router."""
    probes: list = field(default_factory=list)  # [Probe]
    problems: dict = field(default_factory=dict)  # Router key -> why it couldn't be read
    read: set = field(default_factory=set)  # Router keys read


def is_nomad_tag(tag):
    return (tag or "").strip().upper().startswith(TAG_PREFIX)


def make_tag(label):
    printable = re.sub(r"[^\x21-\x7e ]", "", label or "").strip()
    return f"{TAG_PREFIX} {printable}"[:TAG_LENGTH].rstrip()


def make_owner(user=None):
    try:
        user = user if user is not None else getpass.getuser()
    except (OSError, KeyError, ImportError):
        user = ""
    return f"{TAG_PREFIX} {user}".strip()[:TAG_LENGTH]


def address_ok(address):
    """Whether it's an IPv4 address (what NOMAD's probes ping)."""
    try:
        return ipaddress.ip_address(address).version == 4
    except ValueError:
        return False


def address_text(raw):
    """rttMonEchoAdminTargetAddress (4 bytes for IPv4, 16 for IPv6) as text, or ""."""
    if isinstance(raw, bytes) and len(raw) in (4, 16):
        return str(ipaddress.ip_address(raw))
    return raw if isinstance(raw, str) else ""


def number(value):
    return value.value if value is not None and not value.is_exception and isinstance(value.value, int) else 0


# ----------------------------------------------------------------- Reading the routers

def read_probes(client, router, address):
    """The router's NOMAD-tagged ICMP echo probes. Raises SnmpError if it doesn't answer."""
    tags = {}
    for oid, value in client.walk(parse_oid(CTRL_TAG)):
        if not value.is_exception and len(oid) > len(parse_oid(CTRL_TAG)) and is_nomad_tag(text(value)):
            tags[oid[-1]] = text(value)
    found = []
    entries = sorted(tags)
    for start in range(0, len(entries), PROBES_PER_GET):
        chunk = entries[start:start + PROBES_PER_GET]
        columns = (CTRL_RTT_TYPE, ECHO_PROTOCOL, ECHO_TARGET, ECHO_VRF, CTRL_OWNER, CTRL_FREQUENCY, OPER_STATE)
        values = dict(client.get([parse_oid(f"{column}.{entry}") for entry in chunk for column in columns]))
        for entry in chunk:
            row = {column: values.get(parse_oid(f"{column}.{entry}")) for column in columns}
            if number(row[CTRL_RTT_TYPE]) != ECHO or number(row[ECHO_PROTOCOL]) not in (0, ICMP_ECHO):
                continue  # Not an ICMP echo (a UDP jitter probe tagged NOMAD, say)
            target = row[ECHO_TARGET]
            target = address_text(target.value) if target is not None and not target.is_exception else ""
            if not target:
                continue
            found.append(Probe(router, address, entry, target, text(row[ECHO_VRF]), tags[entry],
                               text(row[CTRL_OWNER]), number(row[CTRL_FREQUENCY]),
                               OPER_STATES.get(number(row[OPER_STATE]), "")))
    return found


def discover(routers, client_factory, workers=WORKERS):
    """Look for NOMAD probes on every router: routers [(key, address, credential, version, timeout)]."""
    def look(router):
        key, address, credential, version, timeout = router
        try:
            client = client_factory(address, credential, version, timeout=timeout, retries=0)
            return key, read_probes(client, key, address), ""
        except (SnmpError, OSError, ValueError) as error:
            return key, None, str(error) or "no answer"

    discovery = Discovery()
    if not routers:
        return discovery
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(routers)))) as executor:
        for key, probes, problem in executor.map(look, routers):
            if probes is None:
                discovery.problems[key] = problem
            else:
                discovery.read.add(key)
                discovery.probes += probes
    return discovery


def read_results(client, entries):
    """{entry: Reading} of each probe's latest result (with the router's uptime to tell how old it is)."""
    found = {}
    entries = list(entries)
    uptime = None
    for start in range(0, len(entries), PROBES_PER_GET):
        chunk = entries[start:start + PROBES_PER_GET]
        oids = [parse_oid(SYS_UPTIME)] + [parse_oid(f"{column}.{entry}") for entry in chunk
                                          for column in (LATEST_SENSE, LATEST_RTT, LATEST_TIME)]
        values = dict(client.get(oids))
        if uptime is None:
            uptime = number(values.get(parse_oid(SYS_UPTIME)))
        for entry in chunk:
            sense, rtt, time = (number(values.get(parse_oid(f"{column}.{entry}")))
                                for column in (LATEST_SENSE, LATEST_RTT, LATEST_TIME))
            found[entry] = Reading(sense, rtt, time, uptime or 0)
    return found


def poll(targets, client_factory, workers=WORKERS):
    """Read the latest results: targets [(router key, address, credential, version, timeout, [entries])]. Returns
    {router key: {entry: Reading}}, or {router key: why} for a router that didn't answer."""
    def read(target):
        key, address, credential, version, timeout, entries = target
        try:
            client = client_factory(address, credential, version, timeout=timeout, retries=1)
            return key, read_results(client, entries)
        except (SnmpError, OSError, ValueError) as error:
            return key, str(error) or "no answer"

    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as executor:
        return dict(executor.map(read, targets))


def stale(probe, reading):
    """Why a probe's latest result can't be trusted (it isn't running), or ""."""
    if probe.state and probe.state != "active":
        return f"the probe is {probe.state}, not running"
    if not reading.time:
        return "the probe has no result yet"
    age = reading.age
    if age is not None and age > max(60, STALE_AFTER * (probe.frequency or DEFAULT_FREQUENCY)):
        return f"the probe's last result is {int(age)} s old"
    return ""


# ----------------------------------------------------------------- Which probe is each device's

def can_probe(device):
    """Whether NOMAD would put a probe on the device: a Cisco IOS / IOS-XE router or L3 switch it reads over SNMP."""
    if device.source != SNMP or not device.mgmt_ip or device.kind not in NETWORK_KINDS or device.kind == FIREWALL:
        return False
    descr = device.sys_descr or ""
    cisco = (device.sys_object_id or "").startswith("1.3.6.1.4.1.9.") or "cisco" in descr.lower()
    return cisco and not re.search(r"NX-OS|Adaptive Security", descr, re.IGNORECASE)


def readable_routers(network_map):
    """The map's devices that could have NOMAD's probes on them (Cisco, read over SNMP)."""
    return [key for key, device in network_map.devices.items() if can_probe(device)]


def assign(network_map, probes):
    """{device key: Probe}: each device a probe's target belongs to: the device it's the management address of, else
    one with it among its addresses (other than the probe's own router). With more than one for a device, an active
    probe wins, then the lowest-numbered."""
    owners = {device.mgmt_ip: key for key, device in network_map.devices.items() if device.mgmt_ip}
    others = {}
    for key, device in network_map.devices.items():
        for address in [*device.addresses, *(item[0] for item in device.interfaces_l3)]:
            if address and address not in owners:
                others.setdefault(address, []).append(key)
    found = {}
    for probe in sorted(probes, key=lambda item: (item.state not in ("", "active"), item.router, item.entry)):
        key = owners.get(probe.target)
        if key is None:
            key = next((item for item in others.get(probe.target, []) if item != probe.router), None)
        if key is not None and key not in found:
            found[key] = probe
    return found


def candidates(network_map, address, exclude=()):
    """Routers on the map that should reach the address, best first: one with an interface in its subnet (checking
    from that interface's VRF), then the most specific route in any VRF. Default routes don't count."""
    try:
        target = ipaddress.ip_address(address)
    except ValueError:
        return []
    best = {}
    for key, device in network_map.devices.items():
        if key in exclude or not can_probe(device) or device.owns(address):
            continue
        for ip, length, port in device.interfaces_l3:
            try:
                network = ipaddress.ip_network(f"{ip}/{length}", strict=False)
            except ValueError:
                continue
            if target in network and network.prefixlen < network.max_prefixlen:
                vrf = device.port_vrfs.get(short_port(port), "")
                offer(best, Candidate(key, vrf, f"{short_port(port) or 'interface'} {ip}/{length}", True,
                                      network.prefixlen))
        tables = [("", device.routes)] + sorted(device.vrf_routes.items())
        for vrf, routes in tables:
            for destination, next_hop, port, protocol in routes:
                try:
                    network = ipaddress.ip_network(destination, strict=False)
                except ValueError:
                    continue
                if network.prefixlen == 0 or target not in network:
                    continue
                if not next_hop:  # Connected: the interface above says it better, when it was read
                    why = f"connected {destination}" + (f" on {short_port(port)}" if port else "")
                else:
                    why = f"route {destination} via {next_hop}" + (f" ({protocol})" if protocol else "")
                offer(best, Candidate(key, vrf, why, not next_hop, network.prefixlen))
    return sorted(best.values(), key=lambda item: (not item.connected, -item.prefix_length,
                                                   network_map.devices[item.router].label.lower(), item.vrf))


def offer(best, candidate):
    """Keep the better reason for each router and VRF."""
    key = (candidate.router, candidate.vrf)
    held = best.get(key)
    if held is None or (candidate.connected, candidate.prefix_length) > (held.connected, held.prefix_length):
        best[key] = candidate


# ----------------------------------------------------------------- Configuration

def setup_text(entry, target, vrf, tag, owner, frequency=DEFAULT_FREQUENCY, timeout=TIMEOUT_MS):
    """The lines that make and start a probe. The threshold goes in before the timeout: IOS won't schedule one whose
    threshold (5000 ms unless set) is over its timeout."""
    lines = ["configure terminal", f"ip sla {entry}", f" icmp-echo {target}"]
    if vrf:
        lines.append(f"  vrf {vrf}")
    lines += [f"  tag {tag}"]
    if owner:
        lines.append(f"  owner {owner}")
    lines += [f"  threshold {timeout}", f"  timeout {timeout}", f"  frequency {frequency}", " exit",
              f"ip sla schedule {entry} life forever start-time now", "end"]
    return "\n".join(lines)


def removal_text(entry):
    return f"configure terminal\nno ip sla {entry}\nend"


SLA_LINE = re.compile(r"^ip sla (\d+)\s*$")


def parse_sla_config(text_in):
    """`show running-config | section ip sla` as {entry: {"target", "vrf", "tag", "scheduled"}} (any kind of probe:
    target is "" for kinds other than ICMP echo)."""
    found, current = {}, None
    for raw in (text_in or "").splitlines():
        line = raw.rstrip()
        match = SLA_LINE.match(line)
        if match:
            current = found.setdefault(int(match.group(1)), {"target": "", "vrf": "", "tag": "", "scheduled": False})
            continue
        schedule = re.match(r"^ip sla schedule (\d+)\b", line)
        if schedule:
            found.setdefault(int(schedule.group(1)), {"target": "", "vrf": "", "tag": "", "scheduled": False})[
                "scheduled"] = True
            current = None
            continue
        if not line.startswith(" "):
            current = None
            continue
        if current is None:
            continue
        words = line.split()
        if words[0] == "icmp-echo" and len(words) > 1:
            current["target"] = words[1]
        elif words[0] == "vrf" and len(words) > 1:
            current["vrf"] = words[1]
        elif words[0] == "tag":
            current["tag"] = line.strip()[4:].strip()
    return found


def free_entry(used, start=FIRST_ENTRY):
    """The first probe number from start that isn't taken."""
    entry = start
    while entry in used and entry < LAST_ENTRY:
        entry += 1
    return entry


def existing_entry(config, target, vrf):
    """The number of a probe already pinging target in vrf (config: parse_sla_config's), or None."""
    for entry, item in sorted(config.items()):
        if item["target"] == target and item["vrf"] == vrf:
            return entry
    return None


def ping_command(target, vrf):
    return f"ping vrf {vrf} {target} repeat 2 timeout 1" if vrf else f"ping {target} repeat 2 timeout 1"


def ping_summary(answer):
    """"2 of 2 answered (1 ms)" from IOS's ping, or ""."""
    match = re.search(r"Success rate is (\d+) percent \((\d+)/(\d+)\)(?:, round-trip min/avg/max = \d+/(\d+)/\d+)?",
                      answer or "")
    if not match:
        return ""
    summary = f"{match.group(2)} of {match.group(3)} answered"
    return summary + (f" ({match.group(4)} ms)" if match.group(4) else "")
