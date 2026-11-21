"""Cisco IOS / IOS-XE Flexible NetFlow configuration that sends flows to NOMAD.

What it sets up:
- A flow record matching what NOMAD sums: addresses, protocol, ports, ToS, the input interface and direction; and
  collecting the output interface, TCP flags, 64-bit byte and packet counters and when each flow started and ended
  (optionally the NBAR application, and an IPv6 record too).
- An exporter for each computer collecting (NOMAD, or the NOMAD Flow Collector service), sending the interface names
  and (with NBAR) the application names every 5 minutes, and its templates every minute, so a collector started later
  soon reads the flows and names them.
- A monitor with the record and exporters, and cache timeouts of a minute (active) and 15 seconds (inactive): the
  router sends a long flow every minute instead of every 30, so the Flows page is about a minute behind.
- The monitor on the chosen interfaces, input only: each flow is counted once on the way in, and NOMAD counts it on
  the way out of its output interface too, so every interface monitored shows both directions.

build() gives the lines to paste from the enable prompt (configure terminal ... end); undo() takes it out again.
removal() takes out what's there first (a flow record in use can't be changed), for setting it up again. Qt-free.
"""
import ipaddress
import re
from dataclasses import dataclass, field

from .configtext import separated

UPTIME, ABSOLUTE = "uptime", "absolute"
V9, IPFIX = "v9", "ipfix"
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
INTERFACE = re.compile(r"^[A-Za-z][A-Za-z-]*\s*\d+(?:/\d+)*(?:\.\d+)?$")
SKIPPED_INTERFACES = re.compile(r"^(?:Lo|Loopback|Null|NVI|Virtual-Template|Embedded-Service|VoIP-Null)",
                                re.IGNORECASE)
MAX_DESTINATIONS = 2
DEFAULT_PORT = 2055
OPTION_SECONDS = 300  # The interface and application names, every 5 minutes (IOS's 10 leaves new collectors guessing)


@dataclass
class FlowOptions:
    destinations: list = field(default_factory=list)  # The computers collecting (addresses)
    port: int = DEFAULT_PORT
    source_interface: str = ""  # What the flows come from (a loopback or the management VLAN)
    vrf: str = ""  # The VRF the collectors are reached through, if not the global table
    protocol: str = V9
    timestamps: str = UPTIME  # UPTIME works on every IOS and IOS-XE router; ABSOLUTE on IOS-XE 16 and Catalyst 9000
    applications: bool = False  # NBAR: match application name (and send the application table)
    ipv6: bool = False
    interfaces: list = field(default_factory=list)
    sampling: int = 0  # 0: every packet; N: 1 packet in N (busy links on older routers)
    active: int = 60
    inactive: int = 15
    record: str = "NOMAD-RECORD"
    exporter: str = "NOMAD-EXPORTER"
    monitor: str = "NOMAD-MONITOR"
    sampler: str = "NOMAD-SAMPLER"
    write_memory: bool = False


def split_interfaces(text):
    """Interface names from a comma or line separated list (spaces inside a name, such as "Gi 0/1", are kept)."""
    return [item.strip() for item in re.split(r"[,;\n]+", text or "") if item.strip()]


def record6(options):
    return f"{options.record}-V6"


def monitor6(options):
    return f"{options.monitor}-V6"


def exporter_names(options):
    names = []
    for index, _ in enumerate(options.destinations[:MAX_DESTINATIONS]):
        names.append(options.exporter if index == 0 else f"{options.exporter}-{index + 1}")
    return names


def problems(options):
    """What's wrong with options, as sentences ([] when nothing)."""
    found = []
    if not options.destinations:
        found.append("Add where the flows go: this computer, or the computer running the NOMAD Flow Collector "
                     "service.")
    if len(options.destinations) > MAX_DESTINATIONS:
        found.append(f"Send to {MAX_DESTINATIONS} computers at most.")
    for destination in options.destinations:
        try:
            ipaddress.IPv4Address(destination)
        except ValueError:
            found.append(f"'{destination}' isn't an IPv4 address.")
    if not 1 <= int(options.port or 0) <= 65535:
        found.append("The port is 1 to 65535 (NOMAD listens on 2055).")
    for name, what in ((options.record, "record"), (options.exporter, "exporter"), (options.monitor, "monitor"),
                       (options.sampler, "sampler")):
        if not NAME.match(name or ""):
            found.append(f"The flow {what} name is one word: letters, digits, - _ and . (up to 32).")
    if options.vrf and not NAME.match(options.vrf):
        found.append("The VRF name is one word: letters, digits, - _ and . (up to 32).")
    if options.source_interface and not INTERFACE.match(options.source_interface):
        found.append(f"'{options.source_interface}' isn't an interface name (such as Loopback0 or Vlan10).")
    for interface in options.interfaces:
        if not INTERFACE.match(interface):
            found.append(f"'{interface}' isn't an interface name (such as GigabitEthernet0/0/1 or Gi1/0/48).")
    if not 1 <= options.active <= 604800 or not 1 <= options.inactive <= 604800:
        found.append("The cache timeouts are 1 to 604800 seconds.")
    if options.sampling and not 2 <= options.sampling <= 65535:
        found.append("Sampling is 1 packet in 2 to 65535 (or none).")
    return found


def cautions(options):
    found = []
    if options.applications:
        found.append("Naming applications needs NBAR2: ISR 4000, ASR 1000, Catalyst 8000, CSR 1000v and C8000v have "
                     "it; other routers refuse match application name.")
    if options.timestamps == ABSOLUTE:
        found.append("Clock-time timestamps need IOS-XE 16 or later (classic IOS refuses them).")
    if not options.source_interface:
        found.append("Without a source interface the flows come from whichever interface faces the collector: set "
                     "one (a loopback) so NOMAD knows the router by one address.")
    if options.sampling:
        found.append(f"With sampling NOMAD multiplies what it's sent by {options.sampling}: small flows may not "
                     "show.")
    return found


def monitor_line(options, monitor, family="ip"):
    sampler = f" sampler {options.sampler}" if options.sampling else ""
    return f" {family} flow monitor {monitor}{sampler} input"


def record_lines(options, ipv6=False):
    family = "ipv6" if ipv6 else "ipv4"
    lines = [f"flow record {record6(options) if ipv6 else options.record}",
             " description NOMAD: who and what uses each interface",
             f" match {family} {'traffic-class' if ipv6 else 'tos'}",
             f" match {family} protocol",
             f" match {family} source address",
             f" match {family} destination address",
             " match transport source-port",
             " match transport destination-port",
             " match interface input",
             " match flow direction"]
    if options.applications:
        lines.append(" match application name")
    stamp = "absolute" if options.timestamps == ABSOLUTE else "sys-uptime"
    lines += [" collect interface output",
              " collect transport tcp flags",
              " collect counter bytes long",
              " collect counter packets long",
              f" collect timestamp {stamp} first",
              f" collect timestamp {stamp} last"]
    return lines


def exporter_lines(options, name, destination):
    vrf = f" vrf {options.vrf}" if options.vrf else ""
    lines = [f"flow exporter {name}",
             f" description NOMAD collector at {destination}",
             f" destination {destination}{vrf}"]
    if options.source_interface:
        lines.append(f" source {options.source_interface}")
    lines += [f" transport udp {int(options.port)}",
              f" export-protocol {'ipfix' if options.protocol == IPFIX else 'netflow-v9'}",
              " template data timeout 60",
              f" option interface-table timeout {OPTION_SECONDS}"]
    if options.applications:
        lines.append(f" option application-table timeout {OPTION_SECONDS}")
    if options.sampling:
        lines.append(" option sampler-table")
    return lines


def monitor_lines(options, ipv6=False):
    lines = [f"flow monitor {monitor6(options) if ipv6 else options.monitor}",
             " description NOMAD"]
    lines += [f" exporter {name}" for name in exporter_names(options)]
    lines += [f" record {record6(options) if ipv6 else options.record}",
              f" cache timeout active {int(options.active)}",
              f" cache timeout inactive {int(options.inactive)}"]
    return lines


def build(options, interfaces=None, replace=False):
    """The lines to send from the enable prompt. interfaces: the ones to monitor (options.interfaces when None).
    replace: take out what's set up with these names first (on the same interfaces), so it can be set up again."""
    interfaces = options.interfaces if interfaces is None else interfaces
    lines = ["configure terminal"]
    if replace:
        lines += removal_body(options, [(interface, None) for interface in interfaces])
    if options.sampling:
        lines += [f"sampler {options.sampler}", " description NOMAD", f" mode random 1 out-of {options.sampling}"]
    lines += record_lines(options)
    if options.ipv6:
        lines += record_lines(options, ipv6=True)
    for name, destination in zip(exporter_names(options), options.destinations):
        lines += exporter_lines(options, name, destination)
    lines += monitor_lines(options)
    if options.ipv6:
        lines += monitor_lines(options, ipv6=True)
    for interface in interfaces:
        lines.append(f"interface {interface}")
        lines.append(monitor_line(options, options.monitor))
        if options.ipv6:
            lines.append(monitor_line(options, monitor6(options), "ipv6"))
    lines.append("end")
    if options.write_memory:
        lines.append("write memory")
    return separated(lines)


def removal_body(options, monitored, everything=False):
    """The lines (in configuration mode) that take NOMAD's NetFlow out: monitored [(interface, the line that puts a
    monitor on it, or None for the lines build() would have)]. everything: the IPv6 monitor and record and the sampler
    too, whether options have them or not (over SSH, where a line for something not there is harmless)."""
    lines = []
    for interface, line in monitored:
        lines.append(f"interface {interface}")
        if line:
            lines.append(" no " + line.strip())
        else:
            lines.append(" no" + monitor_line(options, options.monitor))
            if options.ipv6:
                lines.append(" no" + monitor_line(options, monitor6(options), "ipv6"))
    ipv6 = options.ipv6 or everything
    lines.append(f"no flow monitor {options.monitor}")
    if ipv6:
        lines.append(f"no flow monitor {monitor6(options)}")
    exporters = exporter_names(options) or [options.exporter]
    if everything:
        exporters = list(dict.fromkeys(exporters + [options.exporter, f"{options.exporter}-2"]))
    lines += [f"no flow exporter {name}" for name in exporters]
    lines.append(f"no flow record {options.record}")
    if ipv6:
        lines.append(f"no flow record {record6(options)}")
    if options.sampling or everything:
        lines.append(f"no sampler {options.sampler}")
    return lines


def undo(options, monitored=None):
    """The lines that take it out again. monitored: [(interface, line)] as parse_monitored() read them from the
    router (else the interfaces in options), when it takes out everything NOMAD's names could be."""
    everything = monitored is not None
    monitored = [(interface, None) for interface in options.interfaces] if monitored is None else monitored
    lines = ["configure terminal", *removal_body(options, monitored, everything), "end"]
    if options.write_memory:
        lines.append("write memory")
    return separated(lines)


def parse_monitored(running, monitor_names):
    """[(interface, line)] of the interfaces with any of monitor_names on them, from show running-config (the
    interface lines and their flow monitor lines are enough)."""
    found = []
    interface = None
    wanted = set(monitor_names)
    for line in running.splitlines():
        if line.startswith("interface "):
            interface = line.split(None, 1)[1].strip()
            continue
        if not line.startswith(" "):
            interface = None
            continue
        match = re.match(r"^\s*(?:ip|ipv6) flow monitor (\S+)", line)
        if interface and match and match.group(1) in wanted:
            found.append((interface, line.strip()))
    return found


def configured_interfaces(running):
    """The interface names in show running-config (or its ^interface lines). Interfaces the router makes for itself,
    such as PIM's register tunnels and Virtual-Access, aren't in it, and refuse being configured."""
    return {line.split()[1] for line in running.splitlines()
            if line.startswith("interface ") and len(line.split()) > 1}


def routed_interfaces(brief, configured=None):
    """The interfaces with an IPv4 address that aren't administratively down, from show ip interface brief
    (loopbacks, Null and the like left out: no traffic comes in on them). configured: the names in the running
    config, when read; any other is one the router made for itself (a PIM register tunnel), so it's left out."""
    found = []
    for line in brief.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] == "Interface":
            continue
        name, address = parts[0], parts[1]
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if SKIPPED_INTERFACES.match(name) or "administratively" in line:
            continue
        if configured and name not in configured:
            continue
        found.append(name)
    return found


GONE = re.compile(r"not found|does not exist|not exist|no such|not configured|not present|failed to delete|"
                  r"is not defined|unknown", re.IGNORECASE)


def harmless_removal(line, errors):
    """A line taking something out refused only because it isn't there (IOS-XE says "Failed to delete sampler" for a
    sampler that never was)."""
    return line.strip().startswith("no ") and any(GONE.search(error) for error in errors)
