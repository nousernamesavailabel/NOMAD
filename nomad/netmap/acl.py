"""ACLs on Cisco IOS / IOS-XE devices: read from the device, edited, and written back as the fewest safe changes.

What's read: `show running-config` (the ACLs with their remarks, object groups, time ranges, and where each ACL is
used: interfaces, VTY lines, and anything else naming one), and `show ip access-lists` / `show ipv6 access-list` (the
sequence numbers running-config leaves out on older IOS, and how many packets each rule has matched).

How edits go back: a rule is changed by sequence number, never by deleting the ACL and typing it in again (which
leaves the interface with no ACL, or an empty one, while it's typed). A rule added goes in at a free number between
its neighbors; one changed goes in at a new number next to the old one before the old one is taken out (so there's
never a moment without it); one moved is added at its new place, then taken from the old. When there's no number
free between two rules, `ip access-list resequence` spreads them out first. A numbered ACL (101) is edited the same
way, through `ip access-list extended 101`. Every change comes with exactly what undoes it.

Qt-free, so it can be tested without a network.
"""
import datetime
import heapq
import ipaddress
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, replace

log = logging.getLogger(__name__)

V4, V6 = "ipv4", "ipv6"
STANDARD, EXTENDED = "standard", "extended"
PERMIT, DENY = "permit", "deny"
ANY, HOST, WILDCARD, PREFIX, GROUP = "any", "host", "wildcard", "prefix", "group"
IN, OUT = "in", "out"
INTERFACE, LINE, OTHER = "interface", "line", "other"
NETWORK, SERVICE = "network", "service"
FAMILY_NAMES = {V4: "IPv4", V6: "IPv6"}
FILE_NAME = "acls.json"
MAX_SEQ = 2147483647
SETTLE_LIMIT = 300  # Rules in a standard ACL put in IOS's order (more: kept as they are)
KEEP_HISTORY = 200

# ----------------------------------------------------------------- Names IOS uses for ports, protocols and ICMP

TCP_PORTS = {
    "bgp": 179, "chargen": 19, "cmd": 514, "daytime": 13, "discard": 9, "domain": 53, "drip": 3949, "echo": 7,
    "exec": 512, "finger": 79, "ftp": 21, "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194,
    "klogin": 543, "kshell": 544, "login": 513, "lpd": 515, "msrpc": 135, "nntp": 119, "onep-plain": 15001,
    "onep-tls": 15002, "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "smtp": 25, "sunrpc": 111, "tacacs": 49,
    "talk": 517, "telnet": 23, "time": 37, "uucp": 540, "whois": 43, "www": 80,
}
UDP_PORTS = {
    "biff": 512, "bootpc": 68, "bootps": 67, "discard": 9, "dnsix": 195, "domain": 53, "echo": 7, "isakmp": 500,
    "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138, "netbios-ns": 137, "netbios-ss": 139,
    "non500-isakmp": 4500, "ntp": 123, "pim-auto-rp": 496, "rip": 520, "ripv6": 521, "snmp": 161, "snmptrap": 162,
    "sunrpc": 111, "syslog": 514, "tacacs": 49, "talk": 517, "tftp": 69, "time": 37, "who": 513, "xdmcp": 177,
}
# Typed by people but not IOS keywords: taken as their numbers (and written as numbers)
EXTRA_PORTS = {"ssh": 22, "https": 443, "http": 80, "dns": 53, "rdp": 3389, "ldap": 389, "ldaps": 636,
               "kerberos": 88, "smb": 445, "radius": 1812, "radius-acct": 1813, "sql": 1433, "mysql": 3306}

PROTOCOLS = {"ip": 0, "ipv6": 0, "icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "udp": 17, "gre": 47, "esp": 50,
             "ahp": 51, "eigrp": 88, "ospf": 89, "nos": 94, "pim": 103, "pcp": 108, "sctp": 132}
PROTOCOL_NAMES = {number: name for name, number in PROTOCOLS.items() if name not in ("ip", "ipv6")}
ICMPV6 = 58

ICMP_NAMES = {  # name: (type, code or None)
    "echo-reply": (0, None), "unreachable": (3, None), "net-unreachable": (3, 0), "host-unreachable": (3, 1),
    "protocol-unreachable": (3, 2), "port-unreachable": (3, 3), "packet-too-big": (3, 4),
    "source-route-failed": (3, 5), "network-unknown": (3, 6), "host-unknown": (3, 7), "host-isolated": (3, 8),
    "dod-net-prohibited": (3, 9), "dod-host-prohibited": (3, 10), "net-tos-unreachable": (3, 11),
    "host-tos-unreachable": (3, 12), "administratively-prohibited": (3, 13), "host-precedence-unreachable": (3, 14),
    "precedence-unreachable": (3, 15), "source-quench": (4, None), "redirect": (5, None), "net-redirect": (5, 0),
    "host-redirect": (5, 1), "net-tos-redirect": (5, 2), "host-tos-redirect": (5, 3), "alternate-address": (6, None),
    "echo": (8, None), "router-advertisement": (9, None), "router-solicitation": (10, None),
    "time-exceeded": (11, None), "ttl-exceeded": (11, 0), "reassembly-timeout": (11, 1),
    "parameter-problem": (12, None), "general-parameter-problem": (12, 0), "option-missing": (12, 1),
    "timestamp-request": (13, None), "timestamp-reply": (14, None), "information-request": (15, None),
    "information-reply": (16, None), "mask-request": (17, None), "mask-reply": (18, None), "traceroute": (30, None),
    "conversion-error": (31, None), "mobile-redirect": (32, None),
}
ICMPV6_NAMES = {
    "unreachable": (1, None), "no-admin": (1, 1), "no-route": (1, 0), "address-unreachable": (1, 3),
    "port-unreachable": (1, 4), "packet-too-big": (2, None), "time-exceeded": (3, None), "hop-limit": (3, 0),
    "reassembly-timeout": (3, 1), "parameter-problem": (4, None), "header": (4, 0), "next-header": (4, 1),
    "parameter-option": (4, 2), "echo-request": (128, None), "echo-reply": (129, None), "mld-query": (130, None),
    "mld-report": (131, None), "mld-reduction": (132, None), "router-solicitation": (133, None),
    "router-advertisement": (134, None), "nd-ns": (135, None), "nd-na": (136, None), "redirect": (137, None),
    "router-renumbering": (138, None), "mldv2-report": (143, None),
}
TCP_FLAGS = ("ack", "fin", "psh", "rst", "syn", "urg")
LOG_WORDS = ("log", "log-input")
EXTRA_WITH_VALUE = ("dscp", "precedence", "tos", "option", "flow-label", "routing-type", "reflect", "evaluate")

STANDARD_NUMBERS = (range(1, 100), range(1300, 2000))
EXTENDED_NUMBERS = (range(100, 200), range(2000, 2700))


def numbered_kind(name):
    """STANDARD or EXTENDED for a numbered ACL's number, else ""."""
    if not str(name).isdigit():
        return ""
    number = int(name)
    if any(number in span for span in STANDARD_NUMBERS):
        return STANDARD
    if any(number in span for span in EXTENDED_NUMBERS):
        return EXTENDED
    return ""


def port_number(token, protocol=""):
    """A port's number from a number or one of IOS's names (for that protocol when it has its own), else None."""
    token = token.lower()
    if token.isdigit():
        number = int(token)
        return number if 0 <= number <= 65535 else None
    for table in ((TCP_PORTS, UDP_PORTS) if protocol != "udp" else (UDP_PORTS, TCP_PORTS)):
        if token in table:
            return table[token]
    return EXTRA_PORTS.get(token)


def port_name(number, protocol=""):
    """IOS's name for a port of tcp or udp, else the number."""
    table = UDP_PORTS if protocol == "udp" else TCP_PORTS
    for name, value in table.items():
        if value == number:
            return name
    return str(number)


def protocol_number(protocol):
    """The IP protocol number a rule's protocol word means (0: any), or None."""
    protocol = (protocol or "").lower()
    if protocol.isdigit():
        return int(protocol)
    return PROTOCOLS.get(protocol)


# ----------------------------------------------------------------- What an ACL is made of

@dataclass
class Address:
    """A rule's source or destination."""
    kind: str = ANY
    address: str = ""
    wildcard: str = ""  # IPv4 wildcard bits (WILDCARD)
    prefix: int = 0  # IPv6 prefix length (PREFIX)
    group: str = ""  # Object group's name (GROUP)

    def text(self):
        if self.kind == ANY:
            return "any"
        if self.kind == HOST:
            return f"host {self.address}"
        if self.kind == GROUP:
            return f"object-group {self.group}"
        if self.kind == PREFIX:
            return f"{self.address}/{self.prefix}"
        return f"{self.address} {self.wildcard}"

    def short(self):
        """As shown in the rules table."""
        if self.kind == HOST:
            return self.address
        if self.kind == WILDCARD:
            length = prefix_of_wildcard(self.wildcard)
            return f"{self.address}/{length}" if length is not None else f"{self.address} {self.wildcard}"
        return self.text()


@dataclass
class Ports:
    """Which ports: eq/neq one or more, lt, gt, or a range; op "" for any."""
    op: str = ""
    values: list = field(default_factory=list)

    def __bool__(self):
        return bool(self.op)

    def text(self, protocol="", names=False):
        if not self.op:
            return ""
        shown = [port_name(value, protocol) if names else str(value) for value in self.values]
        return f"{self.op} {' '.join(shown)}"

    def intervals(self):
        """[(low, high)] of the ports it means."""
        if not self.op:
            return [(0, 65535)]
        if self.op == "eq":
            return [(value, value) for value in sorted(set(self.values))]
        if self.op == "neq":
            spans, low = [], 0
            for value in sorted(set(self.values)):
                if value > low:
                    spans.append((low, value - 1))
                low = value + 1
            if low <= 65535:
                spans.append((low, 65535))
            return spans
        if self.op == "lt":
            return [(0, self.values[0] - 1)] if self.values[0] > 0 else []
        if self.op == "gt":
            return [(self.values[0] + 1, 65535)] if self.values[0] < 65535 else []
        if self.op == "range":
            return [(min(self.values), max(self.values))]
        return [(0, 65535)]

    def matches(self, port):
        return any(low <= port <= high for low, high in self.intervals())


@dataclass
class Rule:
    """One line of an ACL (a permit or deny), with the remarks above it."""
    seq: int = 0  # Its sequence number on the device (0: not on it yet)
    action: str = PERMIT
    protocol: str = "ip"  # A protocol word or number; "" with service_group
    service_group: str = ""
    src: Address = field(default_factory=Address)
    src_ports: Ports = field(default_factory=Ports)
    dst: Address = field(default_factory=Address)
    dst_ports: Ports = field(default_factory=Ports)
    icmp_name: str = ""  # As typed ("echo"), or "" when given by number
    icmp_type: object = None
    icmp_code: object = None
    established: bool = False
    tcp_flags: list = field(default_factory=list)  # ["syn"] or with match-any/match-all: ["match-all", "+syn", "-ack"]
    fragments: bool = False
    log: str = ""
    time_range: str = ""
    extra: list = field(default_factory=list)  # Words kept as they were (dscp ef, ttl eq 1...)
    remark: str = ""  # The remark lines just above it, joined by newlines
    hits: object = None  # Matches counted (None: not read)
    want_seq: int = 0  # A number to put it at, if free (one typed in; undoing a delete puts it back where it was)
    origin: int = field(default=-1, compare=False)  # Its place in the ACL acl_change was given (Change.numbers)

    def body(self, family=V4, kind=EXTENDED, names=False):
        """The rule as IOS writes it, without its number."""
        parts = [self.action]
        if kind == STANDARD:
            parts.append(self.src.address if self.src.kind == HOST else self.src.text())
        else:
            parts.append(f"object-group {self.service_group}" if self.service_group else self.protocol)
            parts.append(self.src.text())
            if self.src_ports:
                parts.append(self.src_ports.text(self.protocol, names))
            parts.append(self.dst.text())
            if self.dst_ports:
                parts.append(self.dst_ports.text(self.protocol, names))
            if self.icmp_name:
                parts.append(self.icmp_name)
            elif self.icmp_type is not None:
                parts.append(str(self.icmp_type) + (f" {self.icmp_code}" if self.icmp_code is not None else ""))
            if self.established:
                parts.append("established")
            parts += self.tcp_flags
            parts += self.extra
            if self.fragments:
                parts.append("fragments")
            if self.time_range:
                parts.append(f"time-range {self.time_range}")
        if self.log:
            parts.append(self.log)
        return " ".join(part for part in parts if part)

    def key(self, family=V4, kind=EXTENDED):
        """What it does, for telling two rules apart (remarks, numbers and counts left out)."""
        return self.body(family, kind)

    def options_text(self):
        """Everything after the ports, as shown in the rules table."""
        parts = []
        if self.icmp_name:
            parts.append(self.icmp_name)
        elif self.icmp_type is not None:
            parts.append(f"type {self.icmp_type}" + (f" code {self.icmp_code}" if self.icmp_code is not None else ""))
        if self.established:
            parts.append("established")
        parts += self.tcp_flags + self.extra
        if self.fragments:
            parts.append("fragments")
        if self.time_range:
            parts.append(f"time-range {self.time_range}")
        if self.log:
            parts.append(self.log)
        return " ".join(parts)

    def copy(self, **changes):
        rule = replace(self, src=replace(self.src), dst=replace(self.dst),
                       src_ports=Ports(self.src_ports.op, list(self.src_ports.values)),
                       dst_ports=Ports(self.dst_ports.op, list(self.dst_ports.values)),
                       tcp_flags=list(self.tcp_flags), extra=list(self.extra))
        for name, value in changes.items():
            setattr(rule, name, value)
        return rule


@dataclass
class Acl:
    name: str
    family: str = V4
    kind: str = EXTENDED
    rules: list = field(default_factory=list)
    trailing_remark: str = ""  # Remarks after the last rule
    shown: list = field(default_factory=list)  # Rule numbers in the order show access-lists lists them

    @property
    def numbered(self):
        return self.family == V4 and self.name.isdigit()

    @property
    def key(self):
        return (self.family, self.name)

    @property
    def title(self):
        if self.family == V6:
            return f"IPv6 {self.name}"
        return f"{self.name} ({self.kind})"

    def mode_line(self):
        """The line that goes into the ACL's own configuration mode."""
        if self.family == V6:
            return f"ipv6 access-list {self.name}"
        return f"ip access-list {self.kind} {self.name}"

    def delete_line(self):
        if self.family == V6:
            return f"no ipv6 access-list {self.name}"
        if self.numbered:
            return f"no access-list {self.name}"
        return f"no ip access-list {self.kind} {self.name}"

    def rule_line(self, rule, seq=None):
        seq = rule.seq if seq is None else seq
        body = rule.body(self.family, self.kind)
        if not seq:
            return body
        return f"sequence {seq} {body}" if self.family == V6 else f"{seq} {body}"

    def no_rule_line(self, seq):
        return f"no sequence {seq}" if self.family == V6 else f"no {seq}"

    def copy(self, **changes):
        acl = replace(self, rules=[rule.copy() for rule in self.rules])
        for name, value in changes.items():
            setattr(acl, name, value)
        return acl

    def config(self, with_seq=True):
        """The whole ACL as configuration lines (to type in where there's none)."""
        lines = [self.mode_line()]
        for rule in self.rules:
            lines += [f" remark {text}" for text in rule.remark.splitlines() if text.strip()]
            lines.append(" " + self.rule_line(rule, rule.seq if with_seq else 0))
        lines += [f" remark {text}" for text in self.trailing_remark.splitlines() if text.strip()]
        return lines


@dataclass
class ObjectGroup:
    name: str
    kind: str = NETWORK  # NETWORK or SERVICE
    family: str = V4
    entries: list = field(default_factory=list)  # Lines as written ("host 10.1.1.1", "tcp eq 443")
    description: str = ""

    @property
    def keyword(self):
        return ("v6-" if self.family == V6 else "") + self.kind

    def mode_line(self):
        return f"object-group {self.keyword} {self.name}"

    def config(self):
        lines = [self.mode_line()]
        if self.description:
            lines.append(f" description {self.description}")
        return lines + [f" {entry}" for entry in self.entries]


@dataclass
class TimeRange:
    name: str
    entries: list = field(default_factory=list)  # "periodic weekdays 8:00 to 17:00", "absolute start ... end ..."

    def mode_line(self):
        return f"time-range {self.name}"

    def config(self):
        return [self.mode_line()] + [f" {entry}" for entry in self.entries]


@dataclass
class Applied:
    """Where an ACL is used."""
    acl: str
    family: str = V4
    where: str = INTERFACE  # INTERFACE, LINE or OTHER
    target: str = ""  # "GigabitEthernet1/0/1", "vty 0 4", or the block the line is in ("" at the top)
    direction: str = IN
    text: str = ""  # The line itself

    def label(self):
        if self.where == INTERFACE:
            return f"{self.target} {self.direction}"
        if self.where == LINE:
            return f"line {self.target} {self.direction}"
        return f"{self.target}: {self.text}" if self.target else self.text


@dataclass
class Interface:
    name: str
    addresses: list = field(default_factory=list)  # [(address, prefix length)]
    addresses6: list = field(default_factory=list)  # [(address, prefix length)]
    vrf: str = ""
    shutdown: bool = False
    description: str = ""

    def networks(self):
        found = []
        for address, length in self.addresses + self.addresses6:
            try:
                found.append(ipaddress.ip_interface(f"{address}/{length}"))
            except ValueError:
                pass
        return found


@dataclass
class DeviceAcls:
    """Everything about ACLs read from one device."""
    read: bool = False
    problem: str = ""
    hostname: str = ""
    acls: dict = field(default_factory=dict)  # (family, name): Acl
    groups: dict = field(default_factory=dict)  # name: ObjectGroup
    ranges: dict = field(default_factory=dict)  # name: TimeRange
    applied: list = field(default_factory=list)  # [Applied]
    interfaces: dict = field(default_factory=dict)  # name: Interface
    lines: dict = field(default_factory=dict)  # "vty 0 4": {"access-class in": name, ...}
    archive_path: str = ""
    toward_pc: str = ""  # The interface this PC is reached through (show ip cef), if read
    hits_read: bool = False
    when: str = ""
    # Route policy (routepolicy.py)
    prefix_lists: dict = field(default_factory=dict)  # (family, name): PrefixList
    route_maps: dict = field(default_factory=dict)  # name: RouteMap
    policy_uses: list = field(default_factory=list)  # [PolicyUse]
    processes: dict = field(default_factory=dict)  # "router bgp 65000": RoutingProcess
    as_paths: dict = field(default_factory=dict)  # name: [(action, regex)] (read only, for the route tester)
    communities: dict = field(default_factory=dict)  # name: (standard / expanded, [(action, text)]) (the same)

    def acl(self, family, name):
        return self.acls.get((family, name))

    def uses_of(self, acl):
        family, name = acl if isinstance(acl, tuple) else acl.key
        return [item for item in self.applied if item.acl == name and item.family == family]

    def group_users(self, name):
        """The ACLs with rules naming the object group."""
        users = []
        for acl in self.acls.values():
            if any(name in (rule.service_group, rule.src.group, rule.dst.group) for rule in acl.rules):
                users.append(acl)
        for group in self.groups.values():
            if f"group-object {name}" in group.entries:
                users.append(group)
        return users

    def range_users(self, name):
        return [acl for acl in self.acls.values() if any(rule.time_range == name for rule in acl.rules)]

    def copy(self):
        return replace(self, acls={key: acl.copy() for key, acl in self.acls.items()},
                       groups={key: replace(group, entries=list(group.entries)) for key, group in self.groups.items()},
                       ranges={key: replace(item, entries=list(item.entries)) for key, item in self.ranges.items()},
                       applied=[replace(item) for item in self.applied],
                       lines={key: dict(value) for key, value in self.lines.items()},
                       prefix_lists={key: item.copy() for key, item in self.prefix_lists.items()},
                       route_maps={key: item.copy() for key, item in self.route_maps.items()},
                       policy_uses=[item.copy() for item in self.policy_uses])


# ----------------------------------------------------------------- Addresses and wildcards

def ip_int(text):
    return int(ipaddress.IPv4Address(text))


def is_ipv4(token):
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def prefix_of_wildcard(wildcard):
    """The prefix length a contiguous wildcard means (0.0.0.255 -> 24), else None."""
    try:
        bits = ip_int(wildcard)
    except ValueError:
        return None
    if bits & (bits + 1):
        return None
    return 32 - bits.bit_length()


def wildcard_of_prefix(length):
    return str(ipaddress.IPv4Address((1 << (32 - length)) - 1 if length < 32 else 0))


def looks_like_mask(wildcard):
    """A wildcard written as a subnet mask (255.255.255.0 where 0.0.0.255 was meant)."""
    try:
        bits = ip_int(wildcard)
    except ValueError:
        return False
    if bits in (0, 0xFFFFFFFF):
        return False
    inverted = bits ^ 0xFFFFFFFF
    return not (inverted & (inverted + 1)) and prefix_of_wildcard(wildcard) is None


def parse_address_text(text, family=V4):
    """An Address from what someone typed: any, host, 10.1.1.1, 10.1.0.0/16, 10.1.0.0 0.0.255.255,
    10.1.0.0 255.255.0.0 (a mask, turned into its wildcard), object-group NAME, or an IPv6 address or prefix.
    Raises ValueError."""
    tokens = (text or "").split()
    if not tokens or tokens == ["any"]:
        return Address()
    if tokens[0] == "object-group" and len(tokens) == 2:
        return Address(GROUP, group=tokens[1])
    if tokens[0] == "host" and len(tokens) == 2:
        tokens = tokens[1:]
    if family == V6:
        if len(tokens) != 1:
            raise ValueError("An IPv6 address or prefix, such as 2001:db8::/32.")
        network = ipaddress.IPv6Network(tokens[0], strict=False) if "/" in tokens[0] else None
        if network is None:
            return Address(HOST, str(ipaddress.IPv6Address(tokens[0])))
        if network.prefixlen == 128:
            return Address(HOST, str(network.network_address))
        if network.prefixlen == 0:
            return Address()
        return Address(PREFIX, str(network.network_address), prefix=network.prefixlen)
    if len(tokens) == 1:
        if "/" in tokens[0]:
            network = ipaddress.IPv4Network(tokens[0], strict=False)
            if network.prefixlen == 32:
                return Address(HOST, str(network.network_address))
            if network.prefixlen == 0:
                return Address()
            return Address(WILDCARD, str(network.network_address), wildcard_of_prefix(network.prefixlen))
        return Address(HOST, str(ipaddress.IPv4Address(tokens[0])))
    if len(tokens) == 2:
        address, bits = str(ipaddress.IPv4Address(tokens[0])), str(ipaddress.IPv4Address(tokens[1]))
        if looks_like_mask(bits):
            bits = str(ipaddress.IPv4Address(ip_int(bits) ^ 0xFFFFFFFF))
        return wildcard_address(address, bits)
    raise ValueError("An address such as any, 10.1.1.1, 10.1.0.0/16 or 10.1.0.0 0.0.255.255.")


def wildcard_address(address, wildcard):
    """An Address for address + wildcard, as IOS keeps it (host for 0.0.0.0, any for all ones)."""
    if wildcard == "0.0.0.0":
        return Address(HOST, address)
    if wildcard == "255.255.255.255":
        return Address()
    return Address(WILDCARD, address, wildcard)


def stored_address(address):
    """The address IOS keeps for address + wildcard (bits under the wildcard zeroed)."""
    if address.kind != WILDCARD:
        return address.address
    return str(ipaddress.IPv4Address(ip_int(address.address) & ~ip_int(address.wildcard) & 0xFFFFFFFF))


# ----------------------------------------------------------------- Reading a rule

class Tokens:
    def __init__(self, words):
        self.words, self.at = list(words), 0

    def peek(self, ahead=0):
        index = self.at + ahead
        return self.words[index] if index < len(self.words) else ""

    def take(self):
        word = self.peek()
        self.at += 1
        return word

    def __bool__(self):
        return self.at < len(self.words)


MATCHES = re.compile(r"\s*\((\d+) match(?:es)?\)", re.IGNORECASE)
TAG = re.compile(r"\s*\(tag = [^)]*\)", re.IGNORECASE)
SEQUENCE_AFTER = re.compile(r"\s+sequence\s+(\d+)\s*$", re.IGNORECASE)


def parse_rule(text, family=V4, kind=EXTENDED):
    """A Rule from a line of an ACL (as running-config or show access-lists writes it, with or without its number),
    or None when it isn't a permit or deny."""
    hits = None
    found = MATCHES.search(text)
    if found:
        hits = int(found.group(1))
        text = text[:found.start()] + text[found.end():]
    text = TAG.sub("", text).replace(", wildcard bits ", " ")
    seq = 0
    after = SEQUENCE_AFTER.search(text)
    if after:
        seq = int(after.group(1))
        text = text[:after.start()]
    words = Tokens(text.split())
    if words.peek() == "sequence" and words.peek(1).isdigit():
        words.take()
        seq = int(words.take())
    elif words.peek().isdigit():
        seq = int(words.take())
    action = words.take()
    if action not in (PERMIT, DENY):
        return None
    rule = Rule(seq=seq, action=action, hits=hits)
    if kind == STANDARD:
        rule.protocol = "ip"
        rule.src = read_address(words, family, standard=True)
    else:
        protocol = words.take()
        if protocol == "object-group":
            rule.protocol, rule.service_group = "", words.take()
        else:
            rule.protocol = protocol
        rule.src = read_address(words, family)
        rule.src_ports = read_ports(words, rule.protocol)
        rule.dst = read_address(words, family)
        rule.dst_ports = read_ports(words, rule.protocol)
    read_options(words, rule, family)
    return rule


def read_address(words, family, standard=False):
    word = words.take()
    if word == "any":
        return Address()
    if word == "host":
        return Address(HOST, words.take())
    if word in ("object-group", "addrgroup"):
        return Address(GROUP, group=words.take())
    if family == V6:
        if "/" in word:
            address, _, length = word.partition("/")
            return Address(PREFIX, address, prefix=int(length))
        return Address(HOST, word)
    if is_ipv4(words.peek()):
        return wildcard_address(word, words.take())
    return Address(HOST, word)


def read_ports(words, protocol):
    op = words.peek()
    if op not in ("eq", "neq", "lt", "gt", "range"):
        return Ports()
    words.take()
    values = []
    if op == "range":
        for _ in range(2):
            number = port_number(words.take(), protocol)
            values.append(number if number is not None else 0)
    elif op in ("lt", "gt"):
        number = port_number(words.take(), protocol)
        values.append(number if number is not None else 0)
    else:
        while words:
            number = port_number(words.peek(), protocol)
            if number is None:
                break
            values.append(number)
            words.take()
    return Ports(op, values)


def read_options(words, rule, family):
    names = ICMPV6_NAMES if family == V6 else ICMP_NAMES
    icmp = protocol_number(rule.protocol) == 1 or (family == V6 and rule.protocol == "icmp")
    first = True
    while words:
        word = words.take()
        if first and icmp and word.isdigit():
            rule.icmp_type = int(word)
            if words.peek().isdigit():
                rule.icmp_code = int(words.take())
        elif first and icmp and word in names:
            rule.icmp_name = word
            rule.icmp_type, rule.icmp_code = names[word]
        elif word == "established":
            rule.established = True
        elif word in LOG_WORDS:
            rule.log = word
        elif word == "time-range":
            rule.time_range = words.take()
        elif word == "fragments":
            rule.fragments = True
        elif word in ("match-any", "match-all"):
            rule.tcp_flags.append(word)
            while words.peek()[:1] in ("+", "-") and words.peek()[1:] in TCP_FLAGS:
                rule.tcp_flags.append(words.take())
        elif word in TCP_FLAGS:
            rule.tcp_flags.append(word)
        elif word == "ttl":
            rule.extra.append(word)
            op = words.take()
            rule.extra.append(op)
            rule.extra.append(words.take())
            if op == "range":
                rule.extra.append(words.take())
        elif word in EXTRA_WITH_VALUE:
            rule.extra += [word, words.take()]
        else:
            rule.extra.append(word)
        first = False


# ----------------------------------------------------------------- Reading running-config

def blocks(text):
    """[(top line, [indented lines])] of a running-config."""
    found = []
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.startswith("!"):
            continue
        if line[0] not in " \t":
            found.append((line.strip(), []))
        elif found:
            found[-1][1].append(line.strip())
    return found


REFERENCE_WORDS = {"access-class", "access-group", "list", "access", "address", "name", "traffic-filter",
                   "ro", "rw", "ipv4", "ipv6", "acl", "access-list", "filter"}


def parse_running(text):
    """DeviceAcls from show running-config."""
    device = DeviceAcls(read=True)
    numbered_lines = {}
    for top, inner in blocks(text):
        words = top.split()
        if words[0] == "hostname" and len(words) > 1:
            device.hostname = words[1]
        elif words[:2] == ["ip", "access-list"] and len(words) >= 4 and words[2] in (STANDARD, EXTENDED):
            acl = Acl(words[3], V4, words[2])
            fill_rules(acl, inner)
            device.acls[acl.key] = acl
        elif words[:2] == ["ipv6", "access-list"] and len(words) == 3:
            acl = Acl(words[2], V6, EXTENDED)
            fill_rules(acl, inner)
            device.acls[acl.key] = acl
        elif words[0] == "access-list" and len(words) >= 3 and words[1].isdigit() and numbered_kind(words[1]):
            numbered_lines.setdefault(words[1], []).append(" ".join(words[2:]))
        elif words[0] == "object-group" and len(words) >= 3:
            keyword = words[1]
            family = V6 if keyword.startswith("v6-") else V4
            kind = keyword[3:] if family == V6 else keyword
            if kind in (NETWORK, SERVICE):
                group = ObjectGroup(words[2], kind, family)
                for line in inner:
                    if line.startswith("description "):
                        group.description = line[len("description "):]
                    else:
                        group.entries.append(line)
                device.groups[group.name] = group
        elif words[0] == "time-range" and len(words) == 2:
            device.ranges[words[1]] = TimeRange(words[1], list(inner))
        elif words[0] == "interface" and len(words) >= 2:
            read_interface(device, " ".join(words[1:]), inner)
        elif words[0] == "line" and len(words) >= 2:
            read_line(device, " ".join(words[1:]), inner)
        elif words[0] == "archive":
            for line in inner:
                if line.startswith("path "):
                    device.archive_path = line[5:].strip()
    for number, lines in numbered_lines.items():
        acl = Acl(number, V4, numbered_kind(number))
        fill_rules(acl, lines)
        device.acls[acl.key] = acl
    find_references(device, text)
    from .routepolicy import read_policies
    read_policies(device, text)
    return device


def fill_rules(acl, lines):
    remarks = []
    for line in lines:
        words = line.split()
        if not words:
            continue
        at = 1 if words[0].isdigit() else 2 if words[0] == "sequence" and len(words) > 1 else 0
        if len(words) > at and words[at] == "remark":
            remarks.append(" ".join(words[at + 1:]))
            continue
        rule = parse_rule(line, acl.family, acl.kind)
        if rule is None:
            continue
        rule.remark = "\n".join(remarks)
        remarks = []
        acl.rules.append(rule)
    acl.trailing_remark = "\n".join(remarks)


def read_interface(device, name, inner):
    interface = Interface(name)
    for line in inner:
        words = line.split()
        if words[:2] == ["ip", "address"] and len(words) >= 4 and is_ipv4(words[2]) and is_ipv4(words[3]):
            try:
                length = ipaddress.IPv4Network(f"0.0.0.0/{words[3]}").prefixlen
            except ValueError:
                continue
            interface.addresses.append((words[2], length))
        elif words[:2] == ["ipv6", "address"] and len(words) >= 3 and "/" in words[2]:
            address, _, length = words[2].partition("/")
            if length.isdigit():
                interface.addresses6.append((address, int(length)))
        elif words[:2] == ["ip", "access-group"] and len(words) >= 4:
            device.applied.append(Applied(words[2], V4, INTERFACE, name, words[3], line))
        elif words[:2] == ["ipv6", "traffic-filter"] and len(words) >= 4:
            device.applied.append(Applied(words[2], V6, INTERFACE, name, words[3], line))
        elif words[0] == "shutdown":
            interface.shutdown = True
        elif words[0] == "description":
            interface.description = " ".join(words[1:])
        elif words[:2] in (["vrf", "forwarding"], ["ip", "vrf"]) and len(words) >= 3:
            interface.vrf = words[-1]
    device.interfaces[name] = interface


def read_line(device, name, inner):
    settings = device.lines.setdefault(name, {})
    for line in inner:
        words = line.split()
        if words[0] == "access-class" and len(words) >= 3:
            device.applied.append(Applied(words[1], V4, LINE, name, words[2], line))
            settings[f"access-class {words[2]}"] = words[1]
        elif words[:2] == ["ipv6", "access-class"] and len(words) >= 4:
            device.applied.append(Applied(words[2], V6, LINE, name, words[3], line))
            settings[f"ipv6 access-class {words[3]}"] = words[2]
        elif words[:2] == ["transport", "input"]:
            settings["transport input"] = " ".join(words[2:])


def find_references(device, text):
    """Lines elsewhere naming an ACL (snmp-server community x RO NAME, match ip address NAME, ip nat ... list NAME):
    Applied entries with where OTHER."""
    names = {name for _, name in device.acls}
    if not names:
        return
    for top, inner in blocks(text):
        words = top.split()
        if words[0] in ("access-list", "object-group", "time-range") or words[1:2] == ["access-list"]:
            continue
        for line, target in [(top, "")] + [(line, top) for line in inner]:
            words = line.split()
            if target and top.split()[0] in ("interface", "line") and                     (words[0] == "access-class" or words[1:2] in (["access-group"], ["traffic-filter"],
                                                                   ["access-class"])):
                continue  # Read as INTERFACE or LINE already
            for index in range(1, len(words)):
                if words[index] in names and words[index - 1].lower() in REFERENCE_WORDS:
                    family = V6 if "ipv6" in words[:index] else V4
                    if (family, words[index]) not in device.acls:
                        family = V4 if family == V6 else V6
                    device.applied.append(Applied(words[index], family, OTHER, target, "", line))
                    break


HEADER = re.compile(r"^(Standard|Extended) IP access list (\S+)|^IPv6 access list (\S+)", re.IGNORECASE)


def parse_show(text):
    """{(family, name): [Rule with seq and hits]} from show ip access-lists / show ipv6 access-list."""
    found, current = {}, None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        header = HEADER.match(line.strip())
        if header:
            if header.group(3):
                current = (V6, header.group(3), EXTENDED)
            else:
                current = (V4, header.group(2), header.group(1).lower())
            found.setdefault(current[:2], [])
            continue
        if not line.startswith((" ", "\t")):
            current = None
            continue
        if current is None:
            continue
        rule = parse_rule(line.strip(), current[0], current[2])
        if rule is not None:
            found[current[:2]].append(rule)
    return found


def merge_show(device, shown):
    """Fill in the rules' numbers (where running-config leaves them out) and counts from parse_show's."""
    device.hits_read = True
    for key, acl in device.acls.items():
        rules = shown.get(key)
        if rules is None:
            continue
        by_seq = {rule.seq: rule for rule in rules if rule.seq}
        unused = list(rules)
        for index, rule in enumerate(acl.rules):
            if rule.seq and rule.seq in by_seq:
                match = by_seq[rule.seq]
            else:
                wanted = rule.key(acl.family, acl.kind)
                match = next((item for item in unused if item.key(acl.family, acl.kind) == wanted), None)
                if match is None and index < len(rules) and rules[index] in unused:
                    match = rules[index]
            if match is None:
                continue
            if match in unused:
                unused.remove(match)
            if not rule.seq:
                rule.seq = match.seq
            rule.hits = match.hits if match.hits is not None else 0
        acl.rules.sort(key=lambda rule: rule.seq or MAX_SEQ)
        acl.shown = [rule.seq for rule in rules if rule.seq]
    return device


CEF_PORT = re.compile(r"(?:attached to|nexthop \S+|via \S+,?)\s+([A-Za-z][\w\-/.:]*\d[\w/.:]*)")


def parse_toward(text):
    """The interface show ip cef / show ip route sends to an address through, or ""."""
    found = CEF_PORT.search(text or "")
    if found:
        return found.group(1).rstrip(",")
    connected = re.search(r"directly connected, via (\S+)", text or "")
    return connected.group(1) if connected else ""


# ----------------------------------------------------------------- Changes, as configuration lines

@dataclass
class Change:
    """Lines to type in configuration mode, and the lines that undo them."""
    title: str
    lines: list = field(default_factory=list)
    undo: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    stage: int = 2  # Order among several: see STAGES
    after: object = None  # The ACL (or group, range) as it is once done

    def __bool__(self):
        return bool(self.lines)

    @property
    def numbers(self):
        """{place of a rule (or prefix list / route map entry) in what the change was planned from: the number it
        has once done}."""
        items = getattr(self.after, "rules", None) if isinstance(self.after, Acl) else \
            getattr(self.after, "entries", None)
        if items is None:
            return {}
        return {item.origin: item.seq for item in items if item.origin >= 0}


# Where a change goes among several sent at once: taken off interfaces (and neighbors...) first, groups and time
# ranges before the ACLs naming them, ACLs and prefix lists before the route maps matching them, put on interfaces
# after, route maps deleted after they're off everything, ACLs and prefix lists after them, groups after the ACLs.
UNAPPLY, OBJECTS, ACLS, MAPS, APPLY, DELETE_MAPS, DELETE_ACL, DELETE_OBJECTS = range(8)


def config_text(changes, revert_minutes=0):
    """Changes as one block: configure terminal (with a revert timer when given), the lines in order, end."""
    ordered = sorted((change for change in changes if change), key=lambda change: change.stage)
    first = f"configure terminal revert timer {revert_minutes}" if revert_minutes else "configure terminal"
    lines = [first]
    for change in ordered:
        lines += change.lines
    return "\n".join(lines + ["end"])


def undo_text(changes):
    ordered = sorted((change for change in changes if change), key=lambda change: change.stage, reverse=True)
    lines = ["configure terminal"]
    for change in ordered:
        lines += change.undo
    return "\n".join(lines + ["end"])


def longest_increasing(values):
    """Indexes of a longest strictly increasing run (not necessarily adjacent) of values; None values skipped."""
    tails, previous, tail_index = [], {}, []
    for index, value in enumerate(values):
        if value is None:
            continue
        low, high = 0, len(tails)
        while low < high:
            middle = (low + high) // 2
            if tails[middle] < value:
                low = middle + 1
            else:
                high = middle
        if low == len(tails):
            tails.append(value)
            tail_index.append(index)
        else:
            tails[low] = value
            tail_index[low] = index
        previous[index] = tail_index[low - 1] if low > 0 else None
    chosen, index = [], tail_index[-1] if tail_index else None
    while index is not None:
        chosen.append(index)
        index = previous[index]
    return set(chosen)


def round_numbers(low, high, count, taken):
    """count free multiples of 10 above low (and below high), or fewer when there aren't that many."""
    found, number = [], (low // 10 + 1) * 10
    top = high if high is not None else MAX_SEQ + 1
    while len(found) < count and number < top:
        if number not in taken:
            found.append(number)
        number += 10
    return found


def spread(low, high, count, taken):
    """count free numbers between low and high (high None: after low): round ones when there are enough, else
    spread evenly. None when there aren't enough free."""
    if not count:
        return []
    tens = round_numbers(low, high, count, taken)
    if len(tens) == count:
        return tens
    if high is None:
        return None
    free = high - low - 1 - sum(1 for number in taken if low < number < high)
    if free < count:
        return None
    result, last = [], low
    for index in range(count):
        number = max(last + 1, low + (high - low) * (index + 1) // (count + 1))
        while number in taken:
            number += 1
        if number >= high:  # Pushed past the top by taken ones: take the next free ones upward from the last
            number = last + 1
            while number in taken:
                number += 1
        if number >= high:
            return None
        result.append(number)
        last = number
    return result


def fill_gap(low, high, wanted, taken, hard=None):
    """Numbers for len(wanted) rules between low and high (high None: after low), avoiding taken: each rule's own
    want_seq where it fits (between its neighbors, in order, and not one of hard: numbers staying put; taken
    defaults to hard), the rest round numbers when there are enough free, else spread evenly. None when there aren't
    enough free numbers."""
    hard = taken if hard is None else hard
    top = high if high is not None else MAX_SEQ + 1
    valid = [want if want and low < want < top and want not in hard else None for want in wanted]
    for anchors in (longest_increasing(valid), set()):
        result, start, below = [None] * len(wanted), 0, low
        avoid = set(taken) | {valid[index] for index in anchors}
        for index in sorted(anchors) + [len(wanted)]:
            above = valid[index] if index < len(wanted) else high
            numbers = spread(below, above, index - start, avoid)
            if numbers is None:
                break
            result[start:index] = numbers
            avoid.update(numbers)
            if index < len(wanted):
                result[index] = valid[index]
                below, start = valid[index], index + 1
        else:
            return result
    return None


def assign(before, after, family, kind, same=None, top=None):
    """(numbers for after's rules, which of them stay where they are) or None when the gaps are too small. same:
    whether a rule at a number is still the one there (default same_rule); top: the number past the last allowed."""
    same = same or (lambda a, b: same_rule(a, b, family, kind))
    by_seq = {rule.seq: rule for rule in before}
    identity = [rule.seq if rule.seq in by_seq and same(rule, by_seq[rule.seq]) and
                rule.want_seq in (0, rule.seq) else None for rule in after]  # A number typed in moves it
    fixed = longest_increasing(identity)
    numbers = [after[index].seq if index in fixed else None for index in range(len(after))]
    taken = set(by_seq)
    hard = {number for number in numbers if number}
    index = 0
    while index < len(after):
        if numbers[index] is not None:
            index += 1
            continue
        end = index
        while end < len(after) and numbers[end] is None:
            end += 1
        low = numbers[index - 1] if index > 0 else 0
        high = numbers[end] if end < len(after) else top
        gap = fill_gap(low, high, [after[spot].want_seq for spot in range(index, end)], taken, hard)
        if gap is None:
            return None
        numbers[index:end] = gap
        taken.update(gap)
        hard.update(gap)
        index = end
    return numbers, fixed


def same_rule(a, b, family, kind):
    return a.key(family, kind) == b.key(family, kind) and a.remark == b.remark


def resequenced(rules, step):
    return [rule.copy(seq=step * (index + 1)) for index, rule in enumerate(rules)]


def single_address(address):
    return address.kind == HOST or (address.kind == WILDCARD and address.wildcard == "0.0.0.0")


def device_order(acl):
    """acl's rules in the order the device lists them, which is the order ip access-list resequence numbers them in:
    a standard ACL's single addresses come first, in an order of IOS's own; the rest go by number."""
    rules = sorted(acl.rules, key=lambda rule: rule.seq)
    if acl.shown:
        place = {seq: index for index, seq in enumerate(acl.shown)}
        rules.sort(key=lambda rule: place.get(rule.seq, len(place)))
    return rules


def settle_order(before, after, family, kind):
    """after's rules in an order that does exactly the same (two rules no packet matches both of can go either way
    round), kept as close to before's numbering as it can be. Only for standard ACLs: IOS lists their single
    addresses in an order of its own (and renumbers them that way), so their order there means nothing; moving them
    to match would take rules out and put them back for nothing. Other kinds keep after's order as it is."""
    if kind != STANDARD or family != V4 or not 1 < len(after) <= SETTLE_LIMIT:
        return list(after)
    from .aclcheck import overlaps
    by_seq = {rule.seq: rule for rule in before}
    keys, last = [], 0
    for index, rule in enumerate(after):
        if rule.want_seq:
            last = rule.want_seq
            keys.append((rule.want_seq, 0, index))
        elif rule.seq in by_seq and same_rule(rule, by_seq[rule.seq], family, kind):
            last = rule.seq
            keys.append((rule.seq, 0, index))
        else:  # A new or changed rule goes just after the device's rule above it here
            keys.append((last, 1, index))
    waiting = [0] * len(after)
    later = [[] for _ in after]
    for second in range(len(after)):
        for first in range(second):
            if overlaps(after[first], after[second], family, kind, {}):
                later[first].append(second)
                waiting[second] += 1
    ready = [keys[index] for index in range(len(after)) if not waiting[index]]
    heapq.heapify(ready)
    order = []
    while ready:
        index = heapq.heappop(ready)[2]
        order.append(after[index])
        for other in later[index]:
            waiting[other] -= 1
            if not waiting[other]:
                heapq.heappush(ready, keys[other])
    return order


def resequence_step(shown, wanted, family, kind):
    """A step for ip access-list resequence leaving room, at round numbers, for the most rules wanted between two
    that stay (shown and wanted's rules numbered by their place in shown)."""
    by_seq = {rule.seq: rule for rule in shown}
    identity = [rule.seq if rule.seq in by_seq and same_rule(rule, by_seq[rule.seq], family, kind) else None
                for rule in wanted]
    fixed = longest_increasing(identity)
    longest = run = 0
    for index in range(len(wanted)):
        run = 0 if index in fixed else run + 1
        longest = max(longest, run)
    return 10 * (longest + 1)


def blockers(rule, present, family, kind):
    """Rules on the device that keep IOS from taking rule: the same rule at another number (IOS quietly drops the
    new one), or, in a standard ACL, a lower-numbered rule taking every packet a single address would (IOS refuses
    it)."""
    from .aclcheck import covers
    found = []
    key = rule.key(family, kind)
    for other in present:
        if other.key(family, kind) == key or other.seq == rule.seq:
            found.append(other)
        elif kind == STANDARD and family == V4 and single_address(rule.src) and other.seq < rule.seq and \
                covers(other, rule, family, kind, {}):
            found.append(other)
    return found


def acl_change(before, after, with_undo=True):
    """The Change taking an ACL from before to after (either None: create or delete). after's rules say which of
    before's they are by seq (0 for a new one)."""
    if before is None and after is None:
        return Change("Nothing")
    if after is not None:
        after = after.copy(rules=[rule.copy(origin=index) for index, rule in enumerate(after.rules)])
    if before is None:
        return create_acl(after)
    if after is None:
        return delete_acl(before)
    family, kind = before.family, before.kind
    old = sorted(before.rules, key=lambda rule: rule.seq)
    notes, reseq = [], []
    after = after.copy(rules=settle_order(old, after.rules, family, kind))
    planned = assign(old, after.rules, family, kind)
    if planned is None:  # No room: renumber first, the way the device will (the order it lists the rules in)
        shown = device_order(before)
        place = {rule.seq: index + 1 for index, rule in enumerate(shown)}
        source = after.rules
        by_place = [rule.copy(seq=place[rule.seq]) for rule in shown]
        wanted = settle_order(by_place, [rule.copy(seq=place.get(rule.seq, 0)) for rule in source], family, kind)
        step = resequence_step(by_place, wanted, family, kind)
        while planned is None and step * len(shown) <= MAX_SEQ:
            prefix = "ipv6" if family == V6 else "ip"
            reseq = [f"{prefix} access-list resequence {before.name} {step} {step}"]
            old = [rule.copy(seq=step * place[rule.seq]) for rule in shown]
            renumbered = [rule.copy(seq=step * place[rule.seq] if rule.seq in place else 0) for rule in source]
            after = after.copy(rules=settle_order(old, renumbered, family, kind))
            planned = assign(old, after.rules, family, kind)
            step *= 10
    if planned is None:
        return Change(f"Change {before.title}", notes=["There aren't enough sequence numbers free."])
    if reseq:
        how = " (IOS numbers a standard ACL's single addresses first, the way it lists them)" if \
            [rule.seq for rule in device_order(before)] != sorted(rule.seq for rule in before.rules) else ""
        notes.append(f"The rules are renumbered first ({reseq[0]}), to make room{how}. Undo leaves them "
                     "renumbered.")
    numbers, fixed = planned
    for index, rule in enumerate(after.rules):
        if rule.want_seq and numbers[index] != rule.want_seq and with_undo:
            notes.append(f"Line {rule.origin + 1} can't have number {rule.want_seq} (another rule has it, or it's "
                         f"out of order with the rules around it): it gets {numbers[index]}.")
    old_by_seq = {rule.seq: rule for rule in old}
    final = after.copy(rules=[rule.copy(seq=numbers[index], want_seq=0) for index, rule in enumerate(after.rules)])
    for index, rule in enumerate(final.rules):
        rule.hits = after.rules[index].hits if index in fixed else None
    kept = {after.rules[index].seq for index in fixed}
    added = [(index, rule) for index, rule in enumerate(final.rules) if index not in fixed]
    removed = [rule for rule in old if rule.seq not in kept]
    lines = []
    if added or removed or before.trailing_remark != after.trailing_remark:
        lines.append(before.mode_line())
        present = {rule.seq: rule for rule in old}
        going = {rule.seq for rule in removed}
        early = []
        for _, rule in added:  # A changed rule goes in before the old one comes out, unless IOS won't take it then
            for blocker in blockers(rule, present.values(), family, kind):
                if blocker.seq in going:
                    lines.append(" " + final.no_rule_line(blocker.seq))
                    going.discard(blocker.seq)
                    del present[blocker.seq]
                    early.append(blocker.seq)
            lines += [f" remark {text}" for text in rule.remark.splitlines() if text.strip()]
            lines.append(" " + final.rule_line(rule))
            present[rule.seq] = rule
        for rule in removed:
            if rule.seq in going:
                lines.append(" " + final.no_rule_line(rule.seq))
        if early:
            numbers_text = ", ".join(str(seq) for seq in early[:6]) + ("..." if len(early) > 6 else "")
            notes.append(f"Rule(s) {numbers_text} come out just before their new place goes in (IOS won't hold the "
                         "same rule twice, or a single address after a rule taking it already), so for that moment "
                         "they aren't there.")
        if before.trailing_remark != after.trailing_remark:
            lines += [f" no remark {text}" for text in before.trailing_remark.splitlines() if text.strip()]
            lines += [f" remark {text}" for text in after.trailing_remark.splitlines() if text.strip()]
        lines.append(" exit")
    if not lines:
        return Change(f"No changes to {before.title}", after=final)
    lines = reseq + lines
    # Undo: the same, from final back to before (deleted rules put back at their own numbers, where free)
    to_final = {after.rules[index].seq: numbers[index] for index in range(len(after.rules)) if after.rules[index].seq}
    back = []
    for rule in old:
        if rule.seq in kept:
            back.append(rule.copy())
        elif rule.seq in to_final:
            back.append(rule.copy(seq=to_final[rule.seq], want_seq=rule.seq))
        else:
            back.append(rule.copy(seq=0, want_seq=rule.seq))
    undo = acl_change(final, before.copy(rules=back), with_undo=False).lines if with_undo else []
    change = Change(f"Change {before.title}", lines, undo, notes, ACLS, final)
    summary = []
    changed = sum(1 for index, _ in added if after.rules[index].seq in old_by_seq)
    new = len(added) - changed
    gone = len(removed) - changed
    if new:
        summary.append(f"{new} added")
    if changed:
        summary.append(f"{changed} changed or moved")
    if gone:
        summary.append(f"{gone} removed")
    if summary:
        change.title += ": " + ", ".join(summary)
    return change


def align(before, wanted):
    """wanted (from the library, or another device) with each rule marked as before's rule doing the same (by its
    seq), so acl_change only touches what differs."""
    unused = sorted(before.rules, key=lambda rule: rule.seq) if before is not None else []
    rules = []
    for rule in wanted.rules:
        key = rule.key(wanted.family, wanted.kind)
        match = next((item for item in unused if item.key(before.family, before.kind) == key), None)
        if match is not None:
            unused.remove(match)
            rules.append(rule.copy(seq=match.seq, want_seq=0, hits=match.hits))
        else:
            rules.append(rule.copy(seq=0, want_seq=0, hits=None))
    return wanted.copy(rules=rules)


def create_acl(acl):
    numbers = fill_gap(0, None, [rule.want_seq for rule in acl.rules], set())
    rules = [rule.copy(seq=number) for rule, number in zip(acl.rules, numbers)] if numbers is not None else \
        resequenced(acl.rules, 10)
    final = acl.copy(rules=rules)
    lines = final.config() + [" exit"]
    return Change(f"Create {acl.title}", lines, [final.delete_line()], [], ACLS, final)


def delete_acl(acl):
    rules = sorted(acl.rules, key=lambda rule: rule.seq)
    return Change(f"Delete {acl.title}", [acl.delete_line()], acl.copy(rules=rules).config() + [" exit"], [],
                  DELETE_ACL, None)


def object_change(before, after):
    """The Change for an object group or time range (before or after None: create or delete)."""
    item = after or before
    stage = OBJECTS
    word = "object group" if isinstance(item, ObjectGroup) else "time range"
    if before is None:
        return Change(f"Create {word} {after.name}", after.config() + [" exit"], [f"no {after.mode_line()}"], [],
                      stage, after)
    if after is None:
        return Change(f"Delete {word} {before.name}", [f"no {before.mode_line()}"], before.config() + [" exit"], [],
                      DELETE_OBJECTS, None)
    old, new = list(before.entries), list(after.entries)
    adds = [entry for entry in new if entry not in old]
    takes = [entry for entry in old if entry not in new]
    lines, undo = [], []
    old_text = getattr(before, "description", "")
    new_text = getattr(after, "description", "")
    if adds or takes or old_text != new_text:
        lines = [before.mode_line()] + [f" {entry}" for entry in adds] + [f" no {entry}" for entry in takes]
        undo = [before.mode_line()] + [f" {entry}" for entry in takes] + [f" no {entry}" for entry in adds]
        if old_text != new_text:
            lines.append(f" description {new_text}" if new_text else " no description")
            undo.append(f" description {old_text}" if old_text else " no description")
        lines.append(" exit")
        undo.append(" exit")
    return Change(f"Change {word} {before.name}", lines, undo, [], stage, after)


def apply_line(family, where, acl, direction):
    if where == LINE:
        return f"{'ipv6 ' if family == V6 else ''}access-class {acl} {direction}"
    return f"ipv6 traffic-filter {acl} {direction}" if family == V6 else f"ip access-group {acl} {direction}"


def mode_for(where, target):
    return f"line {target}" if where == LINE else f"interface {target}"


def apply_change(device, family, where, target, acl, direction):
    """Put acl on an interface or VTY lines (target) in direction. Undo puts back what was there, if anything."""
    current = next((item for item in device.applied if item.where == where and item.target == target and
                    item.family == family and item.direction == direction), None)
    mode = mode_for(where, target)
    lines = [mode, " " + apply_line(family, where, acl, direction), " exit"]
    if current is not None:
        undo = [mode, " " + apply_line(family, where, current.acl, direction), " exit"]
        notes = [f"It takes the place of {current.acl}, on {target} {direction} now."]
    else:
        undo = [mode, " no " + apply_line(family, where, acl, direction), " exit"]
        notes = []
    where_text = f"line {target}" if where == LINE else target
    return Change(f"Apply {acl} to {where_text} {direction}", lines, undo, notes, APPLY)


def set_applied(device, family, where, target, name, direction):
    """Put name on target (in device's list), in place of what's there that way."""
    device.applied = [item for item in device.applied if not (item.where == where and item.target == target and
                                                               item.family == family and item.direction == direction)]
    line = apply_line(family, where, name, direction)
    device.applied.append(Applied(name, family, where, target, direction, line))


def take_off(device, family, where, target, name, direction):
    device.applied = [item for item in device.applied if not (item.where == where and item.target == target and
                                                               item.family == family and item.direction == direction
                                                               and item.acl == name)]


def unapply_change(applied):
    """Take an ACL off the interface or lines it's on (where OTHER can't be: it's somebody else's line)."""
    mode = mode_for(applied.where, applied.target)
    line = apply_line(applied.family, applied.where, applied.acl, applied.direction)
    where_text = f"line {applied.target}" if applied.where == LINE else applied.target
    return Change(f"Take {applied.acl} off {where_text} {applied.direction}", [mode, " no " + line, " exit"],
                  [mode, " " + line, " exit"], [], UNAPPLY)


def acl_differs(a, b):
    def shape(item):
        rules = [(rule.seq, rule.want_seq or rule.seq, rule.key(item.family, item.kind), rule.remark)
                 for rule in item.rules]
        return rules, item.trailing_remark
    return a.kind != b.kind or shape(a) != shape(b)


def placed(device):
    """{(family, where, target, direction): ACL name} of the ACLs on interfaces and lines."""
    return {(item.family, item.where, item.target, item.direction): item.acl for item in device.applied
            if item.where in (INTERFACE, LINE)}


def device_changes(before, after):
    """[Change] taking a device from before (as read) to after (as edited): ACLs, object groups, time ranges and
    where ACLs are applied."""
    changes = []
    for key in dict.fromkeys(list(before.acls) + list(after.acls)):
        old, new = before.acls.get(key), after.acls.get(key)
        if old is None or new is None or acl_differs(old, new):
            change = acl_change(old, new)
            if change or change.notes:
                changes.append(change)
    for old_items, new_items in ((before.groups, after.groups), (before.ranges, after.ranges)):
        for name in dict.fromkeys(list(old_items) + list(new_items)):
            old, new = old_items.get(name), new_items.get(name)
            if old is not None and new is not None and old.entries == new.entries and \
                    getattr(old, "description", "") == getattr(new, "description", "") and \
                    getattr(old, "kind", "") == getattr(new, "kind", ""):
                continue
            change = object_change(old, new)
            if change:
                changes.append(change)
    old_spots, new_spots = placed(before), placed(after)
    for spot, name in new_spots.items():
        if old_spots.get(spot) != name:
            family, where, target, direction = spot
            changes.append(apply_change(before, family, where, target, name, direction))
    for spot, name in old_spots.items():
        if spot not in new_spots:
            family, where, target, direction = spot
            changes.append(unapply_change(Applied(name, family, where, target, direction)))
    from .routepolicy import policy_changes
    return changes + policy_changes(before, after)


def edited_rule_state(before_acl, rule, family, kind):
    """"new", "changed" or "" (as on the device) for a rule of an edited ACL."""
    if before_acl is None or not rule.seq:
        return "new"
    old = next((item for item in before_acl.rules if item.seq == rule.seq), None)
    if old is None:
        return "new"
    return "" if same_rule(old, rule, family, kind) else "changed"


# ----------------------------------------------------------------- A whole device's configuration of ACLs as text

def library_config(acl, groups=(), ranges=()):
    """An ACL with the object groups and time ranges it needs, as configuration text (how the library keeps it)."""
    lines = []
    for item in list(ranges) + list(groups):
        lines += item.config()
    return "\n".join(lines + acl.config(with_seq=True))


def needed(acl, device):
    """(object groups, time ranges) of device the ACL's rules name, nested groups included."""
    groups, ranges, pending = {}, {}, []
    for rule in acl.rules:
        pending += [name for name in (rule.service_group, rule.src.group, rule.dst.group) if name]
        if rule.time_range and rule.time_range in device.ranges:
            ranges[rule.time_range] = device.ranges[rule.time_range]
    while pending:
        name = pending.pop()
        group = device.groups.get(name)
        if group is None or name in groups:
            continue
        groups[name] = group
        pending += [entry.split()[1] for entry in group.entries if entry.startswith("group-object ")]
    return list(groups.values()), list(ranges.values())


# ----------------------------------------------------------------- The library and history, kept on this PC

@dataclass
class LibraryEntry:
    id: str
    name: str
    config: str  # library_config text
    notes: str = ""
    saved: str = ""
    item: str = ""  # What it keeps: "" an ACL, "route-map NAME", "prefix-list ipv4 NAME"

    def device(self):
        """The text read as a DeviceAcls (the ACL with its groups and time ranges, or the prefix list, or the route
        map with what it matches)."""
        return parse_running(self.config)

    def acl(self):
        """The ACL it keeps (None when it keeps a prefix list or route map)."""
        if self.item:
            return None
        device = self.device()
        return next(iter(device.acls.values()), None)

    def main(self):
        """What it keeps: an Acl, PrefixList or RouteMap (None when the text has none)."""
        device = self.device()
        words = self.item.split()
        if words[:1] == ["route-map"] and len(words) == 2:
            return device.route_maps.get(words[1])
        if words[:1] == ["prefix-list"] and len(words) == 3:
            return device.prefix_lists.get((words[1], words[2]))
        return next(iter(device.acls.values()), None)


@dataclass
class HistoryEntry:
    """A change sent to a device, with what undoes it."""
    id: str
    device: str  # Shown name
    address: str
    title: str
    lines: str
    undo: str
    when: str = ""
    how: str = ""  # "SSH" or the session's name
    outcome: str = ""  # "Confirmed", "Rolled back", "Sent", "Refused: ...", "Undone"


class AclStore:
    """The ACL library and the changes sent from this PC, in a JSON file in the app's folder."""

    def __init__(self, path=None):
        self.path = path
        self.library, self.history = [], []

    @classmethod
    def default(cls):
        from ..system import app_data_dir
        store = cls(app_data_dir() / FILE_NAME)
        store.load()
        return store

    def load(self):
        self.library, self.history = [], []
        if self.path is None:
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
            self.library = [LibraryEntry(**item) for item in data.get("library", [])]
            self.history = [HistoryEntry(**item) for item in data.get("history", [])]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as error:
            log.warning("Couldn't read the ACLs from %s: %s", self.path, error)

    def save(self):
        if self.path is None:
            return
        from dataclasses import asdict
        from ..system import replace_file
        self.history = self.history[:KEEP_HISTORY]
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump({"version": 1, "library": [asdict(item) for item in self.library],
                       "history": [asdict(item) for item in self.history]}, file, indent=1)
        replace_file(temporary, self.path)

    def add_to_library(self, name, config, notes="", item=""):
        existing = next((entry for entry in self.library if entry.name == name), None)
        when = now_text()
        if existing is not None:
            existing.config, existing.notes, existing.saved = config, notes or existing.notes, when
            existing.item = item
            entry = existing
        else:
            entry = LibraryEntry(uuid.uuid4().hex, name, config, notes, when, item)
            self.library.append(entry)
        self.save()
        return entry

    def remove_from_library(self, entry_id):
        self.library = [item for item in self.library if item.id != entry_id]
        self.save()

    def record(self, device, address, title, lines, undo, how, outcome):
        entry = HistoryEntry(uuid.uuid4().hex, device, address, title, lines, undo, now_text(), how, outcome)
        self.history.insert(0, entry)
        self.save()
        return entry

    def update(self, entry):
        self.save()


def now_text():
    return datetime.datetime.now().isoformat(timespec="seconds")
