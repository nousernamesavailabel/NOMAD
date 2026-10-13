"""What an ACL does: which rule a packet matches, rules that can never match, mistakes IOS takes without a word, and
whether a change would lock this PC out of the device.

A rule covers another when every packet the other matches, it matches too: then the other, further down, never
matches anything (shadowed when they disagree, not needed when they agree). Wildcards are compared bit by bit, so
non-contiguous ones (10.0.0.0 0.255.0.255) are right too; object groups are compared entry by entry, so a rule
covered only by several entries together isn't said to be (a finding can be missed, never made up).

Qt-free, so it can be tested without a network.
"""
import datetime
import ipaddress
import re
from dataclasses import dataclass, field

from .acl import ANY, DENY, GROUP, HOST, ICMPV6, IN, INTERFACE, LINE, PERMIT, PREFIX, STANDARD, V4, V6, WILDCARD, \
    Address, Ports, ip_int, looks_like_mask, prefix_of_wildcard, protocol_number, single_address, stored_address
from .vlans import ERROR, INFO, WARNING

ALL_PORTS = [(0, 65535)]
EPHEMERAL = 50000  # The source port a login is checked from
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
DAY_WORDS = {"daily": DAYS, "weekdays": DAYS[:5], "weekend": DAYS[5:]}
MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
          "november", "december"]
TCP, UDP = 6, 17
ND_TYPES = (135, 136)  # Neighbor solicitation and advertisement: an IPv6 ACL permits them before its implicit deny


@dataclass
class Packet:
    src: str
    dst: str
    protocol: int = TCP
    src_port: int = EPHEMERAL
    dst_port: int = 0
    icmp_type: object = None
    icmp_code: object = None
    flags: set = field(default_factory=set)  # TCP flags set: {"syn"}, {"ack"}...
    fragment: bool = False  # A non-initial fragment
    when: object = None  # datetime for time ranges (None: now)

    @property
    def family(self):
        return V6 if ":" in self.src or ":" in self.dst else V4


@dataclass
class Verdict:
    permitted: bool
    rule: object = None  # The Rule that matched, or None (the implicit deny, or an implicit ND permit)
    text: str = ""
    notes: list = field(default_factory=list)


@dataclass
class Finding:
    severity: str
    text: str
    index: int = -1  # The row of the rule it's about (-1: the ACL)
    other: int = -1  # The row of the rule it's because of


def rule_label(rule, index):
    """Rule 30, or for one not on the device yet, the new rule on line 4."""
    return f"Rule {rule.seq}" if rule.seq else f"The new rule on line {index + 1}"


def lower_first(text):
    return text[:1].lower() + text[1:]


# ----------------------------------------------------------------- Addresses

def address_spans(address, family, groups, depth=0):
    """[(kind, value...)] the address means: ("wild", address int, wildcard int) for IPv4, ("net", network) for
    IPv6, ("range", low, high); [] for an unknown group (matches nothing), None for any."""
    if address.kind == ANY:
        return None
    if address.kind == GROUP:
        group = groups.get(address.group)
        if group is None or depth > 8:
            return []
        spans = []
        for entry in group.entries:
            found = group_entry_spans(entry, family, groups, depth)
            if found is None:
                return None
            spans += found
        return spans
    if family == V6:
        length = address.prefix if address.kind == PREFIX else 128
        try:
            return [("net", ipaddress.IPv6Network(f"{address.address}/{length}", strict=False))]
        except ValueError:
            return []
    try:
        bits = 0 if address.kind == HOST else ip_int(address.wildcard)
        return [("wild", ip_int(address.address) & ~bits & 0xFFFFFFFF, bits)]
    except ValueError:
        return []


def group_entry_spans(entry, family, groups, depth):
    words = entry.split()
    if not words:
        return []
    try:
        if words[0] == "any":
            return None
        if words[0] == "group-object" and len(words) > 1:
            return address_spans(Address(GROUP, group=words[1]), family, groups, depth + 1)
        if words[0] == "host" and len(words) > 1:
            words = words[1:]
        if words[0] == "range" and len(words) == 3:
            return [("range", int(ipaddress.ip_address(words[1])), int(ipaddress.ip_address(words[2])))]
        if family == V6 or ":" in words[0]:
            return [("net", ipaddress.IPv6Network(words[0], strict=False))]
        if "/" in words[0]:
            network = ipaddress.IPv4Network(words[0], strict=False)
            return [("wild", int(network.network_address), int(network.hostmask))]
        if len(words) >= 2:  # Network object groups take a subnet mask, not a wildcard
            mask = ip_int(words[1])
            return [("wild", ip_int(words[0]) & mask, mask ^ 0xFFFFFFFF)]
        return [("wild", ip_int(words[0]), 0)]
    except ValueError:
        return []


def span_has(span, value):
    if span[0] == "wild":
        return (value & ~span[2] & 0xFFFFFFFF) == span[1]
    if span[0] == "net":
        return value in span[1]
    return span[1] <= int(value) <= span[2]


def address_matches(address, ip, family, groups):
    spans = address_spans(address, family, groups)
    if spans is None:
        return True
    value = ipaddress.ip_address(ip)
    value = int(value) if family == V4 else value
    return any(span_has(span, value) for span in spans)


def span_covers(a, b):
    """Every address of span b is in span a."""
    if a[0] == "wild" and b[0] == "wild":
        return (b[2] & ~a[2]) == 0 and (b[1] & ~a[2] & 0xFFFFFFFF) == a[1]
    if a[0] == "net" and b[0] == "net":
        return b[1].version == a[1].version and b[1].subnet_of(a[1])
    if b[0] == "range":
        low, high = b[1], b[2]
        if a[0] == "range":
            return a[1] <= low and high <= a[2]
        if a[0] == "wild" and prefix_of_wildcard(str(ipaddress.IPv4Address(a[2]))) is not None:
            return a[1] <= low and high <= a[1] + a[2]
        return False
    if a[0] == "range" and b[0] == "wild" and prefix_of_wildcard(str(ipaddress.IPv4Address(b[2]))) is not None:
        return a[1] <= b[1] and b[1] + b[2] <= a[2]
    if a[0] == "range" and b[0] == "net":
        return a[1] <= int(b[1].network_address) and int(b[1].broadcast_address) <= a[2]
    return False


def spans_overlap(a, b):
    if a[0] == "wild" and b[0] == "wild":
        return ((a[1] ^ b[1]) & ~a[2] & ~b[2] & 0xFFFFFFFF) == 0
    if a[0] == "net" and b[0] == "net":
        return a[1].overlaps(b[1])
    return True  # Ranges against others: taken to overlap (only used to be careful)


def address_covers(a, b, family, groups):
    spans_a, spans_b = address_spans(a, family, groups), address_spans(b, family, groups)
    if spans_a is None:
        return True
    if spans_b is None:
        return False
    return all(any(span_covers(x, y) for x in spans_a) for y in spans_b)


def address_overlaps(a, b, family, groups):
    spans_a, spans_b = address_spans(a, family, groups), address_spans(b, family, groups)
    if spans_a is None or spans_b is None:
        return True
    return any(spans_overlap(x, y) for x in spans_a for y in spans_b)


# ----------------------------------------------------------------- Services (protocol + ports + ICMP)

@dataclass
class Service:
    protocol: int  # 0: any
    src: list = field(default_factory=lambda: list(ALL_PORTS))
    dst: list = field(default_factory=lambda: list(ALL_PORTS))
    icmp_type: object = None
    icmp_code: object = None
    ported: bool = False  # Names ports (so a non-initial fragment can't match it)


def rule_services(rule, family, groups, depth=0):
    """[Service] a rule (or its service object group) means."""
    if rule.service_group:
        group = groups.get(rule.service_group)
        if group is None:
            return []
        return group_services(group, family, groups, depth)
    number = protocol_number(rule.protocol)
    if number is None:
        return []
    if family == V6 and number == 1:
        number = ICMPV6
    return [Service(number, rule.src_ports.intervals(), rule.dst_ports.intervals(), rule.icmp_type, rule.icmp_code,
                    bool(rule.src_ports or rule.dst_ports))]


def group_services(group, family, groups, depth):
    services = []
    for entry in group.entries:
        words = entry.split()
        if not words:
            continue
        if words[0] == "group-object" and len(words) > 1:
            inner = groups.get(words[1])
            if inner is not None and depth < 8:
                services += group_services(inner, family, groups, depth + 1)
            continue
        protocols = [TCP, UDP] if words[0] == "tcp-udp" else [protocol_number(words[0])]
        if protocols[0] is None:
            continue
        rest = words[1:]
        src, dst = Ports(), Ports()
        if rest[:1] == ["source"]:
            src, rest = take_ports(rest[1:])
        if rest[:1] == ["destination"]:
            rest = rest[1:]
        if rest and rest[0] in ("eq", "neq", "lt", "gt", "range"):
            dst, rest = take_ports(rest)
        icmp_type = icmp_code = None
        if protocols[0] == 1 and rest:
            from .acl import ICMP_NAMES, ICMPV6_NAMES
            names = ICMPV6_NAMES if family == V6 else ICMP_NAMES
            if rest[0] in names:
                icmp_type, icmp_code = names[rest[0]]
            elif rest[0].isdigit():
                icmp_type = int(rest[0])
        for number in protocols:
            if family == V6 and number == 1:
                number = ICMPV6
            services.append(Service(number, src.intervals(), dst.intervals(), icmp_type, icmp_code,
                                    bool(src or dst)))
    return services


def take_ports(words):
    from .acl import port_number
    op = words[0] if words else ""
    if op not in ("eq", "neq", "lt", "gt", "range"):
        return Ports(), words
    count = 2 if op == "range" else 1
    values = [port_number(word) or 0 for word in words[1:1 + count]]
    return Ports(op, values), words[1 + count:]


def intervals_cover(outer, inner):
    return all(any(low >= a and high <= b for a, b in outer) for low, high in inner)


def intervals_overlap(a, b):
    return any(low <= y and x <= high for low, high in a for x, y in b)


def has_port(intervals, port):
    return any(low <= port <= high for low, high in intervals)


def service_covers(a, b):
    if a.protocol and a.protocol != b.protocol:
        return False
    if a.protocol in (TCP, UDP):
        if not (intervals_cover(a.src, b.src) and intervals_cover(a.dst, b.dst)):
            return False
    if a.icmp_type is not None:
        if b.icmp_type != a.icmp_type:
            return False
        if a.icmp_code is not None and b.icmp_code != a.icmp_code:
            return False
    return True


def service_overlaps(a, b):
    if a.protocol and b.protocol and a.protocol != b.protocol:
        return False
    if a.protocol in (TCP, UDP) and b.protocol in (TCP, UDP):
        if not (intervals_overlap(a.src, b.src) and intervals_overlap(a.dst, b.dst)):
            return False
    if a.icmp_type is not None and b.icmp_type is not None and a.icmp_type != b.icmp_type:
        return False
    return True


def service_matches(service, packet):
    if service.protocol and service.protocol != packet.protocol:
        return False
    if packet.fragment and service.ported:
        return False
    if service.protocol in (TCP, UDP):
        if not (has_port(service.src, packet.src_port) and has_port(service.dst, packet.dst_port)):
            return False
    if service.icmp_type is not None:
        if packet.icmp_type != service.icmp_type:
            return False
        if service.icmp_code is not None and packet.icmp_code != service.icmp_code:
            return False
    return True


# ----------------------------------------------------------------- Time ranges

def parse_clock(text):
    hours, _, minutes = text.partition(":")
    return int(hours) * 60 + int(minutes or 0)


def periodic_active(entry, moment):
    """Whether "periodic weekdays 8:00 to 17:00" (or "periodic monday 22:00 to tuesday 6:00") covers moment."""
    words = entry.lower().split()[1:]
    if "to" not in words:
        return False
    at = words.index("to")
    start, end = words[:at], words[at + 1:]
    start_days = [day for word in start[:-1] for day in DAY_WORDS.get(word, [word])]
    end_days = [day for word in end[:-1] for day in DAY_WORDS.get(word, [word])]
    try:
        start_minute, end_minute = parse_clock(start[-1]), parse_clock(end[-1])
    except (ValueError, IndexError):
        return False
    day = DAYS[moment.weekday()]
    minute = moment.hour * 60 + moment.minute
    if not end_days:  # The same day(s): from start to end on each
        return day in start_days and start_minute <= minute <= end_minute
    if len(start_days) == 1 and len(end_days) == 1:  # One stretch from a day to a later one
        first, last = DAYS.index(start_days[0]), DAYS.index(end_days[0])
        now = DAYS.index(day) * 1440 + minute
        begin, finish = first * 1440 + start_minute, last * 1440 + end_minute
        if finish < begin:
            finish += 7 * 1440
            if now < begin:
                now += 7 * 1440
        return begin <= now <= finish
    return day in start_days and minute >= start_minute or day in end_days and minute <= end_minute


def parse_moment(words):
    """'08:00 1 January 2026' -> datetime, or None."""
    try:
        clock, day, month, year = words[:4]
        hours, minutes = clock.split(":")
        return datetime.datetime(int(year), MONTHS.index(month.lower()) + 1, int(day), int(hours), int(minutes))
    except (ValueError, IndexError):
        return None


def time_range_active(time_range, moment):
    """Whether a TimeRange lets its rules match at moment (absolute window and any periodic one)."""
    periodic = [entry for entry in time_range.entries if entry.lower().startswith("periodic")]
    for entry in time_range.entries:
        words = entry.split()
        if words[:1] != ["absolute"]:
            continue
        rest = words[1:]
        if "start" in rest:
            start = parse_moment(rest[rest.index("start") + 1:])
            if start is not None and moment < start:
                return False
        if "end" in rest:
            end = parse_moment(rest[rest.index("end") + 1:])
            if end is not None and moment > end:
                return False
    return not periodic or any(periodic_active(entry, moment) for entry in periodic)


# ----------------------------------------------------------------- Matching

def flags_match(rule, packet):
    if rule.established and not packet.flags & {"ack", "rst"}:
        return False
    words = rule.tcp_flags
    if not words:
        return True
    if words[0] in ("match-any", "match-all"):
        checks = [(word[1:], word[0] == "+") for word in words[1:]]
        results = [(flag in packet.flags) == wanted for flag, wanted in checks]
        return any(results) if words[0] == "match-any" else all(results)
    return all(flag in packet.flags for flag in words)


def matches(rule, packet, family, kind, groups, ranges, notes=None):
    """Whether the rule matches the packet. notes (a list) gets what was assumed."""
    if rule.time_range:
        time_range = ranges.get(rule.time_range)
        if time_range is None:
            if notes is not None:
                notes.append(f"Time range {rule.time_range} isn't on the device: its rules are taken as not active.")
            return False
        if not time_range_active(time_range, packet.when or datetime.datetime.now()):
            return False
    if kind == STANDARD:
        return address_matches(rule.src, packet.src, family, groups)
    if not any(service_matches(service, packet) for service in rule_services(rule, family, groups)):
        return False
    if rule.fragments and not packet.fragment:
        return False
    if (rule.established or rule.tcp_flags) and packet.protocol != TCP:
        return False
    if not flags_match(rule, packet):
        return False
    if rule.extra and notes is not None:
        notes.append(f"Rule {rule.seq}'s {' '.join(rule.extra)} isn't checked: taken as matching.")
    return address_matches(rule.src, packet.src, family, groups) and \
        address_matches(rule.dst, packet.dst, family, groups)


def evaluate(acl, packet, groups=None, ranges=None):
    """The Verdict an ACL gives a packet: the first rule that matches, else IPv6's implicit ND permits, else the
    implicit deny. An ACL with no rules (or one not on the device) permits everything where it's applied."""
    groups, ranges = groups or {}, ranges or {}
    notes = []
    if acl is None:
        return Verdict(True, None, "The ACL isn't on the device, so IOS lets everything through.")
    if not acl.rules:
        return Verdict(True, None, "The ACL has no rules, so IOS lets everything through.")
    for index, rule in enumerate(acl.rules):
        if matches(rule, packet, acl.family, acl.kind, groups, ranges, notes):
            verb = "Permitted" if rule.action == PERMIT else "Denied"
            which = lower_first(rule_label(rule, index))
            return Verdict(rule.action == PERMIT, rule, f"{verb} by {which}: {rule.body(acl.family, acl.kind)}",
                           notes)
    if acl.family == V6 and packet.protocol == ICMPV6 and packet.icmp_type in ND_TYPES:
        return Verdict(True, None, "Permitted by IPv6's implicit neighbor discovery rules (before the implicit deny).",
                       notes)
    return Verdict(False, None, "Denied by the implicit deny at the end (no rule matched).", notes)


# ----------------------------------------------------------------- Rules against rules

def covers(a, b, family, kind, groups):
    """Every packet rule b matches, rule a matches too."""
    if a.time_range and a.time_range != b.time_range:
        return False
    if a.fragments and not b.fragments:
        return False
    if a.extra and a.extra != b.extra:
        return False
    if (a.established or a.tcp_flags) and (a.established != b.established or a.tcp_flags != b.tcp_flags):
        return False
    if not address_covers(a.src, b.src, family, groups):
        return False
    if kind == STANDARD:
        return True
    services_a, services_b = rule_services(a, family, groups), rule_services(b, family, groups)
    if not services_b or not all(any(service_covers(x, y) for x in services_a) for y in services_b):
        return False
    if b.fragments and any(service.ported for service in services_a):
        return False
    return address_covers(a.dst, b.dst, family, groups)


def overlaps(a, b, family, kind, groups):
    """Some packet could match both."""
    if not address_overlaps(a.src, b.src, family, groups):
        return False
    if kind == STANDARD:
        return True
    services_a, services_b = rule_services(a, family, groups), rule_services(b, family, groups)
    if not any(service_overlaps(x, y) for x in services_a for y in services_b):
        return False
    return address_overlaps(a.dst, b.dst, family, groups)


def findings(acl, groups=None, ranges=None):
    """[Finding] about an ACL (its rules in the order they're in), worst first."""
    groups, ranges = groups or {}, ranges or {}
    found = []
    rules = list(acl.rules)
    family, kind = acl.family, acl.kind
    for index, rule in enumerate(rules):
        found += rule_mistakes(rule, index, family, kind, groups, ranges)
    for index, rule in enumerate(rules):
        name = rule_label(rule, index)
        for spot, earlier in enumerate(rules[:index]):
            if not covers(earlier, rule, family, kind, groups):
                continue
            other = lower_first(rule_label(earlier, spot))
            if covers(rule, earlier, family, kind, groups) and rule.action == earlier.action:
                found.append(Finding(WARNING, f"{name} is the same as {other}, so it never matches anything (IOS "
                                              "keeps only one of them).", index, spot))
            elif kind == STANDARD and family == V4 and single_address(rule.src):
                found.append(Finding(ERROR, f"{name} can't go in: IOS refuses a single address after {other}, which "
                                            "takes it already. Put it above that rule, or take it out.", index, spot))
            elif rule.action != earlier.action:
                found.append(Finding(WARNING, f"{name} never matches: {other} (a {earlier.action}) takes "
                                              "everything it would.", index, spot))
            else:
                found.append(Finding(INFO, f"{name} isn't needed: {other} already {earlier.action}s all of it.",
                                     index, spot))
            break
        else:
            later = next((spot for spot in range(index + 1, len(rules)) if rules[spot].action == rule.action and
                          covers(rules[spot], rule, family, kind, groups)), None)
            if later is not None and not any(item.action != rule.action and overlaps(item, rule, family, kind, groups)
                                             for item in rules[index + 1:later]):
                found.append(Finding(INFO, f"{name} isn't needed: {lower_first(rule_label(rules[later], later))}, "
                                           f"further down, {rule.action}s all of it too.", index, later))
    if rules and all(rule.action == DENY for rule in rules):
        found.append(Finding(WARNING, "Every rule denies, so the ACL lets nothing through (the implicit deny at the "
                                      "end takes the rest)."))
    if not rules:
        found.append(Finding(INFO, "It has no rules: applied anywhere, IOS lets everything through."))
    if family == V6:
        found += neighbor_discovery(rules, kind, groups)
    if kind == STANDARD and acl.shown and acl.shown != sorted(acl.shown):
        found.append(Finding(INFO, "The device lists this ACL's single addresses first, in an order of its own (show "
                                   "access-lists and the running-config both), not by number. Every packet still "
                                   "gets what it gets in the order here: IOS won't put a single address after a "
                                   "rule covering it."))
    unseen = [rule for rule in rules if rule.hits == 0]
    if unseen and any(rule.hits for rule in rules):
        numbers = ", ".join(str(rule.seq) for rule in unseen[:8]) + ("..." if len(unseen) > 8 else "")
        found.append(Finding(INFO, f"{len(unseen)} rule(s) haven't matched anything since the counters were last "
                                   f"cleared: {numbers}."))
    order = {ERROR: 0, WARNING: 1, INFO: 2}
    found.sort(key=lambda item: order[item.severity])
    return found


def rule_mistakes(rule, index, family, kind, groups, ranges):
    found = []
    name = rule_label(rule, index)
    for side, address in (("source", rule.src), ("destination", rule.dst)):
        if kind == STANDARD and side == "destination":
            continue
        if address.kind == WILDCARD and family == V4:
            if looks_like_mask(address.wildcard):
                length = bin(ip_int(address.wildcard)).count("1")
                right = str(ipaddress.IPv4Address(ip_int(address.wildcard) ^ 0xFFFFFFFF))
                found.append(Finding(ERROR, f"{name}'s {side} wildcard {address.wildcard} looks like a subnet mask "
                                            f"(a /{length} is written {right} in an ACL).", index))
            elif prefix_of_wildcard(address.wildcard) is None:
                found.append(Finding(INFO, f"{name}'s {side} wildcard {address.wildcard} isn't contiguous, so it "
                                           "matches addresses scattered through the range. Meant?", index))
            stored = stored_address(address)
            if stored != address.address and not looks_like_mask(address.wildcard):
                found.append(Finding(WARNING, f"{name}'s {side} {address.address} {address.wildcard} has bits set "
                                              f"under the wildcard: IOS keeps it as {stored} {address.wildcard}.",
                                     index))
        if address.kind == GROUP and address.group not in groups:
            found.append(Finding(ERROR, f"{name} names object group {address.group}, which isn't on the device.",
                                 index))
    if rule.service_group and rule.service_group not in groups:
        found.append(Finding(ERROR, f"{name} names service object group {rule.service_group}, which isn't on the "
                                    "device.", index))
    if rule.time_range and rule.time_range not in ranges:
        found.append(Finding(WARNING, f"{name} names time range {rule.time_range}, which isn't on the device.", index))
    if kind != STANDARD and not rule.service_group:
        number = protocol_number(rule.protocol)
        if number is None:
            found.append(Finding(ERROR, f"{name}'s protocol {rule.protocol} isn't one IOS knows.", index))
        if (rule.src_ports or rule.dst_ports) and number not in (TCP, UDP):
            found.append(Finding(ERROR, f"{name} names ports, but only tcp and udp have them.", index))
        if (rule.established or rule.tcp_flags) and number != TCP:
            found.append(Finding(ERROR, f"{name}: established and TCP flags only go with tcp.", index))
    return found


def neighbor_discovery(rules, kind, groups):
    """An explicit deny that catches IPv6 neighbor discovery before the implicit permits for it."""
    for nd_type in ND_TYPES:
        probe = Packet("fe80::1", "fe80::2", ICMPV6, icmp_type=nd_type)
        for index, rule in enumerate(rules):
            if matches(rule, probe, V6, kind, groups, {}):
                if rule.action == DENY:
                    return [Finding(WARNING, f"{rule_label(rule, index)} denies IPv6 neighbor discovery "
                                             "(nd-ns/nd-na), which IOS only permits on its own before the implicit "
                                             "deny at the end. Add permit icmp any any nd-ns and nd-na above it.",
                                    index)]
                break
    return []


# ----------------------------------------------------------------- Locking yourself out

@dataclass
class Lockout:
    severity: str  # ERROR (this PC can't log in any more), WARNING, or INFO (all good)
    text: str
    acl: str = ""
    seq: int = 0
    where: str = ""  # "line vty 0 4" or the interface: what refuses


def interfaces_of(device, address):
    """The interfaces whose address is address, and the ones whose subnet holds it."""
    owning, holding = [], []
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return owning, holding
    for interface in device.interfaces.values():
        for network in interface.networks():
            if network.ip == value:
                owning.append(interface.name)
            elif value in network.network:
                holding.append(interface.name)
    return owning, holding


def lockout(device, pc_ip, device_ip, port=22):
    """[Lockout] for logging in from pc_ip to device_ip (over SSH, port 22) with the ACLs of device as they'd be.
    Checks the VTY lines' access-class and the inbound ACLs on the interface this PC's packets come in on (the one
    show ip cef said, else the one holding this PC's subnet) and the interface owning device_ip. Outbound ACLs don't
    filter what a router sends itself, so they're left out."""
    found = []
    if not pc_ip or not device_ip:
        return [Lockout(INFO, "This PC's address or the device's isn't known, so the lockout check couldn't run.")]
    family = V6 if ":" in pc_ip else V4
    packet = Packet(pc_ip, device_ip, TCP, EPHEMERAL, port, flags={"syn"})
    groups, ranges = device.groups, device.ranges
    on_lines = {item.target: item.acl for item in device.applied if item.where == LINE and item.direction == IN and
                item.family == family}
    vty = [name for name in dict.fromkeys(list(device.lines) + list(on_lines)) if name.startswith("vty")]
    blocked, open_lines = [], []
    for name in vty:
        acl_name = on_lines.get(name)
        if not acl_name:
            open_lines.append(name)
            continue
        acl = device.acl(family, acl_name)
        if acl is None:
            open_lines.append(name)
            continue
        # A VTY access-class checks who's logging in: a standard ACL the source, an extended one source and
        # destination (any of the router's addresses)
        verdict = evaluate(acl, packet, groups, ranges)
        if verdict.permitted:
            open_lines.append(name)
        else:
            blocked.append((name, acl_name, verdict))
    if vty and not open_lines and blocked:
        name, acl_name, verdict = blocked[0]
        found.append(Lockout(ERROR, f"line {name}: access-class {acl_name} would refuse this PC ({pc_ip}). "
                                    f"{verdict.text}", acl_name, verdict.rule.seq if verdict.rule else 0, "lines"))
    elif blocked:
        names = ", ".join(name for name, _, _ in blocked)
        found.append(Lockout(WARNING, f"line {names} would refuse this PC; it can still log in on line "
                                      f"{', '.join(open_lines)} while one's free.", blocked[0][1]))
    owning, holding = interfaces_of(device, device_ip)
    _, pc_side = interfaces_of(device, pc_ip)
    incoming = [device.toward_pc] if device.toward_pc and device.toward_pc in device.interfaces else []
    incoming = incoming or pc_side
    checked = []
    for interface in dict.fromkeys(incoming + owning):
        for applied in device.applied:
            if applied.where != INTERFACE or applied.target != interface or applied.direction != IN or \
                    applied.family != family:
                continue
            checked.append(f"{interface} {applied.acl} in")
            acl = device.acl(family, applied.acl)
            verdict = evaluate(acl, packet, groups, ranges)
            if not verdict.permitted:
                found.append(Lockout(ERROR, f"{interface}: {applied.acl} in would drop this PC's login "
                                            f"({pc_ip} to {device_ip} port {port}). {verdict.text}", applied.acl,
                                     verdict.rule.seq if verdict.rule else 0, interface))
    if not any(item.severity == ERROR for item in found):
        where = "; ".join(checked) if checked else "no ACL in on its interfaces"
        how = "" if incoming else " This PC isn't on a subnet of the device, and the way back to it wasn't read, " \
                                  "so only the interface holding its address was checked."
        found.append(Lockout(INFO, f"This PC ({pc_ip}) can still log in to {device_ip} (VTY lines; {where}). "
                                   f"ACLs on routers in between aren't checked.{how}"))
    return found


def packet_from_text(src, dst, protocol, src_port="", dst_port="", icmp="", flags="", when=None, fragment=False):
    """A Packet from what's typed in the tester. Raises ValueError."""
    from .acl import ICMP_NAMES, ICMPV6_NAMES, port_number
    src_ip, dst_ip = str(ipaddress.ip_address(src.strip())), str(ipaddress.ip_address(dst.strip()))
    family = V6 if ":" in src_ip else V4
    if (":" in dst_ip) != (family == V6):
        raise ValueError("The source and destination have to be both IPv4 or both IPv6.")
    number = protocol_number(protocol.strip() or "ip")
    if number is None:
        raise ValueError(f"Unknown protocol {protocol}.")
    if family == V6 and number == 1:
        number = ICMPV6
    packet = Packet(src_ip, dst_ip, number, EPHEMERAL, 0, when=when, fragment=fragment)
    if number in (TCP, UDP):
        word = "udp" if number == UDP else "tcp"
        if src_port.strip():
            value = port_number(src_port.strip(), word)
            if value is None:
                raise ValueError(f"Unknown port {src_port}.")
            packet.src_port = value
        value = port_number(dst_port.strip(), word) if dst_port.strip() else None
        if value is None:
            raise ValueError("Give a destination port (a number or a name such as www).")
        packet.dst_port = value
        packet.flags = {flag for flag in re.split(r"[\s,+]+", flags.lower()) if flag}
        if number == TCP and not packet.flags:
            packet.flags = {"syn"}
    elif number in (1, ICMPV6) and icmp.strip():
        names = ICMPV6_NAMES if family == V6 else ICMP_NAMES
        words = icmp.split()
        if words[0] in names:
            packet.icmp_type, code = names[words[0]]
            packet.icmp_code = code if code is not None else 0
        else:
            packet.icmp_type = int(words[0])
            packet.icmp_code = int(words[1]) if len(words) > 1 else 0
    return packet


def lockout_change(before, after, pc_ip, device_ip, port=22):
    """lockout() of the device as edited, where a refusal the device as read gives too (yet NOMAD logged in to it)
    is only a warning: this PC's packets must come in some other way than the check can see."""
    already = {(item.where, item.acl) for item in lockout(before, pc_ip, device_ip, port) if item.severity == ERROR}         if before is not None else set()
    found = lockout(after, pc_ip, device_ip, port)
    for item in found:
        if item.severity == ERROR and (item.where, item.acl) in already:
            item.severity = WARNING
            item.text += (" The device as it is now gives the same answer, yet NOMAD logs in to it, so this PC's "
                          "packets come some other way than the check sees.")
    return found
