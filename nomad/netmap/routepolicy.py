"""Prefix lists and route maps on Cisco IOS / IOS-XE devices: read, edited, and written back as the fewest safe
changes, the way acl.py does ACLs (and on the same page).

What's read (from the same show running-config): ip / ipv6 prefix-list entries and descriptions, route-map entries
(description, match, continue, set), where they're used (BGP neighbors and peer groups per address family,
redistribution and default-information originate, policy routing on interfaces and ip local policy, distribute lists
and OSPF area filter lists, and any other line naming one), the BGP neighbors and routing processes (to apply them
to), and AS-path and community lists (for the route tester only). show ip prefix-list detail gives the hit counts,
show route-map the policy routing counts.

How edits go back (each found on IOS 15.7 IOL):
- A prefix list entry can't be changed at its number ("seq # exists with different policy"), the same entry can't be
  in twice ("prefix-list entry exists"), and `no` needs the whole entry. So a changed entry goes in at a new number
  before the old one is taken out; a moved one is taken out just before its new place goes in. There's no
  resequence: with no number free, the entries are renumbered one by one.
- A route-map entry is changed where it is, by its number: an entry's match lines with the same keyword are one
  list (match ip address prefix-list A, then B, gives A B; no ... A takes just A), so values are added before the old
  ones are taken out (it never matches more than before or after); set lines are taken out before the new ones go in
  (set community adds to what's there). Permit / deny changes in place. A moved entry is made at its new number
  before the old one goes. `no route-map NAME` alone deletes the whole map, so an entry is always named with its
  number.
- Applying: a line in the place it goes (neighbor ... route-map NAME in, ip policy route-map NAME, distribute-list
  prefix NAME in, ...) takes the place of what was there. A route map comes off a redistribution with `no
  redistribute PROTOCOL route-map NAME`, which leaves the redistribution as it was.

Qt-free, so it can be tested without a network.
"""
import ipaddress
import re
from dataclasses import dataclass, field, replace

from .acl import ACLS, APPLY, DELETE_ACL, DELETE_MAPS, DENY, MAPS, PERMIT, UNAPPLY, V4, V6, Change, assign, \
    blocks, fill_gap
from .vlans import ERROR, INFO, WARNING

PREFIX_LIST, ROUTE_MAP = "prefix-list", "route-map"
BGP, REDIST, PBR, DISTRIBUTE, OTHER = "bgp", "redistribution", "pbr", "distribute", "other"
WHERE_NAMES = {BGP: "BGP", REDIST: "Redistribution", PBR: "Policy routing", DISTRIBUTE: "Distribute list",
               OTHER: "Other"}
MAX_PREFIX_SEQ = 4294967294
MAX_MAP_SEQ = 65535
IN, OUT = "in", "out"
ROUTING = ("bgp", "ospf", "ospfv3", "eigrp", "rip", "isis", "odr")
WITH_ID = ("bgp", "ospf", "ospfv3", "eigrp", "isis")  # Redistributed protocols named with a process number / tag

# Match keywords whose values add up to one list (match tag 5, then match tag 7, gives match tag 5 7). Longest first.
MULTI_MATCH = ("ip address prefix-list", "ipv6 address prefix-list", "ip next-hop prefix-list",
               "ipv6 next-hop prefix-list", "ip route-source prefix-list", "ipv6 route-source prefix-list",
               "ip address", "ipv6 address", "ip next-hop", "ipv6 next-hop", "ip route-source", "ipv6 route-source",
               "tag", "as-path", "community", "extcommunity", "large-community", "interface", "local-preference",
               "policy-list")
CLASHING = {"ip address": "ip address prefix-list", "ip address prefix-list": "ip address",
            "ipv6 address": "ipv6 address prefix-list", "ipv6 address prefix-list": "ipv6 address",
            "ip next-hop": "ip next-hop prefix-list", "ip next-hop prefix-list": "ip next-hop",
            "ip route-source": "ip route-source prefix-list", "ip route-source prefix-list": "ip route-source"}
MATCH_CHOICES = ["ip address prefix-list", "ip address", "ipv6 address prefix-list", "ipv6 address",
                 "ip next-hop prefix-list", "ip next-hop", "ip route-source prefix-list", "as-path", "community",
                 "tag", "metric", "local-preference", "interface", "route-type", "source-protocol", "length"]
SET_CHOICES = ["local-preference", "weight", "metric", "metric-type", "as-path prepend", "community",
               "comm-list", "origin", "tag", "ip next-hop", "ipv6 next-hop", "ip default next-hop", "interface",
               "default interface", "ip precedence", "ip dscp", "vrf"]
WELL_KNOWN = {"internet": "internet", "no-export": "no-export", "no-advertise": "no-advertise",
              "local-as": "local-AS", "local-AS": "local-AS", "gshut": "gshut"}


# ----------------------------------------------------------------- What they're made of

@dataclass
class PrefixEntry:
    seq: int = 0
    action: str = PERMIT
    prefix: str = ""  # "10.0.0.0/8", as IOS keeps it (host bits cleared)
    ge: int = 0
    le: int = 0
    hits: object = None  # From show ip prefix-list detail (None: not read)
    want_seq: int = 0  # A number typed in
    origin: int = field(default=-1, compare=False)

    @property
    def network(self):
        return ipaddress.ip_network(self.prefix, strict=False)

    def key(self, *_):
        return self.action, str(self.network), self.ge, self.le

    def body(self):
        text = f"{self.action} {self.network}"
        if self.ge:
            text += f" ge {self.ge}"
        if self.le:
            text += f" le {self.le}"
        return text

    def lengths(self):
        """(shortest, longest) prefix length it matches."""
        network = self.network
        top = network.max_prefixlen
        if self.ge and self.le:
            return self.ge, self.le
        if self.ge:
            return self.ge, top
        if self.le:
            return network.prefixlen, self.le
        return network.prefixlen, network.prefixlen

    def explain(self):
        """In words: which prefixes it matches."""
        network = self.network
        low, high = self.lengths()
        if low == high == network.prefixlen:
            return f"just {network}"
        within = f" within {network}" if network.prefixlen else ""
        if not network.prefixlen and low == 0 and high == network.max_prefixlen:
            return "every prefix"
        if low == high:
            return f"/{low} prefixes{within}"
        return f"/{low} to /{high} prefixes{within}"

    def copy(self, **changes):
        entry = replace(self)
        for name, value in changes.items():
            setattr(entry, name, value)
        return entry


@dataclass
class PrefixList:
    name: str
    family: str = V4
    entries: list = field(default_factory=list)
    description: str = ""

    @property
    def key(self):
        return self.family, self.name

    @property
    def keyword(self):
        return "ipv6 prefix-list" if self.family == V6 else "ip prefix-list"

    @property
    def title(self):
        return f"{'IPv6 ' if self.family == V6 else ''}prefix list {self.name}"

    def entry_line(self, entry, seq=None):
        seq = entry.seq if seq is None else seq
        return f"{self.keyword} {self.name} seq {seq} {entry.body()}" if seq else \
            f"{self.keyword} {self.name} {entry.body()}"

    def config(self):
        lines = [f"{self.keyword} {self.name} description {self.description}"] if self.description else []
        return lines + [self.entry_line(entry) for entry in self.entries]

    def copy(self, **changes):
        item = replace(self, entries=[entry.copy() for entry in self.entries])
        for name, value in changes.items():
            setattr(item, name, value)
        return item


@dataclass
class MapEntry:
    seq: int = 0
    action: str = PERMIT
    matches: list = field(default_factory=list)  # "ip address prefix-list A B" (without "match")
    sets: list = field(default_factory=list)  # "local-preference 200" (without "set")
    cont: str = ""  # continue: "" none, "next" (to the next entry), or the entry's number
    description: str = ""  # Its description lines (IOS keeps every one typed), joined with newlines
    hits: object = None  # Policy routing matches (packets), from show route-map
    want_seq: int = 0
    origin: int = field(default=-1, compare=False)

    def key(self, *_):
        return self.action, tuple(sorted(self.matches)), tuple(sorted(self.sets)), self.cont, self.description

    def clauses(self):
        """Its lines (without the route-map line), in the order IOS shows them."""
        lines = [f"description {text}" for text in self.description.splitlines() if text.strip()]
        lines += [f"match {text}" for text in self.matches]
        if self.cont:
            lines.append("continue" if self.cont == "next" else f"continue {self.cont}")
        return lines + [f"set {text}" for text in self.sets]

    def copy(self, **changes):
        entry = replace(self, matches=list(self.matches), sets=list(self.sets))
        for name, value in changes.items():
            setattr(entry, name, value)
        return entry


@dataclass
class RouteMap:
    name: str
    entries: list = field(default_factory=list)

    @property
    def key(self):
        return self.name

    @property
    def title(self):
        return f"route map {self.name}"

    def head(self, entry, seq=None):
        return f"route-map {self.name} {entry.action} {entry.seq if seq is None else seq}"

    def entry_config(self, entry, seq=None):
        return [self.head(entry, seq)] + [f" {line}" for line in entry.clauses()] + [" exit"]

    def config(self):
        lines = []
        for entry in self.entries:
            lines += self.entry_config(entry)
        return lines

    def copy(self, **changes):
        item = replace(self, entries=[entry.copy() for entry in self.entries])
        for name, value in changes.items():
            setattr(item, name, value)
        return item


@dataclass
class PolicyUse:
    """Where a prefix list or route map is used (or, kind "", a redistribution with no route map on it yet)."""
    kind: str  # PREFIX_LIST, ROUTE_MAP or ""
    name: str
    where: str  # BGP, REDIST, PBR, DISTRIBUTE or OTHER
    path: tuple = ()  # The mode lines it's in: ("router bgp 65000", "address-family ipv4"); () at the top
    slot: str = ""  # What it is, one per place: "neighbor 10.1.1.1 route-map in", "redistribute static"
    line: str = ""  # The line itself
    direction: str = ""
    family: str = V4

    @property
    def spot(self):
        return self.path, self.slot

    def label(self):
        process = self.path[0] if self.path else ""
        family = af_label(self.path[1]) if len(self.path) > 1 and self.path[1].startswith("address-family") else ""
        family = f", {family}" if family and family != "IPv4" else ""
        if self.where == BGP:
            neighbor = self.slot.split()[1]
            return f"BGP {neighbor} {self.direction}{family}"
        if self.where == REDIST:
            return f"{self.slot} into {process}{family}"
        if self.where == PBR:
            return f"policy routing on {process[len('interface '):]}" if process.startswith("interface ") else \
                "this router's own traffic (local policy)"
        if self.where == DISTRIBUTE:
            return f"{self.slot} ({process})"
        return f"{process}: {self.line}" if process else self.line

    def copy(self, **changes):
        use = replace(self)
        for name, value in changes.items():
            setattr(use, name, value)
        return use


@dataclass
class Neighbor:
    name: str  # The address, or a peer group's name
    remote_as: str = ""
    group: bool = False  # A peer group
    member_of: str = ""
    description: str = ""
    afs: list = field(default_factory=list)  # The address-family lines it's activated in


@dataclass
class RoutingProcess:
    line: str  # "router bgp 65000"
    protocol: str = ""
    afs: list = field(default_factory=list)  # Its address-family lines
    neighbors: dict = field(default_factory=dict)  # BGP: name -> Neighbor

    def bgp_paths(self):
        """[(path, label)] a BGP neighbor's policy can go in."""
        paths = [((self.line, af), af_label(af)) for af in self.afs]
        if not any(af_label(af) == "IPv4" for af in self.afs):
            paths.insert(0, ((self.line,), "IPv4"))
        return paths


def af_label(line):
    """"address-family ipv4 vrf RED" -> "IPv4 VRF RED"."""
    words = line.split()[1:]
    if not words:
        return ""
    text = {"ipv4": "IPv4", "ipv6": "IPv6", "vpnv4": "VPNv4", "vpnv6": "VPNv6", "l2vpn": "L2VPN"}.get(words[0],
                                                                                                  words[0])
    rest = [word for word in words[1:] if word != "unicast"]
    if "vrf" in rest:
        at = rest.index("vrf")
        text += f" VRF {rest[at + 1]}" if at + 1 < len(rest) else ""
        rest = rest[:at] + rest[at + 2:]
    return " ".join([text] + [word for word in rest if not word.isdigit() and word != "autonomous-system"])


# ----------------------------------------------------------------- Reading running-config

PREFIX_LINE = re.compile(r"^(ip|ipv6) prefix-list (\S+) (?:seq (\d+) )?(permit|deny) (\S+)(.*)$")
DESCRIPTION_LINE = re.compile(r"^(ip|ipv6) prefix-list (\S+) description (.*)$")
MAP_HEAD = re.compile(r"^route-map (\S+)(?: (permit|deny))?(?: (\d+))?$")


def parse_prefix_entry(action, prefix, rest, seq=0):
    entry = PrefixEntry(seq, action, str(ipaddress.ip_network(prefix, strict=False)))
    words = rest.split()
    for index in range(0, len(words) - 1):
        if words[index] in ("ge", "le") and words[index + 1].isdigit():
            setattr(entry, words[index], int(words[index + 1]))
    return entry


def normal_clause(word, text):
    """A match / set line's text as kept: communities as AA:NN (IOS shows them as one number without
    ip bgp-community new-format)."""
    text = " ".join(text.split())
    if word == "set" and text.startswith("community "):
        words = text.split()
        text = " ".join(words[:1] + [community_text(item) for item in words[1:]])
    return text


def community_text(token):
    if token.isdigit() and int(token) > 65535:
        number = int(token)
        return f"{number >> 16}:{number & 0xFFFF}"
    return WELL_KNOWN.get(token, token)


def read_policies(device, text):
    """Fill device (an acl.DeviceAcls) with the prefix lists, route maps, where they're used, BGP neighbors and
    routing processes in a running-config."""
    found = blocks(text)
    for top, inner in found:
        described = DESCRIPTION_LINE.match(top)
        if described:
            family = V6 if described.group(1) == "ipv6" else V4
            item = device.prefix_lists.setdefault((family, described.group(2)),
                                                  PrefixList(described.group(2), family))
            item.description = described.group(3).strip()
            continue
        entry = PREFIX_LINE.match(top)
        if entry:
            family = V6 if entry.group(1) == "ipv6" else V4
            try:
                parsed = parse_prefix_entry(entry.group(4), entry.group(5), entry.group(6),
                                            int(entry.group(3) or 0))
            except ValueError:
                continue
            item = device.prefix_lists.setdefault((family, entry.group(2)), PrefixList(entry.group(2), family))
            item.entries.append(parsed)
            continue
        head = MAP_HEAD.match(top)
        if head and head.group(3):
            item = device.route_maps.setdefault(head.group(1), RouteMap(head.group(1)))
            map_entry = MapEntry(int(head.group(3)), head.group(2) or PERMIT)
            for line in inner:
                words = line.split()
                if words[0] == "description":
                    text = line[len("description "):].strip()
                    map_entry.description = f"{map_entry.description}\n{text}" if map_entry.description else text
                elif words[0] == "match" and len(words) > 1:
                    map_entry.matches.append(normal_clause("match", line[6:]))
                elif words[0] == "set" and len(words) > 1:
                    map_entry.sets.append(normal_clause("set", line[4:]))
                elif words[0] == "continue":
                    map_entry.cont = words[1] if len(words) > 1 else "next"
            item.entries.append(map_entry)
            continue
        words = top.split()
        if words[:3] == ["ip", "as-path", "access-list"] and len(words) >= 6:
            device.as_paths.setdefault(words[3], []).append((words[4], " ".join(words[5:])))
        elif words[:2] == ["ip", "community-list"] and len(words) >= 4:
            read_community_list(device, words[2:])
    for item in device.route_maps.values():
        item.entries.sort(key=lambda value: value.seq)
    for item in device.prefix_lists.values():
        if all(entry.seq for entry in item.entries):
            item.entries.sort(key=lambda value: value.seq)
    read_uses(device, found)
    return device


def read_community_list(device, words):
    """ip community-list [standard|expanded] NAME permit|deny ...; numbered 1-99 standard, 100-500 expanded."""
    if words[0] in ("standard", "expanded") and len(words) >= 4:
        kind, name, rest = words[0], words[1], words[2:]
    elif words[0].isdigit():
        kind = "standard" if int(words[0]) < 100 else "expanded"
        name, rest = words[0], words[1:]
    else:
        return
    if not rest or rest[0] not in (PERMIT, DENY):
        return
    kind_now, entries = device.communities.get(name, (kind, []))
    entries.append((rest[0], " ".join(rest[1:])))
    device.communities[name] = (kind_now, entries)


def read_uses(device, found):
    for top, inner in found:
        words = top.split()
        if words[0] == "router" and len(words) >= 2:
            read_router(device, top, inner)
        elif words[0] == "interface" and len(words) >= 2:
            for line in inner:
                parts = line.split()
                if parts[1:3] == ["policy", "route-map"] and parts[0] in ("ip", "ipv6") and len(parts) >= 4:
                    device.policy_uses.append(PolicyUse(ROUTE_MAP, parts[3], PBR, (top,), f"{parts[0]} policy",
                                                        line, "", V6 if parts[0] == "ipv6" else V4))
                else:
                    other_use(device, line, (top,))
        elif words[1:4] == ["local", "policy", "route-map"] and words[0] in ("ip", "ipv6") and len(words) >= 5:
            device.policy_uses.append(PolicyUse(ROUTE_MAP, words[4], PBR, (), f"{words[0]} local policy", top, "",
                                                V6 if words[0] == "ipv6" else V4))
        elif words[0] in ("route-map", "ip", "ipv6") and (MAP_HEAD.match(top) or "prefix-list" in words[:2]):
            continue  # Their own definitions
        else:
            other_use(device, top, ())
            for line in inner:
                other_use(device, line, (top,))


def other_use(device, line, path):
    """A line naming a known route map or prefix list somewhere NOMAD doesn't edit."""
    words = line.split()
    for index in range(1, len(words)):
        word = words[index - 1]
        if word == "route-map" and words[index] in device.route_maps:
            device.policy_uses.append(PolicyUse(ROUTE_MAP, words[index], OTHER, path, line, line))
            return
        if word == "prefix-list" and any(key[1] == words[index] for key in device.prefix_lists):
            family = V6 if "ipv6" in words[:index] else V4
            device.policy_uses.append(PolicyUse(PREFIX_LIST, words[index], OTHER, path, line, line, "", family))
            return


def read_router(device, top, inner):
    words = top.split()
    process = RoutingProcess(top, words[1])
    device.processes[top] = process
    af, sub = "", ""
    for line in inner:
        parts = line.split()
        if parts[0] == "address-family":
            af, sub = line, ""
            if af not in process.afs:
                process.afs.append(af)
            continue
        if parts[0] == "exit-address-family":
            af, sub = "", ""
            continue
        if parts[0] == "topology":
            sub = line
            continue
        if parts[0] == "exit-af-topology":
            sub = ""
            continue
        path = tuple(item for item in (top, af, sub) if item)
        family = V6 if af.split()[1:2] == ["ipv6"] or process.protocol == "ospfv3" and "ipv6" in af else V4
        if parts[0] == "neighbor" and len(parts) >= 3 and process.protocol == "bgp":
            read_neighbor(device, process, path, af, line, parts, family)
        elif parts[0] == "redistribute" and len(parts) >= 2:
            proto = parts[:3] if parts[1] in WITH_ID and len(parts) >= 3 else parts[:2]
            slot = " ".join(proto)
            name = word_after(parts, "route-map")
            device.policy_uses.append(PolicyUse(ROUTE_MAP if name else "", name, REDIST, path, slot, line, "",
                                                family))
        elif parts[:2] == ["default-information", "originate"]:
            name = word_after(parts, "route-map")
            device.policy_uses.append(PolicyUse(ROUTE_MAP if name else "", name, REDIST, path,
                                                "default-information originate", line, "", family))
        elif parts[0] == "distribute-list" and len(parts) >= 4 and parts[1] in ("prefix", ROUTE_MAP) and \
                parts[3] in (IN, OUT):
            slot = " ".join(["distribute-list", parts[1], parts[3]] + parts[4:])
            kind = PREFIX_LIST if parts[1] == "prefix" else ROUTE_MAP
            device.policy_uses.append(PolicyUse(kind, parts[2], DISTRIBUTE, path, slot, line, parts[3], family))
        elif parts[0] == "area" and parts[2:4] == ["filter-list", "prefix"] and len(parts) >= 6:
            device.policy_uses.append(PolicyUse(PREFIX_LIST, parts[4], DISTRIBUTE, path,
                                                f"area {parts[1]} filter-list {parts[5]}", line, parts[5], family))
        else:
            other_use(device, line, path)


def read_neighbor(device, process, path, af, line, parts, family):
    name = parts[1]
    neighbor = process.neighbors.get(name)
    if neighbor is None:
        neighbor = process.neighbors[name] = Neighbor(name)
    what = parts[2]
    if what == "remote-as" and len(parts) >= 4:
        neighbor.remote_as = parts[3]
    elif what == "peer-group":
        if len(parts) == 3:
            neighbor.group = True
        else:
            neighbor.member_of = parts[3]
    elif what == "description":
        neighbor.description = " ".join(parts[3:])
    elif what == "activate" and af and af not in neighbor.afs:
        neighbor.afs.append(af)
    elif what in (ROUTE_MAP, PREFIX_LIST) and len(parts) >= 5 and parts[4] in (IN, OUT):
        device.policy_uses.append(PolicyUse(what, parts[3], BGP, path, f"neighbor {name} {what} {parts[4]}", line,
                                            parts[4], family))
    else:
        other_use(device, line, path)


def word_after(words, word):
    if word in words:
        at = words.index(word)
        if at + 1 < len(words):
            return words[at + 1]
    return ""


SHOW_PREFIX_HEAD = re.compile(r"^(ip|ipv6) prefix-list (\S+):")
SHOW_PREFIX_ENTRY = re.compile(r"^\s+seq (\d+) (permit|deny) (\S+)(.*?)(?:\(hit count: (\d+)|$)")
SHOW_MAP_HEAD = re.compile(r"^route-map (\S+), (permit|deny), sequence (\d+)")
SHOW_MAP_HITS = re.compile(r"Policy routing matches: (\d+) packets")


def merge_show_prefix(device, text):
    """Numbers (where running-config leaves them out: no ip prefix-list sequence-number) and hit counts from
    show ip prefix-list detail / show ipv6 prefix-list detail."""
    current, shown = None, {}
    for line in (text or "").splitlines():
        head = SHOW_PREFIX_HEAD.match(line.strip())
        if head:
            current = (V6 if head.group(1) == "ipv6" else V4, head.group(2))
            shown.setdefault(current, [])
            continue
        entry = SHOW_PREFIX_ENTRY.match(line)
        if entry and current is not None:
            try:
                parsed = parse_prefix_entry(entry.group(2), entry.group(3), entry.group(4), int(entry.group(1)))
            except ValueError:
                continue
            parsed.hits = int(entry.group(5)) if entry.group(5) else None
            shown[current].append(parsed)
    for key, item in device.prefix_lists.items():
        entries = shown.get(key)
        if not entries:
            continue
        by_key = {entry.key(): entry for entry in entries}
        for index, entry in enumerate(item.entries):
            match = by_key.get(entry.key())
            if match is None and index < len(entries):
                match = entries[index]
            if match is None:
                continue
            entry.seq = entry.seq or match.seq
            entry.hits = match.hits
        item.entries.sort(key=lambda value: value.seq)
    return device


def merge_show_maps(device, text):
    """Policy routing counts from show route-map."""
    current = None
    for line in (text or "").splitlines():
        head = SHOW_MAP_HEAD.match(line.strip())
        if head:
            item = device.route_maps.get(head.group(1))
            current = next((entry for entry in item.entries if entry.seq == int(head.group(3))), None) \
                if item is not None else None
            continue
        hits = SHOW_MAP_HITS.search(line)
        if hits and current is not None:
            current.hits = int(hits.group(1))
    return device


# ----------------------------------------------------------------- Changes to prefix lists

def same_entry(a, b):
    return a.key() == b.key()


def prefix_blockers(entry, present):
    """Entries on the device that keep IOS from taking entry: the same entry at another number, or another at its
    number."""
    return [other for other in present if other.key() == entry.key() or other.seq == entry.seq]


def prefix_change(before, after, with_undo=True):
    """The Change taking a prefix list from before to after (either None: create or delete)."""
    if before is None and after is None:
        return Change("Nothing")
    if after is not None:
        after = after.copy(entries=[entry.copy(origin=index) for index, entry in enumerate(after.entries)])
    if before is None:
        numbers = fill_gap(0, MAX_PREFIX_SEQ + 1, [entry.want_seq for entry in after.entries], set())
        final = after.copy(entries=[entry.copy(seq=number, want_seq=0)
                                    for entry, number in zip(after.entries, numbers or [])])
        lines = final.config()
        undo = [f"no {final.keyword} {final.name}"] + ([f"no {final.keyword} {final.name} description"]
                                                         if final.description else [])
        return Change(f"Create {after.title}", lines, undo, [], ACLS, final)
    if after is None:
        lines = [f"no {before.keyword} {before.name}"]
        if before.description:
            lines.append(f"no {before.keyword} {before.name} description")
        return Change(f"Delete {before.title}", lines, before.config(), [], DELETE_ACL, None)
    old = sorted(before.entries, key=lambda entry: entry.seq)
    notes = []
    planned = assign(old, after.entries, None, None, same=same_entry, top=MAX_PREFIX_SEQ + 1)
    if planned is None:  # No room, and no resequence for prefix lists: number them all again
        numbers = fill_gap(0, MAX_PREFIX_SEQ + 1, [entry.want_seq for entry in after.entries], set())
        if numbers is None:
            return Change(f"Change {before.title}", notes=["There aren't enough sequence numbers free."])
        by_seq = {entry.seq: entry for entry in old}
        fixed = {index for index, entry in enumerate(after.entries)
                 if numbers[index] == entry.seq and entry.seq in by_seq and same_entry(entry, by_seq[entry.seq])}
        notes.append("There's no number free where an entry goes (and prefix lists can't be renumbered at once), "
                     "so entries are renumbered one by one.")
        planned = numbers, fixed
    numbers, fixed = planned
    for index, entry in enumerate(after.entries):
        if entry.want_seq and numbers[index] != entry.want_seq and with_undo:
            notes.append(f"Line {entry.origin + 1} can't have number {entry.want_seq} (another entry has it, or "
                         f"it's out of order with the entries around it): it gets {numbers[index]}.")
    final = after.copy(entries=[entry.copy(seq=numbers[index], want_seq=0)
                                for index, entry in enumerate(after.entries)])
    for index, entry in enumerate(final.entries):
        entry.hits = after.entries[index].hits if index in fixed else None
    kept = {after.entries[index].seq for index in fixed}
    added = [entry for index, entry in enumerate(final.entries) if index not in fixed]
    removed = [entry for entry in old if entry.seq not in kept]
    lines, early = [], []
    present = {entry.seq: entry for entry in old}
    going = {entry.seq for entry in removed}
    for entry in added:  # In before the old one comes out, unless IOS won't take it then
        for blocker in prefix_blockers(entry, list(present.values())):
            if blocker.seq in going:
                lines.append(f"no {before.entry_line(blocker)}")
                going.discard(blocker.seq)
                del present[blocker.seq]
                early.append(blocker.seq)
        lines.append(final.entry_line(entry))
        present[entry.seq] = entry
    for entry in removed:
        if entry.seq in going:
            lines.append(f"no {before.entry_line(entry)}")
    if early:
        numbers_text = ", ".join(str(seq) for seq in early[:6]) + ("..." if len(early) > 6 else "")
        notes.append(f"Entry {numbers_text} come(s) out just before the new one goes in (IOS won't hold the same "
                     "entry twice, or two at one number), so for that moment it isn't there.")
    if before.description != after.description:
        lines.append(f"{before.keyword} {before.name} description {after.description}" if after.description
                     else f"no {before.keyword} {before.name} description")
    if not lines:
        return Change(f"No changes to {before.title}", after=final)
    back = []
    to_final = {after.entries[index].seq: numbers[index] for index in range(len(after.entries))
                if after.entries[index].seq}
    for entry in old:
        if entry.seq in kept:
            back.append(entry.copy())
        elif entry.seq in to_final:
            back.append(entry.copy(seq=to_final[entry.seq], want_seq=entry.seq))
        else:
            back.append(entry.copy(seq=0, want_seq=entry.seq))
    undo = prefix_change(final, before.copy(entries=back), with_undo=False).lines if with_undo else []
    change = Change(f"Change {before.title}", lines, undo, notes, ACLS, final)
    summary = counts(len(added), len(removed), sum(1 for index, entry in enumerate(after.entries)
                                                   if index not in fixed and entry.seq in present_seqs(old)))
    if summary:
        change.title += ": " + summary
    return change


def present_seqs(entries):
    return {entry.seq for entry in entries}


def counts(added, removed, changed):
    parts = []
    if added - changed:
        parts.append(f"{added - changed} added")
    if changed:
        parts.append(f"{changed} changed or moved")
    if removed - changed:
        parts.append(f"{removed - changed} removed")
    return ", ".join(parts)


# ----------------------------------------------------------------- Changes to route maps

def split_clause(text):
    """(keyword, values) of a match line's text, values None when it's one whole (not a list to add to)."""
    if "exact-match" in text.split():
        return text, None
    for head in MULTI_MATCH:
        if text == head or text.startswith(head + " "):
            values = text[len(head):].split()
            return head, values
    return text, None


def match_lines(old, new):
    """Lines changing an entry's match clauses from old to new: values added before the old ones come out, so it
    never matches more than it did or will (except where IOS won't hold both: an ACL and a prefix list)."""
    def grouped(lines):
        lists, whole = {}, []
        for text in lines:
            head, values = split_clause(text)
            if values is None:
                whole.append(text)
            else:
                lists.setdefault(head, [])
                lists[head] += [value for value in values if value not in lists[head]]
        return lists, whole
    old_lists, old_whole = grouped(old)
    new_lists, new_whole = grouped(new)
    first, adds, takes = [], [], []
    for head, values in old_lists.items():
        gone = [value for value in values if value not in new_lists.get(head, [])]
        if not gone:
            continue
        line = f" no match {head} {' '.join(gone)}"
        if CLASHING.get(head) in new_lists and CLASHING.get(head) not in old_lists:
            first.append(line)  # IOS won't hold an ACL and a prefix list in one entry
        else:
            takes.append(line)
    for head, values in new_lists.items():
        added = [value for value in values if value not in old_lists.get(head, [])]
        if added:
            adds.append(f" match {head} {' '.join(added)}")
    first += [f" no match {text}" for text in old_whole if text not in new_whole]
    adds += [f" match {text}" for text in new_whole if text not in old_whole]
    return first + adds + takes


def set_lines(old, new):
    """Lines changing an entry's set clauses: the old ones out first (set community adds to what's there)."""
    takes = [f" no set {text}" for text in old if text not in new]
    return takes + [f" set {text}" for text in new if text not in old]


def entry_edit(rmap, old, new, seq):
    """Lines changing route-map entry seq from old to new where it is (permit / deny changes in place)."""
    body = []
    if old.description != new.description:  # Each description line adds one; no description takes them all
        body += [" no description"] if old.description else []
        body += [f" description {text}" for text in new.description.splitlines() if text.strip()]
    body += match_lines(old.matches, new.matches)
    if old.cont != new.cont:
        if new.cont:
            body.append(" continue" if new.cont == "next" else f" continue {new.cont}")
        else:
            body.append(" no continue" if old.cont == "next" else f" no continue {old.cont}")
    body += set_lines(old.sets, new.sets)
    if not body and old.action == new.action:
        return []
    return [f"route-map {rmap.name} {new.action} {seq}"] + body + [" exit"]


def map_change(before, after, with_undo=True):
    """The Change taking a route map from before to after (either None: create or delete). after's entries say
    which of before's they are by seq (0 for a new one)."""
    if before is None and after is None:
        return Change("Nothing")
    if after is not None:
        after = after.copy(entries=[entry.copy(origin=index) for index, entry in enumerate(after.entries)])
    if before is None:
        numbers = fill_gap(0, MAX_MAP_SEQ + 1, [entry.want_seq for entry in after.entries], set())
        final = after.copy(entries=[entry.copy(seq=number, want_seq=0)
                                    for entry, number in zip(after.entries, numbers or [])])
        if numbers is None:
            return Change(f"Create {after.title}", notes=["There aren't enough sequence numbers free."])
        return Change(f"Create {after.title}", final.config(), [f"no route-map {after.name}"], [], MAPS, final)
    if after is None:
        return Change(f"Delete {before.title}", [f"no route-map {before.name}"], before.config(), [], DELETE_MAPS,
                      None)
    old = sorted(before.entries, key=lambda entry: entry.seq)
    notes = []
    planned = assign(old, after.entries, None, None, same=lambda a, b: True, top=MAX_MAP_SEQ + 1)
    if planned is None:
        numbers = fill_gap(old[-1].seq if old else 0, MAX_MAP_SEQ + 1,
                           [0] * len(after.entries), set())  # All made again above the old ones, then those go
        if numbers is None:
            return Change(f"Change {before.title}", notes=["There aren't enough sequence numbers free."])
        planned = numbers, set()
        notes.append("There's no number free where an entry goes, so the whole route map is made again at new "
                     "numbers, then the old entries are taken out.")
    numbers, fixed = planned
    for index, entry in enumerate(after.entries):
        if entry.want_seq and numbers[index] != entry.want_seq and with_undo:
            notes.append(f"Line {entry.origin + 1} can't have number {entry.want_seq} (another entry has it, or "
                         f"it's out of order with the entries around it): it gets {numbers[index]}.")
    moved = {after.entries[index].seq: numbers[index] for index in range(len(after.entries))
             if after.entries[index].seq and index not in fixed}
    final_entries = []
    for index, entry in enumerate(after.entries):
        cont = entry.cont
        if cont.isdigit() and int(cont) in moved:  # continue to an entry that moves: to its new number
            cont = str(moved[int(cont)])
        final_entries.append(entry.copy(seq=numbers[index], want_seq=0, cont=cont,
                                        hits=entry.hits if index in fixed else None))
    final = after.copy(entries=final_entries)
    old_by_seq = {entry.seq: entry for entry in old}
    kept = {after.entries[index].seq for index in fixed}
    lines = []
    for index, entry in enumerate(final.entries):  # New and moved entries in first
        if index not in fixed:
            lines += final.entry_config(entry)
    edited = 0
    for index, entry in enumerate(final.entries):  # Then the ones changed where they are
        if index in fixed:
            edit = entry_edit(final, old_by_seq[entry.seq], entry, entry.seq)
            if edit:
                edited += 1
                lines += edit
    removed = [entry for entry in old if entry.seq not in kept]
    for entry in removed:
        lines.append(f"no {before.head(entry)}")
    if not lines:
        return Change(f"No changes to {before.title}", after=final)
    if not final.entries:
        notes.append("Taking out its last entry deletes the route map.")
    undo = []
    if with_undo:
        back = []
        for entry in old:
            if entry.seq in kept:
                back.append(entry.copy())
            elif entry.seq in moved:
                back.append(entry.copy(seq=moved[entry.seq], want_seq=entry.seq))
            else:
                back.append(entry.copy(seq=0, want_seq=entry.seq))
        undo = map_change(final, before.copy(entries=back), with_undo=False).lines if final.entries else \
            before.config()
    change = Change(f"Change {before.title}", lines, undo, notes, MAPS, final)
    moved_count = sum(1 for index, entry in enumerate(after.entries) if index not in fixed and entry.seq)
    added = sum(1 for index in range(len(after.entries)) if index not in fixed)
    parts = []
    if added - moved_count:
        parts.append(f"{added - moved_count} added")
    if edited:
        parts.append(f"{edited} changed")
    if moved_count:
        parts.append(f"{moved_count} moved")
    if len(removed) - moved_count:
        parts.append(f"{len(removed) - moved_count} removed")
    if parts:
        change.title += ": " + ", ".join(parts)
    return change


def map_differs(a, b):
    def shape(item):
        return [(entry.seq, entry.want_seq or entry.seq, entry.key()) for entry in item.entries]
    return shape(a) != shape(b)


def prefix_differs(a, b):
    def shape(item):
        return [(entry.seq, entry.want_seq or entry.seq, entry.key()) for entry in item.entries], item.description
    return shape(a) != shape(b)


# ----------------------------------------------------------------- Where they're used

def enter(path):
    return [(" " * depth) + line for depth, line in enumerate(path)]


def leave(path):
    lines = []
    for depth in range(len(path) - 1, -1, -1):
        word = "exit-address-family" if path[depth].startswith("address-family") else \
            "exit-af-topology" if path[depth].startswith("topology") else "exit"
        lines.append((" " * depth) + word)
    return lines


def slot_lines(old, new):
    """Lines (in the place's mode) taking a place from old to new (either None: nothing there)."""
    if new is None:
        if old.where == REDIST:
            return [f"no {old.slot}"]  # A redistribution NOMAD made (only an undo does this)
        return [f"no {old.line}"]
    if old is not None and new.where == REDIST and not new.name and old.name:
        lines = [f"no {old.slot} route-map {old.name}"]  # Leaves the redistribution as it was
        if old.slot.startswith("default-information") and new.line != old.slot:
            lines.append(new.line)
        return lines
    return [new.line]


def placed_policies(device):
    """{(path, slot): PolicyUse} of the places NOMAD can change."""
    return {use.spot: use for use in device.policy_uses if use.where != OTHER}


def use_changes(before, after):
    changes = []
    old_spots, new_spots = placed_policies(before), placed_policies(after)
    for spot in dict.fromkeys(list(old_spots) + list(new_spots)):
        old, new = old_spots.get(spot), new_spots.get(spot)
        if old is not None and new is not None and old.line == new.line:
            continue
        path = spot[0]
        depth = " " * len(path)
        lines = enter(path) + [depth + line for line in slot_lines(old, new)] + leave(path)
        undo = enter(path) + [depth + line for line in slot_lines(new, old)] + leave(path)
        if new is None or (new.where == REDIST and not new.name):
            title, stage = f"Take {old.name} off {old.label()}", UNAPPLY
        elif old is not None and old.name and old.name != new.name:
            title, stage = f"Put {new.name} on {new.label()} (in place of {old.name})", APPLY
        else:
            title, stage = f"Put {new.name} on {new.label()}", APPLY
        notes = []
        if new is not None and old is None and new.where == REDIST:
            notes.append(f"{new.slot} into {path[0]} is new: routes start being redistributed (through "
                         f"{new.name}) once it's sent.")
        changes.append(Change(title, lines, undo, notes, stage))
    return changes


def policy_changes(before, after):
    """[Change] for a device's prefix lists, route maps and where they're used (before: as read, after: edited)."""
    changes = []
    for key in dict.fromkeys(list(before.prefix_lists) + list(after.prefix_lists)):
        old, new = before.prefix_lists.get(key), after.prefix_lists.get(key)
        if old is None or new is None or prefix_differs(old, new):
            change = prefix_change(old, new)
            if change or change.notes:
                changes.append(change)
    for key in dict.fromkeys(list(before.route_maps) + list(after.route_maps)):
        old, new = before.route_maps.get(key), after.route_maps.get(key)
        if old is None or new is None or map_differs(old, new):
            change = map_change(old, new)
            if change or change.notes:
                changes.append(change)
    return changes + use_changes(before, after)


def set_use(device, use):
    """Put use in device's list, in place of what's in its place."""
    device.policy_uses = [item for item in device.policy_uses if item.where == OTHER or item.spot != use.spot]
    device.policy_uses.append(use)


def take_use_off(device, use):
    """Take a prefix list or route map off its place (a redistribution stays, without it)."""
    if use.where == REDIST:
        words = use.line.split()
        if "route-map" in words:
            at = words.index("route-map")
            words = words[:at] + words[at + 2:]
        set_use(device, use.copy(kind="", name="", line=" ".join(words)))
        return
    device.policy_uses = [item for item in device.policy_uses if item.where == OTHER or item.spot != use.spot]


def uses_of(device, kind, name, family=V4):
    """The places using a prefix list (of family) or route map, and for a prefix list or ACL, the route maps
    matching it."""
    return [use for use in device.policy_uses if use.kind == kind and use.name == name and
            (kind != PREFIX_LIST or use.family == family)]


def maps_naming(device, kind, name, family=V4):
    """[(route map, entry)] whose match lines name a prefix list (kind PREFIX_LIST) or an ACL ("acl")."""
    found = []
    for rmap in device.route_maps.values():
        for entry in rmap.entries:
            for text in entry.matches:
                head, values = split_clause(text)
                values = values if values is not None else text.split()[1:]
                if kind == PREFIX_LIST and head.endswith("prefix-list") and name in values and \
                        (head.startswith("ipv6") == (family == V6)):
                    found.append((rmap, entry))
                elif kind == "acl" and head in ("ip address", "ipv6 address", "ip next-hop", "ip route-source") \
                        and name in values:
                    found.append((rmap, entry))
    return found


def use_line(kind, name, where, slot, extra=""):
    """The line for a place: slot "neighbor X route-map in" -> "neighbor X route-map NAME in"."""
    words = slot.split()
    if where == BGP:
        return f"neighbor {words[1]} {kind} {name} {words[3]}"
    if where == PBR:
        return f"{slot} route-map {name}"
    if where == DISTRIBUTE:
        if words[0] == "area":
            return f"area {words[1]} filter-list prefix {name} {words[3]}"
        return f"distribute-list {'prefix' if kind == PREFIX_LIST else ROUTE_MAP} {name} " + " ".join(words[2:])
    if where == REDIST:
        return f"{extra or slot} route-map {name}"
    return slot


def redistribution_line(old_line, name):
    """old_line (a redistribute / default-information line) with route-map name in place of any it has."""
    words = old_line.split()
    if "route-map" in words:
        at = words.index("route-map")
        words = words[:at] + words[at + 2:]
    return " ".join(words + ["route-map", name])


# ----------------------------------------------------------------- BGP soft clears

@dataclass
class SoftClear:
    neighbor: str
    direction: str
    command: str
    label: str
    group: bool = False


def clear_command(path, neighbor, direction, group=False):
    af = path[1] if len(path) > 1 and path[1].startswith("address-family") else ""
    words = af.split()[1:]
    target = f"peer-group {neighbor}" if group else neighbor
    if not words or words[0] == "ipv4" and (len(words) == 1 or words[1:2] == ["unicast"]) and "vrf" not in words:
        return f"clear ip bgp {target} soft {direction}"
    if words[0] == "ipv4" and "vrf" in words:
        vrf = words[words.index("vrf") + 1]
        return f"clear ip bgp vrf {vrf} {target} soft {direction}"
    safi = next((word for word in words[1:] if word in ("unicast", "multicast")), "unicast")
    return f"clear bgp {words[0]} {safi} {target} soft {direction}"


def bgp_affected(before, after):
    """[SoftClear] for the BGP neighbors (and peer groups) whose in / out policy the changes from before to after
    touch: a prefix list or route map put on, taken off or changed (or an ACL, prefix list a route map there
    matches)."""
    changed_lists = {key for key in set(before.prefix_lists) | set(after.prefix_lists)
                     if key not in before.prefix_lists or key not in after.prefix_lists or
                     prefix_differs(before.prefix_lists[key], after.prefix_lists[key])}
    changed_acls = set()
    if hasattr(before, "acls"):
        from .acl import acl_differs
        changed_acls = {key[1] for key in set(before.acls) | set(after.acls)
                        if key not in before.acls or key not in after.acls or
                        acl_differs(before.acls[key], after.acls[key])}
    changed_maps = {name for name in set(before.route_maps) | set(after.route_maps)
                    if name not in before.route_maps or name not in after.route_maps or
                    map_differs(before.route_maps[name], after.route_maps[name])}
    for name, rmap in after.route_maps.items():
        for entry in rmap.entries:
            for text in entry.matches:
                head, values = split_clause(text)
                values = values or []
                if head.endswith("prefix-list") and any(
                        (V6 if head.startswith("ipv6") else V4, value) in changed_lists for value in values):
                    changed_maps.add(name)
                elif head in ("ip address", "ipv6 address") and any(value in changed_acls for value in values):
                    changed_maps.add(name)
    old_spots, new_spots = placed_policies(before), placed_policies(after)
    found, seen = [], set()
    for spot in dict.fromkeys(list(new_spots) + list(old_spots)):
        old, new = old_spots.get(spot), new_spots.get(spot)
        use = new or old
        if use.where != BGP:
            continue
        touched = (old is None or new is None or old.line != new.line or
                   (use.kind == ROUTE_MAP and use.name in changed_maps) or
                   (use.kind == PREFIX_LIST and (use.family, use.name) in changed_lists))
        if not touched:
            continue
        neighbor = use.slot.split()[1]
        process = after.processes.get(use.path[0]) or before.processes.get(use.path[0])
        group = bool(process and neighbor in process.neighbors and process.neighbors[neighbor].group)
        command = clear_command(use.path, neighbor, use.direction, group)
        if command in seen:
            continue
        seen.add(command)
        found.append(SoftClear(neighbor, use.direction, command, use.label(), group))
    return found


# ----------------------------------------------------------------- What they do: the route tester

@dataclass
class Route:
    network: object  # ipaddress network
    next_hop: str = ""
    as_path: str = ""  # "65001 65002"
    communities: list = field(default_factory=list)  # ["65000:1", "no-export"]
    tag: object = None
    metric: object = None
    local_pref: object = None

    @property
    def family(self):
        return V6 if self.network.version == 6 else V4


def route_from_text(prefix, next_hop="", as_path="", communities="", tag="", metric="", local_pref=""):
    """A Route from what's typed in the tester. Raises ValueError."""
    text = prefix.strip()
    if not text:
        raise ValueError("Type a prefix (10.1.0.0/16).")
    network = ipaddress.ip_network(text, strict=False)
    route = Route(network)
    if next_hop.strip():
        route.next_hop = str(ipaddress.ip_address(next_hop.strip()))
    path = as_path.replace(",", " ").split()
    if any(not word.isdigit() for word in path):
        raise ValueError("An AS path is AS numbers: 65001 65002.")
    route.as_path = " ".join(path)
    route.communities = [community_text(word) for word in communities.replace(",", " ").split()]
    for name, value in (("tag", tag), ("metric", metric), ("local_pref", local_pref)):
        if value.strip():
            if not value.strip().isdigit():
                raise ValueError(f"The {name.replace('_', '-')} is a number.")
            setattr(route, name, int(value.strip()))
    return route


def prefix_matches(entry, network):
    try:
        own = entry.network
    except ValueError:
        return False
    if own.version != network.version or network.prefixlen < own.prefixlen:
        return False
    if network.supernet(new_prefix=own.prefixlen).network_address != own.network_address:
        return False
    low, high = entry.lengths()
    return low <= network.prefixlen <= high


def evaluate_prefix_list(plist, network):
    """(permitted, entry or None, text) for a prefix list and a prefix."""
    if plist is None or not plist.entries:
        return True, None, "The prefix list isn't on the device."
    for index, entry in enumerate(plist.entries):
        if prefix_matches(entry, network):
            label = f"entry {entry.seq}" if entry.seq else f"the new entry on line {index + 1}"
            verb = "Permitted" if entry.action == PERMIT else "Denied"
            return entry.action == PERMIT, entry, f"{verb} by {label}: {entry.body()}"
    return False, None, "Denied by the implicit deny at the end (no entry matched)."


def cisco_regex(text):
    """An AS-path / community regular expression as Python's: _ is any delimiter (or the start, the end)."""
    return text.replace("_", r"(?:^|$|[ ,{}()])")


def as_path_permits(entries, path):
    for action, pattern in entries:
        try:
            if re.search(cisco_regex(pattern), path):
                return action == PERMIT
        except re.error:
            continue
    return False


def community_permits(kind, entries, communities, exact=False):
    have = set(communities)
    for action, text in entries:
        if kind == "standard":
            wanted = {community_text(word) for word in text.split()}
            hit = (wanted == have) if exact else wanted <= have
        else:
            try:
                hit = bool(re.search(cisco_regex(text), " ".join(communities)))
            except re.error:
                hit = False
        if hit:
            return action == PERMIT
    return False


def acl_permits(device, name, address, mask_text):
    """Whether ACL name permits a route (standard: its network; extended: network as the source, mask as the
    destination, the way BGP and redistribution use them), or None when the ACL isn't on the device."""
    from .aclcheck import Packet, evaluate
    family = V6 if ":" in address else V4
    item = device.acls.get((family, name))
    if item is None:
        return None
    packet = Packet(address, mask_text if family == V4 else address, 0)
    return evaluate(item, packet, device.groups, device.ranges).permitted


def clause_matches(text, route, device, notes, label):
    """Whether a match line matches route (None: the tester can't tell)."""
    head, values = split_clause(text)
    words = text.split()
    values = values if values is not None else words[1:]
    network = route.network
    if head in ("ip address prefix-list", "ipv6 address prefix-list"):
        family = V6 if head.startswith("ipv6") else V4
        results = []
        for name in values:
            plist = device.prefix_lists.get((family, name))
            if plist is None:
                notes.append(f"{label}: prefix list {name} isn't on the device (taken as matching).")
                return True
            results.append(evaluate_prefix_list(plist, network)[0])
        return any(results)
    if head in ("ip next-hop prefix-list", "ipv6 next-hop prefix-list"):
        if not route.next_hop:
            notes.append(f"{label} matches the next hop: give one to test it.")
            return None
        hop = ipaddress.ip_network(route.next_hop)
        family = V6 if hop.version == 6 else V4
        return any(evaluate_prefix_list(device.prefix_lists.get((family, name)), hop)[0] for name in values)
    if head in ("ip address", "ipv6 address"):
        mask = str(network.netmask) if network.version == 4 else ""
        results = [acl_permits(device, name, str(network.network_address), mask) for name in values]
        if any(result is None for result in results):
            notes.append(f"{label}: an ACL it names isn't on the device (taken as matching).")
            return True
        return any(results)
    if head == "ip next-hop":
        if not route.next_hop:
            notes.append(f"{label} matches the next hop: give one to test it.")
            return None
        results = [acl_permits(device, name, route.next_hop, "255.255.255.255") for name in values]
        return any(result for result in results if result is not None)
    if head == "tag":
        if route.tag is None:
            notes.append(f"{label} matches a tag: give one to test it.")
            return None
        return str(route.tag) in values
    if head == "local-preference":
        if route.local_pref is None:
            notes.append(f"{label} matches local-preference: give one to test it.")
            return None
        return str(route.local_pref) in values
    if words[0] == "metric" and len(words) >= 2 and words[1].isdigit():
        if route.metric is None:
            notes.append(f"{label} matches a metric: give one to test it.")
            return None
        deviation = int(words[3]) if len(words) >= 4 and words[2] == "+-" and words[3].isdigit() else 0
        return abs(route.metric - int(words[1])) <= deviation
    if head == "as-path":
        results = []
        for name in values:
            entries = device.as_paths.get(name)
            if entries is None:
                notes.append(f"{label}: AS-path list {name} isn't on the device.")
                continue
            results.append(as_path_permits(entries, route.as_path))
        return any(results)
    if words[0] == "community":
        exact = "exact-match" in words
        results = []
        for name in [word for word in words[1:] if word != "exact-match"]:
            if name not in device.communities:
                notes.append(f"{label}: community list {name} isn't on the device.")
                continue
            kind, entries = device.communities[name]
            results.append(community_permits(kind, entries, route.communities, exact))
        return any(results)
    notes.append(f"{label}: the tester can't check match {text} (taken as not matching).")
    return None


@dataclass
class MapVerdict:
    permitted: bool
    entries: list = field(default_factory=list)  # The entries that matched, in order
    sets: list = field(default_factory=list)
    text: str = ""
    notes: list = field(default_factory=list)


def evaluate_map(rmap, route, device):
    """What a route map does with a route: the entries that match (following continue), what they set."""
    if rmap is None or not rmap.entries:
        return MapVerdict(False, text="The route map isn't on the device.")
    notes, matched, sets = [], [], []
    entries = list(rmap.entries)
    index = 0
    while index < len(entries):
        entry = entries[index]
        label = f"Entry {entry.seq}" if entry.seq else f"The new entry on line {index + 1}"
        results = [clause_matches(text, route, device, notes, label) for text in entry.matches]
        if all(result is True for result in results):
            matched.append(entry)
            if entry.action == DENY:
                return MapVerdict(False, matched, sets, f"Denied by {label.lower()}.", notes)
            sets += entry.sets
            if entry.cont:
                target = entry.seq + 1 if entry.cont == "next" else int(entry.cont)
                index = next((place for place, other in enumerate(entries) if other.seq >= target), len(entries))
                continue
            break
        index += 1
    if not matched:
        return MapVerdict(False, [], [], "Denied: no entry matched (the implicit deny at the end).", notes)
    which = ", ".join(str(entry.seq or "new") for entry in matched)
    text = f"Permitted by entr{'ies' if len(matched) > 1 else 'y'} {which}"
    text += (": sets " + "; ".join(sets)) if sets else " (sets nothing)"
    return MapVerdict(True, matched, sets, text + ".", notes)


# ----------------------------------------------------------------- Checks

@dataclass
class Finding:
    severity: str
    text: str
    index: int = -1
    other: int = -1


def prefix_covers(a, b):
    """Every prefix entry b matches, entry a matches too."""
    try:
        net_a, net_b = a.network, b.network
    except ValueError:
        return False
    if net_a.version != net_b.version or net_b.prefixlen < net_a.prefixlen:
        return False
    if net_b.supernet(new_prefix=net_a.prefixlen).network_address != net_a.network_address:
        return False
    low_a, high_a = a.lengths()
    low_b, high_b = b.lengths()
    return low_a <= low_b and high_b <= high_a


def entry_label(entry, index):
    return f"Entry {entry.seq}" if entry.seq else f"The new entry on line {index + 1}"


def prefix_problem(entry, family):
    """Why IOS won't take an entry, or ""."""
    try:
        network = ipaddress.ip_network(entry.prefix, strict=False)
    except ValueError:
        return f"{entry.prefix} isn't a prefix."
    if (network.version == 6) != (family == V6):
        return f"{entry.prefix} isn't an {'IPv6' if family == V6 else 'IPv4'} prefix."
    top = network.max_prefixlen
    length = network.prefixlen
    if entry.ge and not length < entry.ge <= top:
        return f"ge has to be more than /{length} (and at most {top})."
    if entry.le and not length < entry.le <= top:
        return f"le has to be more than /{length} (and at most {top})."
    if entry.ge and entry.le and entry.ge > entry.le:
        return "ge can't be more than le."
    return ""


def prefix_findings(plist):
    found = []
    entries = plist.entries
    for index, entry in enumerate(entries):
        problem = prefix_problem(entry, plist.family)
        if problem:
            found.append(Finding(ERROR, f"{entry_label(entry, index)}: IOS won't take it: {problem}", index))
            continue
        for earlier in range(index):
            other = entries[earlier]
            if other.key() == entry.key():
                found.append(Finding(ERROR, f"{entry_label(entry, index)} is the same as "
                                            f"{entry_label(other, earlier).lower()}: IOS won't take it twice.",
                                     index, earlier))
                break
            if prefix_covers(other, entry):
                if other.action != entry.action:
                    found.append(Finding(WARNING, f"{entry_label(entry, index)} never matches anything: "
                                                  f"{entry_label(other, earlier).lower()} takes every prefix it "
                                                  f"would, and {other.action}s them.", index, earlier))
                else:
                    found.append(Finding(INFO, f"{entry_label(entry, index)} isn't needed: "
                                               f"{entry_label(other, earlier).lower()} {other.action}s every prefix "
                                               f"it would already.", index, earlier))
                break
    if entries and not any(entry.action == PERMIT for entry in entries):
        found.append(Finding(WARNING, "It has no permit: every prefix is denied (the implicit deny at the end)."))
    return found


def map_findings(rmap, device):
    found = []
    entries = rmap.entries
    numbers = [entry.seq for entry in entries]
    for index, entry in enumerate(entries):
        label = entry_label(entry, index)
        heads = [split_clause(text)[0] for text in entry.matches]
        if any(CLASHING.get(head) in heads for head in heads):
            found.append(Finding(ERROR, f"{label} matches an ACL and a prefix list in one match ip address: IOS "
                                        "won't take both in one entry.", index))
        for text in entry.matches:
            head, values = split_clause(text)
            values = values if values is not None else text.split()[1:]
            if head.endswith("prefix-list"):
                family = V6 if head.startswith("ipv6") else V4
                for name in values:
                    if (family, name) not in device.prefix_lists:
                        found.append(Finding(WARNING, f"{label} matches prefix list {name}, which isn't on the "
                                                      "device.", index))
            elif head in ("ip address", "ipv6 address"):
                family = V6 if head.startswith("ipv6") else V4
                for name in values:
                    if (family, name) not in device.acls:
                        found.append(Finding(WARNING, f"{label} matches ACL {name}, which isn't on the device.",
                                             index))
            elif head == "as-path":
                for name in values:
                    if name not in device.as_paths:
                        found.append(Finding(WARNING, f"{label} matches AS-path list {name}, which isn't on the "
                                                      "device.", index))
        if entry.action == DENY and entry.sets:
            found.append(Finding(INFO, f"{label} denies, so its set lines do nothing.", index))
        if entry.cont and entry.cont != "next":
            target = int(entry.cont) if entry.cont.isdigit() else 0
            own = entry.seq or entry.want_seq
            if own and target <= own:
                found.append(Finding(ERROR, f"{label}'s continue {entry.cont} goes back: IOS refuses it (a loop "
                                            "in the route map).", index))
            elif target not in numbers:
                found.append(Finding(WARNING, f"{label}'s continue {entry.cont} names no entry here.", index))
        if entry.cont and entry.action == DENY:
            found.append(Finding(INFO, f"{label} denies, so its continue does nothing.", index))
    found += unsupported(rmap, device)
    for index, entry in enumerate(entries):
        if not entry.matches and not entry.cont and index < len(entries) - 1:
            found.append(Finding(WARNING, f"{entry_label(entry, index)} matches everything ({entry.action}, with no "
                                          f"match lines), so the entries after it are never used.", index + 1, index))
            break
    if entries and not any(entry.action == PERMIT for entry in entries):
        found.append(Finding(WARNING, "It has no permit entry: everything is denied."))
    return found


BGP_ONLY = ("as-path", "community", "extcommunity", "large-community", "local-preference", "policy-list")
PBR_MATCHES = ("ip address", "ipv6 address", "ip address prefix-list", "ipv6 address prefix-list", "length",
               "mpls-label")


def supported_place(use, protocol):
    """Where a route map is used, in words, and a test of a match keyword there (None: anything goes)."""
    if use.where == PBR:
        return "policy routing", lambda head: head in PBR_MATCHES
    if use.where == BGP and use.direction == IN:
        return "a BGP neighbor (in)", lambda head: head not in ("tag", "interface", "length", "route-type")
    if use.where in (REDIST, DISTRIBUTE) and protocol not in ("bgp", ""):
        return f"{protocol.upper()} ({use.label()})", lambda head: head not in BGP_ONLY
    return "", None


def unsupported(rmap, device):
    """Match lines (and continue) IOS doesn't support where the route map is used: it warns, and the entry then acts
    as if it had no match lines (found on IOS 15.7). NOMAD's send takes that warning as a refusal."""
    found, said = [], set()
    for use in uses_of(device, ROUTE_MAP, rmap.name):
        process = device.processes.get(use.path[0]) if use.path else None
        protocol = process.protocol if process is not None else ""
        place, allowed = supported_place(use, protocol)
        if allowed is None:
            continue
        for index, entry in enumerate(rmap.entries):
            label = entry_label(entry, index)
            for text in entry.matches:
                head, values = split_clause(text)
                head = head if values is not None else text.split()[0]
                if not allowed(head) and (index, head, place) not in said:
                    said.add((index, head, place))
                    found.append(Finding(WARNING, f"{label}: match {head} isn't supported for {place}: IOS says "
                                                  "so, and the entry then acts as if it had no match lines (NOMAD "
                                                  "puts the change back when IOS says it).", index))
            if entry.cont and use.where != BGP and (index, "continue", place) not in said:
                said.add((index, "continue", place))
                found.append(Finding(WARNING, f"{label}: continue only works in BGP, not for {place}.", index))
    return found


# ----------------------------------------------------------------- The library

def library_config(item, device):
    """A prefix list, or a route map with the prefix lists and ACLs it matches, as configuration text."""
    from .acl import library_config as acl_config, needed
    if isinstance(item, PrefixList):
        return "\n".join(item.config())
    lines = []
    for family, name in sorted(names_matched(item)):
        plist = device.prefix_lists.get((family, name))
        if plist is not None:
            lines += plist.config()
    for family, name in sorted(acls_matched(item)):
        found = device.acls.get((family, name))
        if found is not None:
            groups, ranges = needed(found, device)
            lines += acl_config(found, groups, ranges).splitlines()
    return "\n".join(lines + item.config())


def names_matched(rmap):
    found = set()
    for entry in rmap.entries:
        for text in entry.matches:
            head, values = split_clause(text)
            if values and head.endswith("prefix-list"):
                found |= {(V6 if head.startswith("ipv6") else V4, value) for value in values}
    return found


def acls_matched(rmap):
    found = set()
    for entry in rmap.entries:
        for text in entry.matches:
            head, values = split_clause(text)
            if values and head in ("ip address", "ipv6 address", "ip next-hop", "ip route-source"):
                found |= {(V6 if head.startswith("ipv6") else V4, value) for value in values}
    return found


def align_prefix(before, wanted):
    """wanted with each entry marked as before's doing the same (by its seq), so only what differs changes."""
    unused = sorted(before.entries, key=lambda entry: entry.seq) if before is not None else []
    entries = []
    for entry in wanted.entries:
        match = next((item for item in unused if item.key() == entry.key()), None)
        if match is not None:
            unused.remove(match)
            entries.append(entry.copy(seq=match.seq, want_seq=0, hits=match.hits))
        else:  # Made new on the device: at the numbers it had
            entries.append(entry.copy(seq=0, want_seq=0 if before is not None else entry.want_seq or entry.seq,
                                      hits=None))
    return wanted.copy(entries=entries, description=wanted.description)


def align_map(before, wanted):
    """wanted's entries kept at before's numbers where before has an entry there (changed in place), else new."""
    numbers = {entry.seq for entry in before.entries} if before is not None else set()
    entries = [entry.copy(seq=entry.seq if entry.seq in numbers else 0, want_seq=0 if entry.seq in numbers
                          else entry.seq, hits=None) for entry in wanted.entries]
    return wanted.copy(entries=entries)
