"""A configuration as a tree of lines that keep their line numbers: the lines indented under a line (a mode, such as
interface Gi0/1) are its children. Comments ("!"), blank lines, end and exit lines aren't in the tree, nor are the
lines noise.noise_lines finds (when they're given)."""
import re
from dataclasses import dataclass, field

from ..netmap import vpn

IOS, NXOS, ASA, ARUBA, PFSENSE, OTHER = "ios", "nxos", "asa", "aruba", "pfsense", "other"
PLATFORM_NAMES = {IOS: "Cisco IOS / IOS XE", NXOS: "Cisco NX-OS", ASA: "Cisco ASA", ARUBA: "ArubaOS",
                  PFSENSE: "pfSense", OTHER: "Other"}
FIXABLE = {IOS, NXOS, ASA}  # The platforms NOMAD writes fix commands for

SKIPPED = re.compile(r"^(?:!|end$|exit$|exit-[a-z-]+$)")


@dataclass
class Node:
    line: str  # Runs of spaces made one, no indent
    number: int  # Where it is in the text (0-based)
    depth: int
    children: list = field(default_factory=list)
    parent: object = None
    end: int = 0  # Its last line (or its last child's), 0-based

    @property
    def path(self):
        """The lines of the modes it's in, outermost first."""
        lines, node = [], self.parent
        while node is not None:
            lines.append(node.line)
            node = node.parent
        return lines[::-1]

    @property
    def parent_line(self):
        return self.parent.line if self.parent is not None else ""

    def render(self, depth=0):
        lines = [" " * depth + self.line]
        for child in self.children:
            lines += child.render(depth + 1)
        return lines

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def parse(text, skip=()):
    """[Node] at the top of a configuration. skip: line numbers left out (noise)."""
    lines = text.splitlines() if isinstance(text, str) else list(text)
    roots = []
    stack = []  # (indent, node)
    skip = set(skip)
    for number, raw in enumerate(lines):
        if number in skip:
            continue
        line = raw.replace("\t", " ").rstrip()
        stripped = line.strip()
        if not stripped or SKIPPED.match(stripped):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else None
        node = Node(vpn.collapse(stripped), number, len(stack), parent=parent, end=number)
        (parent.children if parent is not None else roots).append(node)
        ancestor = parent
        while ancestor is not None:
            ancestor.end = number
            ancestor = ancestor.parent
        stack.append((indent, node))
    return roots


def walk(nodes):
    for node in nodes:
        yield from node.walk()


def paths_by_line(nodes):
    """{line number: "interface Gi0/1 > ..."} for every line in the tree: the modes it's in (and its own, for a
    mode's line)."""
    paths = {}
    for node in walk(nodes):
        chain = node.path
        paths[node.number] = " > ".join(chain)
    return paths


def key_of(line, parent_line=""):
    """What identifies a line among its siblings (vpn.key_of: a slot such as description, a mode's name, an ACL rule
    without its number)."""
    return vpn.key_of(line, parent_line)


def platform_of(text):
    """Which platform a configuration came from, by what it says."""
    head = (text or "")[:4000]
    if re.search(r"<\?xml|<pfsense>", head):
        return PFSENSE
    if re.search(r"^!Command: show (?:running|startup)-config|^!Time:|^feature \S+|^!Running configuration last done",
                 head, re.MULTILINE):
        return NXOS
    if re.search(r"^:\s*Saved|^ASA Version|^: Hardware:|^Cryptochecksum:", text or "", re.MULTILINE):
        return ASA
    if re.search(r"ArubaOS|^\(\S+\) \[mynode\]|^ap-group |^wlan ssid-profile ", head, re.MULTILINE):
        return ARUBA
    if re.search(r"^(?:hostname|interface|version)\s", head, re.MULTILINE):
        return IOS
    return OTHER


def platform_for_device(device):
    """The platform of a map device (netmap.model.Device) from what SNMP read."""
    from ..inventory import detect_platform
    from ..netmap import model
    from ..netmap.collect import is_pfsense
    if is_pfsense(device.sys_descr or ""):
        return PFSENSE
    if device.kind == model.WLC or "arubaos" in (device.sys_descr or "").lower():
        return ARUBA
    found = detect_platform(device)
    return {"ios": IOS, "nxos": NXOS, "asa": ASA}.get(found, IOS if not found else OTHER)


def hostname_in(text):
    """The hostname a configuration sets (hostname x, or pfSense's <hostname>), or ""."""
    found = re.search(r"^hostname\s+(\S+)", text or "", re.MULTILINE) or \
        re.search(r"<hostname>([^<]+)</hostname>", text or "")
    return found.group(1).strip().strip('"') if found else ""
