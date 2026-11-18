"""The commands that take a device's configuration (current) to another (wanted): Cisco IOS / IOS XE, NX-OS and ASA.

By mode, as the section-aware comparison sees them: a line only wanted is typed in its mode; a line only current is
taken away with its no form; a line that takes another's place (description, ip address...) is just typed. A physical
interface is never removed (it can't be): its lines are taken away instead. Lines nobody can type (version, the
certificate data, the boot markers) are left alone, and an ACL rule that only changed number is left as it is."""
import re

from ..configtext import separated
from ..netmap import routepolicy, vpn
from . import diff, noise, text

UNTOUCHABLE = re.compile(r"^(?:version\s|boot-start-marker|boot-end-marker|Building configuration|Current configuration"
                         r"|end$|ASA Version|Cryptochecksum|: )")
UNTOUCHABLE_MODES = ("crypto pki certificate chain", "crypto ca certificate chain")
LOGICAL_INTERFACES = re.compile(r"^interface\s+(?:Loopback|Tunnel|Vlan|Port-channel|port-channel|BDI|Dialer|"
                                r"Virtual-Template|Virtual-Access|nve|BVI|Null|Management\d)", re.IGNORECASE)


def physical_interface(line):
    return line.startswith("interface ") and not LOGICAL_INTERFACES.match(line) and "." not in line.split()[-1]


class FixBuilder:
    def __init__(self):
        self.groups = {}  # (mode lines...) -> {"remove": [lines], "add": [lines]}, in the order first met

    def group(self, path):
        return self.groups.setdefault(tuple(path), {"remove": [], "add": []})

    def remove(self, path, node):
        parent_line = path[-1] if path else ""
        if UNTOUCHABLE.match(node.line):
            return
        if not path and physical_interface(node.line):
            for child in node.children:
                self.remove([node.line], child)
            return
        self.group(path)["remove"].append(vpn.no_form(node.line, parent_line))

    def add(self, path, node):
        if UNTOUCHABLE.match(node.line):
            return
        self.group(path)["add"].extend(node.render(0))

    def compare(self, current, wanted, path):
        if any(" ".join(path).startswith(mode) for mode in UNTOUCHABLE_MODES):
            return
        parent_line = path[-1] if path else ""
        if vpn.parent_type(parent_line) == "acl":
            self.compare_acl(current, wanted, path)
            return
        b_keyed = diff.keyed(wanted, parent_line)
        a_keyed = diff.paired(diff.keyed(current, parent_line), b_keyed)
        a_map, b_map = dict(a_keyed), dict(b_keyed)
        for key, b_node in b_keyed:
            a_node = a_map.get(key)
            if a_node is None:
                self.add(path, b_node)
                continue
            if a_node.line != b_node.line:
                if acl_renumbered(a_node.line, b_node.line, parent_line):
                    continue
                if vpn.slot_of(b_node.line, parent_line) and not a_node.children and not b_node.children:
                    if not UNTOUCHABLE.match(b_node.line):
                        self.group(path)["add"].append(b_node.line)  # Takes the old one's place
                    continue
                self.remove(path, a_node)
                self.add(path, b_node)
                continue
            if not diff.same_leaves(a_node, b_node):
                self.compare(a_node.children, b_node.children, path + [b_node.line])
        for key, a_node in a_keyed:
            if key not in b_map:
                self.remove(path, a_node)

    def compare_acl(self, current, wanted, path):
        """An ACL's rules by their whole line, number and all: the rules that aren't exactly wanted go first (no N),
        then the wanted ones that aren't there yet, so a rule moving to a number another rule had doesn't collide."""
        current_lines = [node.line for node in current]
        wanted_lines = [node.line for node in wanted]
        for node in current:
            if node.line not in wanted_lines:
                self.remove(path, node)
        for node in wanted:
            if node.line not in current_lines:
                self.add(path, node)

    def lines(self):
        result = []
        for path, group in self.groups.items():
            removes = list(dict.fromkeys(group["remove"]))
            adds = [line for line in dict.fromkeys(group["add"]) if line not in removes]
            if not removes and not adds:
                continue
            depth = len(path)
            result += routepolicy.enter(list(path))
            result += [" " * depth + line for line in removes]
            result += [" " * depth + line for line in adds]
            if path:
                result += routepolicy.leave(list(path))
        return result


def acl_renumbered(old, new, parent_line):
    """Whether two ACL rules are the same rule under another sequence number."""
    if vpn.parent_type(parent_line) != "acl":
        return False
    old_words, new_words = old.split(), new.split()
    return bool(old_words and new_words and old_words[0].isdigit() and new_words[0].isdigit() and
                old_words[1:] == new_words[1:])


def fix_commands(current, wanted):
    """The configuration lines (in their modes, with exit after each) that take current to wanted, or [] when
    nothing needs typing."""
    current_lines, wanted_lines = diff.lines_of(current), diff.lines_of(wanted)
    current_tree = text.parse(current_lines, skip=noise.noise_lines(current_lines))
    wanted_tree = text.parse(wanted_lines, skip=noise.noise_lines(wanted_lines))
    builder = FixBuilder()
    builder.compare(current_tree, wanted_tree, [])
    return builder.lines()


def as_config(lines, revert_minutes=0):
    """Lines wrapped for typing: configure terminal (with the revert timer when given), "!" between blocks, end."""
    first = f"configure terminal revert timer {revert_minutes}" if revert_minutes else "configure terminal"
    return "\n".join(separated([first] + list(lines) + ["end"]))
