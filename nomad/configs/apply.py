"""Roughly how a configuration looks after configuration lines are typed into it, for comparing a page's preview
with the device as it is (Show as Diff): each line goes in its mode, taking the place of the line it replaces (vpn's
slots), and no lines take lines away. It's an approximation: the device has the last word (defaults it hides, lines it
rewrites)."""
import re

from ..configtext import separated
from ..netmap import vpn

MODE_OPENERS = ("interface ", "router ", "line ", "ip access-list ", "ipv6 access-list ", "route-map ", "class-map ",
                "policy-map ", "vlan ", "vrf ", "ip vrf ", "key chain ", "track ", "ip sla ", "crypto ",
                "object-group ", "monitor session ", "archive", "control-plane", "event manager applet ",
                "snmp-server view ", "aaa group server ", "ip dhcp pool ", "address-family ", "template ")
TOP_LEVEL = ("ip route ", "ipv6 route ", "ip prefix-list ", "ipv6 prefix-list ", "snmp-server ", "logging ", "ntp ",
             "hostname ", "access-list ", "username ", "aaa ", "service ", "spanning-tree ", "ip domain", "ip name-server",
             "ip ssh ", "banner ", "clock ", "ip http", "cdp ", "lldp ", "vtp ", "enable ", "ip default-gateway",
             "ip routing", "ipv6 unicast-routing", "default interface ")
SHOWN_AS_NO = ("ip http", "service ", "cdp run", "ip domain lookup", "ip domain-lookup", "ip source-route", "ip bootp",
               "ip gratuitous-arps", "ip finger", "lldp run", "ip forward-protocol", "logging console", "ip routing")
SKIP = re.compile(r"^(?:!|conf(?:igure)?(?:\s+t(?:erminal)?)?(?:\s+revert\s+timer\s+\d+)?$|write|copy |do )")


def simulate(running, commands):
    """(before, after): running as NOMAD renders it, and the same with commands typed in (both with "!" between
    blocks, so only the commands' changes differ)."""
    lines = running.splitlines() if isinstance(running, str) else list(running)
    before = vpn.parse_tree("\n".join(lines))
    root = vpn.Block("", vpn.parse_tree("\n".join(lines)))
    command_lines = commands.splitlines() if isinstance(commands, str) else list(commands)
    indented = any(line[:1] == " " and line.strip() for line in command_lines)
    stack = [root]
    for raw in command_lines:
        line = vpn.collapse(raw.strip())
        if not line or SKIP.match(line):
            continue
        if line == "end":
            stack = [root]
            continue
        if line == "exit" or line.startswith("exit-"):
            if len(stack) > 1:
                stack.pop()
            continue
        if indented:
            depth = min(len(raw) - len(raw.lstrip(" ")), len(stack) - 1)
        elif line.startswith(MODE_OPENERS) or line.startswith(TOP_LEVEL) or \
                (line.startswith("no ") and line[3:].startswith(MODE_OPENERS + TOP_LEVEL)):
            depth = 0
        else:
            depth = len(stack) - 1
        stack = stack[:depth + 1]
        entered = apply_line(stack[-1], line)
        stack.append(entered if entered is not None else vpn.Block("(gone)"))
    return as_text(before), as_text(root.children)


def as_text(blocks):
    return "\n".join(separated(vpn.render(blocks)))


def apply_line(parent, line):
    """Type line in parent's mode: the block it made or changed (to type lines under), or None for a no line."""
    if line.startswith("default interface ") and parent.line == "":
        name = "interface " + line[len("default interface "):]
        found = next((child for child in parent.children if child.line == name), None)
        if found is not None:
            found.children = []
        return None
    if line.startswith("no "):
        remove_matching(parent, line[3:])
        return None
    key = vpn.key_of(line, parent.line)
    found = next((child for child in parent.children if vpn.key_of(child.line, parent.line) == key), None)
    if found is not None:
        found.line = line
        return found
    for child in parent.children:
        if child.line == "no " + line:  # no ip http server, then ip http server
            parent.children.remove(child)
            break
    block = vpn.Block(line)
    parent.children.append(block)
    return block


def remove_matching(parent, target):
    """Take away the lines no target removes: the line itself, lines it starts (no description), the ACL rule with
    that number (no 20), or the line in target's slot."""
    words = target.split()
    target_key = vpn.key_of(target, parent.line)
    in_acl = vpn.parent_type(parent.line) == "acl"
    kept = []
    removed = False
    for child in parent.children:
        if child.line == target or child.line.startswith(target + " ") or \
                (in_acl and len(words) == 1 and words[0].isdigit() and child.line.split()[:1] == words) or \
                (vpn.slot_of(target, parent.line) and vpn.key_of(child.line, parent.line) == target_key):
            removed = True
            continue
        kept.append(child)
    parent.children = kept
    if parent.line == "" and target.startswith(SHOWN_AS_NO) and \
            not any(child.line == "no " + target for child in parent.children):
        parent.children.append(vpn.Block("no " + target))  # no ip http server shows as itself
    return removed
