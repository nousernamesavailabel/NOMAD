"""Cisco IOS / IOS-XE (Catalyst) configuration that sets a switch up for NOMAD: SNMP read access (community strings
or SNMPv3 users, limited by an access list), the traps and syslog messages that tell the Map Watcher something was
plugged in, CDP and LLDP for the map's crawls, and link-status logging and MAC notifications on the access ports.

build() gives the lines to paste (or send) from the enable prompt: configure terminal ... end, and write memory if
chosen. undo() gives the lines that take it out again. Qt-free; the SNMP Config page is the form for it.
"""
import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from .snmp import community_is_valid
from .snmpv3 import AUTH_PRIV, AUTH_NO_PRIV, NO_AUTH, V3User

# Trap categories: key -> (what follows "snmp-server enable traps", what they're about, whether NOMAD acts on them)
TRAP_CATEGORIES = {
    "snmp": ("snmp linkdown linkup coldstart warmstart", "Ports going up and down, restarts", True),
    "mac-notification": ("mac-notification change move", "MAC addresses learned and moved on access ports", True),
    "config": ("config", "Configuration changes", False),
    "entity": ("entity", "Modules, power supplies and fans added or removed", False),
    "envmon": ("envmon", "Temperature, fan and power problems", False),
    "errdisable": ("errdisable", "Ports shut down by errdisable", False),
    "port-security": ("port-security", "Port security violations", False),
}
DEFAULT_TRAPS = ["snmp", "mac-notification"]
SYSLOG_LEVELS = {"notifications": "Notifications (level 5): ports up and down, PoE, CDP",
                 "informational": "Informational (level 6): more detail, more messages",
                 "warnings": "Warnings (level 4): problems only (misses ports coming up)"}
# IOS keywords for SNMPv3 protocols
IOS_AUTH = {"md5": "md5", "sha": "sha", "sha256": "sha-2 256", "sha384": "sha-2 384", "sha512": "sha-2 512"}
IOS_PRIV = {"des": "des", "aes128": "aes 128", "aes192": "aes 192", "aes256": "aes 256"}
IOS_LEVEL = {NO_AUTH: "noauth", AUTH_NO_PRIV: "auth", AUTH_PRIV: "priv"}
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
RANGE_PART = r"[A-Za-z][A-Za-z-]*\s*\d+(?:/\d+)*(?:\s*-\s*\d+)?"
INTERFACE_RANGE = re.compile(rf"^{RANGE_PART}(?:\s*,\s*{RANGE_PART}){{0,4}}$")
INTERFACE = re.compile(r"^[A-Za-z][A-Za-z-]*\s*\d+(?:/\d+)*(?:\.\d+)?$")


@dataclass
class ConfigOptions:
    # Read access: NOMAD reads the switch with the community string, the SNMPv3 user, or both
    access: bool = True
    community: str = ""
    v3_user: Optional[V3User] = None
    # More community strings and SNMPv3 users allowed to read (such as the rest of a map's); traps go with the two above
    more_communities: list = field(default_factory=list)
    more_users: list = field(default_factory=list)
    group: str = "NOMAD"
    view: str = "NOMAD-VIEW"
    acl: str = "NOMAD-SNMP"
    permit: list = field(default_factory=list)  # Hosts and subnets allowed to read (the computers running NOMAD)
    location: str = ""
    contact: str = ""
    ifindex_persist: bool = True
    # Where traps and syslog go (the computers watching)
    destinations: list = field(default_factory=list)
    traps: bool = True
    trap_version: str = "v2c"  # Or "v3": sent as v3_user
    trap_categories: list = field(default_factory=lambda: list(DEFAULT_TRAPS))
    syslog: bool = True
    syslog_level: str = "notifications"
    timestamps: bool = False
    source_interface: str = ""  # What traps and syslog come from (a VLAN or loopback with a fixed address)
    cdp: bool = True
    lldp: bool = True
    access_ports: str = ""  # An interface range for link-status logging and MAC notifications
    poe: bool = True  # Log PoE power changes on the access ports (switches without PoE refuse the command)
    write_memory: bool = False


def communities(options):
    """Every community string allowed to read, the one traps go with first."""
    return list(dict.fromkeys(([options.community] if options.community else []) + list(options.more_communities)))


def users(options):
    """Every SNMPv3 user allowed to read, the one traps go with first."""
    return list(dict.fromkeys(([options.v3_user] if options.v3_user is not None else []) + list(options.more_users)))


def problems(options):
    """What's wrong with options, as sentences ([] when nothing)."""
    found = []
    if options.access:
        if not communities(options) and not users(options):
            found.append("Choose a community string or an SNMPv3 user for NOMAD to read the switch with.")
        found += _permit_problems(options.permit)
        if not NAME.match(options.acl):
            found.append("The access list name is one word: letters, digits, - _ and . (up to 32).")
    for community in communities(options):
        what = "community string" if community == options.community else f"community string {community}"
        found += _secret_problems(community, f"The {what}")
        if not community_is_valid(community):
            found.append(f"The {what} can't be over 255 bytes or contain control characters.")
        if "@" in community:
            found.append(f"Leave @ out of the {what}: community@vlan is how the per-VLAN MAC tables are read.")
    names = set()
    for user in users(options):
        found += [user.problem()] if user.problem() else []
        if user.user in names:
            found.append(f"There are two SNMPv3 users named {user.user}: a switch keeps one of each name.")
        names.add(user.user)
        if user.auth == "sha224":
            found.append("IOS doesn't offer SHA-224 for SNMPv3 users: choose SHA-1 or SHA-256 and up.")
        for secret, what in ((user.auth_password, "The authentication password"),
                             (user.priv_password, "The privacy password")):
            if secret:
                found += _secret_problems(secret, what if user == options.v3_user else f"{what} of {user.user}")
    if users(options):
        for name, what in ((options.group, "SNMP group"), (options.view, "SNMP view")):
            if options.access and not NAME.match(name):
                found.append(f"The {what} name is one word: letters, digits, - _ and . (up to 32).")
    if options.traps or options.syslog:
        if not options.destinations:
            found.append("Add where traps and syslog messages go (the computer watching the map).")
        for destination in options.destinations:
            try:
                ipaddress.IPv4Address(destination)
            except ValueError:
                found.append(f"'{destination}' isn't an IPv4 address to send traps and syslog to.")
    if options.traps:
        if options.trap_version == "v3" and options.v3_user is None:
            found.append("Traps sent with SNMPv3 need the SNMPv3 user.")
        if options.trap_version == "v2c" and not options.community:
            found.append("Traps sent with v2c need the community string.")
        unknown = [name for name in options.trap_categories if name not in TRAP_CATEGORIES]
        if unknown or not options.trap_categories:
            found.append("Choose which traps to send.")
    if options.syslog and options.syslog_level not in SYSLOG_LEVELS:
        found.append("Choose the syslog level.")
    if options.source_interface and not INTERFACE.match(options.source_interface.strip()):
        found.append(f"'{options.source_interface}' isn't an interface name, such as Vlan10 or Loopback0.")
    if options.access_ports and not INTERFACE_RANGE.match(options.access_ports.strip()):
        found.append(f"'{options.access_ports}' isn't an interface range, such as Gi1/0/1 - 48 (up to five, "
                     "separated by commas).")
    for text, what in ((options.location, "location"), (options.contact, "contact")):
        if any(ord(character) < 32 for character in text) or "?" in text:
            found.append(f"The {what} can't contain ? or control characters.")
    return found


def _secret_problems(secret, what):
    if any(character.isspace() or character == "?" or ord(character) < 32 for character in secret):
        return [f"{what} can't contain spaces or ?, which the switch's command line treats specially."]
    return []


def _permit_problems(permit):
    if not permit:
        return ["Add the addresses allowed to read SNMP (this computer and the Map Watcher's)."]
    found = []
    for item in permit:
        try:
            ipaddress.IPv4Network(item, strict=False)
        except ValueError:
            found.append(f"'{item}' isn't an IPv4 address or subnet to allow.")
    return found


def permit_line(item):
    network = ipaddress.IPv4Network(item, strict=False)
    if network.prefixlen == 32:
        return f" permit host {network.network_address}"
    return f" permit {network.network_address} {network.hostmask}"


def user_line(options, user=None):
    user = user or options.v3_user
    line = f"snmp-server user {user.user} {options.group} v3"
    if user.auth != "none":
        line += f" auth {IOS_AUTH[user.auth]} {user.auth_password}"
        if user.priv != "none":
            line += f" priv {IOS_PRIV[user.priv]} {user.priv_password}"
    return line + f" access {options.acl}"


def trap_host(options, destination):
    if options.trap_version == "v3":
        user = options.v3_user
        return f"snmp-server host {destination} version 3 {IOS_LEVEL[user.level]} {user.user}"
    return f"snmp-server host {destination} version 2c {options.community}"


def _levels(options):
    """The IOS security levels of the SNMPv3 users, the first user's first."""
    return list(dict.fromkeys(IOS_LEVEL[user.level] for user in users(options)))


def build(options, now=None):
    """The configuration lines for options. Raises ValueError with the first problem."""
    found = problems(options)
    if found:
        raise ValueError(found[0])
    now = now or datetime.datetime.now()
    lines = ["configure terminal", f"! Set up for NOMAD monitoring ({now:%Y-%m-%d %H:%M})"]
    source = options.source_interface.strip()
    if options.access:
        lines += ["! Who may read SNMP"]
        lines += [f"ip access-list standard {options.acl}"] + [permit_line(item) for item in options.permit]
        lines.append("exit")
        lines += [f"snmp-server community {community} RO {options.acl}" for community in communities(options)]
        if users(options):
            lines.append(f"snmp-server view {options.view} iso included")
            for index, level in enumerate(_levels(options)):  # A group for each security level the users have
                lines.append(f"snmp-server group {options.group} v3 {level} read {options.view} access {options.acl}")
                if index == 0:
                    lines.append("! Catalyst keeps each VLAN's MAC address table in context vlan-<number>")
                lines.append(f"snmp-server group {options.group} v3 {level} context vlan- match prefix read "
                             f"{options.view} access {options.acl}")
            lines += [user_line(options, user) for user in users(options)]
        if options.ifindex_persist:
            lines.append("snmp-server ifindex persist")
    if options.location:
        lines.append(f"snmp-server location {options.location}")
    if options.contact:
        lines.append(f"snmp-server contact {options.contact}")
    if options.traps:
        lines += ["! Traps to the computers watching"]
        lines += [f"snmp-server enable traps {TRAP_CATEGORIES[name][0]}" for name in TRAP_CATEGORIES
                  if name in options.trap_categories]
        if "mac-notification" in options.trap_categories:
            lines.append("mac address-table notification change")
        lines += [trap_host(options, destination) for destination in options.destinations]
        if source:
            lines.append(f"snmp-server trap-source {source}")
    if options.syslog:
        lines += ["! Syslog to the computers watching"]
        lines += [f"logging host {destination}" for destination in options.destinations]
        lines.append(f"logging trap {options.syslog_level}")
        if source:
            lines.append(f"logging source-interface {source}")
        if options.timestamps:
            lines.append("service timestamps log datetime msec localtime show-timezone")
    if options.cdp or options.lldp:
        lines += ["! Neighbor discovery, for the map's crawls"] + (["cdp run"] if options.cdp else []) + \
            (["lldp run"] if options.lldp else [])
    if options.access_ports.strip():
        lines += ["! Access ports: say when something is plugged in", f"interface range {options.access_ports.strip()}"]
        if options.syslog:
            lines.append(" logging event link-status")
            if options.poe:
                lines.append(" logging event power-inline-status")
        if options.traps:
            lines.append(" snmp trap link-status")
            if "mac-notification" in options.trap_categories:
                lines.append(" snmp trap mac-notification change added")
        lines.append("exit")
    lines.append("end")
    if options.write_memory:
        lines.append("write memory")
    return lines


def undo(options):
    """Lines taking out what build() adds (CDP, LLDP and ifindex persist are left on). Raises ValueError."""
    found = problems(options)
    if found:
        raise ValueError(found[0])
    lines = ["configure terminal", "! Take out NOMAD's SNMP set-up"]
    source = options.source_interface.strip()
    if options.access_ports.strip():
        lines.append(f"interface range {options.access_ports.strip()}")
        if options.traps and "mac-notification" in options.trap_categories:
            lines.append(" no snmp trap mac-notification change added")
        lines.append("exit")
    if options.syslog:
        lines += [f"no logging host {destination}" for destination in options.destinations]
        if source:
            lines.append("no logging source-interface")
    if options.traps:
        lines += [f"no {trap_host(options, destination)}" for destination in options.destinations]
        lines += [f"no snmp-server enable traps {TRAP_CATEGORIES[name][0]}" for name in TRAP_CATEGORIES
                  if name in options.trap_categories]
        if "mac-notification" in options.trap_categories:
            lines.append("no mac address-table notification change")
        if source:
            lines.append("no snmp-server trap-source")
    if options.location:
        lines.append("no snmp-server location")
    if options.contact:
        lines.append("no snmp-server contact")
    if options.access:
        if users(options):
            lines += [f"no snmp-server user {user.user} {options.group} v3" for user in users(options)]
            for level in _levels(options):
                lines += [f"no snmp-server group {options.group} v3 {level} context vlan- match prefix",
                          f"no snmp-server group {options.group} v3 {level}"]
            lines.append(f"no snmp-server view {options.view} iso")
        lines += [f"no snmp-server community {community}" for community in communities(options)]
        lines.append(f"no ip access-list standard {options.acl}")
    lines.append("end")
    if options.write_memory:
        lines.append("write memory")
    return lines
