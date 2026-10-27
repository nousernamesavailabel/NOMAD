"""Ansible inventories made from what NOMAD knows: the open network map's devices (with their sites, buildings and
rooms) and the saved SSH sessions (with their folders), written as YAML or INI.

Each device gets the ansible_network_os (and connection) its make and model call for, worked out from what the map
read of it (detect_platform) or chosen by hand. Passwords are never written: the inventory says to run with
--ask-pass or ansible-vault.
"""
import re
from dataclasses import dataclass, field

from .netmap.model import AP, FIREWALL, HOST, KIND_NAMES, NETWORK_KINDS, PHONE, ROUTER, SERVER, SWITCH, UNKNOWN, \
    WLC, display_name, normalize_name

YAML, INI = "yaml", "ini"
FORMAT_NAMES = {YAML: "YAML", INI: "INI"}
EXTENSIONS = {YAML: ".yml", INI: ".ini"}

NETWORK_CLI = "ansible.netcommon.network_cli"
HTTPAPI = "ansible.netcommon.httpapi"
NETCONF = "ansible.netcommon.netconf"
HTTPS = (("ansible_httpapi_use_ssl", True), ("ansible_httpapi_validate_certs", False))

CISCO = "1.3.6.1.4.1.9."
PALO_ALTO = "1.3.6.1.4.1.25461."
JUNIPER = "1.3.6.1.4.1.2636."
ARISTA = "1.3.6.1.4.1.30065."
FORTINET = "1.3.6.1.4.1.12356."


@dataclass(frozen=True)
class Platform:
    """What Ansible needs to know to manage a kind of device."""
    key: str
    name: str
    group: str  # The inventory group of its devices
    network_os: str = ""
    connection: str = ""
    collection: str = ""  # The Ansible collection with its modules
    extra: tuple = ()  # Other variables it needs: ((name, value), ...)
    enable: bool = False  # Its command line has an enable mode, which become can turn on


PLATFORMS = {platform.key: platform for platform in [
    Platform("ios", "Cisco IOS / IOS XE", "cisco_ios", "cisco.ios.ios", NETWORK_CLI, "cisco.ios", enable=True),
    Platform("nxos", "Cisco NX-OS", "cisco_nxos", "cisco.nxos.nxos", NETWORK_CLI, "cisco.nxos"),
    Platform("iosxr", "Cisco IOS XR", "cisco_iosxr", "cisco.iosxr.iosxr", NETWORK_CLI, "cisco.iosxr"),
    Platform("asa", "Cisco ASA", "cisco_asa", "cisco.asa.asa", NETWORK_CLI, "cisco.asa", enable=True),
    Platform("panos", "Palo Alto PAN-OS", "panos", "paloaltonetworks.panos.panos", HTTPAPI,
             "paloaltonetworks.panos", HTTPS),
    Platform("junos", "Juniper Junos", "junos", "junipernetworks.junos.junos", NETCONF, "junipernetworks.junos"),
    Platform("eos", "Arista EOS", "arista_eos", "arista.eos.eos", NETWORK_CLI, "arista.eos", enable=True),
    Platform("fortios", "Fortinet FortiOS", "fortios", "fortinet.fortios.fortios", HTTPAPI, "fortinet.fortios",
             HTTPS),
    Platform("linux", "Linux / Unix (SSH)", "linux"),
]}
NONE = ""  # No platform: not a device Ansible manages, or not known

KIND_GROUPS = {SWITCH: "switches", ROUTER: "routers", FIREWALL: "firewalls", WLC: "wireless_controllers",
               AP: "access_points", PHONE: "phones", SERVER: "servers", HOST: "end_hosts", UNKNOWN: "unknown_devices"}
RESERVED_GROUPS = {"all", "ungrouped"}
SSH_PORT = 22


def detect_platform(device):
    """The PLATFORMS key for a map Device, from its SNMP sysObjectID and description or its CDP/LLDP model, or NONE
    when it isn't a device Ansible's network collections manage (or can't be told)."""
    words = f"{device.sys_descr} {device.platform}".lower()
    model = device.platform.lower().strip()
    oid = device.sys_object_id + "."
    if device.kind in (AP, PHONE, HOST):
        return NONE
    if oid.startswith(PALO_ALTO) or "palo alto" in words or "pan-os" in words:
        return "panos"
    if oid.startswith(FORTINET) or "fortigate" in words or "fortios" in words:
        return "fortios"
    if oid.startswith(JUNIPER) or "junos" in words or "juniper" in words:
        return "junos"
    if oid.startswith(ARISTA) or "arista" in words:
        return "eos"
    if "firepower" in words or model.startswith("ftd"):
        return NONE  # Managed through FMC, not a command line Ansible's Cisco collections drive
    if "adaptive security appliance" in words or model.startswith(("asa", "cisco asa")):
        return "asa"
    if "ios xr" in words or "ios-xr" in words or "iosxr" in words:
        return "iosxr"
    if "nx-os" in words or "nexus" in words or re.search(r"\bn\d+k-|\bn77-", words):
        return "nxos"
    if "cisco ios" in words or "ios-xe" in words or "ios xe" in words or "iosxe" in words:
        return "ios"
    if oid.startswith(CISCO) or (model.startswith("cisco") and device.kind in NETWORK_KINDS):
        return "ios"  # A Cisco switch or router that said nothing clearer: CDP gives "cisco WS-C2960X-48TS-L"
    return NONE


@dataclass
class Entry:
    """A device that can go in the inventory: from the map, a saved session, or both (the same device)."""
    key: str  # "device:<map key>" or "session:<id>": what choices and platforms chosen by hand are kept under
    name: str
    address: str = ""
    port: int = 0  # The saved session's SSH port (0: none)
    username: str = ""  # The saved session's
    kind: str = ""  # The map's kind of device ("" for a session alone)
    model: str = ""
    detected: str = NONE  # The platform worked out from the map
    location: list = field(default_factory=list)  # [site, building, room] names, as much as the map has
    folder: str = ""  # The saved session's folder, "Site A/Core"
    from_map: bool = False
    from_session: bool = False

    @property
    def source_text(self):
        return " + ".join(name for name, used in (("Map", self.from_map), ("Session", self.from_session)) if used)

    @property
    def kind_text(self):
        return KIND_NAMES.get(self.kind, self.kind) if self.kind else ""

    @property
    def location_text(self):
        return " / ".join(self.location)

    def default_choice(self):
        """Whether it goes in the inventory unless chosen otherwise: network devices and saved sessions with an
        address to reach them at."""
        return bool(self.address) and (self.from_session or self.kind in NETWORK_KINDS or self.detected != NONE)


def collect_entries(network_map=None, sessions=()):
    """Entries for a map's devices and SSH sessions, a session of a device on the map joining its entry (by address,
    or by name). Sorted by name."""
    entries, by_device = [], {}
    if network_map is not None:
        for device in network_map.devices.values():
            address = device.mgmt_ip or next((item for item in device.addresses if item), "")
            entry = Entry(key=f"device:{device.key}", name=display_name(device.label) or device.key, address=address,
                          kind=device.kind, model=device.platform, detected=detect_platform(device),
                          location=[group.name for group in network_map.group_path(device.key)], from_map=True)
            entries.append(entry)
            by_device[device.key] = entry
    for session in sessions:
        if session.protocol != "SSH" or not session.host.strip():
            continue
        device = _device_for(network_map, session) if network_map is not None else None
        entry = by_device.get(device.key) if device is not None else None
        if entry is None:
            entry = Entry(key=f"session:{session.id}", name=session.name, address=session.host.strip())
            entries.append(entry)
        elif entry.from_session:
            continue  # The device's first session says how to reach it
        entry.from_session = True
        entry.port, entry.username, entry.folder = int(session.port or 0), session.username, session.folder
        entry.address = entry.address or session.host.strip()
    return sorted(entries, key=lambda entry: (entry.name.lower(), entry.key))


def _device_for(network_map, session):
    host = session.host.strip()
    names = {normalize_name(host), normalize_name(session.name)} - {""}
    for device in network_map.devices.values():
        if device.owns(host):
            return device
    for device in network_map.devices.values():
        if device.name and normalize_name(device.name) in names:
            return device
    return None


@dataclass
class Options:
    format: str = YAML
    by_location: bool = True  # Site, building and room groups, nested
    by_kind: bool = True  # switches, routers, firewalls...
    by_platform: bool = True  # cisco_ios, panos..., holding the platform's variables
    by_folder: bool = True  # The saved sessions' folders, nested
    short_names: bool = True  # Names without their domain: core-sw1, not core-sw1.corp.example
    username: str = ""  # ansible_user for everything ("" leaves it out)
    session_users: bool = True  # A saved session's own user name, where it differs
    become: bool = False  # Enable mode on the devices that have one
    nomad_vars: bool = False  # nomad_kind, nomad_model, nomad_location, nomad_folder


@dataclass
class Group:
    vars: dict = field(default_factory=dict)
    hosts: list = field(default_factory=list)
    children: list = field(default_factory=list)


@dataclass
class Inventory:
    hosts: dict = field(default_factory=dict)  # Inventory name -> {variable: value}
    groups: dict = field(default_factory=dict)  # Name -> Group
    top: list = field(default_factory=list)  # The groups directly under all
    all_vars: dict = field(default_factory=dict)
    collections: list = field(default_factory=list)
    problems: list = field(default_factory=list)  # Worth telling the user before they use it
    names: dict = field(default_factory=dict)  # Entry key -> its inventory name


def host_name(text):
    """A name Ansible takes as a host: letters, digits, dots, dashes and underscores."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text.strip()).strip("-.")


def short_name(name):
    """A name without its domain; an address as it is."""
    name = name.strip()
    return name if re.fullmatch(r"[\d.]+|.*:.*", name) else name.split(".")[0]


def group_name(*parts):
    """A valid Ansible group name (a Python identifier) for a site, folder and so on: "HQ", "Bldg A" -> hq_bldg_a."""
    name = "_".join(re.sub(r"[^a-z0-9]+", "_", part.lower()).strip("_") for part in parts)
    name = re.sub(r"_+", "_", name).strip("_") or "group"
    return f"g_{name}" if name[0].isdigit() else name


def build(entries, options, platforms=None):
    """The Inventory of entries. platforms: {entry key: platform key} chosen by hand, over what was detected."""
    platforms = platforms or {}
    inventory = Inventory()
    if options.username:
        inventory.all_vars["ansible_user"] = options.username
    used, chosen = set(), []
    for entry in entries:
        platform = PLATFORMS.get(platforms.get(entry.key, entry.detected))
        name = host_name(short_name(entry.name) if options.short_names else entry.name)
        name = name or host_name(entry.address)
        if not name:
            inventory.problems.append(f"{entry.name or entry.key}: left out, with no name or address.")
            continue
        base, number = name, 2
        while name.lower() in used:
            name, number = f"{base}-{number}", number + 1
        used.add(name.lower())
        inventory.names[entry.key] = name
        if not entry.address:
            inventory.problems.append(f"{name}: no address, so Ansible will look its name up in DNS.")
        if platform is None and entry.kind in NETWORK_KINDS:
            inventory.problems.append(f"{name}: its Ansible OS isn't known; choose it with Set Ansible OS.")
        chosen.append((entry, name, platform))

    for entry, name, platform in chosen:
        host_vars = {}
        if entry.address and entry.address != name:
            host_vars["ansible_host"] = entry.address
        if entry.port and entry.port != SSH_PORT and (platform is None or platform.connection == NETWORK_CLI
                                                      or not platform.connection):
            host_vars["ansible_port"] = entry.port
        if options.session_users and entry.username and entry.username != options.username:
            host_vars["ansible_user"] = entry.username
        if platform is not None and not options.by_platform:
            host_vars.update(platform_vars(platform, options))
        if options.nomad_vars:
            for variable, value in (("nomad_kind", entry.kind_text), ("nomad_model", entry.model),
                                    ("nomad_location", entry.location_text), ("nomad_folder", entry.folder)):
                if value:
                    host_vars[variable] = value
        inventory.hosts[name] = host_vars

    taken = {name.lower() for name in inventory.hosts}

    def group(name, parent=None, variables=None):
        if name in RESERVED_GROUPS or name in taken:
            problem = f"Group {name} is called {name}_group: " + (
                "Ansible keeps that name for itself." if name in RESERVED_GROUPS else "a device has that name.")
            if problem not in inventory.problems:
                inventory.problems.append(problem)
            name += "_group"
        if name not in inventory.groups:
            inventory.groups[name] = Group(dict(variables or {}))
            if parent is None:
                inventory.top.append(name)
        if parent is not None and name not in inventory.groups[parent].children:
            inventory.groups[parent].children.append(name)
        return name

    def nested(parts, name):
        """Groups for a path of names (site, building, room; or folders), each in the one before; the host goes in
        the innermost."""
        parent = None
        for depth in range(len(parts)):
            parent = group(group_name(*parts[:depth + 1]), parent)
        _add_host(inventory.groups[parent], name)

    if options.by_location:
        for entry, name, _ in sorted(chosen, key=lambda item: [part.lower() for part in item[0].location]):
            if entry.location:
                nested(entry.location, name)
    if options.by_folder:
        for entry, name, _ in sorted(chosen, key=lambda item: item[0].folder.lower()):
            folders = [part for part in entry.folder.split("/") if part.strip()]
            if folders:
                nested(folders, name)
    if options.by_kind:
        for kind, kind_group in KIND_GROUPS.items():
            for entry, name, _ in chosen:
                if entry.kind == kind:
                    _add_host(inventory.groups[group(kind_group)], name)
    collections = set()
    for platform in PLATFORMS.values():
        members = [name for _, name, chosen_platform in chosen if chosen_platform is platform]
        if not members:
            continue
        if platform.collection:
            collections.add(platform.collection)
        if platform.connection.startswith("ansible.netcommon."):
            collections.add("ansible.netcommon")
        if options.by_platform:
            target = inventory.groups[group(platform.group, variables=platform_vars(platform, options))]
            for name in members:
                _add_host(target, name)
    inventory.collections = sorted(collections)
    return inventory


def _add_host(target, name):
    if name not in target.hosts:
        target.hosts.append(name)


def platform_vars(platform, options):
    variables = {}
    if platform.network_os:
        variables["ansible_network_os"] = platform.network_os
    if platform.connection:
        variables["ansible_connection"] = platform.connection
    variables.update(platform.extra)
    if options.become and platform.enable:
        variables["ansible_become"] = True
        variables["ansible_become_method"] = "enable"
    return variables


def header(inventory, made_by="NOMAD", sources=""):
    """Comment lines for the top of the file: where it came from, the collections it needs, and passwords."""
    lines = [f"Ansible inventory made by {made_by}" + (f" from {sources}" if sources else "") + "."]
    if inventory.collections:
        lines.append("Collections it needs: ansible-galaxy collection install " + " ".join(inventory.collections))
    lines.append("Passwords aren't kept here: run with --ask-pass (-k), or keep ansible_password in an "
                 "ansible-vault file.")
    return ["# " + line for line in lines]


def render(inventory, fmt=YAML, comments=()):
    text = render_ini(inventory) if fmt == INI else render_yaml(inventory)
    return "".join(line + "\n" for line in comments) + ("\n" if comments else "") + text


# ----------------------------------------------------------------- YAML

YAML_WORDS = {"y", "n", "yes", "no", "true", "false", "on", "off", "null", "~", ""}
YAML_SPECIAL = re.compile(  # What YAML 1.1 (as Ansible reads it) or 1.2 would take as a number, date or so on
    r"[-+]?(0|[1-9][0-9_]*)|0[0-7_]+|0x[0-9a-f_]+|0b[01_]+|[-+]?([0-9][0-9_]*)?\.[0-9_]*(e[-+]?[0-9]+)?"
    r"|[-+]?[0-9][0-9_]*e[-+]?[0-9]+"
    r"|[-+]?\.(inf|nan)|\d{4}-\d\d?-\d\d?.*|[-+]?[0-9][0-9_]*(:[0-5]?[0-9])+(\.[0-9_]*)?")
YAML_PLAIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./@+-]*")


def yaml_scalar(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if YAML_PLAIN.fullmatch(text) and text.lower() not in YAML_WORDS and not YAML_SPECIAL.fullmatch(text.lower()):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_yaml(inventory):
    lines = ["all:"]
    if inventory.all_vars:
        lines.append("  vars:")
        lines += _yaml_vars(inventory.all_vars, 4)
    if inventory.hosts:
        lines.append("  hosts:")
        for name, variables in sorted(inventory.hosts.items(), key=lambda item: item[0].lower()):
            lines.append(f"    {yaml_scalar(name)}:")
            lines += _yaml_vars(variables, 6)
    if inventory.top:
        lines.append("  children:")
        for name in inventory.top:
            _yaml_group(inventory, name, 4, lines)
    return "\n".join(lines) + "\n"


def _yaml_vars(variables, indent):
    return [f"{' ' * indent}{name}: {yaml_scalar(value)}" for name, value in variables.items()]


def _yaml_group(inventory, name, indent, lines):
    group = inventory.groups[name]
    pad = " " * indent
    lines.append(f"{pad}{name}:")
    if group.vars:
        lines.append(f"{pad}  vars:")
        lines += _yaml_vars(group.vars, indent + 4)
    if group.hosts:
        lines.append(f"{pad}  hosts:")
        lines += [f"{pad}    {yaml_scalar(host)}:" for host in sorted(group.hosts, key=str.lower)]
    if group.children:
        lines.append(f"{pad}  children:")
        for child in group.children:
            _yaml_group(inventory, child, indent + 4, lines)


# ----------------------------------------------------------------- INI

def ini_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text and not re.search(r"[\s\"'#;=\\]", text):
        return text
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_ini(inventory):
    """Hosts with their variables first (they leave "ungrouped" when a group below takes them), then every group:
    its hosts, its children and its variables."""
    lines = []
    for name, variables in sorted(inventory.hosts.items(), key=lambda item: item[0].lower()):
        lines.append(" ".join([name] + [f"{variable}={ini_value(value)}" for variable, value in variables.items()]))
    sections = []
    if inventory.all_vars:
        sections.append(["[all:vars]"] + [f"{name}={ini_value(value)}" for name, value in inventory.all_vars.items()])
    for name in _group_order(inventory):
        group = inventory.groups[name]
        if group.hosts or not group.children:
            sections.append([f"[{name}]"] + sorted(group.hosts, key=str.lower))
        if group.children:
            sections.append([f"[{name}:children]"] + group.children)
        if group.vars:
            sections.append([f"[{name}:vars]"] + [f"{variable}={ini_value(value)}"
                                                  for variable, value in group.vars.items()])
    blocks = (["\n".join(lines)] if lines else []) + ["\n".join(section) for section in sections]
    return "\n\n".join(blocks) + "\n"


def _group_order(inventory):
    """Each top group followed by the groups in it, depth first."""
    order = []

    def visit(name):
        if name not in order:
            order.append(name)
            for child in inventory.groups[name].children:
                visit(child)
    for name in inventory.top:
        visit(name)
    return order
