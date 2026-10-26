"""A device's hardware read at its command line, for the ones whose SNMP doesn't say (no ENTITY-MIB, no serial
numbers, or no SNMP at all): Cisco IOS, IOS XE, NX-OS and ASA's show inventory (each chassis, stack member, module,
power supply, fan and transceiver, with its model and serial number) and show version (the software it runs, its
hostname, and each stack member's base MAC).

What it finds is put in the same shape as the SNMP read's (hardware.parts), so the map and the Assets page treat it
the same. Nothing is changed on the device: both are show commands. Qt-free.
"""
import re

from ..oui import format_mac
from . import hardware

INVENTORY_COMMANDS = ["show inventory"]
VERSION_COMMANDS = ["show version"]
INVENTORY_TIMEOUT = 60  # A big chassis' inventory takes a while

NAME_LINE = re.compile(r'^\s*NAME:\s*"(?P<name>[^"]*)"\s*,\s*DESCR:\s*"(?P<descr>[^"]*)"', re.IGNORECASE)
PID_LINE = re.compile(r"^\s*PID:\s*(?P<pid>[^,]*?)\s*,\s*VID:\s*(?P<vid>[^,]*?)\s*,\s*SN:\s*(?P<sn>\S*)",
                      re.IGNORECASE)
MEMBER_NAME = re.compile(r"^(?:switch\s*)?(\d+)$", re.IGNORECASE)  # "Switch 2", or a 3750's "2"
MEMBER_PREFIX = re.compile(r"^switch\s*(\d+)\b", re.IGNORECASE)  # "Switch 2 - Power Supply A"
PORT_NAME = re.compile(r"^(?:[A-Za-z][A-Za-z\-]*)?(\d+)(?:/\d+)+$")  # "Te1/1/1", "GigabitEthernet2/0/49", "Ethernet1/49"
TRANSCEIVER_WORDS = re.compile(r"\b(?:transceiver|sfp\+?|qsfp\d*|gbic|xfp|cfp\d*)\b|^(?:sfp|qsfp|glc|cvr|xfp)-",
                               re.IGNORECASE)
POWER_WORDS = re.compile(r"power[ -]?supply|\bpsu\b|^pwr-|^ps-|^nxa-pac|^nxa-pdc|^n\d+k-pac", re.IGNORECASE)
FAN_WORDS = re.compile(r"\bfan|fan\b|-fan", re.IGNORECASE)
CHASSIS_WORDS = re.compile(r"\bchassis\b|^switch system$", re.IGNORECASE)
STACK_WORDS = re.compile(r"\bstack$", re.IGNORECASE)  # "c93xx Stack": the stack itself, with the active's serial

NXOS_VERSION = re.compile(r"^\s*(?:NXOS|system):\s+version\s+(\S+)", re.IGNORECASE | re.MULTILINE)
UPTIME = re.compile(r"^(\S+)\s+uptime is\b", re.MULTILINE)
NOT_HOSTNAMES = {"kernel", "system", "switch", "device", "router"}  # NX-OS: "Kernel uptime is ..."
PROMPT_END = re.compile(r"(?:\([^)]*\))?[>#]$")  # "sw1#", "sw1>", "fw1(config)#"
ACTIVE_MEMBER = re.compile(r"^\*\s+(\d+)\s", re.MULTILINE)  # The stack table's active member, starred
MEMBER_SECTION = re.compile(r"^Switch\s+0*(\d+)\s*\n-{3,}", re.IGNORECASE | re.MULTILINE)
BASE_MAC = re.compile(r"^\s*Base\s+ethernet\s+MAC\s+Address\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
BOARD_SERIAL = re.compile(r"^\s*(?:System\s+serial\s+number\s*:|Processor\s+board\s+ID)\s*(\S+)",
                          re.IGNORECASE | re.MULTILINE)
MODEL = re.compile(r"^\s*Model\s+number\s*:\s*(\S+)|^cisco\s+(\S+)\s+\(.*\)\s+processor", re.IGNORECASE | re.MULTILINE)


def inventory_entries(text):
    """[(name, descr, pid, vid, serial)] in the order show inventory lists them."""
    entries, current = [], None
    for line in (text or "").splitlines():
        match = NAME_LINE.match(line)
        if match:
            current = [match["name"].strip(), match["descr"].strip()]
            continue
        match = PID_LINE.match(line)
        if match and current is not None:
            entries.append((current[0], current[1], hardware.clean(match["pid"]), hardware.clean(match["vid"]),
                            hardware.clean(match["sn"])))
            current = None
    return entries


def part_class(name, descr, pid):
    """What an inventory entry is: hardware.CHASSIS, POWER, FAN, TRANSCEIVER or MODULE (None for the stack itself)."""
    if STACK_WORDS.search(name) and STACK_WORDS.search(descr):
        return None
    if MEMBER_NAME.match(name) or CHASSIS_WORDS.search(name):
        return hardware.CHASSIS
    words = " ".join((name, descr, pid))
    if POWER_WORDS.search(name) or POWER_WORDS.search(descr) or POWER_WORDS.search(pid):
        return hardware.POWER
    if FAN_WORDS.search(name) or FAN_WORDS.search(descr) or "FAN" in pid.upper():
        return hardware.FAN
    if PORT_NAME.match(name) or TRANSCEIVER_WORDS.search(words):
        return hardware.TRANSCEIVER
    if CHASSIS_WORDS.search(descr):  # Last: NX-OS describes its power supplies as "... chassis Power Supply"
        return hardware.CHASSIS
    return hardware.MODULE


def member_of(name):
    """The stack member an entry's name says it's in ("Switch 2 - Power Supply A", "Te2/1/1"), or 0."""
    for pattern in (MEMBER_NAME, MEMBER_PREFIX, PORT_NAME):
        match = pattern.match(name)
        if match:
            return int(match.group(1))
    return 0


def parse_inventory(text):
    """A device's chassis and parts from show inventory, as hardware.parts gives them (chassis first). An inventory
    that names no chassis has its first entry with a serial number stand for it."""
    found = []
    for index, (name, descr, pid, vid, serial) in enumerate(inventory_entries(text), start=1):
        kind = part_class(name, descr, pid)
        if kind is None:
            continue
        found.append({"index": index, "class": kind, "name": name, "descr": descr, "model": pid, "serial": serial,
                      "hardware": vid, "firmware": "", "software": "", "maker": "Cisco",
                      "position": member_of(name) if kind == hardware.CHASSIS else 0, "chassis": 0})
    if found and not hardware.chassis(found):
        first = next((part for part in found if part["serial"]), found[0])
        first["class"] = hardware.CHASSIS
    members = hardware.chassis(found)
    by_number = {part["position"]: part for part in members if part["position"]}
    for part in found:
        if part["class"] == hardware.CHASSIS:
            continue
        member = by_number.get(member_of(part["name"])) if len(members) > 1 else None
        part["chassis"] = (member or members[0])["index"] if members else 0
    found.sort(key=lambda part: (part["class"] != hardware.CHASSIS, part["chassis"], part["index"]))
    return found


def parse_version(text):
    """{"software", "hostname", "os", "macs" ({stack member: base MAC}), "serial", "model"} from show version ("" or
    {} for what it doesn't say)."""
    text = text or ""
    match = NXOS_VERSION.search(text)
    software = match.group(1) if match else hardware.software_version(text)
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    os_name = first.split(",")[0] if first.lower().startswith("cisco") else ""
    os_name = re.sub(r"\s+Version\s+\S+.*$", "", os_name, flags=re.IGNORECASE)
    hostname = next((name for name in UPTIME.findall(text) if name.lower() not in NOT_HOSTNAMES), "")
    macs = {}
    sections = list(MEMBER_SECTION.finditer(text))
    active = ACTIVE_MEMBER.search(text)
    head = text[:sections[0].start()] if sections else text
    mac = BASE_MAC.search(head)
    if mac and format_mac(mac.group(1)):
        macs[int(active.group(1)) if active else 1] = format_mac(mac.group(1))
    for at, section in enumerate(sections):
        end = sections[at + 1].start() if at + 1 < len(sections) else len(text)
        mac = BASE_MAC.search(text[section.end():end])
        if mac and format_mac(mac.group(1)):
            macs[int(section.group(1))] = format_mac(mac.group(1))
    serial = BOARD_SERIAL.search(head)
    model = MODEL.search(head)
    return {"software": software, "hostname": hostname, "os": os_name, "macs": macs,
            "serial": hardware.clean(serial.group(1)) if serial else "",
            "model": hardware.clean(next((group for group in model.groups() if group), "")) if model else ""}


def device_hardware(inventory_text, version_text):
    """(parts, version info) of a device from its show inventory and show version: parts as hardware.parts gives them,
    each chassis with its base MAC where show version says it."""
    parts = parse_inventory(inventory_text)
    info = parse_version(version_text)
    if not parts and (info["serial"] or info["model"]):  # No inventory (an old image): show version's word for it
        parts = [hardware.blank_chassis(info["serial"], info["model"])]
        parts[0].update(index=1, maker="Cisco")
    members = hardware.chassis(parts)
    macs = info["macs"]
    if len(members) == 1:
        hardware.set_chassis_macs(parts, base=next(iter(macs.values()), ""))
    else:
        stack = {part["index"]: macs[part["position"]] for part in members if part["position"] in macs}
        hardware.set_chassis_macs(parts, stack)
    return parts, info


def read_device(asker, address, names=()):
    """(parts, version info, problem) of one device over SSH (asker: a macssh.SshAsker): problem is "" when it was
    read, or why it couldn't be."""
    inventory = asker.run(address, INVENTORY_COMMANDS, names, INVENTORY_TIMEOUT)
    if inventory is None:
        return [], {}, asker.problems.get(address) or "Couldn't log in."
    version = asker.run(address, VERSION_COMMANDS, names) or ""
    parts, info = device_hardware(inventory, version)
    shell = asker.shells.get(address)
    prompt = PROMPT_END.sub("", getattr(shell, "prompt", "") or "").strip()
    if prompt and " " not in prompt:
        info["hostname"] = prompt  # As it names itself at its prompt
    if not parts:
        return [], info, ("It didn't answer show inventory with any hardware (not a Cisco device?)." if not inventory
                          else "Its show inventory listed nothing NOMAD could read.")
    return parts, info, ""
