"""A device's hardware and software, as the map keeps it: the model and serial number of each chassis (one per stack
member) and, with them, its modules, power supplies, fans and transceivers, from ENTITY-MIB; and the software version
it runs, from sysDescr (where Cisco, Juniper, Arista and HPE write it), a vendor MIB (PAN-OS, FortiOS) or the
chassis' own entPhysicalSoftwareRev.

Phones and other end devices say what they are to the switch they're plugged into: CDP gives their model and
software, and LLDP-MED their serial number too (LLDP-EXT-MED-MIB, read from the switch).

Each chassis' base MAC is kept with it: the first of the block of MACs burned into it, which its ports and VLAN
interfaces take theirs from, so it stays with the hardware as its serial number does. A stack's members each give
theirs in CISCO-STACKWISE-MIB; a device on its own gives it as its LLDP chassis ID or its bridge address. (A stack's
own bridge address is the active member's, or a MAC set by hand, so it moves: it's no one member's.)

The parsers take the (oid, Value) pairs a walk or get returns, like collect's, so they can be tested without a network.
"""
import re

from ..oui import normalize_mac
from ..snmp import parse_oid
from .collect import column, columns, mac_text, text

ENT_PHYSICAL_ENTRY = "1.3.6.1.2.1.47.1.1.1.1"  # entPhysicalTable (index entPhysicalIndex)
DESCR, CONTAINED_IN, CLASS, POSITION, NAME = 2, 4, 5, 6, 7
HARDWARE_REV, FIRMWARE_REV, SOFTWARE_REV, SERIAL, MAKER, MODEL = 8, 9, 10, 11, 12, 13
DETAIL_COLUMNS = (DESCR, POSITION, NAME, HARDWARE_REV, FIRMWARE_REV, SOFTWARE_REV, MAKER, MODEL)
# entPhysicalClass values, and what the map calls the ones it keeps
OTHER, CHASSIS_CLASS, POWER_CLASS, FAN_CLASS, MODULE_CLASS, PORT_CLASS = 1, 3, 6, 7, 9, 10
CHASSIS, MODULE, POWER, FAN, TRANSCEIVER = "chassis", "module", "power supply", "fan", "transceiver"
PART_CLASSES = {CHASSIS_CLASS: CHASSIS, MODULE_CLASS: MODULE, POWER_CLASS: POWER, FAN_CLASS: FAN,
                PORT_CLASS: TRANSCEIVER, OTHER: MODULE}
PART_NAMES = {CHASSIS: "Chassis", MODULE: "Module", POWER: "Power supply", FAN: "Fan", TRANSCEIVER: "Transceiver"}
GET_BATCH = 12  # OIDs asked for in one GET: well inside what any agent's reply can hold

# Vendors that keep the software version (and serial) in their own MIB, not in sysDescr
PAN_SW_VERSION, PAN_SERIAL = "1.3.6.1.4.1.25461.2.1.2.1.1.0", "1.3.6.1.4.1.25461.2.1.2.1.3.0"  # PAN-COMMON-MIB
FORTI_VERSION = "1.3.6.1.4.1.12356.101.4.1.1.0"  # FORTINET-FORTIGATE-MIB fgSysVersion
FORTI_SERIAL = "1.3.6.1.4.1.12356.100.1.1.1.0"  # FORTINET-CORE-MIB fnSysSerial
# ArubaOS: WLSX-SYSTEMEXT-MIB wlsxSysExtSerialNumber. Its version (wlsxSysExtSwVersion, "8.10.0.15 LSR") leaves out
# the "-FIPS" sysDescr and its APs' table give, so sysDescr's is kept, to match theirs
ARUBA_SERIAL = "1.3.6.1.4.1.14823.2.2.1.2.1.29.0"
VENDOR_SCALARS = {"1.3.6.1.4.1.25461": (PAN_SW_VERSION, PAN_SERIAL), "1.3.6.1.4.1.12356": (FORTI_VERSION, FORTI_SERIAL),
                  "1.3.6.1.4.1.14823": ("", ARUBA_SERIAL)}

# Base MACs: CISCO-STACKWISE-MIB cswSwitchMacAddress (index entPhysicalIndex: the member's chassis), LLDP-MIB's local
# chassis ID (a MAC when its subtype is 4) and BRIDGE-MIB dot1dBaseBridgeAddress
STACK_MAC = "1.3.6.1.4.1.9.9.500.1.2.1.1.7"
LLDP_LOC_CHASSIS_SUBTYPE, LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.1.0", "1.0.8802.1.1.2.1.3.2.0"
BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"
LLDP_MAC_SUBTYPE = 4
MAC_BLOCK = 0x1000  # How far past its base MAC a chassis' own MACs can be
BASE, MANAGEMENT = "base", "management interface"  # Where a chassis' MAC came from

# LLDP-EXT-MED-MIB lldpXMedRemInventoryTable (index: time mark, local port, remote index), as a switch has it for each
# LLDP-MED neighbor (phones, mostly): 1 hardware, 2 firmware, 3 software revision, 4 serial, 5 maker, 6 model
LLDP_MED_INVENTORY_ENTRY = "1.0.8802.1.1.2.1.5.4795.1.3.3.1"
# A neighbor's CDP name with its serial number, as Nexus switches send it: "sw1(FOC1234X0YZ)"
SERIAL_IN_NAME = re.compile(r"\(([A-Za-z0-9]{8,14})\)\s*$")

VERSION_PATTERNS = [
    re.compile(r"\bJUNOS\s+([0-9][\w.\-]*)", re.IGNORECASE),  # Junos: "kernel JUNOS 21.4R3-S1.5"
    re.compile(r"\brevision\s+([A-Z]{2}\.[0-9][\w.]*)"),  # HPE/Aruba ProCurve: "revision WC.16.10.0012"
    re.compile(r"\bVersion\s+([0-9][\w.()\-:]*[\w)])", re.IGNORECASE),  # Cisco, Arista: "Version 17.9.4a,"
]
PLACEHOLDERS = {"", "n/a", "na", "none", "unknown", "not available", "0", "-"}


def software_version(descr):
    """The software version a device's sysDescr (or a neighbor's CDP version) names: "17.9.4a", "15.2(7)E4",
    "9.3(8)", "21.4R3-S1.5", or "" when it names none."""
    for pattern in VERSION_PATTERNS:
        match = pattern.search(descr or "")
        if match:
            return match.group(1)
    return ""


def neighbor_software(version_text):
    """What a CDP neighbor's version says it runs: the version in it, or for a phone (whose CDP version is just its
    firmware's name, "sip88xx.14-1-1-0001-136") the first line as it is."""
    found = software_version(version_text)
    if found:
        return found
    first = (version_text or "").strip().splitlines()[0].strip() if (version_text or "").strip() else ""
    return first[:60] if len(first) <= 60 and " " not in first.strip() else ""


def serial_in_name(name):
    """The serial number a CDP name carries ("sw1(FOC1234X0YZ)" -> "FOC1234X0YZ"), or ""."""
    match = SERIAL_IN_NAME.search(name or "")
    return match.group(1).upper() if match else ""


def clean(value):
    """A value as kept: "" for the placeholders agents fill empty fields with."""
    value = (value or "").strip()
    return "" if value.lower() in PLACEHOLDERS else value


def _numbers(rows, number):
    return {index[0]: value.value for index, value in column(rows, f"{ENT_PHYSICAL_ENTRY}.{number}").items()
            if len(index) == 1}


def _serials(rows):
    return {index[0]: clean(text(value)) for index, value in column(rows, f"{ENT_PHYSICAL_ENTRY}.{SERIAL}").items()
            if len(index) == 1}


def _choose(classes, parents, serials):
    """(the indexes worth reading in full, the one standing in for the chassis or None): see chosen_indexes."""
    chosen = [index for index, kind in classes.items() if kind == CHASSIS_CLASS]
    chosen += [index for index, kind in classes.items() if kind in PART_CLASSES and kind != CHASSIS_CLASS
               and serials.get(index)]
    stand_in = None
    if chosen and not any(classes.get(index) == CHASSIS_CLASS for index in chosen):
        wanted = set(chosen)
        outermost = [index for index in chosen if not _ancestor_in(parents, index, wanted)]
        stand_in = min(outermost) if outermost else None
    return sorted(set(chosen)), stand_in


def chosen_indexes(class_rows, serial_rows, contained_rows=()):
    """The entPhysicalIndexes worth reading in full: every chassis, and the parts with a serial number (modules,
    power supplies, fans, and ports with one, which are transceivers). Sensors, containers and plain ports are left
    out: a big chassis has thousands."""
    return _choose(_numbers(class_rows, CLASS), _numbers(contained_rows, CONTAINED_IN), _serials(serial_rows))[0]


def _ancestor_in(parents, index, wanted):
    seen = set()
    parent = parents.get(index, 0)
    while parent and parent not in seen:
        if parent in wanted:
            return True
        seen.add(parent)
        parent = parents.get(parent, 0)
    return False


def detail_oids(indexes, columns_wanted=DETAIL_COLUMNS):
    """The OIDs to GET for the chosen rows' details."""
    entry = parse_oid(ENT_PHYSICAL_ENTRY)
    return [entry + (number, index) for index in indexes for number in columns_wanted]


def parts(class_rows, contained_rows, serial_rows, detail_rows):
    """The device's chassis and parts as the map keeps them: [{"index", "class" (CHASSIS, MODULE, POWER, FAN or
    TRANSCEIVER), "name", "descr", "model", "serial", "hardware", "firmware", "software", "maker", "position",
    "chassis" (the entPhysicalIndex of the chassis it's in, 0 for a chassis itself or when it can't be told)}],
    chassis first. detail_rows: the chosen rows' details (walked or got). When the table lists no chassis (some
    agents list just modules), the outermost part with a serial number stands for it."""
    classes, parents = _numbers(class_rows, CLASS), _numbers(contained_rows, CONTAINED_IN)
    serials = _serials(serial_rows)
    details = {index[0]: row for index, row in columns(detail_rows, ENT_PHYSICAL_ENTRY).items() if len(index) == 1}
    chosen, stand_in = _choose(classes, parents, serials)
    chassis_indexes = {index for index in chosen if classes.get(index) == CHASSIS_CLASS or index == stand_in}
    found = []
    for index in chosen:
        row = details.get(index, {})
        position = row[POSITION].value if POSITION in row and isinstance(row[POSITION].value, int) else 0
        found.append({"index": index,
                      "class": CHASSIS if index in chassis_indexes else PART_CLASSES.get(classes.get(index), MODULE),
                      "name": clean(text(row.get(NAME))), "descr": clean(text(row.get(DESCR))),
                      "model": clean(text(row.get(MODEL))), "serial": serials.get(index, ""),
                      "hardware": clean(text(row.get(HARDWARE_REV))), "firmware": clean(text(row.get(FIRMWARE_REV))),
                      "software": clean(text(row.get(SOFTWARE_REV))), "maker": clean(text(row.get(MAKER))),
                      "position": max(position, 0), "chassis": 0})
    for part in found:
        if part["class"] != CHASSIS:
            part["chassis"] = _chassis_of(parents, part["index"], chassis_indexes)
    found.sort(key=lambda part: (part["class"] != CHASSIS, part["chassis"], part["index"]))
    return found


def _chassis_of(parents, index, chassis_indexes):
    """The chassis an entity is in (following entPhysicalContainedIn up), or the only chassis there is, or 0."""
    seen = set()
    parent = parents.get(index, 0)
    while parent and parent not in seen:
        if parent in chassis_indexes:
            return parent
        seen.add(parent)
        parent = parents.get(parent, 0)
    return next(iter(chassis_indexes)) if len(chassis_indexes) == 1 else 0


def blank_chassis(serial="", model=""):
    """A chassis known only from elsewhere (a vendor MIB's serial number): what parts would have listed."""
    return {"index": 0, "class": CHASSIS, "name": "", "descr": "", "model": model, "serial": serial, "hardware": "",
            "firmware": "", "software": "", "maker": "", "position": 0, "chassis": 0}


def chassis(device_parts):
    """The chassis among a device's parts, in order (a stack's members, or the one chassis)."""
    return [part for part in device_parts if part.get("class") == CHASSIS]


def vendor_scalars(object_id):
    """(version OID, serial OID) of the vendor MIB a device keeps them in ("" for one it doesn't), or None."""
    return next((oids for prefix, oids in VENDOR_SCALARS.items() if (object_id + ".").startswith(prefix + ".")), None)


def device_software(descr, device_parts=(), vendor_version=""):
    """The software version a device runs: its vendor MIB's, else what sysDescr says, else its first chassis'
    entPhysicalSoftwareRev."""
    version = clean(vendor_version)
    if version:
        return version.split(",")[0].lstrip("vV")  # FortiOS: "v7.2.5,build1517,230606 (GA.F)"
    found = software_version(descr)
    if found:
        return found
    return next((part["software"] for part in chassis(device_parts) if part.get("software")), "")


def _real_mac(raw):
    mac = mac_text(raw)
    return "" if not mac or not normalize_mac(mac).strip("0") else mac


def stack_macs(rows):
    """{entPhysicalIndex: base MAC} of a stack's members, from a walk of cswSwitchMacAddress."""
    found = {}
    for index, value in column(rows, STACK_MAC).items():
        mac = _real_mac(value.value) if len(index) == 1 and not value.is_exception else ""
        if mac:
            found[index[0]] = mac
    return found


def base_mac(values):
    """A device's base MAC: its LLDP chassis ID when that's a MAC, else its bridge address, else "". values: {OID
    text: Value} got of LLDP_LOC_CHASSIS_SUBTYPE, LLDP_LOC_CHASSIS_ID and BRIDGE_ADDRESS."""
    def value_of(oid):
        value = values.get(oid)
        return None if value is None or value.is_exception else value.value
    if value_of(LLDP_LOC_CHASSIS_SUBTYPE) == LLDP_MAC_SUBTYPE:
        mac = _real_mac(value_of(LLDP_LOC_CHASSIS_ID))
        if mac:
            return mac
    return _real_mac(value_of(BRIDGE_ADDRESS))


def management_mac(address, addresses, interface_macs):
    """The MAC of the interface a device was asked on (addresses: [(ip, ifIndex, mask)]; interface_macs: {ifIndex:
    MAC}), or "" (a loopback has none)."""
    return next((interface_macs.get(if_index, "") for ip, if_index, _ in addresses if ip == address), "")


def mac_number(mac):
    digits = normalize_mac(mac)
    return int(digits, 16) if digits else -1


def set_chassis_macs(device_parts, stack=None, base="", management="", own_macs=()):
    """Put each chassis' MAC on it: "mac" (a stack member's from stack, {entPhysicalIndex: MAC}; a chassis on its own
    the device's base MAC, else the MAC of the interface it was asked on), "mac_source" (BASE or MANAGEMENT) and
    "mac_last", the last of its own MACs seen (own_macs: its interfaces'), so that a MAC of one of its ports or VLAN
    interfaces can be told to be the chassis'. A stack's members get no MAC but their own."""
    stack = stack or {}
    members = chassis(device_parts)
    for part in members:
        mac, source = stack.get(part["index"], ""), BASE
        if not mac and len(members) == 1:
            mac, source = (base, BASE) if base else (management, MANAGEMENT)
        part["mac"], part["mac_source"], part["mac_last"] = mac, source if mac else "", ""
    starts = sorted(((mac_number(part["mac"]), part) for part in members if part["mac_source"] == BASE),
                    key=lambda pair: pair[0])
    for mac in own_macs:
        number = mac_number(mac)
        owner = None
        for start, part in starts:  # The nearest base MAC below it
            if start <= number < start + MAC_BLOCK:
                owner = part
        if owner is not None and number > mac_number(owner["mac_last"] or owner["mac"]):
            owner["mac_last"] = mac


def owns_mac(part, mac):
    """Whether a MAC is one of a chassis' own: its MAC, or (a base MAC) one of the block from it to the last of its
    MACs seen."""
    number, start = mac_number(mac), mac_number(part.get("mac", ""))
    if number < 0 or start < 0:
        return False
    if number == start:
        return True
    return part.get("mac_source") == BASE and start < number <= mac_number(part.get("mac_last", ""))


def med_inventory(rows):
    """{(local port, remote index): {"hardware", "firmware", "software", "serial", "maker", "model"}} from a walk of
    lldpXMedRemInventoryTable: what each LLDP-MED neighbor (a phone) says it is."""
    found = {}
    names = {1: "hardware", 2: "firmware", 3: "software", 4: "serial", 5: "maker", 6: "model"}
    for index, row in columns(rows, LLDP_MED_INVENTORY_ENTRY).items():
        if len(index) != 3:
            continue
        values = {name: clean(text(row.get(number))) for number, name in names.items()}
        if any(values.values()):
            found[(index[1], index[2])] = values
    return found
