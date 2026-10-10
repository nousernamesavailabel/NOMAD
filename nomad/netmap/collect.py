"""Reading a device's SNMP tables for the map: its identity, CDP/LLDP neighbors, VLANs, MAC table and ARP table.

The parsers take the (oid, Value) pairs a walk returns, so they can be tested without a network.
"""
import ipaddress
import socket
from dataclasses import dataclass, field

from ..oui import format_mac
from ..snmp import IP_ADDRESS, OBJECT_ID, oid_text, parse_oid
from .model import AP, FIREWALL, HOST, PHONE, ROUTER, SWITCH, UNKNOWN, normalize_vtp_domain

SYS_DESCR, SYS_OBJECT_ID, SYS_NAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_STACK_STATUS = "1.3.6.1.2.1.31.1.2.1.3"  # Index: higher layer ifIndex, lower layer ifIndex (port-channel members)
LAG_ATTACHED = "1.2.840.10006.300.43.1.2.1.1.13"  # dot3adAggPortAttachedAggID: member ifIndex -> aggregate ifIndex
IP_ADDR_ENTRY = "1.3.6.1.2.1.4.20.1"
ARP_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"
FDB_ENTRY = "1.3.6.1.2.1.17.4.3.1"
Q_FDB_ENTRY = "1.3.6.1.2.1.17.7.1.2.2.1"  # Q-BRIDGE-MIB dot1qTpFdbTable: index is VLAN then MAC, so VLANs are known
BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
CDP_CACHE_ENTRY = "1.3.6.1.4.1.9.9.23.1.2.1.1"
VTP_DOMAIN_ENTRY = "1.3.6.1.4.1.9.9.46.1.2.1.1"  # managementDomainTable: 2 name, 3 local mode (index: domain)
VTP_VLAN_STATE = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"
VTP_VLAN_NAME = "1.3.6.1.4.1.9.9.46.1.3.1.1.4"  # vtpVlanName (index: domain, VLAN)
VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"  # CISCO-VLAN-MEMBERSHIP-MIB vmVlan: an access port's VLAN (index ifIndex)
VM_VOICE_VLAN = "1.3.6.1.4.1.9.9.68.1.5.1.1.1"  # vmVoiceVlanId: a port's voice VLAN
TRUNK_PORT_ENTRY = "1.3.6.1.4.1.9.9.46.1.6.1.1"  # vlanTrunkPortTable (index ifIndex)
TRUNK_NATIVE_VLAN = "1.3.6.1.4.1.9.9.46.1.6.1.1.5"  # vlanTrunkPortNativeVlan
# vlanTrunkPortTable's columns: VLANs allowed (bitmaps of VLANs 0-1023, 1024-2047, 2048-3071, 3072-4095), native
# VLAN, and whether it's trunking (1) or not (2)
TRUNK_ALLOWED_COLUMNS = {4: 0, 17: 1024, 18: 2048, 19: 3072}
TRUNK_NATIVE, TRUNK_STATUS = 5, 14
Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # Q-BRIDGE-MIB dot1qVlanStaticName (index VLAN)
Q_VLAN_EGRESS = "1.3.6.1.2.1.17.7.1.4.2.1.4"  # dot1qVlanCurrentEgressPorts (index time mark, VLAN): bridge ports
Q_VLAN_UNTAGGED = "1.3.6.1.2.1.17.7.1.4.2.1.5"  # dot1qVlanCurrentUntaggedPorts: of those, the ones sent untagged
Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # dot1qPvid (index bridge port): the VLAN untagged frames go in
VTP_MODES = {1: "client", 2: "server", 3: "transparent", 4: "off"}
STP_TYPE = "1.3.6.1.4.1.9.9.82.1.6.1"  # CISCO-STP-EXTENSIONS-MIB stpxSpanningTreeType (a scalar: .0)
STP_TYPES = {1: "pvst", 2: "mistp", 3: "mistp-pvst", 4: "mst", 5: "rapid-pvst"}
# stpxSMSTInstanceTable (index: MST instance): 2 a bitmap of VLANs 0-2047 mapped to it, 3 of VLANs 2048-4095
MST_INSTANCE_ENTRY = "1.3.6.1.4.1.9.9.82.1.14.5.1"
# stpxRSTPPortRoleValue (index: instance, which is the VLAN on Rapid-PVST or the MST instance on MST, then bridge port)
RSTP_PORT_ROLE = "1.3.6.1.4.1.9.9.82.1.12.2.1.3"
RSTP_ROLES = {1: "disabled", 2: "root", 3: "designated", 4: "alternate", 5: "backup", 6: "boundary", 7: "master"}
STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"  # BRIDGE-MIB dot1dStpPortState (index bridge port); per VLAN on PVST+
STP_STATES = {1: "disabled", 2: "blocking", 3: "listening", 4: "learning", 5: "forwarding", 6: "broken"}
FORWARDING, BLOCKING, DISABLED = "forwarding", "blocking", "disabled"  # A port's STP state, simplified
STP_ROOT_PORT = "1.3.6.1.2.1.17.2.7"  # BRIDGE-MIB dot1dStpRootPort (a scalar): 0 on the root bridge
# Interfaces: shut down or not, up or down, speed and duplex (the Link Speed overlay), and the counters monitoring
# polls on linked ports (the Utilization overlay)
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"  # Bits per second (tops out at 4.29 Gb/s)
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"  # Megabits per second
DOT3_DUPLEX = "1.3.6.1.2.1.10.7.2.1.19"  # EtherLike-MIB dot3StatsDuplexStatus: 1 unknown, 2 half, 3 full
IF_IN_DISCARDS, IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.13", "1.3.6.1.2.1.2.2.1.14"
IF_OUT_DISCARDS, IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.19", "1.3.6.1.2.1.2.2.1.20"
IF_HC_IN_OCTETS, IF_HC_OUT_OCTETS = "1.3.6.1.2.1.31.1.1.1.6", "1.3.6.1.2.1.31.1.1.1.10"
OPER_STATES = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "not present",
               7: "lower layer down"}
DUPLEXES = {2: "half", 3: "full"}
# VRFs: which interfaces are in which, and each VRF's routing table (ipCidrRouteTable has only the global one)
CV_VRF_NAME = "1.3.6.1.4.1.9.9.711.1.1.1.1.2"  # CISCO-VRF-MIB cvVrfName (index cvVrfIndex)
CV_VRF_INTERFACE_ENTRY = "1.3.6.1.4.1.9.9.711.1.2.1.1"  # cvVrfInterfaceTable (index cvVrfIndex, ifIndex)
L3VPN_IF_CLASSIFICATION = "1.3.6.1.2.1.10.166.11.1.2.1.1.2"  # MPLS-L3VPN-STD-MIB (index VRF name, ifIndex)
L3VPN_ROUTE_ENTRY = "1.3.6.1.2.1.10.166.11.1.4.1.1"  # mplsL3VpnVrfRteTable: 7 ifIndex, 8 type, 9 protocol
L3VPN_ROUTE_COLUMNS = (7, 8, 9)
ACCESS, TRUNK = "access", "trunk"
LLDP_LOC_PORT_ENTRY = "1.0.8802.1.1.2.1.3.7.1"
LLDP_REM_ENTRY = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN_ADDR_IF_SUBTYPE = "1.0.8802.1.1.2.1.4.2.1.3"
CIDR_ROUTE_ENTRY = "1.3.6.1.2.1.4.24.4.1"  # ipCidrRouteTable: index destination, mask, TOS, next hop
IP_ROUTE_ENTRY = "1.3.6.1.2.1.4.21.1"  # The older ipRouteTable, for devices without the one above
ROUTE_PROTOCOLS = {1: "other", 2: "connected", 3: "static", 4: "icmp", 8: "rip", 9: "is-is", 11: "igrp", 13: "ospf",
                   14: "bgp", 16: "eigrp"}

CISCO = "1.3.6.1.4.1.9"
PALO_ALTO = "1.3.6.1.4.1.25461"
RESERVED_VLANS = range(1002, 1006)  # FDDI/Token Ring defaults every Catalyst lists
FDB_LEARNED = 3
AP_WORDS = ("air-", "access point", "c9105", "c9115", "c9120", "c9130", "c9136", "c9162", "c9164", "c9166", "cw916")
# IOL and vIOS lab images name no model: their image names say which is the router (I86BI_LINUX-, VIOS-) and which
# the switch (I86BI_LINUXL2-, VIOS_L2-)
ROUTER_WORDS = ("isr", "asr1", "asr9", "csr1000", "c8200", "c8300", "c8500", "c8000", "c1100", "c1111", "c1121",
                "c1161", "router", "i86bi_linux-", "vios-adventerprise", "virtual xe")
SWITCH_WORDS = ("catalyst", "nexus", "nx-os", "switch", "c9200", "c9300", "c9400", "c9500", "c9600", "c2960",
                "c3560", "c3650", "c3750", "c3850", "c4500", "c6500", "c6800", "ws-c", "ie-", "cat9k", "cat3k",
                "linuxl2", "vios_l2", "viosl2")
# Operating systems a computer's LLDP agent names in its system description
HOST_WORDS = ("windows", "microsoft", "mac os", "macos", "darwin", "ubuntu", "debian", "red hat", "linux")

# CDP capability bits (cdpCacheCapabilities, a 4-byte bitmask)
CDP_CAPABILITIES = {0x01: "router", 0x02: "bridge", 0x04: "bridge", 0x08: "switch", 0x10: "host", 0x80: "phone"}
# LLDP system capabilities (a BITS value: the first byte's top bit is bit 0)
LLDP_CAPABILITIES = {2: "bridge", 3: "ap", 4: "router", 5: "phone", 7: "station"}


@dataclass
class Neighbor:
    local_port: str
    name: str
    port: str = ""
    address: str = ""
    platform: str = ""
    capabilities: frozenset = frozenset()
    protocol: str = "cdp"
    chassis_mac: str = ""  # LLDP chassis ID when it's a MAC address
    port_mac: str = ""  # LLDP port ID when it's a MAC address, as a computer's LLDP agent sends it


@dataclass
class SystemInfo:
    name: str = ""
    descr: str = ""
    object_id: str = ""


@dataclass
class DeviceTables:
    """Everything read from one device."""
    info: SystemInfo = field(default_factory=SystemInfo)
    interfaces: dict = field(default_factory=dict)  # ifIndex -> name
    addresses: list = field(default_factory=list)  # [(ip, ifIndex, mask)]
    neighbors: list = field(default_factory=list)  # [Neighbor]
    arp: dict = field(default_factory=dict)  # MAC -> [ip]
    fdb: list = field(default_factory=list)  # [(MAC, ifIndex, vlan)]
    own_macs: set = field(default_factory=set)
    lag_parents: dict = field(default_factory=dict)  # Member ifIndex -> aggregate ifIndex
    routes: list = field(default_factory=list)  # [(destination, next hop, ifIndex, protocol)]
    timings: dict = field(default_factory=dict)  # Step -> seconds, for the crawl log
    notes: list = field(default_factory=list)  # Worth a line in the crawl log
    routes_truncated: bool = False
    warnings: list = field(default_factory=list)
    vtp_domain: str = ""
    vtp_mode: str = ""
    vlan_names: dict = field(default_factory=dict)  # VLAN -> name, for the VLANs it has
    port_vlans: dict = field(default_factory=dict)  # ifIndex -> PortVlans
    vlans_in_use: list = field(default_factory=list)  # VLANs its ports are in (access, voice, trunks' native)
    interface_vrfs: dict = field(default_factory=dict)  # ifIndex -> VRF name, for interfaces in one
    vrf_routes: dict = field(default_factory=dict)  # VRF name -> [(destination, next hop, ifIndex, protocol)]
    routes_read: bool = False  # Set when routes were read (a crawl always reads them; Read Again only when asked)
    stp_mode: str = ""  # pvst, rapid-pvst, mst... (STP_TYPES), "" when it didn't say
    stp_instance: int = -1  # With an STP read for one VLAN: its spanning tree instance (the VLAN, or an MST instance)
    stp_ports: dict = field(default_factory=dict)  # ifIndex -> (FORWARDING, BLOCKING or DISABLED, role or state)
    stp_read: bool = False  # An STP read for one VLAN was made (stp_ports may still be empty)
    stp_root: object = None  # With that read: whether it's the root bridge of the VLAN's tree (None: unknown)
    port_status: dict = field(default_factory=dict)  # ifIndex -> {"oper", "speed" (Mb/s), "duplex"}: not shut down
    status_read: bool = False  # Its interfaces' status was read


@dataclass
class PortVlans:
    """A switch port's VLANs: an access port's VLAN (and voice VLAN), or a trunk's native and allowed VLANs."""
    mode: str = ""  # ACCESS, TRUNK, or "" when the switch didn't say
    vlan: int = 0  # An access port's VLAN
    voice: int = 0
    native: int = 0
    allowed: frozenset = frozenset()  # A trunk's


def text(value):
    """An OCTET STRING as text."""
    if value is None or value.is_exception:
        return ""
    if isinstance(value.value, bytes):
        return value.value.decode("utf-8", "replace").rstrip("\0").strip()
    return "" if value.value is None else str(value.value)


def mac_text(raw):
    return format_mac(raw.hex()) if isinstance(raw, bytes) and len(raw) == 6 else ""


def is_printable(raw):
    try:
        decoded = raw.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return False
    return bool(decoded.strip("\0")) and all(character.isprintable() for character in decoded.rstrip("\0"))


def columns(rows, entry):
    """Split a walked table into {index: {column: Value}}. Index is the tuple of OID numbers after the column."""
    entry = parse_oid(entry) if isinstance(entry, str) else tuple(entry)
    table = {}
    for oid, value in rows:
        if oid[:len(entry)] != entry or len(oid) <= len(entry) + 1 or value.is_exception:
            continue
        table.setdefault(oid[len(entry) + 1:], {})[oid[len(entry)]] = value
    return table


def column(rows, root):
    """One walked column as {index: Value}."""
    root = parse_oid(root) if isinstance(root, str) else tuple(root)
    return {oid[len(root):]: value for oid, value in rows
            if oid[:len(root)] == root and len(oid) > len(root) and not value.is_exception}


def system_info(results):
    """From a get of SYS_DESCR, SYS_OBJECT_ID and SYS_NAME."""
    info = SystemInfo()
    for oid, value in results:
        name = oid_text(oid)
        if name == SYS_NAME:
            info.name = text(value)
        elif name == SYS_DESCR:
            info.descr = text(value)
        elif name == SYS_OBJECT_ID and value.tag == OBJECT_ID:
            info.object_id = oid_text(value.value)
    return info


def interface_names(name_rows, descr_rows=()):
    """ifIndex -> ifName, falling back to ifDescr for interfaces without one."""
    names = {index[0]: text(value) for index, value in column(descr_rows, IF_DESCR).items() if len(index) == 1}
    for index, value in column(name_rows, IF_NAME).items():
        if len(index) == 1 and text(value):
            names[index[0]] = text(value)
    return names


def own_macs(rows):
    return {mac for mac in (mac_text(value.value) for value in column(rows, IF_PHYS_ADDRESS).values()) if mac}


def cdp_capabilities(value):
    if value is None or not isinstance(value.value, bytes):
        return frozenset()
    bits = int.from_bytes(value.value[-4:], "big")
    return frozenset(name for bit, name in CDP_CAPABILITIES.items() if bits & bit)


def lldp_capabilities(value):
    if value is None or not isinstance(value.value, bytes):
        return frozenset()
    raw = value.value
    found = set()
    for bit, name in LLDP_CAPABILITIES.items():
        byte, offset = divmod(bit, 8)
        if byte < len(raw) and raw[byte] & (0x80 >> offset):
            found.add(name)
    return frozenset(found)


def cdp_neighbors(rows, interfaces):
    """cdpCacheTable: index is (local ifIndex, device index)."""
    neighbors = []
    for index, row in sorted(columns(rows, CDP_CACHE_ENTRY).items()):
        name = text(row.get(6))
        if not name or len(index) != 2:
            continue
        address = ""
        raw = row.get(4)
        if raw is not None and isinstance(raw.value, bytes) and len(raw.value) == 4 \
                and (row.get(3) is None or row[3].value == 1):
            address = socket.inet_ntoa(raw.value)
        neighbors.append(Neighbor(local_port=interfaces.get(index[0], f"ifIndex {index[0]}"), name=name,
                                  port=text(row.get(7)), address=address, platform=text(row.get(8)),
                                  capabilities=cdp_capabilities(row.get(9)), protocol="cdp"))
    return neighbors


def lldp_local_ports(rows):
    """lldpLocPortTable: local port number -> interface name."""
    ports = {}
    for index, row in columns(rows, LLDP_LOC_PORT_ENTRY).items():
        port_id, description = row.get(3), text(row.get(4))
        subtype = row[2].value if 2 in row else 0
        name = text(port_id) if port_id is not None and subtype in (5, 7) and is_printable(port_id.value) else ""
        ports[index[0]] = name or description or text(port_id)
    return ports


def lldp_management_addresses(rows):
    """lldpRemManAddrTable, walked by one column: {(local port, remote index): [IPv4 addresses]}. The address is in the
    index (time mark, local port, remote index, address subtype, length, address bytes)."""
    addresses = {}
    for index in column(rows, LLDP_REM_MAN_ADDR_IF_SUBTYPE):
        if len(index) >= 9 and index[3] == 1 and index[4] == 4:
            address = ".".join(str(number) for number in index[5:9])
            found = addresses.setdefault((index[1], index[2]), [])
            if address not in found:
                found.append(address)
    return addresses


def lldp_neighbors(rows, local_ports, interfaces, management_addresses):
    """lldpRemTable: index is (time mark, local port number, remote index)."""
    neighbors = []
    for index, row in sorted(columns(rows, LLDP_REM_ENTRY).items()):
        if len(index) != 3:
            continue
        _, local, remote = index
        chassis = row.get(5)
        chassis_subtype = row[4].value if 4 in row else 0
        chassis_mac = mac_text(chassis.value) if chassis is not None and chassis_subtype == 4 else ""
        name = text(row.get(9)) or chassis_mac or (text(chassis) if chassis is not None
                                                    and is_printable(chassis.value) else "")
        if not name:
            continue
        port_id, port_subtype = row.get(7), (row[6].value if 6 in row else 0)
        port_mac = mac_text(port_id.value) if port_id is not None and port_subtype == 3 else ""
        if port_id is not None and port_subtype in (5, 7) and is_printable(port_id.value):
            port = text(port_id)
        elif port_id is not None and port_subtype == 3:
            port = text(row.get(8)) or port_mac
        else:
            port = text(row.get(8)) or (text(port_id) if port_id is not None and is_printable(port_id.value) else "")
        local_port = local_ports.get(local) or interfaces.get(local, f"port {local}")
        descr = text(row.get(10))
        for address in management_addresses.get((local, remote), []) or [""]:
            neighbors.append(Neighbor(local_port=local_port, name=name, port=port, address=address,
                                      platform=descr.splitlines()[0][:80] if descr else "",
                                      capabilities=lldp_capabilities(row.get(12)), protocol="lldp",
                                      chassis_mac=chassis_mac, port_mac=port_mac))
    return neighbors


def vlans(rows):
    """VLAN numbers from CISCO-VTP-MIB vtpVlanState (index: domain, VLAN), operational ones only."""
    found = set()
    for index, value in column(rows, VTP_VLAN_STATE).items():
        if len(index) == 2 and value.value == 1 and index[1] not in RESERVED_VLANS:
            found.add(index[1])
    return sorted(found)


def usable_vlan(value, highest=4094):
    """A VLAN number from a table, or 0 for none (or the FDDI/Token Ring ones every Catalyst lists)."""
    vlan = value.value if value is not None and isinstance(value.value, int) else 0
    return vlan if 1 <= vlan <= highest and vlan not in RESERVED_VLANS else 0


def vtp_domain(rows):
    """(VTP domain name, its mode here: server, client, transparent or off) from managementDomainTable."""
    for _, row in sorted(columns(rows, VTP_DOMAIN_ENTRY).items()):
        name = normalize_vtp_domain(text(row.get(2)))
        mode = VTP_MODES.get(row[3].value, "") if 3 in row else ""
        if name or mode:
            return name, mode
    return "", ""


def vlan_names(state_rows, name_rows=()):
    """{VLAN: name} for the operational VLANs in CISCO-VTP-MIB's vtpVlanTable (index: domain, VLAN)."""
    names = {index[1]: text(value) for index, value in column(name_rows, VTP_VLAN_NAME).items() if len(index) == 2}
    return {vlan: names.get(vlan, "") for vlan in vlans(state_rows)}


def q_vlan_names(rows):
    """{VLAN: name} from Q-BRIDGE-MIB's dot1qVlanStaticTable, for switches without CISCO-VTP-MIB."""
    return {index[0]: text(value) for index, value in column(rows, Q_VLAN_STATIC_NAME).items()
            if len(index) == 1 and 1 <= index[0] <= 4094}


def bitmap_members(raw, first=0):
    """The numbers set in a bitmap (the first byte's top bit stands for `first`): a trunk's VLANs, or a VLAN's
    bridge ports (which start at 1)."""
    if not isinstance(raw, bytes):
        return set()
    return {first + byte_number * 8 + bit for byte_number, byte in enumerate(raw) if byte
            for bit in range(8) if byte & (0x80 >> bit)}


def trunk_ports(rows):
    """vlanTrunkPortTable as {ifIndex: (trunking: True, False or None if unknown, native VLAN, allowed VLANs)}."""
    found = {}
    for index, row in columns(rows, TRUNK_PORT_ENTRY).items():
        if len(index) != 1:
            continue
        allowed = set()
        for number, first in TRUNK_ALLOWED_COLUMNS.items():
            if number in row:
                allowed |= bitmap_members(row[number].value, first)
        status = row[TRUNK_STATUS].value if TRUNK_STATUS in row else None
        found[index[0]] = (None if status not in (1, 2) else status == 1, usable_vlan(row.get(TRUNK_NATIVE)),
                           frozenset(vlan for vlan in allowed if 1 <= vlan <= 4094))
    return found


def cisco_port_vlans(trunk_rows, access_rows, voice_rows=()):
    """{ifIndex: PortVlans} for a Catalyst or Nexus: trunks from vlanTrunkPortTable, access ports from
    CISCO-VLAN-MEMBERSHIP-MIB."""
    access = {index[0]: usable_vlan(value) for index, value in column(access_rows, VM_VLAN).items()
              if len(index) == 1}
    voice = {index[0]: usable_vlan(value, 4093) for index, value in column(voice_rows, VM_VOICE_VLAN).items()
             if len(index) == 1}
    ports = {}
    for if_index, (trunking, native, allowed) in trunk_ports(trunk_rows).items():
        # Every switchport has a row: trunking says which are trunks (a row without it, and not an access port's)
        if trunking or (trunking is None and if_index not in access):
            ports[if_index] = PortVlans(TRUNK, native=native, allowed=allowed)
    for if_index, vlan in access.items():
        if vlan and if_index not in ports:
            ports[if_index] = PortVlans(ACCESS, vlan=vlan)
    for if_index, vlan in voice.items():
        if vlan:
            ports.setdefault(if_index, PortVlans(ACCESS)).voice = vlan
    return ports


def q_port_vlans(pvid_rows, egress_rows, untagged_rows, base_port_rows):
    """{ifIndex: PortVlans} from Q-BRIDGE-MIB: a port sending any VLAN tagged is a trunk (its PVID is the native
    VLAN); otherwise it's an access port in its PVID."""
    base_ports = {index[0]: value.value for index, value in column(base_port_rows, BASE_PORT_IFINDEX).items()
                  if len(index) == 1}
    untagged = {}
    for index, value in column(untagged_rows, Q_VLAN_UNTAGGED).items():
        if len(index) == 2:
            untagged[index[1]] = bitmap_members(value.value, 1)
    tagged = {}  # Bridge port -> VLANs it sends tagged
    for index, value in column(egress_rows, Q_VLAN_EGRESS).items():
        if len(index) != 2 or not 1 <= index[1] <= 4094:
            continue
        for port in bitmap_members(value.value, 1) - untagged.get(index[1], set()):
            tagged.setdefault(port, set()).add(index[1])
    ports = {}
    for index, value in column(pvid_rows, Q_PVID).items():
        if_index = base_ports.get(index[0]) if len(index) == 1 else None
        if not if_index:
            continue
        pvid = usable_vlan(value)
        if index[0] in tagged:
            ports[if_index] = PortVlans(TRUNK, native=pvid, allowed=frozenset(tagged[index[0]] | {pvid} - {0}))
        elif pvid:
            ports[if_index] = PortVlans(ACCESS, vlan=pvid)
    return ports


def ports_vlans_in_use(ports):
    """The VLANs ports put hosts in: access ports' VLANs, voice VLANs and trunks' native VLANs. Hosts are on these, so
    on a Catalyst they're the only MAC tables worth reading (a VTP domain can list hundreds the switch doesn't
    carry)."""
    found = set()
    for port in ports.values():
        found |= {port.vlan, port.voice, port.native}
    found.discard(0)
    return sorted(found)


def _length_prefixed(index, position):
    """A variable-length index part (an octet string or OID, written as its length then its numbers): (the numbers,
    the position after it), or (None, position) when the index is too short."""
    if position >= len(index):
        return None, position
    length = index[position]
    end = position + 1 + length
    return (tuple(index[position + 1:end]), end) if end <= len(index) else (None, position)


def _name(numbers):
    return bytes(number & 0xFF for number in numbers).decode("utf-8", "replace")


def cisco_vrf_interfaces(name_rows, interface_rows):
    """{ifIndex: VRF name} from CISCO-VRF-MIB: cvVrfName (index cvVrfIndex) and cvVrfInterfaceTable, whose index
    is (cvVrfIndex, ifIndex); any of its columns will do, as only the index is used."""
    names = {index[0]: text(value) for index, value in column(name_rows, CV_VRF_NAME).items() if len(index) == 1}
    found = {}
    for index in columns(interface_rows, CV_VRF_INTERFACE_ENTRY):
        if len(index) == 2 and names.get(index[0]):
            found[index[1]] = names[index[0]]
    return found


def l3vpn_vrf_interfaces(rows):
    """{ifIndex: VRF name} from MPLS-L3VPN-STD-MIB's mplsL3VpnIfConfTable (index: VRF name, ifIndex)."""
    found = {}
    for index in column(rows, L3VPN_IF_CLASSIFICATION):
        name, position = _length_prefixed(index, 0)
        if name and position + 1 == len(index):
            found[index[position]] = _name(name)
    return found


def l3vpn_routes(rows):
    """Each VRF's routes from MPLS-L3VPN-STD-MIB's mplsL3VpnVrfRteTable, as {VRF: [(destination, next hop, ifIndex,
    protocol)]}, next hop "" for directly connected networks. The index is (VRF name, destination type, destination,
    prefix length, policy, next hop type, next hop), the variable-length parts each written length first."""
    found = {}
    for index, row in columns(rows, L3VPN_ROUTE_ENTRY).items():
        name, position = _length_prefixed(index, 0)
        if not name or position >= len(index):
            continue
        destination_type = index[position]
        destination, position = _length_prefixed(index, position + 1)
        if destination is None or position >= len(index) or destination_type != 1 or len(destination) != 4:
            continue  # IPv4 only, as the global table
        prefix = index[position]
        _, position = _length_prefixed(index, position + 1)  # Policy
        next_hop = None
        if position < len(index):
            next_hop, position = _length_prefixed(index, position + 1)
        kind = row[8].value if 8 in row else 0
        network = _network(_dotted(destination), prefix_mask(prefix))
        if not network or kind == 2:  # Reject (null) routes lead nowhere
            continue
        hop = _dotted(next_hop) if next_hop and len(next_hop) == 4 else ""
        protocol = ROUTE_PROTOCOLS.get(row[9].value, "other") if 9 in row else "other"
        found.setdefault(_name(name), []).append(
            (network, "" if kind == 3 or hop in ("", "0.0.0.0") else hop, row[7].value if 7 in row else 0, protocol))
    for routes_found in found.values():
        routes_found.sort(key=lambda route: (ipaddress.ip_network(route[0]).network_address,
                                             ipaddress.ip_network(route[0]).prefixlen, route[1]))
    return found


def prefix_mask(prefix):
    try:
        return str(ipaddress.ip_network(f"0.0.0.0/{int(prefix)}").netmask)
    except ValueError:
        return ""


def fdb(entry_rows, base_port_rows, vlan=0):
    """Learned MACs from dot1dTpFdbTable as [(MAC, ifIndex, vlan)]; the switch's own MACs (status self) are left
    out."""
    base_ports = {index[0]: value.value for index, value in column(base_port_rows, BASE_PORT_IFINDEX).items()
                  if len(index) == 1}
    entries = []
    for index, row in columns(entry_rows, FDB_ENTRY).items():
        if len(index) != 6 or 2 not in row or (3 in row and row[3].value != FDB_LEARNED):
            continue
        if_index = base_ports.get(row[2].value)
        if if_index:
            entries.append((format_mac(bytes(index).hex()), if_index, vlan))
    return entries


def fdb_by_vlan(entry_rows, base_port_rows):
    """Learned MACs from Q-BRIDGE-MIB's dot1qTpFdbTable as [(MAC, ifIndex, vlan)], for switches that keep one table
    for every VLAN (NX-OS and most non-Cisco switches). The VLAN is the table's FDB ID, which is the VLAN number on
    the switches that have it."""
    base_ports = {index[0]: value.value for index, value in column(base_port_rows, BASE_PORT_IFINDEX).items()
                  if len(index) == 1}
    entries = []
    for index, row in columns(entry_rows, Q_FDB_ENTRY).items():
        if len(index) != 7 or 2 not in row or (3 in row and row[3].value != FDB_LEARNED):
            continue
        if_index = base_ports.get(row[2].value)
        if if_index:
            entries.append((format_mac(bytes(index[1:]).hex()), if_index, index[0]))
    return entries


def arp(rows):
    """ipNetToMediaPhysAddress (index: ifIndex, IPv4 address) as {MAC: [ip]}."""
    table = {}
    for index, value in column(rows, ARP_PHYS_ADDRESS).items():
        mac = mac_text(value.value)
        if len(index) == 5 and mac:
            table.setdefault(mac, []).append(".".join(str(number) for number in index[1:]))
    for addresses in table.values():
        addresses.sort(key=lambda address: ipaddress.ip_address(address))
    return table


def ip_addresses(rows):
    """ipAddrTable as [(ip, ifIndex, mask)]."""
    found = []
    for index, row in columns(rows, IP_ADDR_ENTRY).items():
        if len(index) != 4:
            continue
        address = ".".join(str(number) for number in index)
        mask = row[3].value if 3 in row and row[3].tag == IP_ADDRESS else ""
        found.append((address, row[2].value if 2 in row else 0, mask))
    return sorted(found, key=lambda item: ipaddress.ip_address(item[0]))


def lag_parents(stack_rows, lag_rows):
    """Port-channel members: {member ifIndex: port-channel ifIndex}, from ifStackTable or IEEE8023-LAG-MIB."""
    parents = {}
    for index, value in column(lag_rows, LAG_ATTACHED).items():
        if len(index) == 1 and isinstance(value.value, int) and value.value and value.value != index[0]:
            parents[index[0]] = value.value
    for index, value in column(stack_rows, IF_STACK_STATUS).items():
        if len(index) == 2 and index[0] and index[1] and value.value == 1:
            parents.setdefault(index[1], index[0])
    return parents


def base_port_ifindexes(rows):
    """{bridge port: ifIndex} from dot1dBasePortIfIndex."""
    return {index[0]: value.value for index, value in column(rows, BASE_PORT_IFINDEX).items()
            if len(index) == 1 and isinstance(value.value, int)}


def stp_mode(rows):
    """The spanning tree a Cisco switch runs (STP_TYPES), from a walk of stpxSpanningTreeType, or ""."""
    for value in column(rows, STP_TYPE).values():
        return STP_TYPES.get(value.value, "")
    return ""


def mst_instance_of(rows, vlan):
    """The MST instance a VLAN is mapped to, from stpxSMSTInstanceTable: 0 (the IST) when no other instance has
    it, or -1 when the table is empty (unknown)."""
    instances = columns(rows, MST_INSTANCE_ENTRY)
    if not instances:
        return -1
    for index, row in sorted(instances.items()):
        if len(index) != 1 or not index[0]:
            continue
        mapped = set()
        if 2 in row:
            mapped |= bitmap_members(row[2].value, 0)
        if 3 in row:
            mapped |= bitmap_members(row[3].value, 2048)
        if vlan in mapped:
            return index[0]
    return 0


def rstp_port_roles(rows, instance, base_ports):
    """{ifIndex: (FORWARDING, BLOCKING or DISABLED, role)} for one spanning tree instance, from
    stpxRSTPPortRoleTable (Rapid-PVST: the instance is the VLAN; MST: the MST instance)."""
    found = {}
    for index, value in column(rows, RSTP_PORT_ROLE).items():
        if len(index) != 2 or index[0] != instance or index[1] not in base_ports:
            continue
        role = RSTP_ROLES.get(value.value, "")
        state = BLOCKING if role in ("alternate", "backup") else DISABLED if role == "disabled" else FORWARDING
        found[base_ports[index[1]]] = (state, role)
    return found


def stp_port_states(rows, base_ports):
    """{ifIndex: (FORWARDING, BLOCKING or DISABLED, state)} from BRIDGE-MIB dot1dStpPortState (PVST+, read for one
    VLAN with community@vlan). Listening and learning ports aren't forwarding yet, so they count as blocking."""
    found = {}
    for index, value in column(rows, STP_PORT_STATE).items():
        if len(index) != 1 or index[0] not in base_ports:
            continue
        state = STP_STATES.get(value.value, "")
        simple = FORWARDING if state == "forwarding" else DISABLED if state == "disabled" else BLOCKING
        found[base_ports[index[0]]] = (simple, state)
    return found


def stp_root(rows):
    """From a walk of dot1dStpRootPort: True on the root bridge (no root port), False if not, None if not said."""
    for value in column(rows, STP_ROOT_PORT).values():
        return value.value == 0 if isinstance(value.value, int) else None
    return None


def port_status(admin_rows, oper_rows, high_speed_rows=(), speed_rows=(), duplex_rows=()):
    """{ifIndex: {"oper": "up", "down"..., "speed": Mb/s, "duplex": "full" or "half"}} for the interfaces that aren't
    shut down (speed and duplex left out when not known). From IF-MIB, and EtherLike-MIB for duplex."""
    admin = {index[0]: value.value for index, value in column(admin_rows, IF_ADMIN_STATUS).items() if len(index) == 1}
    high = {index[0]: value.value for index, value in column(high_speed_rows, IF_HIGH_SPEED).items()
            if len(index) == 1 and isinstance(value.value, int)}
    low = {index[0]: value.value for index, value in column(speed_rows, IF_SPEED).items()
           if len(index) == 1 and isinstance(value.value, int)}
    duplex = {index[0]: DUPLEXES.get(value.value, "") for index, value in column(duplex_rows, DOT3_DUPLEX).items()
              if len(index) == 1}
    found = {}
    for index, value in column(oper_rows, IF_OPER_STATUS).items():
        if len(index) != 1 or admin.get(index[0]) == 2:
            continue  # Shut down: not worth keeping
        if_index = index[0]
        entry = {"oper": OPER_STATES.get(value.value, "unknown")}
        speed = high.get(if_index) or (low.get(if_index, 0) // 1_000_000 if low.get(if_index, 0) < 4_294_967_295
                                       else 0)
        if speed:
            entry["speed"] = speed
        if duplex.get(if_index):
            entry["duplex"] = duplex[if_index]
        found[if_index] = entry
    return found


def classify(object_id="", descr="", capabilities=frozenset(), platform="", switchports=False):
    """Switch, router, firewall, access point, phone or host, from what the device says about itself. switchports: a
    Cisco device's own tables have access or trunk ports, which makes it a switch unless its model is a router's (an
    ISR with a switch module): its neighbors' CDP says "Router Switch" for any multilayer box."""
    words = f"{descr} {platform}".lower()
    if object_id.startswith(PALO_ALTO + ".") or "palo alto" in words or "pan-os" in words:
        return FIREWALL
    if "adaptive security appliance" in words or "firepower" in words or platform.lower().startswith(("asa", "ftd")):
        return FIREWALL
    if "phone" in capabilities or "phone" in words:
        return PHONE
    if "ap" in capabilities or any(word in words for word in AP_WORDS):
        return AP
    # The model says more than the capabilities: an ISR with a switch module announces both
    if any(word in words for word in ROUTER_WORDS):
        return ROUTER
    if any(word in words for word in SWITCH_WORDS):
        return SWITCH
    if switchports and object_id.startswith(CISCO + "."):
        return SWITCH
    if "switch" in capabilities or "bridge" in capabilities:
        return SWITCH
    if "router" in capabilities:
        return ROUTER
    if "station" in capabilities or "host" in capabilities:
        return HOST
    if object_id.startswith(CISCO + "."):
        return ROUTER  # A Cisco box that answers SNMP but said nothing clearer
    return UNKNOWN


def neighbor_kind(neighbor):
    """What a CDP/LLDP neighbor is. A computer's LLDP agent (Windows, lldpd) often announces no capabilities at all:
    with its port ID a MAC address, or an operating system named in its description, it's a host, not a device."""
    kind = classify(capabilities=neighbor.capabilities, platform=neighbor.platform)
    if kind == UNKNOWN and neighbor.protocol == "lldp":
        words = neighbor.platform.lower()
        if neighbor.port_mac or any(word in words for word in HOST_WORDS):
            return HOST
    return kind


def _dotted(numbers):
    return ".".join(str(number) for number in numbers)


def _network(address, mask):
    try:
        return str(ipaddress.ip_network(f"{address}/{mask}", strict=False))
    except ValueError:
        return ""


def routes(cidr_rows, old_rows=()):
    """The routing table as [(destination, next hop, ifIndex, protocol)], from ipCidrRouteTable, or ipRouteTable
    when a device doesn't have that. Next hop is "" for directly connected networks."""
    found = []
    for index, row in columns(cidr_rows, CIDR_ROUTE_ENTRY).items():
        if len(index) != 13:
            continue
        destination = _network(_dotted(index[:4]), _dotted(index[4:8]))
        next_hop = _dotted(index[9:13])
        kind = row[6].value if 6 in row else 0
        if not destination or kind == 2:  # Reject (null) routes lead nowhere
            continue
        protocol = ROUTE_PROTOCOLS.get(row[7].value, "other") if 7 in row else "other"
        found.append((destination, "" if kind == 3 or next_hop == "0.0.0.0" else next_hop,
                      row[5].value if 5 in row else 0, protocol))
    if not found:
        for index, row in columns(old_rows, IP_ROUTE_ENTRY).items():
            if len(index) != 4 or 11 not in row:
                continue
            destination = _network(_dotted(index), row[11].value)
            next_hop = row[7].value if 7 in row and isinstance(row[7].value, str) else ""
            kind = row[8].value if 8 in row else 0
            if not destination or kind == 2:
                continue
            protocol = ROUTE_PROTOCOLS.get(row[9].value, "other") if 9 in row else "other"
            found.append((destination, "" if kind == 3 or next_hop == "0.0.0.0" else next_hop,
                          row[2].value if 2 in row else 0, protocol))
    return sorted(found, key=lambda route: (ipaddress.ip_network(route[0]).network_address,
                                            ipaddress.ip_network(route[0]).prefixlen, route[1]))
