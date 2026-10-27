"""A small made-up network for the map tests: a core switch, two access switches, a router and a firewall, each
answering SNMP from a dict the way the real devices would."""
import socket

from nomad.icmp import IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, EchoReply
from nomad.netmap import collect
from nomad.snmp import IP_ADDRESS, INTEGER, OBJECT_ID, OCTET_STRING, SnmpClient, SnmpError, Value, parse_oid

CISCO_SWITCH = (1, 3, 6, 1, 4, 1, 9, 1, 2494)
CISCO_ROUTER = (1, 3, 6, 1, 4, 1, 9, 1, 1861)
PALO_ALTO = (1, 3, 6, 1, 4, 1, 25461, 2, 3, 38)

CORE_MAC, ACC1_MAC, ACC2_MAC = "00-1A-2B-00-00-01", "00-1A-2B-00-00-11", "00-1A-2B-00-00-12"
FW_MAC = "00-1B-17-00-00-05"
PC1_MAC, PHONE_MAC, PRINTER_MAC = "3C-52-82-00-00-01", "00-AA-BB-CC-DD-EE", "00-00-48-00-00-09"
LAB_MACS = [f"52-54-00-00-00-{number:02X}" for number in range(10)]  # Behind an unmanaged switch


def string(text):
    return Value(OCTET_STRING, text.encode() if isinstance(text, str) else text)


def number(value):
    return Value(INTEGER, value)


def mac_bytes(mac):
    return bytes.fromhex(mac.replace("-", ""))


def oid(*parts):
    numbers = []
    for part in parts:
        numbers += list(parse_oid(part)) if isinstance(part, str) else list(part) if isinstance(part, tuple) else [part]
    return tuple(numbers)


class Device:
    def __init__(self, name, descr, object_id, communities=("public",), v3_users=()):
        self.communities = set(communities)
        self.v3_users = set(v3_users)  # V3Users it answers to
        self.mib = {}
        self.contexts = {}  # VLAN -> {oid: Value}, answered for community@vlan (or a v3 user in context vlan-N)
        self.vlan_instances = True  # False: like some IOS images, community@vlan and vlan- contexts don't answer
        self.set(collect.SYS_DESCR, string(descr))
        self.set(collect.SYS_OBJECT_ID, Value(OBJECT_ID, object_id))
        self.set(collect.SYS_NAME, string(name))

    def set(self, *parts, value=None, mib=None):
        *oid_parts, value = parts if value is None else (*parts, value)
        (self.mib if mib is None else mib)[oid(*oid_parts)] = value

    def interface(self, index, name, mac=None):
        self.set(collect.IF_DESCR, index, string(name))
        self.set(collect.IF_NAME, index, string(name))  # Real switches give the short name; long is fine here
        if mac:
            self.set(collect.IF_PHYS_ADDRESS, index, string(mac_bytes(mac)))

    def address(self, ip, if_index, mask="255.255.255.0"):
        numbers = tuple(int(part) for part in ip.split("."))
        self.set(collect.IP_ADDR_ENTRY, 1, numbers, Value(IP_ADDRESS, ip))
        self.set(collect.IP_ADDR_ENTRY, 2, numbers, number(if_index))
        self.set(collect.IP_ADDR_ENTRY, 3, numbers, Value(IP_ADDRESS, mask))

    def cdp(self, if_index, device_index, name, port, address="", platform="", capabilities=0x28):
        entry = (collect.CDP_CACHE_ENTRY,)
        if address:
            self.set(*entry, 3, if_index, device_index, number(1))
            self.set(*entry, 4, if_index, device_index, string(socket.inet_aton(address)))
        self.set(*entry, 6, if_index, device_index, string(name))
        self.set(*entry, 7, if_index, device_index, string(port))
        self.set(*entry, 8, if_index, device_index, string(platform))
        self.set(*entry, 9, if_index, device_index, string(capabilities.to_bytes(4, "big")))

    def lldp(self, local_port, local_name, remote_index, name, port, address="", chassis_mac="", capabilities=0x08,
             descr="", port_mac=""):
        self.set(collect.LLDP_LOC_PORT_ENTRY, 2, local_port, number(5))
        self.set(collect.LLDP_LOC_PORT_ENTRY, 3, local_port, string(local_name))
        index = (0, local_port, remote_index)
        entry = collect.LLDP_REM_ENTRY
        if chassis_mac:
            self.set(entry, 4, index, number(4))
            self.set(entry, 5, index, string(mac_bytes(chassis_mac)))
        if port_mac:  # Port ID subtype 3: a MAC address, as a computer's LLDP agent sends it
            self.set(entry, 6, index, number(3))
            self.set(entry, 7, index, string(mac_bytes(port_mac)))
        else:
            self.set(entry, 6, index, number(5))
            self.set(entry, 7, index, string(port))
        self.set(entry, 9, index, string(name))
        self.set(entry, 10, index, string(descr))
        self.set(entry, 12, index, string(bytes([capabilities, 0])))
        if address:
            numbers = tuple(int(part) for part in address.split("."))
            self.set(collect.LLDP_REM_MAN_ADDR_IF_SUBTYPE, index, 1, 4, numbers, number(2))

    def route(self, destination, mask, next_hop, if_index, kind=4, protocol=3):
        """An ipCidrRouteTable row: kind 3 is connected, 4 remote; protocol 2 is connected, 3 static, 13 OSPF."""
        index = tuple(int(part) for part in f"{destination}.{mask}".split(".")) + (0,)
        index += tuple(int(part) for part in next_hop.split("."))
        self.set(collect.CIDR_ROUTE_ENTRY, 5, index, number(if_index))
        self.set(collect.CIDR_ROUTE_ENTRY, 6, index, number(kind))
        self.set(collect.CIDR_ROUTE_ENTRY, 7, index, number(protocol))

    def arp(self, if_index, ip, mac):
        numbers = tuple(int(part) for part in ip.split("."))
        self.set(collect.ARP_PHYS_ADDRESS, if_index, numbers, string(mac_bytes(mac)))

    def vlan(self, vlan, name=None):
        self.set(collect.VTP_VLAN_STATE, 1, vlan, number(1))
        if name is not None:
            self.set(collect.VTP_VLAN_NAME, 1, vlan, string(name))

    def vtp(self, domain, mode=2):
        self.set(collect.VTP_DOMAIN_ENTRY, 2, 1, string(domain))
        self.set(collect.VTP_DOMAIN_ENTRY, 3, 1, number(mode))

    def trunk(self, if_index, allowed, native=1, trunking=True):
        """A vlanTrunkPortTable row: allowed is the VLAN numbers (set in the four bitmaps)."""
        for column, first in collect.TRUNK_ALLOWED_COLUMNS.items():
            bitmap = bytearray(128)
            for vlan in allowed:
                if first <= vlan < first + 1024:
                    bitmap[(vlan - first) // 8] |= 0x80 >> ((vlan - first) % 8)
            self.set(collect.TRUNK_PORT_ENTRY, column, if_index, string(bytes(bitmap)))
        self.set(collect.TRUNK_PORT_ENTRY, collect.TRUNK_NATIVE, if_index, number(native))
        self.set(collect.TRUNK_PORT_ENTRY, collect.TRUNK_STATUS, if_index, number(1 if trunking else 2))

    def access(self, if_index, vlan, voice=None):
        self.set(collect.VM_VLAN, if_index, number(vlan))
        if voice is not None:
            self.set(collect.VM_VOICE_VLAN, if_index, number(voice))

    def q_vlan(self, vlan, name, ports=(), untagged=()):
        """A Q-BRIDGE VLAN: its name, and the bridge ports it goes out of (untagged ones too)."""
        def bitmap(members):
            raw = bytearray(8)
            for port in members:
                raw[(port - 1) // 8] |= 0x80 >> ((port - 1) % 8)
            return string(bytes(raw))
        self.set(collect.Q_VLAN_STATIC_NAME, vlan, string(name))
        self.set(collect.Q_VLAN_EGRESS, 0, vlan, bitmap(ports))
        self.set(collect.Q_VLAN_UNTAGGED, 0, vlan, bitmap(untagged))

    def cisco_vrf(self, vrf_index, name, if_indexes):
        """A VRF in CISCO-VRF-MIB, with its interfaces."""
        self.set(collect.CV_VRF_NAME, vrf_index, string(name))
        for if_index in if_indexes:
            self.set(collect.CV_VRF_INTERFACE_ENTRY, 2, vrf_index, if_index, number(1))

    def vrf_route(self, vrf, destination, prefix, next_hop, if_index, kind=4, protocol=13):
        """An MPLS-L3VPN-STD-MIB mplsL3VpnVrfRteTable row: kind 3 is connected, 4 remote; protocol 2 connected,
        3 static, 13 OSPF."""
        name = tuple(vrf.encode())
        index = (len(name),) + name + (1, 4) + tuple(int(part) for part in destination.split(".")) + (prefix,)
        index += (2, 0, 0)  # Policy: the OID 0.0
        index += (1, 4) + tuple(int(part) for part in next_hop.split("."))
        self.set(collect.L3VPN_ROUTE_ENTRY, 7, index, number(if_index))
        self.set(collect.L3VPN_ROUTE_ENTRY, 8, index, number(kind))
        self.set(collect.L3VPN_ROUTE_ENTRY, 9, index, number(protocol))

    def pvid(self, bridge_port, if_index, vlan):
        self.set(collect.Q_PVID, bridge_port, number(vlan))
        self.set(collect.BASE_PORT_IFINDEX, bridge_port, number(if_index))

    def learned(self, mac, bridge_port, if_index, vlan=None, status=3):
        mib = self.mib if vlan is None else self.contexts.setdefault(vlan, {})
        index = tuple(mac_bytes(mac))
        self.set(collect.FDB_ENTRY, 1, index, string(mac_bytes(mac)), mib=mib)
        self.set(collect.FDB_ENTRY, 2, index, number(bridge_port), mib=mib)
        self.set(collect.FDB_ENTRY, 3, index, number(status), mib=mib)
        self.set(collect.BASE_PORT_IFINDEX, bridge_port, number(if_index), mib=mib)

    def learned_by_vlan(self, mac, bridge_port, if_index, vlan, status=3):
        """A Q-BRIDGE-MIB dot1qTpFdbTable entry, as NX-OS has."""
        index = (vlan,) + tuple(mac_bytes(mac))
        self.set(collect.Q_FDB_ENTRY, 2, index, number(bridge_port))
        self.set(collect.Q_FDB_ENTRY, 3, index, number(status))
        self.set(collect.BASE_PORT_IFINDEX, bridge_port, number(if_index))

    def lag(self, member, parent):
        self.set(collect.IF_STACK_STATUS, parent, member, number(1))


class FakeAgentClient:
    """Serves one device over real UDP with the SNMP tests' agent; factory() makes SnmpClients that talk to it."""

    def __init__(self, device, community="public"):
        from test_snmp import FakeAgent
        self.agent = FakeAgent(community, device.mib)

    def factory(self, host, community, version, timeout=2000, retries=1, context=""):
        return SnmpClient(host, community, version, timeout=timeout, retries=retries, port=self.agent.port,
                          context=context)

    def close(self):
        self.agent.close()


class FakeNetwork:
    """Addresses -> Device, handing out clients like SnmpClient's."""

    def __init__(self):
        self.devices = {}
        self.pingable = set()
        self.requests = []
        self.paths = {}
        self.traced = []

    def add(self, address, device):
        self.devices[address] = device
        self.pingable.add(address)
        return device

    def client(self, host, community, version, timeout=2000, retries=1, context=""):
        return FakeClient(self, host, community, context)

    def ping(self, address):
        return address in self.pingable

    def echo(self, address, ttl):
        """Traceroute replies: the path in self.paths (default: through the core), then the address itself if it
        pings."""
        path = self.paths.get(address, ["10.0.0.1"])
        full = path + ([address] if address in self.pingable else [])
        self.traced.append(address)
        if ttl > len(full):
            return EchoReply(IP_REQ_TIMED_OUT)
        hop = full[ttl - 1]
        if hop == address:
            return EchoReply(IP_SUCCESS, address, 1)
        return EchoReply(IP_TTL_EXPIRED_TRANSIT, hop) if hop else EchoReply(IP_REQ_TIMED_OUT)


class FakeClient:
    def __init__(self, network, host, community, context=""):
        self.network, self.host, self.community = network, host, community
        device = network.devices.get(host)
        if not isinstance(community, str):  # A V3User: VLAN tables are in contexts vlan-N
            base, vlan = community, context.partition("vlan-")[2]
            known = device is not None and community in device.v3_users
        else:
            base, _, vlan = community.partition("@")
            known = device is not None and base in device.communities
        if not known or (vlan and not device.vlan_instances):
            self.mib = None
        elif vlan:
            self.mib = device.contexts.get(int(vlan), {})
        else:
            self.mib = device.mib
        self.mib_sorted = sorted(self.mib.items()) if self.mib is not None else []

    def check(self):
        self.network.requests.append((self.host, self.community))
        if self.mib is None:
            raise SnmpError(f"No answer from {self.host}.")

    def get(self, oids):
        self.check()
        return [(tuple(item), self.mib.get(tuple(item), Value(0x80, None))) for item in oids]

    def walk(self, root, max_repetitions=25, should_stop=lambda: False, limit=None):
        self.check()
        root = tuple(root)
        for key, value in self.mib_sorted:
            if key[:len(root)] == root:
                yield key, value


def build_network():
    """core (10.0.0.1) -- acc1 (10.0.0.11, per-VLAN MAC tables, a phone and PC on Gi1/0/5)
                       -- acc2 (10.0.0.12, NX-OS, community "secret", an unmanaged switch on Eth1/10)
                       -- rtr1 (10.0.0.254, pings but no SNMP)
                       -- pa-fw1 (10.0.0.5, LLDP only)"""
    network = FakeNetwork()
    core = network.add("10.0.0.1", Device("core.corp.example", "Cisco IOS Software, Catalyst L3 Switch Software "
                                          "(CAT9K_IOSXE)", CISCO_SWITCH))
    core.interface(1, "TenGigabitEthernet1/0/1", CORE_MAC)
    core.interface(2, "TenGigabitEthernet1/0/2", CORE_MAC)
    core.interface(3, "TenGigabitEthernet1/0/3", CORE_MAC)
    core.interface(4, "GigabitEthernet1/0/48", CORE_MAC)
    core.interface(50, "Vlan10", CORE_MAC)
    core.interface(51, "Vlan1", CORE_MAC)
    core.interface(60, "Loopback0")
    core.address("10.0.0.1", 51)
    core.address("10.10.0.1", 50)
    core.address("10.255.0.1", 60, "255.255.255.255")
    core.route("0.0.0.0", "0.0.0.0", "10.0.0.5", 51)
    core.route("10.0.0.0", "255.255.255.0", "0.0.0.0", 51, kind=3, protocol=2)
    core.route("10.10.0.0", "255.255.255.0", "0.0.0.0", 50, kind=3, protocol=2)
    core.route("10.50.0.0", "255.255.0.0", "10.0.0.254", 51)  # Static, through rtr1 (no SNMP)
    core.route("10.60.0.0", "255.255.0.0", "10.0.0.253", 51, protocol=13)  # OSPF, through a router not on the map
    core.route("10.66.0.0", "255.255.0.0", "10.0.0.253", 51, kind=2)  # Reject (null route): left out
    core.cdp(1, 1, "acc1.corp.example(FOC111)", "TenGigabitEthernet1/1/1", "10.0.0.11", "cisco C9300-48P", 0x29)
    core.cdp(2, 1, "acc2(SAL222)", "Ethernet1/49", "10.0.0.12", "N9K-C93180YC-EX", 0x29)
    core.cdp(4, 1, "rtr1.corp.example", "GigabitEthernet0/0/0", "10.0.0.254", "cisco ISR4331/K9", 0x01)
    core.lldp(3, "Te1/0/3", 1, "pa-fw1", "ethernet1/1", "10.0.0.5", FW_MAC, 0x08, "Palo Alto Networks PA-3220")
    core.arp(50, "10.10.0.21", PC1_MAC)
    core.arp(50, "10.10.0.22", PHONE_MAC)
    core.arp(50, "10.10.0.30", PRINTER_MAC)
    core.vlan(1)
    core.vlan(10)
    core.vlan(1002)
    core.learned(ACC1_MAC, 1, 1, vlan=10)
    core.learned(PC1_MAC, 1, 1, vlan=10)  # Behind acc1: must not be placed on the core's uplink

    acc1 = network.add("10.0.0.11", Device("acc1.corp.example", "Cisco IOS Software, Catalyst L3 Switch Software",
                                           CISCO_SWITCH))
    acc1.interface(1, "TenGigabitEthernet1/1/1", ACC1_MAC)
    acc1.interface(5, "GigabitEthernet1/0/5", ACC1_MAC)
    acc1.interface(7, "GigabitEthernet1/0/7", ACC1_MAC)
    acc1.address("10.0.0.11", 1)
    acc1.cdp(1, 1, "core.corp.example(FOC999)", "TenGigabitEthernet1/0/1", "10.0.0.1", "cisco C9500-24Y4C", 0x29)
    acc1.cdp(5, 2, "SEP00AABBCCDDEE", "Port 1", "10.10.0.22", "Cisco IP Phone 8845", 0x90)
    acc1.vlan(1)
    acc1.vlan(10)
    for unused in (20, 30, 40):  # In the VTP domain, not on any of acc1's ports: their MAC tables aren't read
        acc1.vlan(unused)
    acc1.set(collect.VM_VLAN, 5, number(10))  # Access ports' VLANs, from CISCO-VLAN-MEMBERSHIP-MIB
    acc1.set(collect.VM_VLAN, 7, number(10))
    acc1.set(collect.VM_VOICE_VLAN, 5, number(10))
    acc1.set(collect.TRUNK_NATIVE_VLAN, 1, number(1))
    acc1.learned(CORE_MAC, 1, 1, vlan=1)
    acc1.learned(PC1_MAC, 5, 5, vlan=10)
    acc1.learned(PHONE_MAC, 5, 5, vlan=10)
    acc1.learned(PRINTER_MAC, 7, 7, vlan=10)
    acc1.learned(ACC1_MAC, 1, 1, vlan=10, status=4)  # Its own: status self

    acc2 = network.add("10.0.0.12", Device("acc2", "Cisco Nexus Operating System (NX-OS) Software", CISCO_SWITCH,
                                           communities=("secret",)))
    acc2.interface(1, "Ethernet1/49", ACC2_MAC)
    acc2.interface(10, "Ethernet1/10", ACC2_MAC)
    acc2.interface(11, "Ethernet1/11", ACC2_MAC)
    acc2.interface(12, "Ethernet1/12", ACC2_MAC)
    acc2.interface(100, "port-channel1", ACC2_MAC)
    acc2.lag(11, 100)
    acc2.lag(12, 100)
    acc2.cdp(1, 1, "core", "TenGigabitEthernet1/0/2", "10.0.0.1", "cisco C9500-24Y4C", 0x29)
    acc2.vlan(1)
    acc2.vlan(10)
    for position, mac in enumerate(LAB_MACS):
        acc2.learned_by_vlan(mac, 10, 10, 30 if position % 2 else 31)
    acc2.learned_by_vlan(CORE_MAC, 1, 1, 1)
    acc2.learned_by_vlan(FW_MAC, 100, 11, 1)  # The firewall's MAC on a port-channel member: port-channel1 is an uplink

    network.pingable.add("10.0.0.254")  # rtr1: no SNMP for us
    network.pingable.add("10.0.0.253")
    network.paths["10.50.0.1"] = ["10.0.0.1", "10.0.0.254", "", "10.99.0.1"]  # Then silence
    fw = network.add("10.0.0.5", Device("pa-fw1", "Palo Alto Networks PA-3200 series firewall", PALO_ALTO))
    fw.interface(1, "ethernet1/1", FW_MAC)
    fw.interface(2, "ethernet1/2", FW_MAC)
    fw.address("10.0.0.5", 1)
    fw.address("192.0.2.2", 2, "255.255.255.252")
    fw.lldp(1, "ethernet1/1", 1, "core", "Te1/0/3", "10.0.0.1", CORE_MAC, 0x28)
    return network


# An Aruba controller (made up, laid out as ArubaOS 8.10 answers): wlc1 is on the core's Gi1/0/20, ap1 on acc1's
# Gi1/0/8 (seen by LLDP), ap2 down, ap3 up but on no switch the map has
ARUBA_CONTROLLER = (1, 3, 6, 1, 4, 1, 14823, 1, 1, 52)
WLC_MAC = "00-0B-86-AA-00-01"
AP1_MAC, AP2_MAC, AP3_MAC = "00-0B-86-00-00-01", "00-0B-86-00-00-02", "00-0B-86-00-00-03"
AP1_BSSID, AP3_BSSID = "00-0B-86-10-00-10", "00-0B-86-30-00-10"
LAPTOP_MAC, TABLET_MAC, WIRED_USER_MAC = "3C-52-82-00-00-31", "3C-52-82-00-00-32", "3C-52-82-00-00-33"
WLC_SERIAL = "MC0000001"


def add_aruba(network):
    """wlc1 (10.0.0.20, an ArubaOS controller) with three APs and two Wi-Fi clients, linked to the core."""
    from nomad.netmap import aruba, hardware
    from nomad.snmp import GAUGE32, TIMETICKS
    core, acc1 = network.devices["10.0.0.1"], network.devices["10.0.0.11"]
    core.interface(20, "GigabitEthernet1/0/20", CORE_MAC)
    core.lldp(20, "Gi1/0/20", 1, "wlc1", "GE0/0/0", "10.0.0.20", WLC_MAC, 0x28,
              "ArubaOS (MODEL: Aruba7210), Version 8.10.0.15-FIPS LSR")
    acc1.interface(8, "GigabitEthernet1/0/8", ACC1_MAC)
    acc1.lldp(8, "Gi1/0/8", 1, "ap1", AP1_MAC, "10.20.0.11", AP1_MAC, 0x10, "ArubaOS (MODEL: 505), Version Aruba AP")
    acc1.learned(AP1_MAC, 8, 8, vlan=10)
    acc1.learned(LAPTOP_MAC, 8, 8, vlan=10)  # Bridged by the AP: still the AP's Wi-Fi client, not a host on Gi1/0/8

    wlc = network.add("10.0.0.20", Device("wlc1", "ArubaOS (MODEL: Aruba7210), Version 8.10.0.15-FIPS LSR (91324)",
                                          ARUBA_CONTROLLER))
    wlc.interface(1, "GE0/0/0", WLC_MAC)
    wlc.interface(16385, "vlan 1", WLC_MAC)
    wlc.address("10.0.0.20", 16385)
    wlc.lldp(1, "GE0/0/0", 1, "core", "Gi1/0/20", "10.0.0.1", CORE_MAC, 0x28)
    wlc.set(hardware.ARUBA_SERIAL, string(WLC_SERIAL))
    wlc.arp(16385, "10.30.0.6", TABLET_MAC)
    for mac, ip, name, group, model, serial, up, software in (
            (AP1_MAC, "10.20.0.11", "ap1", "campus", "505", "CNAA000001", True, "8.10.0.15-FIPS"),
            (AP2_MAC, "10.20.0.12", "ap2", "campus", "635", "CNAA000002", False, ""),
            (AP3_MAC, "10.20.0.13", "ap3", "lab", "635", "CNAA000003", True, "8.10.0.15-FIPS")):
        index = tuple(mac_bytes(mac))
        entry = aruba.AP_ENTRY
        wlc.set(entry, aruba.AP_IP, index, Value(IP_ADDRESS, ip))
        wlc.set(entry, aruba.AP_NAME, index, string(name))
        wlc.set(entry, aruba.AP_GROUP, index, string(group))
        wlc.set(entry, aruba.AP_SERIAL, index, string(serial))
        wlc.set(entry, aruba.AP_UPTIME, index, Value(TIMETICKS, 360000 if up else 0))
        wlc.set(entry, aruba.AP_MODEL, index, string(model))
        wlc.set(entry, aruba.AP_STATUS, index, number(1 if up else 2))
        wlc.set(entry, aruba.AP_SOFTWARE, index, string(software))
    for ap, bssid in ((AP1_MAC, AP1_BSSID), (AP3_MAC, AP3_BSSID)):
        wlc.set(aruba.BSSID_ESSID, tuple(mac_bytes(ap)), 1, tuple(mac_bytes(bssid)), string("Corp"))
    # The laptop is associated (station table) and signed in as its computer; the tablet only in the user table, as a
    # person, on ap3 by name. The wired user is the controller's own port's
    laptop = tuple(mac_bytes(LAPTOP_MAC))
    wlc.set(aruba.STATION_ENTRY, aruba.STATION_BSSID, laptop, string(mac_bytes(AP1_BSSID)))
    wlc.set(aruba.STATION_ENTRY, aruba.STATION_VLAN, laptop, number(30))
    wlc.set(aruba.STATION_ENTRY, aruba.STATION_ESSID, laptop, string("Corp"))
    wlc.set(aruba.STATION_ENTRY, aruba.STATION_AP, laptop, string("ap1"))
    for mac, ip, user, ap, bssid, wired in ((LAPTOP_MAC, "10.30.0.5", "host/LAPTOP-7", "ap1", AP1_BSSID, 2),
                                            (TABLET_MAC, "0.0.0.0", "jdoe", "ap3", "", 2),
                                            (WIRED_USER_MAC, "10.0.0.99", "", "0/0/0", "", 1)):
        index = tuple(mac_bytes(mac)) + tuple(int(part) for part in ip.split("."))
        wlc.set(aruba.USER_ENTRY, aruba.USER_NAME, index, string(user))
        wlc.set(aruba.USER_ENTRY, aruba.USER_AP, index, string(ap))
        wlc.set(aruba.USER_ENTRY, aruba.USER_BSSID, index, string(bssid))
        wlc.set(aruba.USER_ENTRY, aruba.USER_VLAN, index, number(30))
        wlc.set(aruba.USER_ENTRY, aruba.USER_WIRED, index, number(wired))
    wlc.set(aruba.AP_ENTRY, 99, tuple(mac_bytes(AP1_MAC)), Value(GAUGE32, 0))  # A column that isn't walked
    return wlc
