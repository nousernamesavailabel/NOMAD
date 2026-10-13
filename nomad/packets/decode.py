"""Decoding packets: the packet list's columns (source, destination, protocol, info), the values a display filter
looks at (named as Wireshark names them, such as ip.addr and tcp.flags.syn), and, for the packet being looked at, a
tree of what each part means along with the bytes it came from.

What's decoded is what helps on a switch port: Ethernet, 802.1Q, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS, DHCP, TLS (the
server name a client asks for), HTTP, SMB2, SNMP, syslog, NTP, TFTP, RADIUS, 802.1X, CDP, LLDP, STP, LACP, DTP, VTP,
HSRP, VRRP, OSPF, EIGRP, IGMP, PIM, BGP, GRE, ERSPAN and VXLAN (whose frames inside are decoded too). Anything else is
named by its port.
"""
import re
import socket
import struct

from .. import oui

ETHERNET, LINUX_SLL = 1, 113
RAW_IP_TYPES = {12, 14, 101, 228, 229}
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
BROADCAST = "ff:ff:ff:ff:ff:ff"
MAX_DEPTH = 4  # Tunnels inside tunnels
BARE_VALUE = re.compile(r"[A-Za-z0-9_.:/\-]+")  # A filter value that needn't be quoted

ETHERTYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8035: "RARP", 0x8100: "802.1Q", 0x88A8: "802.1ad",
              0x9100: "802.1Q (QinQ)", 0x88CC: "LLDP", 0x8809: "Slow Protocols", 0x8847: "MPLS", 0x8848: "MPLS",
              0x888E: "802.1X", 0x88E5: "MACsec", 0x9000: "Loopback", 0x88F7: "PTP", 0x893A: "IEEE 1905.1",
              0x88BE: "ERSPAN", 0x22EB: "ERSPAN III", 0x6558: "Ethernet", 0x0842: "Wake-on-LAN",
              0x8863: "PPPoE Discovery", 0x8864: "PPPoE", 0x8902: "CFM", 0x88B5: "Local experimental",
              0x8899: "Realtek", 0x22F0: "AVTP", 0x88E7: "PBB"}
IP_PROTOCOLS = {0: "Hop-by-hop options", 1: "ICMP", 2: "IGMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6",
                43: "Routing", 44: "Fragment", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 59: "No next header",
                60: "Destination options", 88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 115: "L2TP",
                132: "SCTP"}
IPV6_EXTENSIONS = {0, 43, 60}
TCP_PORTS = {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 49: "TACACS+", 53: "DNS", 80: "HTTP",
             88: "Kerberos", 110: "POP", 135: "DCERPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 389: "LDAP",
             443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS", 830: "NETCONF", 993: "IMAPS",
             995: "POPS", 1433: "TDS", 1723: "PPTP", 2000: "Skinny", 3268: "LDAP", 3306: "MySQL", 3389: "RDP",
             5060: "SIP", 5061: "SIP-TLS", 5201: "iPerf3", 5985: "WinRM", 5986: "WinRM", 8080: "HTTP",
             8443: "HTTPS", 9100: "Printer"}
UDP_PORTS = {53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 88: "Kerberos", 123: "NTP", 137: "NBNS", 138: "NBDS",
             161: "SNMP", 162: "SNMP", 443: "QUIC", 500: "ISAKMP", 514: "Syslog", 520: "RIP", 546: "DHCPv6",
             547: "DHCPv6", 1645: "RADIUS", 1646: "RADIUS", 1701: "L2TP", 1812: "RADIUS", 1813: "RADIUS",
             1900: "SSDP", 1985: "HSRP", 2029: "HSRP", 2055: "NetFlow", 3222: "GLBP", 3478: "STUN", 3702: "WS-Discovery",
             3784: "BFD", 3785: "BFD", 4500: "ISAKMP", 4739: "IPFIX", 4789: "VXLAN", 5060: "SIP", 5246: "CAPWAP",
             5247: "CAPWAP", 5353: "MDNS", 5355: "LLMNR", 6343: "sFlow", 8472: "VXLAN", 9995: "NetFlow",
             9996: "NetFlow"}
FILTER_NAMES = {"FTP-DATA": "ftp-data", "TACACS+": "tacplus", "HTTPS": "tls", "SMB": "smb", "NBNS": "nbns",
                "NBDS": "nbdgm", "MDNS": "mdns", "LLMNR": "llmnr", "iPerf3": "iperf3", "SIP-TLS": "tls",
                "LDAPS": "tls", "SMTPS": "tls", "IMAPS": "tls", "POPS": "tls"}
TCP_FLAG_FIELDS = {"URG": "tcp.flags.urg", "ACK": "tcp.flags.ack", "PSH": "tcp.flags.push", "RST": "tcp.flags.reset",
                   "SYN": "tcp.flags.syn", "FIN": "tcp.flags.fin"}
OPTION_FIELDS = {"mss": "tcp.options.mss_val", "scale": "tcp.options.wscale.shift"}
TCP_FLAGS = [(0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"), (0x020, "URG"), (0x010, "ACK"), (0x008, "PSH"),
             (0x004, "RST"), (0x002, "SYN"), (0x001, "FIN")]
ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect",
              8: "Echo (ping) request", 9: "Router advertisement", 10: "Router solicitation", 11: "Time-to-live exceeded",
              12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply"}
UNREACHABLE = {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable", 3: "Port unreachable",
               4: "Fragmentation needed", 5: "Source route failed", 6: "Network unknown", 7: "Host unknown",
               9: "Network administratively prohibited", 10: "Host administratively prohibited",
               13: "Communication administratively filtered"}
ICMPV6_TYPES = {1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded", 4: "Parameter Problem",
                128: "Echo (ping) request", 129: "Echo (ping) reply", 130: "Multicast Listener Query",
                131: "Multicast Listener Report", 132: "Multicast Listener Done", 133: "Router Solicitation",
                134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement",
                137: "Redirect", 143: "Multicast Listener Report Message v2"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             35: "NAPTR", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
             255: "ANY"}
DNS_RCODES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name", 4: "Not implemented",
              5: "Refused"}
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
DHCP_OPTIONS = {1: "Subnet mask", 3: "Router", 6: "Domain name server", 12: "Host name", 15: "Domain name",
                28: "Broadcast address", 42: "NTP servers", 43: "Vendor-specific information", 50: "Requested IP address",
                51: "Lease time", 53: "DHCP message type", 54: "DHCP server identifier", 55: "Parameter request list",
                57: "Maximum message size", 58: "Renewal time", 59: "Rebinding time", 60: "Vendor class identifier",
                61: "Client identifier", 66: "TFTP server name", 67: "Boot file name", 81: "Client FQDN",
                82: "Relay agent information", 119: "Domain search", 121: "Classless static route",
                150: "TFTP server address", 252: "Proxy autodiscovery"}
DHCPV6_TYPES = {1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply",
                8: "Release", 9: "Decline", 10: "Reconfigure", 11: "Information-request", 12: "Relay-forw",
                13: "Relay-reply"}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_CONTENT = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
TLS_HANDSHAKES = {0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
                  8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request",
                  14: "Server Hello Done", 15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished"}
TLS_ALERTS = {0: "Close Notify", 10: "Unexpected Message", 20: "Bad Record MAC", 40: "Handshake Failure",
              42: "Bad Certificate", 43: "Unsupported Certificate", 44: "Certificate Revoked",
              45: "Certificate Expired", 46: "Certificate Unknown", 47: "Illegal Parameter", 48: "Unknown CA",
              49: "Access Denied", 50: "Decode Error", 51: "Decrypt Error", 70: "Protocol Version",
              71: "Insufficient Security", 80: "Internal Error", 86: "Inappropriate Fallback", 90: "User Canceled",
              109: "Missing Extension", 112: "Unrecognized Name", 116: "Certificate Required",
              120: "No Application Protocol"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
SMB2_COMMANDS = ["Negotiate Protocol", "Session Setup", "Session Logoff", "Tree Connect", "Tree Disconnect",
                 "Create", "Close", "Flush", "Read", "Write", "Lock", "Ioctl", "Cancel", "KeepAlive", "Find",
                 "Notify", "GetInfo", "SetInfo", "Break"]
NT_STATUS = {0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED", 0xC0000022: "STATUS_ACCESS_DENIED",
             0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND", 0xC000003A: "STATUS_OBJECT_PATH_NOT_FOUND",
             0xC000006D: "STATUS_LOGON_FAILURE", 0xC0000072: "STATUS_ACCOUNT_DISABLED",
             0xC0000071: "STATUS_PASSWORD_EXPIRED", 0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
             0xC00000CC: "STATUS_BAD_NETWORK_NAME", 0xC0000043: "STATUS_SHARING_VIOLATION",
             0xC000000D: "STATUS_INVALID_PARAMETER", 0xC00000BB: "STATUS_NOT_SUPPORTED",
             0x80000005: "STATUS_BUFFER_OVERFLOW", 0x80000006: "STATUS_NO_MORE_FILES",
             0xC0000203: "STATUS_USER_SESSION_DELETED", 0xC0000128: "STATUS_FILE_CLOSED",
             0x00000103: "STATUS_PENDING", 0xC0000120: "STATUS_CANCELLED", 0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
             0xC0000035: "STATUS_OBJECT_NAME_COLLISION", 0xC0000033: "STATUS_OBJECT_NAME_INVALID",
             0xC000019C: "STATUS_FS_DRIVER_REQUIRED", 0xC0000225: "STATUS_NOT_FOUND",
             0xC0000257: "STATUS_PATH_NOT_COVERED", 0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED"}
SNMP_PDUS = {0xA0: "get-request", 0xA1: "get-next-request", 0xA2: "get-response", 0xA3: "set-request", 0xA4: "trap",
             0xA5: "getBulkRequest", 0xA6: "informRequest", 0xA7: "snmpV2-trap", 0xA8: "report"}
SNMP_ERRORS = {0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr",
               6: "noAccess", 16: "authorizationError", 17: "notWritable"}
SYSLOG_FACILITIES = ["KERN", "USER", "MAIL", "DAEMON", "AUTH", "SYSLOG", "LPR", "NEWS", "UUCP", "CRON", "AUTHPRIV",
                     "FTP", "NTP", "SECURITY", "CONSOLE", "SOLARIS-CRON", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3",
                     "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]
SYSLOG_LEVELS = ["EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"]
NTP_MODES = {1: "symmetric active", 2: "symmetric passive", 3: "client", 4: "server", 5: "broadcast", 6: "control",
             7: "private"}
TFTP_OPCODES = {1: "Read Request", 2: "Write Request", 3: "Data Packet", 4: "Acknowledgement", 5: "Error Code",
                6: "Option Acknowledgement"}
RADIUS_CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
                5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 40: "Disconnect-Request",
                41: "Disconnect-ACK", 42: "Disconnect-NAK", 43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK"}
RADIUS_ATTRIBUTES = {1: "User-Name", 4: "NAS-IP-Address", 5: "NAS-Port", 6: "Service-Type", 8: "Framed-IP-Address",
                     18: "Reply-Message", 25: "Class", 27: "Session-Timeout", 30: "Called-Station-Id",
                     31: "Calling-Station-Id", 32: "NAS-Identifier", 44: "Acct-Session-Id", 61: "NAS-Port-Type",
                     64: "Tunnel-Type", 81: "Tunnel-Private-Group-Id", 87: "NAS-Port-Id"}
EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_TYPES = {1: "Identity", 2: "Notification", 3: "Legacy Nak", 4: "MD5-Challenge", 13: "TLS", 21: "TTLS", 25: "PEAP",
             26: "MS-CHAP-v2", 43: "FAST"}
EAPOL_TYPES = {0: "EAP Packet", 1: "Start", 2: "Logoff", 3: "Key", 4: "Encapsulated ASF Alert", 5: "MKA"}
HSRP_STATES = {0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active"}
HSRP_OPCODES = {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}
OSPF_TYPES = {1: "Hello Packet", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Acknowledge"}
EIGRP_OPCODES = {1: "Update", 3: "Query", 4: "Reply", 5: "Hello", 10: "SIA-Query", 11: "SIA-Reply"}
PIM_TYPES = {0: "Hello", 1: "Register", 2: "Register-stop", 3: "Join/Prune", 4: "Bootstrap", 5: "Assert",
             6: "Graft", 7: "Graft-Ack", 8: "Candidate-RP-Advertisement"}
BGP_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}
LACP_STATE = ["Activity", "Timeout", "Aggregation", "Synchronization", "Collecting", "Distributing", "Defaulted",
              "Expired"]
LLDP_TLVS = {0: "End of LLDPDU", 1: "Chassis ID", 2: "Port ID", 3: "Time to Live", 4: "Port Description",
             5: "System Name", 6: "System Description", 7: "Capabilities", 8: "Management Address",
             127: "Organization Specific"}
CDP_TLVS = {1: "Device ID", 2: "Addresses", 3: "Port ID", 4: "Capabilities", 5: "Software Version", 6: "Platform",
            9: "VTP Management Domain", 10: "Native VLAN", 11: "Duplex", 14: "Voice VLAN", 16: "Power Available",
            20: "System Name", 22: "Management Addresses", 26: "Power Requested"}
VTP_CODES = {1: "Summary Advertisement", 2: "Subset Advertisement", 3: "Advertisement Request", 4: "Join"}
DTP_MODES = {1: "on", 2: "off", 3: "desirable", 4: "auto"}
BFD_STATES = ["AdminDown", "Down", "Init", "Up"]
STP_ROLES = ["Unknown", "Alternate/Backup", "Root", "Designated"]


class Node:
    """A line of the details tree, the bytes (start, end) of the packet it's about, and the display filter for what
    it shows (field), such as ip.src == 10.0.0.5 or a protocol's name ("": the line it's under has one)."""
    __slots__ = ("text", "start", "end", "children", "field")

    def __init__(self, text, start=-1, end=-1, field=""):
        self.text, self.start, self.end, self.children, self.field = text, start, end, [], field

    def add(self, text, start=-1, end=-1, field=""):
        node = Node(text, start, end, field)
        self.children.append(node)
        return node


class NoNode:
    """Stands in for the tree when only the columns and filter values are wanted."""
    __slots__ = ()
    children = ()

    def add(self, text, start=-1, end=-1, field=""):
        return self


NO_NODE = NoNode()


class Dissection:
    def __init__(self, data, tree=False):
        self.data = data
        self.tree = tree
        self.nodes = []  # Top-level lines of the tree, a protocol each
        self.values = {}  # Filter field -> [values]
        self.lazy = []  # (prefix, make): values not worked out yet
        self.protocols = []  # Filter names of the protocols, outermost first
        self.src = self.dst = self.protocol = self.info = ""
        self.malformed = False
        self.depth = 0
        self.packet = self.tracker = None
        self.index = -1
        # For the analysis of the capture: the innermost addresses, ports and TCP header
        self.macs = None  # (source, destination)
        self.addresses = None  # (source, destination) IP addresses as text
        self.ips = None  # The same as Addresses
        self.ip_layers = 0
        self.ports = None  # ("tcp" or "udp", source port, destination port)
        self.tcp = None  # (seq, ack, flags, window, payload length, options)
        self.payload = None  # (start, end) of the TCP or UDP payload

    def layer(self, protocol, text, start, end):
        self.protocols.append(protocol)
        if not self.tree:
            return NO_NODE
        node = Node(text, start, end, protocol)
        self.nodes.append(node)
        return node

    def put(self, name, value):
        values = self.values.get(name)
        if values is None:
            self.values[name] = [value]
        else:
            values.append(value)

    def later(self, prefix, make):
        """Values of a common layer (Ethernet, IP, TCP, UDP), made by make() (name -> value or [values]) only when
        a filter asks for one of them: most packets are never asked."""
        self.lazy.append((prefix, make))

    def get(self, name):
        """A filter field's values."""
        if self.lazy:
            self.make(name.split(".", 1)[0])
        return self.values.get(name, ())

    def make(self, prefix=None):
        waiting, self.lazy = self.lazy, []
        for layer, make in waiting:
            if prefix is not None and layer != prefix:
                self.lazy.append((layer, make))
                continue
            for name, value in make().items():
                if isinstance(value, list):
                    self.values.setdefault(name, []).extend(value)
                else:
                    self.put(name, value)

    def all_values(self):
        self.make()
        return self.values

    def columns(self, protocol, info, src=None, dst=None):
        self.protocol, self.info = protocol, info
        if src is not None:
            self.src, self.dst = src, dst

    def bad(self, what, start=-1):
        self.malformed = True
        self.protocols.append("_ws.malformed")
        self.info = (self.info + " " if self.info else "") + f"[Malformed {what}]"
        if self.tree:
            self.nodes.append(Node(f"[Malformed packet: {what}]", start, len(self.data), "_ws.malformed"))


# ----------------------------------------------------------------- Helpers

def mac(raw):
    return bytes(raw).hex(":")


def field_filter(name, value):
    """The display filter for a field having this value: ip.src == 10.0.0.5, dns.qry.name == "my host"."""
    if isinstance(value, str) and not BARE_VALUE.fullmatch(value):
        value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f"{name} == {value}"


def mac_text(address):
    vendor = oui.vendor(address)
    return f"{address} ({vendor})" if vendor else address


class Address(bytes):
    """An IPv4 or IPv6 address: its bytes (quick to make and compare), shown as text."""
    __slots__ = ()

    def __str__(self):
        return socket.inet_ntoa(self) if len(self) == 4 else socket.inet_ntop(socket.AF_INET6, self)

    def __repr__(self):
        return f"Address('{self}')"

    def __format__(self, spec):
        return format(str(self), spec)

    @property
    def version(self):
        return 4 if len(self) == 4 else 6

    @classmethod
    def parse(cls, text):
        """From text such as 10.0.0.1 or fe80::1. Raises ValueError."""
        try:
            return cls(socket.inet_pton(socket.AF_INET6 if ":" in text else socket.AF_INET, text.strip()))
        except OSError:
            raise ValueError(f"{text} isn't an IP address") from None


ip4 = ip6 = Address


def u8(data, offset):
    return data[offset]


def u16(data, offset):
    return (data[offset] << 8) | data[offset + 1]


def u32(data, offset):
    return struct.unpack_from("!I", data, offset)[0]


def text_of(raw, limit=200):
    """Printable text of bytes, other bytes as dots."""
    raw = bytes(raw[:limit])
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw)


def line_of(raw):
    """The first line of a text protocol's payload."""
    end = raw.find(b"\r\n")
    end = end if end >= 0 else raw.find(b"\n")
    return bytes(raw[:end if end >= 0 else 200]).decode("utf-8", "replace")[:200]


def flag_text(flags):
    return ", ".join(name for bit, name in reversed(TCP_FLAGS) if flags & bit)  # As Wireshark: SYN, ACK


def seconds(value):
    return f"{value:g} second{'' if value == 1 else 's'}"


# ----------------------------------------------------------------- Entry point

def dissect(raw, link_type=ETHERNET, tree=False, packet=None, tracker=None, index=-1):
    """A Dissection of one captured packet. packet (a capfile.Packet) adds the frame line and what the capture's
    analysis worked out (TCP stream, relative sequence numbers, retransmissions). tracker (a capfile.Tracker), while
    the capture is first decoded: works that out as each TCP or UDP header is reached (index: the packet's)."""
    data = bytes(raw)
    d = Dissection(data, tree)
    d.packet, d.tracker, d.index = packet, tracker, index
    if packet is not None and tree:
        frame = Node(f"Frame {packet.number}: {packet.wire_length} bytes on wire, {len(data)} bytes captured", 0,
                     len(data), field_filter("frame.number", packet.number))
        d.nodes.append(frame)
        frame.add(f"Arrival time: {packet.clock()}")
        frame.add(f"Time since first frame: {packet.time:.6f} seconds")
        frame.add(f"Time since previous frame: {packet.delta:.6f} seconds")
        if packet.interface:
            frame.add(f"Interface: {packet.interface}", field=field_filter("frame.interface_name", packet.interface))
        if packet.note:
            frame.add(packet.note)
    try:
        if link_type == ETHERNET:
            ethernet(d, data, 0)
        elif link_type in RAW_IP_TYPES:
            ip_any(d, data, 0)
        elif link_type == LINUX_SLL:
            linux_sll(d, data)
        else:
            d.columns(f"Link {link_type}", f"Link type {link_type} isn't one NOMAD decodes")
    except (struct.error, IndexError, ValueError) as error:
        d.bad(str(error) or type(error).__name__)
    if d.tree and d.nodes and packet is not None:
        d.nodes[0].add("Protocols in frame: " + ":".join(name for name in d.protocols if name != "_ws.malformed"),
                       field=field_filter("frame.protocols", ":".join(d.protocols)))
    return d


def linux_sll(d, data):
    if len(data) < 16:
        return d.bad("Linux cooked header")
    node = d.layer("sll", "Linux cooked capture", 0, 16)
    protocol = u16(data, 14)
    node.add(f"Protocol: {ETHERTYPES.get(protocol, hex(protocol))} (0x{protocol:04x})", 14, 16)
    next_ethertype(d, data, 16, protocol)


def ethernet(d, data, offset):
    if len(data) < offset + 14:
        return d.bad("Ethernet header", offset)
    destination, source = mac(data[offset:offset + 6]), mac(data[offset + 6:offset + 12])
    ethertype = u16(data, offset + 12)
    d.macs = (source, destination)
    d.later("eth", lambda: {"eth.dst": destination, "eth.src": source, "eth.addr": [destination, source],
                            "eth.len" if ethertype <= 1500 else "eth.type": ethertype})
    d.columns("Ethernet", "", source, destination)
    if ethertype <= 1500:
        node = d.layer("eth", d.tree and f"IEEE 802.3 Ethernet, Src: {source}, Dst: {destination}", offset,
                       offset + 14)
        if d.tree:
            node.add(f"Destination: {mac_text(destination)}", offset, offset + 6, field_filter("eth.dst", destination))
            node.add(f"Source: {mac_text(source)}", offset + 6, offset + 12, field_filter("eth.src", source))
            node.add(f"Length: {ethertype}", offset + 12, offset + 14, field_filter("eth.len", ethertype))
        end = min(len(data), offset + 14 + ethertype)
        return llc(d, data, offset + 14, end)
    node = d.layer("eth", d.tree and f"Ethernet II, Src: {source}, Dst: {destination}", offset, offset + 14)
    if d.tree:
        node.add(f"Destination: {mac_text(destination)}", offset, offset + 6, field_filter("eth.dst", destination))
        node.add(f"Source: {mac_text(source)}", offset + 6, offset + 12, field_filter("eth.src", source))
        node.add(f"Type: {ETHERTYPES.get(ethertype, 'Unknown')} (0x{ethertype:04x})", offset + 12, offset + 14,
                 field_filter("eth.type", f"0x{ethertype:04x}"))
    next_ethertype(d, data, offset + 14, ethertype)


def next_ethertype(d, data, offset, ethertype):
    if ethertype == 0x0800 or ethertype == 0x86DD:
        ip_any(d, data, offset)
    elif ethertype in VLAN_TYPES:
        vlan(d, data, offset, ethertype)
    elif ethertype == 0x0806 or ethertype == 0x8035:
        arp(d, data, offset)
    elif ethertype == 0x88CC:
        lldp(d, data, offset, len(data))
    elif ethertype == 0x8809:
        slow_protocols(d, data, offset)
    elif ethertype == 0x888E:
        eapol(d, data, offset)
    elif ethertype in (0x8847, 0x8848):
        mpls(d, data, offset)
    elif ethertype == 0x6558:
        inner_ethernet(d, data, offset)
    elif ethertype == 0x0842:
        wake_on_lan(d, data, offset)
    elif ethertype == 0x9000:
        d.layer("loop", "Configuration Test Protocol (loopback)", offset, len(data))
        d.columns("LOOP", "Reply" if len(data) > offset + 2 and data[offset + 2] == 1 else "Loopback (keepalive)")
    else:
        name = ETHERTYPES.get(ethertype)
        d.columns(name or f"0x{ethertype:04x}", f"Ethernet type 0x{ethertype:04x}" + (f" ({name})" if name else ""))
        rest(d, data, offset, len(data))


def rest(d, data, start, end):
    """Bytes nothing else decoded."""
    if end > start:
        d.layer("data", f"Data ({end - start} bytes)", start, end)
        d.put("data.len", end - start)
        d.put("data.data", data[start:end])


def vlan(d, data, offset, ethertype):
    if len(data) < offset + 4:
        return d.bad("802.1Q tag", offset)
    tci, inner = u16(data, offset), u16(data, offset + 2)
    priority, dei, vlan_id = tci >> 13, (tci >> 12) & 1, tci & 0x0FFF
    d.put("vlan.id", vlan_id)
    d.put("vlan.priority", priority)
    d.put("vlan.dei", dei)
    d.put("vlan.etype", inner)
    node = d.layer("vlan", f"802.1Q Virtual LAN, PRI: {priority}, DEI: {dei}, ID: {vlan_id}", offset, offset + 4)
    if d.tree:
        node.add(f"Priority: {priority}", offset, offset + 2, field_filter("vlan.priority", priority))
        node.add(f"DEI: {dei}", offset, offset + 2, field_filter("vlan.dei", dei))
        node.add(f"ID: {vlan_id}", offset, offset + 2, field_filter("vlan.id", vlan_id))
        node.add(f"Type: {ETHERTYPES.get(inner, 'Unknown')} (0x{inner:04x})", offset + 2, offset + 4,
                 field_filter("vlan.etype", f"0x{inner:04x}"))
    if inner <= 1500:
        return llc(d, data, offset + 4, min(len(data), offset + 4 + inner))
    next_ethertype(d, data, offset + 4, inner)


def llc(d, data, offset, end):
    if end < offset + 3:
        return d.bad("LLC header", offset)
    dsap, ssap, control = data[offset], data[offset + 1], data[offset + 2]
    if dsap == 0xAA and ssap == 0xAA and end >= offset + 8:
        organization, pid = bytes(data[offset + 3:offset + 6]), u16(data, offset + 6)
        node = d.layer("llc", f"Logical-Link Control, SNAP, OUI {organization.hex(':')}, PID 0x{pid:04x}", offset,
                       offset + 8)
        node.add(f"DSAP: SNAP (0xaa), SSAP: SNAP (0xaa), Control: 0x{control:02x}", offset, offset + 3)
        node.add(f"Organization code: {organization.hex(':')}", offset + 3, offset + 6)
        node.add(f"PID: 0x{pid:04x}", offset + 6, offset + 8)
        body = offset + 8
        if organization == b"\x00\x00\x0c":
            if pid == 0x2000:
                return cdp(d, data, body, end)
            if pid == 0x2003:
                return vtp(d, data, body, end)
            if pid == 0x2004:
                return dtp(d, data, body, end)
            if pid == 0x010B:
                return stp(d, data, body, end, pvst=True)
            if pid == 0x0111:
                d.layer("udld", "Unidirectional Link Detection", body, end)
                return d.columns("UDLD", "Unidirectional Link Detection")
        if organization == b"\x00\x00\x00":
            return next_ethertype(d, data[:end], body, pid)
        d.columns("LLC", f"SNAP PID 0x{pid:04x}")
        return rest(d, data, body, end)
    node = d.layer("llc", f"Logical-Link Control, DSAP 0x{dsap:02x}, SSAP 0x{ssap:02x}", offset, offset + 3)
    node.add(f"DSAP: 0x{dsap:02x}, SSAP: 0x{ssap:02x}, Control: 0x{control:02x}", offset, offset + 3)
    if dsap == 0x42 and ssap == 0x42:
        return stp(d, data, offset + 3, end)
    d.columns("LLC", f"DSAP 0x{dsap:02x} SSAP 0x{ssap:02x}")
    rest(d, data, offset + 3, end)


def inner_ethernet(d, data, offset):
    """A whole frame carried inside another (GRE, ERSPAN, VXLAN): decoded as its own, and the columns show it."""
    d.depth += 1
    if d.depth > MAX_DEPTH:
        return rest(d, data, offset, len(data))
    ethernet(d, data, offset)


def wake_on_lan(d, data, offset):
    target = mac(data[offset + 6:offset + 12]) if len(data) >= offset + 12 else ""
    d.layer("wol", f"Wake On LAN, MAC: {target}", offset, len(data))
    d.put("wol.mac", target)
    d.columns("WOL", f"MagicPacket for {target}")


def mpls(d, data, offset):
    while len(data) >= offset + 4:
        entry = u32(data, offset)
        label, bottom, ttl = entry >> 12, (entry >> 8) & 1, entry & 0xFF
        d.put("mpls.label", label)
        d.layer("mpls", f"MultiProtocol Label Switching Header, Label: {label}, TTL: {ttl}", offset, offset + 4)
        offset += 4
        if bottom:
            break
    d.columns("MPLS", "MPLS Label Switched Packet")
    if len(data) > offset and data[offset] >> 4 in (4, 6):
        ip_any(d, data, offset)


# ----------------------------------------------------------------- ARP

def arp(d, data, offset):
    if len(data) < offset + 28:
        return d.bad("ARP", offset)
    hardware, protocol, hardware_size, protocol_size, opcode = struct.unpack_from("!HHBBH", data, offset)
    if hardware_size != 6 or protocol_size != 4:
        d.layer("arp", "Address Resolution Protocol", offset, len(data))
        return d.columns("ARP", f"ARP for hardware type {hardware}")
    sender_mac, sender_ip = mac(data[offset + 8:offset + 14]), ip4(data[offset + 14:offset + 18])
    target_mac, target_ip = mac(data[offset + 18:offset + 24]), ip4(data[offset + 24:offset + 28])
    gratuitous = sender_ip == target_ip
    for name, value in (("arp.opcode", opcode), ("arp.src.hw_mac", sender_mac), ("arp.src.proto_ipv4", sender_ip),
                        ("arp.dst.hw_mac", target_mac), ("arp.dst.proto_ipv4", target_ip)):
        d.put(name, value)
    if gratuitous:
        d.put("arp.isgratuitous", 1)
    if gratuitous:
        info = f"Gratuitous ARP for {sender_ip} ({'Request' if opcode == 1 else 'Reply'})"
    elif opcode == 1 and not any(sender_ip):
        info = f"Who has {target_ip}? (ARP Probe)"
    elif opcode == 1:
        info = f"Who has {target_ip}? Tell {sender_ip}"
    elif opcode == 2:
        info = f"{sender_ip} is at {sender_mac}"
    else:
        info = f"Opcode {opcode}"
    kind = {1: "request", 2: "reply"}.get(opcode, str(opcode))
    node = d.layer("arp", f"Address Resolution Protocol ({kind}{', gratuitous' if gratuitous else ''})", offset,
                   offset + 28)
    if d.tree:
        node.add(f"Hardware type: {'Ethernet' if hardware == 1 else hardware} ({hardware})", offset, offset + 2)
        node.add(f"Protocol type: IPv4 (0x{protocol:04x})", offset + 2, offset + 4)
        node.add(f"Opcode: {kind} ({opcode})", offset + 6, offset + 8, field_filter("arp.opcode", opcode))
        node.add(f"Sender MAC address: {mac_text(sender_mac)}", offset + 8, offset + 14,
                 field_filter("arp.src.hw_mac", sender_mac))
        node.add(f"Sender IP address: {sender_ip}", offset + 14, offset + 18,
                 field_filter("arp.src.proto_ipv4", sender_ip))
        node.add(f"Target MAC address: {mac_text(target_mac)}", offset + 18, offset + 24,
                 field_filter("arp.dst.hw_mac", target_mac))
        node.add(f"Target IP address: {target_ip}", offset + 24, offset + 28,
                 field_filter("arp.dst.proto_ipv4", target_ip))
    destination = d.dst if d.dst != BROADCAST else "Broadcast"
    d.columns("ARP", info, d.src, destination)


# ----------------------------------------------------------------- IP

def ip_any(d, data, offset):
    if len(data) <= offset:
        return d.bad("IP header", offset)
    version = data[offset] >> 4
    if version == 4:
        return ipv4(d, data, offset)
    if version == 6:
        return ipv6(d, data, offset)
    d.bad(f"IP version {version}", offset)


def ipv4(d, data, offset):
    if len(data) < offset + 20:
        return d.bad("IPv4 header", offset)
    header_length = (data[offset] & 0x0F) * 4
    tos, total, ident, flags_offset, ttl, protocol, checksum = struct.unpack_from("!xBHHHBBH", data, offset)
    source, destination = ip4(data[offset + 12:offset + 16]), ip4(data[offset + 16:offset + 20])
    if header_length < 20:
        return d.bad("IPv4 header length", offset)
    end = min(len(data), offset + total) if total >= header_length else len(data)  # 0 when the NIC offloads it
    dont_fragment, more = bool(flags_offset & 0x4000), bool(flags_offset & 0x2000)
    fragment_offset = (flags_offset & 0x1FFF) * 8
    d.later("ip", lambda: {"ip.src": source, "ip.dst": destination, "ip.addr": [source, destination], "ip.ttl": ttl,
                           "ip.proto": protocol, "ip.len": total, "ip.id": ident, "ip.flags.df": int(dont_fragment),
                           "ip.flags.mf": int(more), "ip.frag_offset": fragment_offset, "ip.dsfield.dscp": tos >> 2,
                           "ip.dsfield.ecn": tos & 3, "ip.hdr_len": header_length, "ip.version": 4})
    d.addresses = (str(source), str(destination))
    d.ips = (source, destination)
    d.ip_layers += 1
    d.columns("IPv4", "IPv4", d.addresses[0], d.addresses[1])
    node = d.layer("ip", d.tree and f"Internet Protocol Version 4, Src: {source}, Dst: {destination}", offset,
                   offset + header_length)
    if d.tree:
        node.add(f"Header length: {header_length} bytes", offset, offset + 1, field_filter("ip.hdr_len", header_length))
        node.add(f"Differentiated services: DSCP {tos >> 2}, ECN {tos & 3}", offset + 1, offset + 2,
                 field_filter("ip.dsfield.dscp", tos >> 2))
        node.add(f"Total length: {total}", offset + 2, offset + 4, field_filter("ip.len", total))
        node.add(f"Identification: 0x{ident:04x} ({ident})", offset + 4, offset + 6,
                 field_filter("ip.id", f"0x{ident:04x}"))
        names = [name for name, on in (("Don't fragment", dont_fragment), ("More fragments", more)) if on]
        flags = node.add(f"Flags: {', '.join(names) or 'none'}", offset + 6, offset + 8)
        flags.add(f"Don't fragment: {'Set' if dont_fragment else 'Not set'}", offset + 6, offset + 7,
                  field_filter("ip.flags.df", int(dont_fragment)))
        flags.add(f"More fragments: {'Set' if more else 'Not set'}", offset + 6, offset + 7,
                  field_filter("ip.flags.mf", int(more)))
        node.add(f"Fragment offset: {fragment_offset}", offset + 6, offset + 8,
                 field_filter("ip.frag_offset", fragment_offset))
        node.add(f"Time to live: {ttl}", offset + 8, offset + 9, field_filter("ip.ttl", ttl))
        node.add(f"Protocol: {IP_PROTOCOLS.get(protocol, 'Unknown')} ({protocol})", offset + 9, offset + 10,
                 field_filter("ip.proto", protocol))
        node.add(f"Header checksum: 0x{checksum:04x}", offset + 10, offset + 12)
        node.add(f"Source address: {source}", offset + 12, offset + 16, field_filter("ip.src", source))
        node.add(f"Destination address: {destination}", offset + 16, offset + 20, field_filter("ip.dst", destination))
    start = offset + header_length
    if fragment_offset:
        d.columns("IPv4", f"Fragmented IP protocol (proto={IP_PROTOCOLS.get(protocol, protocol)} {protocol}, "
                          f"off={fragment_offset}, ID={ident:04x})")
        d.put("ip.fragment", 1)
        return rest(d, data, start, end)
    if more:
        d.put("ip.fragment", 1)
    ip_payload(d, data, start, end, protocol)
    if more:
        d.info += " [first fragment]"


def ipv6(d, data, offset):
    if len(data) < offset + 40:
        return d.bad("IPv6 header", offset)
    first, payload_length, next_header, hop_limit = struct.unpack_from("!IHBB", data, offset)
    source, destination = ip6(data[offset + 8:offset + 24]), ip6(data[offset + 24:offset + 40])
    traffic_class, flow = (first >> 20) & 0xFF, first & 0xFFFFF
    d.later("ipv6", lambda: {"ipv6.src": source, "ipv6.dst": destination, "ipv6.addr": [source, destination],
                             "ipv6.nxt": next_header, "ipv6.hlim": hop_limit, "ipv6.plen": payload_length,
                             "ipv6.flow": flow, "ipv6.tclass": traffic_class, "ipv6.version": 6})
    d.addresses = (str(source), str(destination))
    d.ips = (source, destination)
    d.ip_layers += 1
    d.columns("IPv6", "IPv6", d.addresses[0], d.addresses[1])
    node = d.layer("ipv6", d.tree and f"Internet Protocol Version 6, Src: {source}, Dst: {destination}", offset,
                   offset + 40)
    if d.tree:
        node.add(f"Traffic class: 0x{traffic_class:02x}, Flow label: 0x{flow:05x}", offset, offset + 4)
        node.add(f"Payload length: {payload_length}", offset + 4, offset + 6, field_filter("ipv6.plen", payload_length))
        node.add(f"Next header: {IP_PROTOCOLS.get(next_header, 'Unknown')} ({next_header})", offset + 6, offset + 7,
                 field_filter("ipv6.nxt", next_header))
        node.add(f"Hop limit: {hop_limit}", offset + 7, offset + 8, field_filter("ipv6.hlim", hop_limit))
        node.add(f"Source address: {source}", offset + 8, offset + 24, field_filter("ipv6.src", source))
        node.add(f"Destination address: {destination}", offset + 24, offset + 40, field_filter("ipv6.dst", destination))
    end = min(len(data), offset + 40 + payload_length) if payload_length else len(data)
    start = offset + 40
    while next_header in IPV6_EXTENSIONS or next_header == 44:
        if end < start + 8:
            return d.bad("IPv6 extension header", start)
        following = data[start]
        if next_header == 44:
            fragment = u16(data, start + 2)
            node.add(f"Fragment header: offset {fragment & 0xFFF8}, more {fragment & 1}", start, start + 8)
            d.put("ipv6.fragment", 1)
            if fragment & 0xFFF8:
                d.columns("IPv6", f"IPv6 fragment (nxt={IP_PROTOCOLS.get(following, following)}, "
                                  f"off={fragment & 0xFFF8})")
                return rest(d, data, start + 8, end)
            length = 8
        else:
            length = (data[start + 1] + 1) * 8
            node.add(f"{IP_PROTOCOLS[next_header]} header ({length} bytes)", start, start + length)
        start += length
        next_header = following
    ip_payload(d, data, start, end, next_header)


def ip_payload(d, data, start, end, protocol):
    if protocol == 6:
        tcp(d, data, start, end)
    elif protocol == 17:
        udp(d, data, start, end)
    elif protocol == 1:
        icmp(d, data, start, end)
    elif protocol == 58:
        icmpv6(d, data, start, end)
    elif protocol == 2:
        igmp(d, data, start, end)
    elif protocol == 47:
        gre(d, data, start, end)
    elif protocol == 89:
        ospf(d, data, start, end)
    elif protocol == 88:
        eigrp(d, data, start, end)
    elif protocol == 112:
        vrrp(d, data, start, end)
    elif protocol == 103:
        pim(d, data, start, end)
    elif protocol == 50 and end >= start + 8:
        spi, sequence = struct.unpack_from("!II", data, start)
        d.layer("esp", f"Encapsulating Security Payload, SPI 0x{spi:08x}", start, end)
        d.put("esp.spi", spi)
        d.columns("ESP", f"ESP (SPI=0x{spi:08x})")
    elif protocol in (4, 41):
        d.depth += 1
        if d.depth <= MAX_DEPTH:
            ip_any(d, data[:end], start)
    elif protocol == 59:
        d.columns(d.protocol, "IPv6 no next header")
    else:
        name = IP_PROTOCOLS.get(protocol)
        d.columns(name or d.protocol, f"{name or 'IP protocol'} ({protocol})")
        rest(d, data, start, end)


# ----------------------------------------------------------------- ICMP

def icmp(d, data, start, end):
    if end < start + 4:
        return d.bad("ICMP", start)
    kind, code = data[start], data[start + 1]
    d.put("icmp.type", kind)
    d.put("icmp.code", code)
    name = ICMP_TYPES.get(kind, f"Type {kind}")
    info = name
    node = d.layer("icmp", "Internet Control Message Protocol", start, end)
    node.add(f"Type: {kind} ({name})", start, start + 1, field_filter("icmp.type", kind))
    node.add(f"Code: {code}", start + 1, start + 2, field_filter("icmp.code", code))
    if kind in (0, 8) and end >= start + 8:
        ident, sequence = u16(data, start + 4), u16(data, start + 6)
        d.put("icmp.ident", ident)
        d.put("icmp.seq", sequence)
        node.add(f"Identifier: {ident} (0x{ident:04x})", start + 4, start + 6, field_filter("icmp.ident", ident))
        node.add(f"Sequence number: {sequence}", start + 6, start + 8, field_filter("icmp.seq", sequence))
        info += f"  id=0x{ident:04x}, seq={sequence}"
        if d.addresses:
            ttl = d.get("ip.ttl")
            info += f", ttl={ttl[-1]}" if ttl else ""
    elif kind in (3, 11, 5, 12) and end >= start + 8 + 20:
        if kind == 3:
            reason = UNREACHABLE.get(code, f"code {code}")
            info += f" ({reason})"
            if code == 4:
                mtu = u16(data, start + 6)
                d.put("icmp.mtu", mtu)
                info += f", next-hop MTU {mtu}"
                node.add(f"MTU of next hop: {mtu}", start + 6, start + 8)
        elif kind == 11:
            info += " (Time to live exceeded in transit)" if code == 0 else " (Fragment reassembly time exceeded)"
        info += original_packet(d, data, start + 8, end, node)
    d.columns("ICMP", info)


def original_packet(d, data, start, end, node):
    """What an ICMP error is about (the start of the packet it bounced), as text for the info column."""
    try:
        header_length = (data[start] & 0x0F) * 4
        protocol = data[start + 9]
        source, destination = ip4(data[start + 12:start + 16]), ip4(data[start + 16:start + 20])
        d.put("icmp.orig.src", source)
        d.put("icmp.orig.dst", destination)
        text = f"{IP_PROTOCOLS.get(protocol, protocol)} {source}"
        if protocol in (6, 17) and end >= start + header_length + 4:
            source_port, destination_port = struct.unpack_from("!HH", data, start + header_length)
            text = f"{IP_PROTOCOLS[protocol]} {source}:{source_port} → {destination}:{destination_port}"
        else:
            text += f" → {destination}"
        node.add(f"Original packet: {text}", start, end)
        return f" for {text}"
    except (IndexError, struct.error, ValueError):
        return ""


def icmpv6(d, data, start, end):
    if end < start + 4:
        return d.bad("ICMPv6", start)
    kind, code = data[start], data[start + 1]
    d.put("icmpv6.type", kind)
    d.put("icmpv6.code", code)
    name = ICMPV6_TYPES.get(kind, f"Type {kind}")
    info = name
    node = d.layer("icmpv6", "Internet Control Message Protocol v6", start, end)
    node.add(f"Type: {name} ({kind})", start, start + 1)
    node.add(f"Code: {code}", start + 1, start + 2)
    if kind in (128, 129) and end >= start + 8:
        ident, sequence = u16(data, start + 4), u16(data, start + 6)
        d.put("icmpv6.echo.identifier", ident)
        d.put("icmpv6.echo.sequence_number", sequence)
        info += f" id=0x{ident:04x}, seq={sequence}"
    elif kind in (135, 136, 137) and end >= start + 24:
        target = ip6(data[start + 8:start + 24])
        d.put("icmpv6.nd.ns.target_address" if kind == 135 else "icmpv6.nd.na.target_address", target)
        node.add(f"Target address: {target}", start + 8, start + 24)
        info += f" for {target}" if kind == 135 else f" {target}"
        link = nd_link_address(data, start + 24, end)
        if link:
            info += f" from {link}" if kind == 135 else f" is at {link}"
    elif kind == 2 and end >= start + 8:
        mtu = u32(data, start + 4)
        d.put("icmpv6.mtu", mtu)
        info += f" (MTU {mtu})"
    elif kind == 1:
        info += f" (code {code})"
    d.columns("ICMPv6", info)


def nd_link_address(data, offset, end):
    while offset + 8 <= end:
        kind, length = data[offset], data[offset + 1] * 8
        if not length:
            break
        if kind in (1, 2) and length >= 8:
            return mac(data[offset + 2:offset + 8])
        offset += length
    return ""


def igmp(d, data, start, end):
    if end < start + 8:
        return d.bad("IGMP", start)
    kind = data[start]
    names = {0x11: "Membership Query", 0x12: "Membership Report (v1)", 0x16: "Membership Report", 0x17: "Leave Group",
             0x22: "Membership Report (v3)"}
    name = names.get(kind, f"Type 0x{kind:02x}")
    d.put("igmp.type", kind)
    node = d.layer("igmp", f"Internet Group Management Protocol, {name}", start, end)
    groups = []
    if kind == 0x22:
        count, offset = u16(data, start + 6), start + 8
        for _ in range(count):
            if offset + 8 > end:
                break
            sources = u16(data, offset + 2)
            group = ip4(data[offset + 4:offset + 8])
            groups.append(group)
            node.add(f"Group record: {group}", offset, offset + 8 + sources * 4)
            offset += 8 + data[offset + 1] * 4 + sources * 4
    else:
        group = ip4(data[start + 4:start + 8])
        if any(group) or kind != 0x11:
            groups.append(group)
        node.add(f"Multicast address: {group}", start + 4, start + 8)
    for group in groups:
        d.put("igmp.maddr", group)
    version = "v3" if kind == 0x22 or (kind == 0x11 and end - start > 8) else "v2" if kind in (0x11, 0x16, 0x17) \
        else "v1"
    d.columns(f"IGMP{version}", name + "".join(f" group {group}" for group in groups))


# ----------------------------------------------------------------- TCP and UDP

def tcp(d, data, start, end):
    if end < start + 20:
        return d.bad("TCP header", start)
    source, destination, sequence, ack, offset_flags, window, checksum, urgent = struct.unpack_from(
        "!HHIIHHHH", data, start)
    header_length = (offset_flags >> 12) * 4
    flags = offset_flags & 0x1FF
    if header_length < 20 or start + header_length > end:
        return d.bad("TCP header length", start)
    payload_start = start + header_length
    length = end - payload_start
    options = tcp_options(data, start + 20, payload_start)
    d.ports = ("tcp", source, destination)
    d.tcp = (sequence, ack, flags, window, length, options)
    d.payload = (payload_start, end)
    packet = d.packet
    if d.tracker is not None and d.addresses:
        d.tracker.tcp_packet(packet, d.index, d)
    relative = getattr(packet, "relative", None)
    rel_seq, rel_ack = relative if relative else (sequence, ack)
    scaled = getattr(packet, "window", None)
    stream = getattr(packet, "stream", -1)
    analysis = getattr(packet, "analysis", ())
    d.later("tcp", lambda: tcp_values(data, source, destination, sequence, ack, flags, window, length, header_length,
                                      options, rel_seq, rel_ack, scaled, stream, analysis, payload_start, end))
    flag_names = flag_text(flags)
    info = f"{source} → {destination} [{flag_names}] Seq={rel_seq}"
    if flags & 0x010:
        info += f" Ack={rel_ack}"
    info += f" Win={scaled if scaled is not None else window} Len={length}"
    if "mss" in options:
        info += f" MSS={options['mss']}"
    if "scale" in options:
        info += f" WS={2 ** options['scale']}"
    if "sack_perm" in options:
        info += " SACK_PERM"
    marks = analysis_text(analysis)
    node = d.layer("tcp", d.tree and f"Transmission Control Protocol, Src Port: {source}, Dst Port: {destination}, "
                                     f"Seq: {rel_seq}{f', Ack: {rel_ack}' if flags & 0x010 else ''}, Len: {length}",
                   start, payload_start)
    if d.tree:
        node.add(f"Source port: {source}", start, start + 2, field_filter("tcp.srcport", source))
        node.add(f"Destination port: {destination}", start + 2, start + 4, field_filter("tcp.dstport", destination))
        if stream >= 0:
            node.add(f"[Stream index: {stream}]", field=field_filter("tcp.stream", stream))
        node.add(f"Sequence number: {rel_seq}{'    (relative)' if relative else ''}", start + 4, start + 8,
                 field_filter("tcp.seq", rel_seq))
        if relative:
            node.add(f"Sequence number (raw): {sequence}", start + 4, start + 8, field_filter("tcp.seq_raw", sequence))
        node.add(f"Acknowledgment number: {rel_ack}{'    (relative)' if relative else ''}", start + 8, start + 12,
                 field_filter("tcp.ack", rel_ack))
        node.add(f"Header length: {header_length} bytes", start + 12, start + 13,
                 field_filter("tcp.hdr_len", header_length))
        flag_node = node.add(f"Flags: 0x{flags:03x} ({flag_names or 'none'})", start + 12, start + 14,
                             field_filter("tcp.flags", f"0x{flags:03x}"))
        for bit, name in TCP_FLAGS:
            flag_field = TCP_FLAG_FIELDS.get(name)
            flag_node.add(f"{name}: {'Set' if flags & bit else 'Not set'}", start + 12, start + 14,
                          field_filter(flag_field, int(bool(flags & bit))) if flag_field else "")
        node.add(f"Window: {window}", start + 14, start + 16, field_filter("tcp.window_size_value", window))
        if scaled is not None and scaled != window:
            node.add(f"[Calculated window size: {scaled}]", field=field_filter("tcp.window_size", scaled))
        node.add(f"Checksum: 0x{checksum:04x}", start + 16, start + 18)
        if options:
            option_node = node.add("Options: " + ", ".join(option_text(key, value) for key, value in options.items()),
                                   start + 20, payload_start)
            for key, value in options.items():
                option_node.add(option_text(key, value),
                                field=field_filter(OPTION_FIELDS[key], value) if key in OPTION_FIELDS else "")
        if analysis:
            analysis_node = node.add("[SEQ/ACK analysis]", field="tcp.analysis.flags")
            for flag in analysis:
                analysis_node.add(f"[{ANALYSIS_TEXT.get(flag, flag)}]", field=f"tcp.analysis.{flag}")
        if length:
            node.add(f"TCP payload ({length} bytes)", payload_start, end, field_filter("tcp.len", length))
    d.columns("TCP", (marks + " " if marks else "") + info)
    resent = any(flag.endswith("retransmission") or flag == "out_of_order" for flag in analysis)
    if length and not flags & 0x004 and not resent:  # A resent segment is shown as TCP, as in Wireshark
        tcp_application(d, data, payload_start, end, source, destination, marks)
    elif length:
        rest(d, data, payload_start, end)


ANALYSIS_TEXT = {"retransmission": "TCP Retransmission", "fast_retransmission": "TCP Fast Retransmission",
                 "spurious_retransmission": "TCP Spurious Retransmission", "out_of_order": "TCP Out-Of-Order",
                 "lost_segment": "TCP Previous segment not captured", "duplicate_ack": "TCP Dup ACK",
                 "zero_window": "TCP ZeroWindow", "zero_window_probe": "TCP ZeroWindowProbe",
                 "window_full": "TCP Window Full", "keep_alive": "TCP Keep-Alive",
                 "keep_alive_ack": "TCP Keep-Alive ACK", "window_update": "TCP Window Update",
                 "ack_lost_segment": "TCP ACKed unseen segment", "reused_ports": "TCP Port numbers reused"}


def analysis_text(analysis):
    return " ".join(f"[{ANALYSIS_TEXT.get(flag, flag)}]" for flag in analysis)


def tcp_values(data, source, destination, sequence, ack, flags, window, length, header_length, options, rel_seq,
               rel_ack, scaled, stream, analysis, payload_start, end):
    values = {"tcp.srcport": source, "tcp.dstport": destination, "tcp.port": [source, destination],
              "tcp.seq": rel_seq, "tcp.seq_raw": sequence, "tcp.ack": rel_ack, "tcp.ack_raw": ack, "tcp.flags": flags,
              "tcp.flags.syn": int(bool(flags & 0x002)), "tcp.flags.ack": int(bool(flags & 0x010)),
              "tcp.flags.fin": int(bool(flags & 0x001)), "tcp.flags.reset": int(bool(flags & 0x004)),
              "tcp.flags.push": int(bool(flags & 0x008)), "tcp.flags.urg": int(bool(flags & 0x020)),
              "tcp.window_size_value": window, "tcp.window_size": scaled if scaled is not None else window,
              "tcp.len": length, "tcp.hdr_len": header_length}
    if "mss" in options:
        values["tcp.options.mss_val"] = options["mss"]
    if "scale" in options:
        values["tcp.options.wscale.shift"] = options["scale"]
    if stream >= 0:
        values["tcp.stream"] = stream
    for flag in analysis:
        values["tcp.analysis." + flag] = 1
    if analysis:
        values["tcp.analysis.flags"] = 1
    if length:
        values["tcp.payload"] = data[payload_start:end]
    return values


def tcp_options(data, offset, end):
    options = {}
    while offset < end:
        kind = data[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 1 >= end:
            break
        length = data[offset + 1]
        if length < 2 or offset + length > end:
            break
        if kind == 2 and length == 4:
            options["mss"] = u16(data, offset + 2)
        elif kind == 3 and length == 3:
            options["scale"] = min(data[offset + 2], 14)
        elif kind == 4:
            options["sack_perm"] = True
        elif kind == 5:
            options["sack"] = [(u32(data, at), u32(data, at + 4)) for at in range(offset + 2, offset + length - 7, 8)]
        elif kind == 8 and length == 10:
            options["timestamps"] = struct.unpack_from("!II", data, offset + 2)
        offset += length
    return options


def option_text(key, value):
    if key == "mss":
        return f"Maximum segment size: {value} bytes"
    if key == "scale":
        return f"Window scale: {value} (multiply by {2 ** value})"
    if key == "sack_perm":
        return "SACK permitted"
    if key == "sack":
        return "SACK: " + " ".join(f"{left}-{right}" for left, right in value)
    if key == "timestamps":
        return f"Timestamps: TSval {value[0]}, TSecr {value[1]}"
    return key


def udp(d, data, start, end):
    if end < start + 8:
        return d.bad("UDP header", start)
    source, destination, length, checksum = struct.unpack_from("!HHHH", data, start)
    if 8 <= length and start + length < end:
        end = start + length
    d.ports = ("udp", source, destination)
    d.payload = (start + 8, end)
    if d.tracker is not None and d.addresses:
        d.tracker.udp_packet(d.packet, d.index, d)
    stream = getattr(d.packet, "stream", -1)
    d.later("udp", lambda: udp_values(data, source, destination, length, stream, start, end))
    node = d.layer("udp", d.tree and f"User Datagram Protocol, Src Port: {source}, Dst Port: {destination}", start,
                   start + 8)
    if d.tree:
        node.add(f"Source port: {source}", start, start + 2, field_filter("udp.srcport", source))
        node.add(f"Destination port: {destination}", start + 2, start + 4, field_filter("udp.dstport", destination))
        if stream >= 0:
            node.add(f"[Stream index: {stream}]", field=field_filter("udp.stream", stream))
        node.add(f"Length: {length}", start + 4, start + 6, field_filter("udp.length", length))
        node.add(f"Checksum: 0x{checksum:04x}", start + 6, start + 8)
    d.columns("UDP", f"{source} → {destination} Len={end - start - 8}")
    udp_application(d, data, start + 8, end, source, destination)


def udp_values(data, source, destination, length, stream, start, end):
    values = {"udp.srcport": source, "udp.dstport": destination, "udp.port": [source, destination],
              "udp.length": length}
    if stream >= 0:
        values["udp.stream"] = stream
    if end > start + 8:
        values["udp.payload"] = data[start + 8:end]
    return values


def port_name(ports, source, destination):
    low, high = sorted((source, destination))
    return ports.get(low) or ports.get(high) or ("traceroute" if 33434 <= destination <= 33534 and
                                                  ports is UDP_PORTS else None)


def filter_name(name):
    return FILTER_NAMES.get(name, "".join(character for character in name.lower() if character.isalnum()))


def udp_application(d, data, start, end, source, destination):
    if end <= start:
        return
    ports = (source, destination)
    if 53 in ports or 5353 in ports or 5355 in ports:
        return dns(d, data, start, end, "mdns" if 5353 in ports else "llmnr" if 5355 in ports else "dns")
    if 67 in ports or 68 in ports:
        return dhcp(d, data, start, end)
    if 546 in ports or 547 in ports:
        return dhcpv6(d, data, start, end)
    if 69 in ports:
        return tftp(d, data, start, end)
    if 123 in ports:
        return ntp(d, data, start, end)
    if 161 in ports or 162 in ports:
        return snmp(d, data, start, end)
    if 514 in ports:
        return syslog(d, data, start, end)
    if 137 in ports:
        return nbns(d, data, start, end)
    if ports[1] in (1812, 1813, 1645, 1646) or ports[0] in (1812, 1813, 1645, 1646):
        return radius(d, data, start, end)
    if 1985 in ports or 2029 in ports:
        return hsrp(d, data, start, end)
    if 4789 in ports or 8472 in ports:
        return vxlan(d, data, start, end)
    if 1900 in ports:
        return text_protocol(d, data, start, end, "ssdp", "SSDP")
    if 3784 in ports or 3785 in ports:
        return bfd(d, data, start, end)
    if 9 in ports and end - start >= 102 and data[start:start + 6] == b"\xff" * 6:
        return wake_on_lan(d, data, start)
    name = port_name(UDP_PORTS, source, destination)
    if name:
        d.layer(filter_name(name), name, start, end)
        d.columns(name, d.info)
    rest(d, data, start, end)


def tcp_application(d, data, start, end, source, destination, marks):
    ports = (source, destination)
    payload = data[start:start + 16]
    prefix = marks + " " if marks else ""
    if end - start >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3:
        return tls(d, data, start, end, prefix)
    if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1."):
        return http(d, data, start, end, prefix)
    if payload.startswith(b"SSH-"):
        d.layer("ssh", "SSH Protocol", start, end)
        d.put("ssh.protocol", line_of(data[start:end]))
        return d.columns("SSH", prefix + "Server: " + line_of(data[start:end]) if source == 22
                         else prefix + "Client: " + line_of(data[start:end]))
    if 445 in ports or 139 in ports:
        if smb(d, data, start, end, prefix):
            return
    if 53 in ports and end - start > 14:
        return dns(d, data, start + 2, end, "dns")
    if 179 in ports and payload[:16] == b"\xff" * 16:
        return bgp(d, data, start, end)
    if 49 in ports and end - start >= 12:
        kind = data[start + 1]
        d.layer("tacplus", "TACACS+", start, end)
        d.put("tacplus.type", kind)
        names = {1: "Authentication", 2: "Authorization", 3: "Accounting"}
        return d.columns("TACACS+", prefix + f"{names.get(kind, kind)} (seq {data[start + 2]})")
    if ports[0] in (21, 25, 110, 143, 23, 587) or ports[1] in (21, 25, 110, 143, 23, 587):
        name = port_name(TCP_PORTS, source, destination)
        return text_protocol(d, data, start, end, filter_name(name), name, prefix)
    name = port_name(TCP_PORTS, source, destination)
    if name:
        d.layer(filter_name(name), name, start, end)
        d.protocol = "TLS" if filter_name(name) == "tls" else name
    rest(d, data, start, end)


def text_protocol(d, data, start, end, protocol, name, prefix=""):
    first = line_of(data[start:end])
    node = d.layer(protocol, name, start, end)
    if d.tree:
        for line in bytes(data[start:end]).decode("utf-8", "replace").splitlines()[:40]:
            node.add(line)
    d.columns(name, prefix + first)


# ----------------------------------------------------------------- Applications

def dns_name(data, offset, start, end):
    """(name, offset after it) of a DNS name at offset; start is where the DNS message begins (for pointers)."""
    labels, jumped, after, hops = [], False, offset, 0
    while offset < end:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= end or hops > 30:
                raise ValueError("DNS name pointer")
            pointer = start + (((length & 0x3F) << 8) | data[offset + 1])
            if not jumped:
                after = offset + 2
            jumped, hops, offset = True, hops + 1, pointer
            continue
        labels.append(bytes(data[offset + 1:offset + 1 + length]).decode("utf-8", "replace"))
        offset += 1 + length
    if not jumped:
        after = offset
    return ".".join(labels) or "<Root>", after


def dns(d, data, start, end, protocol):
    if end < start + 12:
        return d.bad("DNS header", start)
    ident, flags, questions, answers, authority, additional = struct.unpack_from("!HHHHHH", data, start)
    response, opcode, rcode = flags >> 15, (flags >> 11) & 0xF, flags & 0xF
    name = {"dns": "DNS", "mdns": "MDNS", "llmnr": "LLMNR"}[protocol]
    node = d.layer(protocol, f"Domain Name System ({'response' if response else 'query'})", start, end)
    d.put("dns.id", ident)
    d.put("dns.flags.response", response)
    d.put("dns.flags.opcode", opcode)
    d.put("dns.count.queries", questions)
    d.put("dns.count.answers", answers)
    if response:
        d.put("dns.flags.rcode", rcode)
    if d.tree:
        node.add(f"Transaction ID: 0x{ident:04x}", start, start + 2, field_filter("dns.id", f"0x{ident:04x}"))
        node.add(f"Flags: 0x{flags:04x} {'Standard query response' if response else 'Standard query'}"
                 f"{', ' + DNS_RCODES.get(rcode, str(rcode)) if response else ''}", start + 2, start + 4)
        node.add(f"Questions: {questions}, Answer RRs: {answers}, Authority RRs: {authority}, "
                 f"Additional RRs: {additional}", start + 4, start + 12)
    offset = start + 12
    asked = []
    queries = node.add("Queries") if questions else NO_NODE
    for _ in range(min(questions, 20)):
        query, offset = dns_name(data, offset, start, end)
        kind = u16(data, offset)
        offset += 4
        asked.append(f"{DNS_TYPES.get(kind, kind)} {query}")
        d.put("dns.qry.name", query)
        d.put("dns.qry.type", kind)
        queries.add(f"{query}: type {DNS_TYPES.get(kind, kind)}", field=field_filter("dns.qry.name", query))
    answered = []
    answer_node = node.add("Answers") if answers and d.tree else NO_NODE
    for index in range(min(answers + authority, 60)):
        if offset >= end:
            break
        record_start = offset
        owner, offset = dns_name(data, offset, start, end)
        kind, _, ttl, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        value = data[offset:offset + length]
        text = ""
        if kind == 1 and length == 4:
            address = ip4(value)
            d.put("dns.a", address)
            text = str(address)
        elif kind == 28 and length == 16:
            address = ip6(value)
            d.put("dns.aaaa", address)
            text = str(address)
        elif kind in (5, 12, 2):
            text = dns_name(data, offset, start, end)[0]
            d.put({5: "dns.cname", 12: "dns.ptr.domain_name", 2: "dns.ns"}[kind], text)
        offset += length
        if index < answers:
            d.put("dns.resp.name", owner)
            d.put("dns.resp.ttl", ttl)
            if text:
                answered.append(f"{DNS_TYPES.get(kind, kind)} {text}")
            answer_node.add(f"{owner}: type {DNS_TYPES.get(kind, kind)}, TTL {ttl}{', ' + text if text else ''}",
                            record_start, offset)
    info = f"Standard query{' response' if response else ''} 0x{ident:04x}"
    if response and rcode:
        info += f" {DNS_RCODES.get(rcode, f'Error {rcode}')}"
    info += " " + " ".join(asked)
    if answered:
        info += " " + " ".join(answered[:6])
    d.columns(name, info.strip())


def dhcp(d, data, start, end):
    if end < start + 240:
        return d.bad("DHCP", start)
    op, _, _, hops, xid, secs, flags = struct.unpack_from("!BBBBIHH", data, start)
    client, yours, server, relay = (ip4(data[start + at:start + at + 4]) for at in (12, 16, 20, 24))
    hardware = mac(data[start + 28:start + 34])
    node = d.layer("dhcp", "Dynamic Host Configuration Protocol", start, end)
    for name, value in (("dhcp.type", op), ("dhcp.id", xid), ("dhcp.hw.mac_addr", hardware),
                        ("dhcp.ip.client", client), ("dhcp.ip.your", yours), ("dhcp.ip.server", server),
                        ("dhcp.ip.relay", relay), ("dhcp.hops", hops)):
        d.put(name, value)
    if d.tree:
        node.add(f"Message type: {'Boot Request' if op == 1 else 'Boot Reply'} ({op})", start, start + 1)
        node.add(f"Hops: {hops}", start + 3, start + 4)
        node.add(f"Transaction ID: 0x{xid:08x}", start + 4, start + 8)
        node.add(f"Bootp flags: 0x{flags:04x} ({'Broadcast' if flags & 0x8000 else 'Unicast'})", start + 10,
                 start + 12)
        node.add(f"Client IP address: {client}", start + 12, start + 16)
        node.add(f"Your (client) IP address: {yours}", start + 16, start + 20)
        node.add(f"Next server IP address: {server}", start + 20, start + 24)
        node.add(f"Relay agent IP address: {relay}", start + 24, start + 28)
        node.add(f"Client MAC address: {mac_text(hardware)}", start + 28, start + 34)
    offset = start + 240
    message = None
    while offset < end:
        code = data[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1
            continue
        length = data[offset + 1]
        value = data[offset + 2:offset + 2 + length]
        text = dhcp_option(d, code, value)
        if code == 53 and length >= 1:
            message = value[0]
        node.add(f"Option ({code}) {DHCP_OPTIONS.get(code, 'Unknown')}{': ' + text if text else ''}", offset,
                 offset + 2 + length)
        offset += 2 + length
    name = DHCP_TYPES.get(message, "BOOTP" if message is None else f"Type {message}")
    d.columns("DHCP", f"DHCP {name} - Transaction ID 0x{xid:x}")


def dhcp_option(d, code, value):
    if code == 53 and value:
        d.put("dhcp.option.dhcp", value[0])
        return DHCP_TYPES.get(value[0], str(value[0]))
    if code in (1, 3, 6, 50, 54, 28, 42, 150) and len(value) >= 4 and len(value) % 4 == 0:
        addresses = [ip4(value[at:at + 4]) for at in range(0, len(value), 4)]
        field = {1: "dhcp.option.subnet_mask", 3: "dhcp.option.router", 6: "dhcp.option.domain_name_server",
                 50: "dhcp.option.requested_ip_address", 54: "dhcp.option.dhcp_server_id",
                 28: "dhcp.option.broadcast_address", 42: "dhcp.option.ntp_server",
                 150: "dhcp.option.tftp_server_address"}[code]
        for address in addresses:
            d.put(field, address)
        return ", ".join(str(address) for address in addresses)
    if code in (51, 58, 59) and len(value) == 4:
        lease = u32(value, 0)
        if code == 51:
            d.put("dhcp.option.ip_address_lease_time", lease)
        return seconds(lease)
    if code in (12, 15, 60, 66, 67):
        text = bytes(value).decode("utf-8", "replace").rstrip("\0")
        field = {12: "dhcp.option.hostname", 15: "dhcp.option.domain_name", 60: "dhcp.option.vendor_class_id",
                 66: "dhcp.option.tftp_server_name", 67: "dhcp.option.bootfile_name"}[code]
        d.put(field, text)
        return text
    if code == 61 and len(value) == 7 and value[0] == 1:
        return mac(value[1:])
    if code == 55:
        return ", ".join(str(item) for item in value)
    if code == 82:
        return bytes(value).hex(" ")
    return ""


def dhcpv6(d, data, start, end):
    kind = data[start]
    d.put("dhcpv6.msgtype", kind)
    d.layer("dhcpv6", "DHCPv6", start, end)
    name = DHCPV6_TYPES.get(kind, f"Type {kind}")
    xid = bytes(data[start + 1:start + 4]).hex()
    d.columns("DHCPv6", f"{name} XID: 0x{xid}")


def tftp(d, data, start, end):
    if end < start + 4:
        return d.bad("TFTP", start)
    opcode = u16(data, start)
    d.put("tftp.opcode", opcode)
    node = d.layer("tftp", "Trivial File Transfer Protocol", start, end)
    name = TFTP_OPCODES.get(opcode, f"Opcode {opcode}")
    if opcode in (1, 2):
        parts = bytes(data[start + 2:end]).split(b"\0")
        filename = parts[0].decode("utf-8", "replace")
        mode = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
        d.put("tftp.source_file" if opcode == 1 else "tftp.destination_file", filename)
        node.add(f"File: {filename}")
        info = f"{name}, File: {filename}, Transfer type: {mode}"
    elif opcode in (3, 4):
        block = u16(data, start + 2)
        d.put("tftp.block", block)
        info = f"{name}, Block: {block}" + (" (last)" if opcode == 3 and end - start - 4 < 512 else "")
    elif opcode == 5:
        code = u16(data, start + 2)
        message = bytes(data[start + 4:end]).split(b"\0")[0].decode("utf-8", "replace")
        d.put("tftp.error.code", code)
        d.put("tftp.error.message", message)
        info = f"{name}, Code: {code}, Message: {message}"
    else:
        info = name
    d.columns("TFTP", info)


def ntp(d, data, start, end):
    if end < start + 4:
        return d.bad("NTP", start)
    version, mode, stratum = (data[start] >> 3) & 7, data[start] & 7, data[start + 1]
    d.put("ntp.flags.vn", version)
    d.put("ntp.flags.mode", mode)
    d.put("ntp.stratum", stratum)
    node = d.layer("ntp", "Network Time Protocol", start, end)
    node.add(f"Version: {version}, Mode: {NTP_MODES.get(mode, mode)}", start, start + 1)
    node.add(f"Stratum: {stratum}", start + 1, start + 2)
    d.columns("NTP", f"NTP Version {version}, {NTP_MODES.get(mode, f'mode {mode}')}")


def syslog(d, data, start, end):
    text = bytes(data[start:end]).decode("utf-8", "replace").strip()
    info, message = text, text
    if text.startswith("<") and ">" in text[:6]:
        priority = int(text[1:text.index(">")]) if text[1:text.index(">")].isdigit() else -1
        message = text[text.index(">") + 1:]
        if priority >= 0:
            facility, level = priority >> 3, priority & 7
            d.put("syslog.facility", facility)
            d.put("syslog.level", level)
            name = SYSLOG_FACILITIES[facility] if facility < len(SYSLOG_FACILITIES) else str(facility)
            info = f"{name}.{SYSLOG_LEVELS[level]}: {message}"
    d.put("syslog.msg", message)
    node = d.layer("syslog", "Syslog message", start, end)
    node.add(message)
    d.columns("Syslog", info[:300])


def nbns(d, data, start, end):
    if end < start + 12:
        return d.bad("NBNS", start)
    flags = u16(data, start + 2)
    opcode, response = (flags >> 11) & 0xF, flags >> 15
    name = ""
    if end > start + 13 and data[start + 12] == 32:
        raw = data[start + 13:start + 45]
        decoded = bytes(((raw[at] - 65) << 4) | (raw[at + 1] - 65) for at in range(0, 32, 2))
        name = f"{decoded[:15].decode('ascii', 'replace').rstrip()}<{decoded[15]:02x}>"
        d.put("nbns.name", name)
    d.layer("nbns", "NetBIOS Name Service", start, end)
    what = {0: "Name query", 5: "Registration", 6: "Release", 8: "Refresh"}.get(opcode, f"Opcode {opcode}")
    d.columns("NBNS", f"{what}{' response' if response else ''} NB {name}".strip())


def radius(d, data, start, end):
    if end < start + 20:
        return d.bad("RADIUS", start)
    code, ident, length = data[start], data[start + 1], u16(data, start + 2)
    d.put("radius.code", code)
    d.put("radius.id", ident)
    node = d.layer("radius", f"RADIUS Protocol, {RADIUS_CODES.get(code, code)}", start, end)
    offset, extra = start + 20, ""
    while offset + 2 <= min(end, start + length):
        kind, size = data[offset], data[offset + 1]
        if size < 2:
            break
        value = data[offset + 2:offset + size]
        name = RADIUS_ATTRIBUTES.get(kind)
        if name and kind not in (25, 26):
            text = str(ip4(value)) if kind in (4, 8) and len(value) == 4 else \
                str(u32(value, 0)) if kind in (5, 6, 27, 61, 64) and len(value) == 4 else text_of(value)
            d.put("radius." + name.replace("-", "_"), text)
            node.add(f"{name}: {text}", offset, offset + size)
            if kind == 1:
                extra = f" (User-Name: {text})"
        offset += size
    d.columns("RADIUS", f"{RADIUS_CODES.get(code, f'Code {code}')} id={ident}{extra}")


def hsrp(d, data, start, end):
    if end < start + 20:
        return d.bad("HSRP", start)
    if data[start] == 0:  # Version 1
        opcode, state, hello, hold, priority, group = data[start + 1:start + 7]
        virtual = ip4(data[start + 16:start + 20])
        version = 1
    elif data[start] == 1 and end >= start + 2 + 40:  # Version 2: group state TLV
        offset = start + 2
        version = data[offset]
        opcode, state = data[offset + 1], data[offset + 2]
        group = u16(data, offset + 4)
        priority = u32(data, offset + 12)
        hello, hold = u32(data, offset + 16) // 1000, u32(data, offset + 20) // 1000
        virtual = ip4(data[offset + 24:offset + 28]) if data[offset + 3] == 4 else ip6(data[offset + 24:offset + 40])
        version = 2
    else:
        d.layer("hsrp", "Cisco Hot Standby Router Protocol", start, end)
        return d.columns("HSRP", "HSRP")
    for name, value in (("hsrp.group", group), ("hsrp.state", state), ("hsrp.priority", priority),
                        ("hsrp.opcode", opcode), ("hsrp.virt_ip", virtual)):
        d.put(name, value)
    node = d.layer("hsrp", f"Cisco Hot Standby Router Protocol (version {version})", start, end)
    node.add(f"Group: {group}, State: {HSRP_STATES.get(state, state)}, Priority: {priority}")
    node.add(f"Hello time: {hello} s, Hold time: {hold} s")
    node.add(f"Virtual IP address: {virtual}")
    d.columns("HSRPv2" if version == 2 else "HSRP",
              f"{HSRP_OPCODES.get(opcode, opcode)} (state {HSRP_STATES.get(state, state)}), group {group}, "
              f"priority {priority}, virtual IP {virtual}")


def vrrp(d, data, start, end):
    if end < start + 8:
        return d.bad("VRRP", start)
    version, router, priority, count = data[start] >> 4, data[start + 1], data[start + 2], data[start + 3]
    addresses = [ip4(data[at:at + 4]) for at in range(start + 8, min(end, start + 8 + count * 4), 4)]
    d.put("vrrp.virt_rtr_id", router)
    d.put("vrrp.prio", priority)
    for address in addresses:
        d.put("vrrp.ip_addr", address)
    node = d.layer("vrrp", f"Virtual Router Redundancy Protocol (version {version})", start, end)
    node.add(f"Virtual router ID: {router}, Priority: {priority}")
    for address in addresses:
        node.add(f"IP address: {address}")
    d.columns("VRRP", f"Announcement (v{version}), VRID {router}, priority {priority}"
                      f"{', ' + ', '.join(str(address) for address in addresses) if addresses else ''}")


def ospf(d, data, start, end):
    if end < start + 16:
        return d.bad("OSPF", start)
    version, kind = data[start], data[start + 1]
    router, area = ip4(data[start + 4:start + 8]), ip4(data[start + 8:start + 12])
    d.put("ospf.msg", kind)
    d.put("ospf.srcrouter", router)
    d.put("ospf.area_id", area)
    node = d.layer("ospf", f"Open Shortest Path First, {OSPF_TYPES.get(kind, kind)}", start, end)
    node.add(f"Version: {version}, Router ID: {router}, Area ID: {area}", start, start + 12)
    info = OSPF_TYPES.get(kind, f"Type {kind}")
    if version == 2 and kind == 1 and end >= start + 44:
        hello = start + 24
        mask = ip4(data[hello:hello + 4])
        interval, priority, dead = u16(data, hello + 4), data[hello + 7], u32(data, hello + 8)
        designated, backup = ip4(data[hello + 12:hello + 16]), ip4(data[hello + 16:hello + 20])
        d.put("ospf.hello.network_mask", mask)
        d.put("ospf.hello.hello_interval", interval)
        d.put("ospf.hello.router_dead_interval", dead)
        node.add(f"Network mask: {mask}, Hello interval: {interval} s, Dead interval: {dead} s, Priority: {priority}")
        node.add(f"Designated router: {designated}, Backup: {backup}")
        info += f" (hello {interval} s, dead {dead} s, mask {mask})"
    d.columns("OSPF", info)


def eigrp(d, data, start, end):
    if end < start + 20:
        return d.bad("EIGRP", start)
    opcode, ack, system = data[start + 1], u32(data, start + 12), u16(data, start + 18)
    d.put("eigrp.opcode", opcode)
    d.put("eigrp.as", system)
    d.layer("eigrp", f"Cisco EIGRP, AS {system}", start, end)
    name = EIGRP_OPCODES.get(opcode, f"Opcode {opcode}")
    d.columns("EIGRP", f"{name}{' (Ack)' if opcode == 5 and ack else ''}, AS {system}")


def pim(d, data, start, end):
    kind = data[start] & 0x0F
    d.put("pim.type", kind)
    d.layer("pim", "Protocol Independent Multicast", start, end)
    d.columns("PIMv2", PIM_TYPES.get(kind, f"Type {kind}"))


def bfd(d, data, start, end):
    if end < start + 4:
        return d.bad("BFD", start)
    state = data[start + 1] >> 6
    d.put("bfd.sta", state)
    d.layer("bfd", "Bidirectional Forwarding Detection Control Message", start, end)
    d.columns("BFD Control", f"Diag: {data[start] & 0x1F}, State: {BFD_STATES[state]}")


def snmp(d, data, start, end):
    node = d.layer("snmp", "Simple Network Management Protocol", start, end)
    try:
        tag, body, message_end = ber(data, start)
        offset = body
        _, value_start, value_end = ber(data, offset)
        version = int.from_bytes(data[value_start:value_end], "big")
        d.put("snmp.version", version)
        if version == 3:
            return d.columns("SNMP", "SNMPv3 (encrypted or authenticated)")
        offset = value_end
        _, value_start, value_end = ber(data, offset)
        community = bytes(data[value_start:value_end]).decode("utf-8", "replace")
        d.put("snmp.community", community)
        node.add(f"Version: {'v1' if version == 0 else 'v2c'}, Community: {community}")
        pdu_type, pdu_body, pdu_end = ber(data, value_end)
        name = SNMP_PDUS.get(pdu_type, f"PDU 0x{pdu_type:02x}")
        d.put("snmp.pdu_type", pdu_type)
        if pdu_type == 0xA4:  # SNMPv1 trap: enterprise first
            return d.columns("SNMP", "trap")
        offset = pdu_body
        numbers = []
        for _ in range(3):
            _, value_start, value_end = ber(data, offset)
            numbers.append(int.from_bytes(data[value_start:value_end], "big", signed=True))
            offset = value_end
        request_id, error, _ = numbers
        d.put("snmp.request_id", request_id)
        d.put("snmp.error_status", error)
        _, binds, binds_end = ber(data, offset)
        names, offset = [], binds
        while offset < binds_end and len(names) < 10:
            _, bind, bind_end = ber(data, offset)
            _, oid_start, oid_end = ber(data, bind)
            names.append(oid_text(data[oid_start:oid_end]))
            offset = bind_end
        for name_text in names:
            d.put("snmp.name", name_text)
            node.add(f"Object: {name_text}")
        info = f"{name} {' '.join(names)}"
        if error:
            info += f" ({SNMP_ERRORS.get(error, error)})"
        d.columns("SNMP", info.strip())
    except (IndexError, ValueError):
        d.columns("SNMP", "SNMP (couldn't decode)")


def ber(data, offset):
    """(tag, value start, value end) of a BER element at offset."""
    tag, length = data[offset], data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4:
            raise ValueError("BER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise ValueError("BER element runs past the packet")
    return tag, offset, offset + length


def oid_text(raw):
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def tls(d, data, start, end, prefix):
    parts, offset = [], start
    node = d.layer("tls", "Transport Layer Security", start, end)
    while offset + 5 <= end:
        content, version, length = data[offset], u16(data, offset + 1), u16(data, offset + 3)
        if content not in TLS_CONTENT or version >> 8 != 3:
            break
        body, record_end = offset + 5, min(end, offset + 5 + length)
        d.put("tls.record.content_type", content)
        d.put("tls.record.version", version)
        record = node.add(f"{TLS_VERSIONS.get(version, hex(version))} Record Layer: {TLS_CONTENT[content]}, "
                          f"Length: {length}", offset, record_end)
        if content == 22:
            parts.extend(tls_handshake(d, data, body, record_end, length, record))
        elif content == 21:
            if length == 2 and record_end >= body + 2:
                level, description = data[body], data[body + 1]
                d.put("tls.alert_message.desc", description)
                text = f"Alert ({'Fatal' if level == 2 else 'Warning'}, " \
                       f"{TLS_ALERTS.get(description, description)})"
                parts.append(text)
                record.add(text, body, body + 2)
            else:
                parts.append("Encrypted Alert")
        else:
            parts.append(TLS_CONTENT[content])
        offset = body + length
    if not parts:
        d.protocols.pop()
        if d.tree and d.nodes:
            d.nodes.pop()
        return rest(d, data, start, end)
    if offset > end:
        parts[-1] += " [continues in the next segment]"
    names = list(dict.fromkeys(parts))
    d.columns("TLSv1.3" if "tls.handshake.version" in d.values and 0x0304 in d.values["tls.handshake.version"]
              else "TLS", prefix + ", ".join(names))


def tls_handshake(d, data, body, record_end, length, record):
    parts, offset = [], body
    while offset + 4 <= record_end:
        kind, size = data[offset], int.from_bytes(data[offset + 1:offset + 4], "big")
        if kind not in TLS_HANDSHAKES or (offset + 4 + size > body + length):
            return parts + ["Encrypted Handshake Message"]
        d.put("tls.handshake.type", kind)
        text = TLS_HANDSHAKES[kind]
        message_end = min(record_end, offset + 4 + size)
        if kind in (1, 2):
            text += tls_hello(d, data, offset + 4, message_end, kind)
        record.add(f"Handshake Protocol: {text}", offset, message_end)
        parts.append(text)
        offset += 4 + size
    return parts


def tls_hello(d, data, offset, end, kind):
    """Extra text for a Client or Server Hello: the server name asked for, the version agreed."""
    try:
        version = u16(data, offset)
        offset += 2 + 32
        offset += 1 + data[offset]  # Session ID
        if kind == 1:
            offset += 2 + u16(data, offset)  # Cipher suites
            offset += 1 + data[offset]  # Compression methods
        else:
            d.put("tls.handshake.ciphersuite", u16(data, offset))
            offset += 3
        extensions_end = min(end, offset + 2 + u16(data, offset))
        offset += 2
        text = ""
        while offset + 4 <= extensions_end:
            kind_code, size = u16(data, offset), u16(data, offset + 2)
            value = offset + 4
            if kind_code == 0 and kind == 1 and size >= 5:
                name = bytes(data[value + 5:value + 5 + u16(data, value + 3)]).decode("utf-8", "replace")
                d.put("tls.handshake.extensions_server_name", name)
                text = f" (SNI={name})"
            elif kind_code == 43 and kind == 2 and size == 2:
                version = u16(data, value)
            offset = value + size
        d.put("tls.handshake.version", version)
        return text
    except IndexError:
        return ""


def http(d, data, start, end, prefix):
    raw = bytes(data[start:end])
    head = raw.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
    lines = head.split("\r\n")
    first = lines[0][:300]
    node = d.layer("http", "Hypertext Transfer Protocol", start, end)
    if first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) > 1 and parts[1].isdigit():
            d.put("http.response.code", int(parts[1]))
        d.put("http.response", 1)
    else:
        parts = first.split(" ")
        d.put("http.request.method", parts[0])
        if len(parts) > 1:
            d.put("http.request.uri", parts[1])
        d.put("http.request", 1)
    for line in lines[1:40]:
        node.add(line)
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if name == "host":
            d.put("http.host", value.strip())
        elif name == "user-agent":
            d.put("http.user_agent", value.strip())
    if d.tree:
        node.children.insert(0, Node(first))
    d.columns("HTTP", prefix + first)


def smb(d, data, start, end, prefix):
    """SMB over port 445 (or 139): the SMB2 command and its status. False when it doesn't look like SMB."""
    offset = start + 4  # NetBIOS session header
    if end < offset + 64 or bytes(data[offset:offset + 4]) not in (b"\xfeSMB", b"\xffSMB"):
        return False
    if data[offset] == 0xFF:
        d.layer("smb", "SMB (Server Message Block Protocol)", offset, end)
        d.columns("SMB", prefix + "SMB1 " + {0x72: "Negotiate Protocol"}.get(data[offset + 4], "request"))
        return True
    status = struct.unpack_from("<I", data, offset + 8)[0]
    command = struct.unpack_from("<H", data, offset + 12)[0]
    response = struct.unpack_from("<I", data, offset + 16)[0] & 1
    name = SMB2_COMMANDS[command] if command < len(SMB2_COMMANDS) else f"Command {command}"
    d.put("smb2.cmd", command)
    d.put("smb2.nt_status", status)
    d.put("smb2.flags.response", response)
    node = d.layer("smb2", "SMB2 (Server Message Block Protocol version 2)", offset, end)
    node.add(f"Command: {name} ({command})", offset + 12, offset + 14)
    node.add(f"Status: {NT_STATUS.get(status, f'0x{status:08x}')}", offset + 8, offset + 12)
    info = f"{name} {'Response' if response else 'Request'}"
    if response and status and status not in (0xC0000016, 0x00000103):
        info += f", Error: {NT_STATUS.get(status, f'0x{status:08x}')}"
    d.columns("SMB2", prefix + info)
    return True


def bgp(d, data, start, end):
    names, offset = [], start
    while offset + 19 <= end and bytes(data[offset:offset + 16]) == b"\xff" * 16:
        length, kind = u16(data, offset + 16), data[offset + 18]
        d.put("bgp.type", kind)
        name = BGP_TYPES.get(kind, f"Type {kind}")
        if kind == 3 and offset + 21 <= end:
            name += f" (error {data[offset + 19]}/{data[offset + 20]})"
            d.put("bgp.notify.major_error", data[offset + 19])
        names.append(name)
        if length < 19:
            break
        offset += length
    d.layer("bgp", "Border Gateway Protocol", start, end)
    d.columns("BGP", ", ".join(dict.fromkeys(names)) + " Message")


# ----------------------------------------------------------------- Tunnels

def gre(d, data, start, end):
    if end < start + 4:
        return d.bad("GRE", start)
    flags, protocol = u16(data, start), u16(data, start + 2)
    offset = start + 4
    key = None
    if flags & 0x8000:
        offset += 4
    if flags & 0x2000:
        key = u32(data, offset)
        offset += 4
    sequenced = bool(flags & 0x1000)
    if sequenced:
        d.put("gre.sequence_number", u32(data, offset))
        offset += 4
    d.put("gre.proto", protocol)
    if key is not None:
        d.put("gre.key", key)
    node = d.layer("gre", f"Generic Routing Encapsulation ({ETHERTYPES.get(protocol, hex(protocol))})", start, offset)
    node.add(f"Protocol type: {ETHERTYPES.get(protocol, 'Unknown')} (0x{protocol:04x})", start + 2, start + 4)
    d.columns("GRE", f"Encapsulated {ETHERTYPES.get(protocol, f'0x{protocol:04x}')}")
    if protocol == 0x88BE:
        if not sequenced:  # ERSPAN type I: the frame straight after
            d.layer("erspan", "Encapsulated Remote Switch Packet ANalysis Type I", offset, offset)
            return inner_ethernet(d, data[:end], offset)
        if end < offset + 8:
            return d.bad("ERSPAN header", offset)
        session = u16(data, offset + 2) & 0x03FF
        vlan_id = u16(data, offset) & 0x0FFF
        d.put("erspan.spanid", session)
        d.put("erspan.vlan", vlan_id)
        node = d.layer("erspan", f"Encapsulated Remote Switch Packet ANalysis Type II, Session {session}", offset,
                       offset + 8)
        node.add(f"Session ID: {session}, VLAN: {vlan_id}", offset, offset + 4)
        return inner_ethernet(d, data[:end], offset + 8)
    if protocol == 0x22EB:
        if end < offset + 12:
            return d.bad("ERSPAN header", offset)
        session = u16(data, offset + 2) & 0x03FF
        d.put("erspan.spanid", session)
        subheader = data[offset + 11] & 1
        frame_type = (data[offset + 10] >> 2) & 0x1F
        header_end = offset + 12 + (8 if subheader else 0)
        d.layer("erspan", f"Encapsulated Remote Switch Packet ANalysis Type III, Session {session}", offset,
                header_end)
        if frame_type:
            d.depth += 1
            return ip_any(d, data[:end], header_end)
        return inner_ethernet(d, data[:end], header_end)
    if protocol == 0x6558:
        return inner_ethernet(d, data[:end], offset)
    if protocol in (0x0800, 0x86DD):
        d.depth += 1
        if d.depth <= MAX_DEPTH:
            return ip_any(d, data[:end], offset)
    rest(d, data, offset, end)


def vxlan(d, data, start, end):
    if end < start + 8:
        return d.bad("VXLAN", start)
    vni = int.from_bytes(data[start + 4:start + 7], "big")
    d.put("vxlan.vni", vni)
    d.layer("vxlan", f"Virtual eXtensible Local Area Network, VNI: {vni}", start, start + 8)
    d.columns("VXLAN", f"VNI {vni}")
    inner_ethernet(d, data[:end], start + 8)


# ----------------------------------------------------------------- Layer 2 protocols

def bridge_id(data, offset):
    """(priority, system ID extension (the VLAN), MAC) of a bridge ID."""
    value = u16(data, offset)
    return value & 0xF000, value & 0x0FFF, mac(data[offset + 2:offset + 8])


def stp(d, data, offset, end, pvst=False):
    if end < offset + 4:
        return d.bad("STP", offset)
    version, kind = data[offset + 2], data[offset + 3]
    d.put("stp.version", version)
    d.put("stp.type", kind)
    name = {0: "Spanning Tree Protocol", 2: "Rapid Spanning Tree", 3: "Multiple Spanning Tree"}.get(version, "STP")
    if kind == 0x80:
        d.layer("stp", f"{name}: Topology Change Notification", offset, end)
        d.put("stp.tcn", 1)
        return d.columns("STP", "Topology Change Notification")
    if end < offset + 35:
        return d.bad("STP BPDU", offset)
    flags = data[offset + 4]
    root_priority, root_extension, root_mac = bridge_id(data, offset + 5)
    cost = u32(data, offset + 13)
    bridge_priority, bridge_extension, bridge_mac = bridge_id(data, offset + 17)
    port = u16(data, offset + 25)
    timers = [u16(data, offset + at) / 256 for at in (27, 29, 31, 33)]
    for field_name, value in (("stp.flags", flags), ("stp.flags.tc", flags & 1), ("stp.flags.tcack", flags >> 7),
                              ("stp.root.hw", root_mac), ("stp.root.prio", root_priority),
                              ("stp.root.ext", root_extension), ("stp.root.cost", cost), ("stp.bridge.hw", bridge_mac),
                              ("stp.bridge.prio", bridge_priority), ("stp.bridge.ext", bridge_extension),
                              ("stp.port", port)):
        d.put(field_name, value)
    if pvst and end >= offset + 36 + 6:
        # PVST+ adds the VLAN the BPDU belongs to, as a TLV after the BPDU
        tail = offset + (36 if kind == 2 else 35)
        if tail + 6 <= end and u16(data, tail + 2) == 2:
            d.put("stp.pvst.origvlan", u16(data, tail + 4))
    role = STP_ROLES[(flags >> 2) & 3]
    node = d.layer("stp", f"{name}{' (PVST+)' if pvst else ''}", offset, end)
    if d.tree:
        flag_names = [label for bit, label in ((0x01, "Topology Change"), (0x02, "Proposal"), (0x10, "Learning"),
                                               (0x20, "Forwarding"), (0x40, "Agreement"), (0x80, "TC Acknowledgment"))
                      if flags & bit]
        node.add(f"BPDU flags: 0x{flags:02x} ({', '.join(flag_names) or 'none'}"
                 f"{', port role ' + role if version >= 2 else ''})", offset + 4, offset + 5)
        node.add(f"Root identifier: {root_priority} / {root_extension} / {mac_text(root_mac)}", offset + 5, offset + 13)
        node.add(f"Root path cost: {cost}", offset + 13, offset + 17)
        node.add(f"Bridge identifier: {bridge_priority} / {bridge_extension} / {mac_text(bridge_mac)}", offset + 17,
                 offset + 25)
        node.add(f"Port identifier: 0x{port:04x}", offset + 25, offset + 27)
        node.add(f"Message age: {timers[0]:g}, Max age: {timers[1]:g}, Hello time: {timers[2]:g}, "
                 f"Forward delay: {timers[3]:g}", offset + 27, offset + 35)
    prefix = "RST. " if version >= 2 else "Conf. "
    tc = "TC + " if flags & 1 else ""
    d.columns("RSTP" if version == 2 else "MSTP" if version == 3 else "STP",
              f"{prefix}{tc}Root = {root_priority}/{root_extension}/{root_mac}  Cost = {cost}  Port = 0x{port:04x}")


def tlv_text(raw):
    text = bytes(raw).decode("utf-8", "replace").rstrip("\0")
    return text if text.isprintable() else bytes(raw).hex(":")


def lldp(d, data, offset, end):
    from ..lldp import Neighbor, parse_lldp
    neighbor = Neighbor("LLDP")
    parse_lldp(bytes(data[offset:end]), neighbor)
    node = d.layer("lldp", "Link Layer Discovery Protocol", offset, end)
    if d.tree:
        position = offset
        while position + 2 <= end:
            header = u16(data, position)
            kind, length = header >> 9, header & 0x1FF
            label = LLDP_TLVS.get(kind, f"TLV type {kind}")
            node.add(f"{label}{lldp_value(neighbor, kind)}", position, position + 2 + length)
            position += 2 + length
            if kind == 0:
                break
    for name, value in (("lldp.chassis.id", neighbor.device_id), ("lldp.port.id", neighbor.port_id),
                        ("lldp.tlv.system.name", neighbor.system_name), ("lldp.port.desc", neighbor.port_description),
                        ("lldp.tlv.system.desc", neighbor.description)):
        if value:
            d.put(name, value)
    if neighbor.native_vlan:
        d.put("lldp.ieee.802_1.port_vlan.id", int(neighbor.native_vlan))
    for address in neighbor.management_addresses:
        if address.count(".") == 3:
            d.put("lldp.mgn.addr.ip4", Address.parse(address))
    d.columns("LLDP", f"{neighbor.system_name or neighbor.device_id} port {neighbor.port_id}"
                      f"{' (' + neighbor.port_description + ')' if neighbor.port_description else ''}"
                      f"{', VLAN ' + neighbor.native_vlan if neighbor.native_vlan else ''}  TTL {neighbor.ttl}")


def lldp_value(neighbor, kind):
    value = {1: neighbor.device_id, 2: neighbor.port_id, 3: str(neighbor.ttl), 4: neighbor.port_description,
             5: neighbor.system_name, 6: neighbor.description.splitlines()[0] if neighbor.description else "",
             7: ", ".join(neighbor.capabilities), 8: ", ".join(neighbor.management_addresses)}.get(kind, "")
    return f": {value}" if value else ""


def cdp(d, data, offset, end):
    from ..lldp import Neighbor, parse_cdp
    neighbor = Neighbor("CDP")
    parse_cdp(bytes(data[offset:end]), neighbor)
    node = d.layer("cdp", "Cisco Discovery Protocol", offset, end)
    if d.tree and end >= offset + 4:
        node.add(f"Version: {data[offset]}, TTL: {data[offset + 1]} seconds", offset, offset + 2)
        position = offset + 4
        while position + 4 <= end:
            kind, length = u16(data, position), u16(data, position + 2)
            if length < 4:
                break
            value = data[position + 4:position + length]
            label = CDP_TLVS.get(kind, f"Type 0x{kind:04x}")
            text = {1: neighbor.device_id, 3: neighbor.port_id, 6: neighbor.platform, 10: neighbor.native_vlan,
                    11: neighbor.duplex, 14: neighbor.voice_vlan, 20: neighbor.system_name,
                    2: ", ".join(neighbor.management_addresses), 22: ", ".join(neighbor.management_addresses),
                    4: ", ".join(neighbor.capabilities), 9: tlv_text(value)}.get(kind)
            if kind == 5:
                text = neighbor.description.splitlines()[0] if neighbor.description else ""
            line = node.add(f"{label}{': ' + text if text else ''}", position, position + length)
            if kind == 5:
                for software_line in neighbor.description.splitlines()[1:8]:
                    line.add(software_line)
            if kind == 9:
                d.put("cdp.vtp_management_domain", tlv_text(value))
            position += length
    for name, value in (("cdp.deviceid", neighbor.device_id), ("cdp.portid", neighbor.port_id),
                        ("cdp.platform", neighbor.platform)):
        if value:
            d.put(name, value)
    if neighbor.native_vlan:
        d.put("cdp.native_vlan", int(neighbor.native_vlan))
    if neighbor.duplex:
        d.put("cdp.duplex", neighbor.duplex)
    for address in neighbor.management_addresses:
        try:
            d.put("cdp.address", Address.parse(address))
        except ValueError:
            pass
    d.columns("CDP", f"Device ID: {neighbor.device_id}  Port ID: {neighbor.port_id}"
                     f"{'  Native VLAN: ' + neighbor.native_vlan if neighbor.native_vlan else ''}")


def vtp(d, data, offset, end):
    if end < offset + 36:
        return d.bad("VTP", offset)
    version, code = data[offset], data[offset + 1]
    domain = bytes(data[offset + 4:offset + 4 + min(data[offset + 3], 32)]).decode("utf-8", "replace")
    d.put("vtp.version", version)
    d.put("vtp.code", code)
    d.put("vtp.md", domain)
    info = f"{VTP_CODES.get(code, f'Code {code}')}, domain {domain or '(none)'}"
    if code == 1 and end >= offset + 40:
        revision = u32(data, offset + 36)
        d.put("vtp.conf_rev_num", revision)
        info += f", revision {revision}"
    d.layer("vtp", f"VLAN Trunking Protocol (version {version})", offset, end)
    d.columns("VTP", info)


def dtp(d, data, offset, end):
    mode, domain = "", ""
    position = offset + 1
    while position + 4 <= end:
        kind, length = u16(data, position), u16(data, position + 2)
        if length < 4:
            break
        value = data[position + 4:position + length]
        if kind == 2 and value:
            status = value[0]
            mode = f"{DTP_MODES.get(status & 0x07, status & 0x07)}{', trunking' if status & 0x80 else ''}"
            d.put("dtp.tos", status)
        elif kind == 1:
            domain = tlv_text(value)
        position += length
    d.layer("dtp", "Dynamic Trunk Protocol", offset, end)
    d.columns("DTP", f"Dynamic Trunk Protocol{' (' + mode + ')' if mode else ''}"
                     f"{', domain ' + domain if domain else ''}")


def slow_protocols(d, data, offset):
    subtype = data[offset] if len(data) > offset else 0
    if subtype != 1 or len(data) < offset + 2 + 40:
        d.layer("slow", "Slow Protocols", offset, len(data))
        return d.columns({2: "Marker", 3: "OAM"}.get(subtype, "Slow Protocols"), f"Subtype {subtype}")
    node = d.layer("lacp", "Link Aggregation Control Protocol", offset, len(data))
    parts = []
    for role, start in (("actor", offset + 2), ("partner", offset + 22)):
        if data[start] != (1 if role == "actor" else 2):
            continue
        priority, system = u16(data, start + 2), mac(data[start + 4:start + 10])
        key, port_priority, port, state = u16(data, start + 10), u16(data, start + 12), u16(data, start + 14), \
            data[start + 16]
        for name, value in (("sysid", system), ("key", key), ("port", port), ("state", state),
                            ("sys_priority", priority)):
            d.put(f"lacp.{role}.{name}", value)
        states = [label for bit, label in enumerate(LACP_STATE) if state & (1 << bit)]
        node.add(f"{role.title()}: system {priority}/{system}, key {key}, port {port_priority}/{port}, state "
                 f"0x{state:02x} ({', '.join(states)})", start, start + 20)
        sync = "in sync" if state & 0x08 else "not in sync"
        parts.append(f"{role.title()} {system} key {key} port {port} {sync}")
    d.columns("LACP", "; ".join(parts))


def eapol(d, data, offset):
    if len(data) < offset + 4:
        return d.bad("EAPOL", offset)
    kind = data[offset + 1]
    d.put("eapol.type", kind)
    d.layer("eapol", f"802.1X Authentication, {EAPOL_TYPES.get(kind, kind)}", offset, offset + 4)
    info = EAPOL_TYPES.get(kind, f"Type {kind}")
    if kind == 0 and len(data) >= offset + 8:
        code = data[offset + 4]
        d.put("eap.code", code)
        node = d.layer("eap", f"Extensible Authentication Protocol, {EAP_CODES.get(code, code)}", offset + 4,
                       len(data))
        info = EAP_CODES.get(code, f"Code {code}")
        if code in (1, 2) and len(data) > offset + 8:
            method = data[offset + 8]
            d.put("eap.type", method)
            info += f", {EAP_TYPES.get(method, f'Type {method}')}"
            if method == 1 and code == 2:
                identity = bytes(data[offset + 9:offset + 4 + u16(data, offset + 6)]).decode("utf-8", "replace")
                d.put("eap.identity", identity)
                info += f" ({identity})"
                node.add(f"Identity: {identity}")
        d.columns("EAP", info)
    else:
        d.columns("EAPOL", info)
