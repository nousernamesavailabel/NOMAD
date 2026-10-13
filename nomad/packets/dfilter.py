"""Display filters, written as in Wireshark: ip.addr == 10.0.0.5 && tcp.port == 443, dns, not arp,
ip.src == 10.1.0.0/16, eth.addr == 00:11:22:33:44:55, frame contains "password", http.host matches "^intra",
tcp.port in {80 443 8080}, !(udp.port == 53). Text compares ignoring case.

A filter that's just an address, a MAC or a port number shows that one's packets (10.0.0.5, 443).
"""
import ipaddress
import re

from .. import oui
from .decode import Address

INT, FLOAT, IP, MAC, TEXT, BYTES = "int", "float", "ip", "mac", "text", "bytes"

FIELDS = {
    # Frame
    "frame": (BYTES, "The whole packet (for contains)"), "frame.number": (INT, "Packet number"),
    "frame.len": (INT, "Length on the wire"), "frame.cap_len": (INT, "Length captured"),
    "frame.time_relative": (FLOAT, "Seconds since the first packet"),
    "frame.time_delta": (FLOAT, "Seconds since the previous packet"), "frame.time_epoch": (FLOAT, "Arrival time"),
    "frame.protocols": (TEXT, "Protocols in the packet, such as eth:ip:tcp"),
    "frame.interface_name": (TEXT, "Adapter it was captured on"),
    # Ethernet, VLAN, MPLS
    "eth.addr": (MAC, "Source or destination MAC"), "eth.src": (MAC, "Source MAC"), "eth.dst": (MAC, "Destination MAC"),
    "eth.type": (INT, "EtherType"), "eth.len": (INT, "802.3 length"), "vlan.id": (INT, "802.1Q VLAN ID"),
    "vlan.priority": (INT, "802.1p priority"), "vlan.dei": (INT, "Drop eligible"), "vlan.etype": (INT, "Type inside"),
    "mpls.label": (INT, "MPLS label"), "wol.mac": (MAC, "Wake-on-LAN target"),
    # ARP
    "arp.opcode": (INT, "1 request, 2 reply"), "arp.src.hw_mac": (MAC, "Sender MAC"),
    "arp.src.proto_ipv4": (IP, "Sender IP"), "arp.dst.hw_mac": (MAC, "Target MAC"),
    "arp.dst.proto_ipv4": (IP, "Target IP"), "arp.isgratuitous": (INT, "Gratuitous ARP"),
    # IP
    "ip.addr": (IP, "Source or destination IPv4"), "ip.src": (IP, "Source IPv4"), "ip.dst": (IP, "Destination IPv4"),
    "ip.ttl": (INT, "Time to live"), "ip.proto": (INT, "Protocol number"), "ip.len": (INT, "Total length"),
    "ip.id": (INT, "Identification"), "ip.flags.df": (INT, "Don't fragment"), "ip.flags.mf": (INT, "More fragments"),
    "ip.frag_offset": (INT, "Fragment offset"), "ip.fragment": (INT, "A fragment"),
    "ip.dsfield.dscp": (INT, "DSCP"), "ip.dsfield.ecn": (INT, "ECN"), "ip.hdr_len": (INT, "Header length"),
    "ip.version": (INT, "4"),
    "ipv6.addr": (IP, "Source or destination IPv6"), "ipv6.src": (IP, "Source IPv6"),
    "ipv6.dst": (IP, "Destination IPv6"), "ipv6.nxt": (INT, "Next header"), "ipv6.hlim": (INT, "Hop limit"),
    "ipv6.plen": (INT, "Payload length"), "ipv6.flow": (INT, "Flow label"), "ipv6.tclass": (INT, "Traffic class"),
    "ipv6.version": (INT, "6"), "ipv6.fragment": (INT, "A fragment"),
    # ICMP
    "icmp.type": (INT, "ICMP type (8 echo request, 0 reply, 3 unreachable, 11 TTL exceeded)"),
    "icmp.code": (INT, "ICMP code"), "icmp.ident": (INT, "Echo identifier"), "icmp.seq": (INT, "Echo sequence"),
    "icmp.mtu": (INT, "Next-hop MTU"), "icmp.orig.src": (IP, "Source of the packet an error is about"),
    "icmp.orig.dst": (IP, "Destination of the packet an error is about"),
    "icmpv6.type": (INT, "ICMPv6 type"), "icmpv6.code": (INT, "ICMPv6 code"), "icmpv6.mtu": (INT, "Packet too big MTU"),
    "icmpv6.echo.identifier": (INT, "Echo identifier"), "icmpv6.echo.sequence_number": (INT, "Echo sequence"),
    "icmpv6.nd.ns.target_address": (IP, "Neighbor solicitation target"),
    "icmpv6.nd.na.target_address": (IP, "Neighbor advertisement target"),
    "igmp.type": (INT, "IGMP type"), "igmp.maddr": (IP, "Multicast group"),
    # TCP
    "tcp.port": (INT, "Source or destination port"), "tcp.srcport": (INT, "Source port"),
    "tcp.dstport": (INT, "Destination port"), "tcp.stream": (INT, "Conversation number"),
    "tcp.seq": (INT, "Sequence number (relative)"), "tcp.seq_raw": (INT, "Sequence number"),
    "tcp.ack": (INT, "Acknowledgment number (relative)"), "tcp.ack_raw": (INT, "Acknowledgment number"),
    "tcp.flags": (INT, "Flags"), "tcp.flags.syn": (INT, "SYN"), "tcp.flags.ack": (INT, "ACK"),
    "tcp.flags.fin": (INT, "FIN"), "tcp.flags.reset": (INT, "RST"), "tcp.flags.push": (INT, "PSH"),
    "tcp.flags.urg": (INT, "URG"), "tcp.window_size_value": (INT, "Window"),
    "tcp.window_size": (INT, "Window (scaled)"), "tcp.len": (INT, "Payload length"),
    "tcp.hdr_len": (INT, "Header length"), "tcp.options.mss_val": (INT, "MSS"),
    "tcp.options.wscale.shift": (INT, "Window scale"), "tcp.payload": (BYTES, "Payload"),
    "tcp.analysis.flags": (INT, "Any TCP problem"), "tcp.analysis.retransmission": (INT, "Retransmission"),
    "tcp.analysis.fast_retransmission": (INT, "Fast retransmission"),
    "tcp.analysis.spurious_retransmission": (INT, "Spurious retransmission"),
    "tcp.analysis.out_of_order": (INT, "Out of order"),
    "tcp.analysis.lost_segment": (INT, "Previous segment not captured"),
    "tcp.analysis.ack_lost_segment": (INT, "ACKed unseen segment"),
    "tcp.analysis.duplicate_ack": (INT, "Duplicate ACK"), "tcp.analysis.zero_window": (INT, "Zero window"),
    "tcp.analysis.keep_alive": (INT, "Keep-alive"), "tcp.analysis.keep_alive_ack": (INT, "Keep-alive ACK"),
    "tcp.analysis.window_update": (INT, "Window update"),
    "tcp.analysis.reused_ports": (INT, "Port numbers reused"),
    # UDP
    "udp.port": (INT, "Source or destination port"), "udp.srcport": (INT, "Source port"),
    "udp.dstport": (INT, "Destination port"), "udp.length": (INT, "Length"), "udp.stream": (INT, "Conversation number"),
    "udp.payload": (BYTES, "Payload"),
    # Applications
    "dns.id": (INT, "Transaction ID"), "dns.flags.response": (INT, "0 query, 1 response"),
    "dns.flags.opcode": (INT, "Opcode"), "dns.flags.rcode": (INT, "Reply code (3 no such name)"),
    "dns.qry.name": (TEXT, "Name asked for"), "dns.qry.type": (INT, "Type asked for (1 A, 28 AAAA)"),
    "dns.resp.name": (TEXT, "Name answered"), "dns.resp.ttl": (INT, "Answer TTL"), "dns.a": (IP, "IPv4 answer"),
    "dns.aaaa": (IP, "IPv6 answer"), "dns.cname": (TEXT, "CNAME answer"), "dns.ptr.domain_name": (TEXT, "PTR answer"),
    "dns.ns": (TEXT, "NS answer"), "dns.count.queries": (INT, "Questions"), "dns.count.answers": (INT, "Answers"),
    "dhcp.type": (INT, "1 request, 2 reply"), "dhcp.id": (INT, "Transaction ID"),
    "dhcp.hw.mac_addr": (MAC, "Client MAC"), "dhcp.ip.client": (IP, "Client IP"), "dhcp.ip.your": (IP, "Your IP"),
    "dhcp.ip.server": (IP, "Next server"), "dhcp.ip.relay": (IP, "Relay agent"), "dhcp.hops": (INT, "Hops"),
    "dhcp.option.dhcp": (INT, "Message type (1 Discover, 2 Offer, 3 Request, 5 ACK, 6 NAK)"),
    "dhcp.option.subnet_mask": (IP, "Subnet mask"), "dhcp.option.router": (IP, "Router"),
    "dhcp.option.domain_name_server": (IP, "DNS server"), "dhcp.option.requested_ip_address": (IP, "Requested IP"),
    "dhcp.option.dhcp_server_id": (IP, "Server identifier"), "dhcp.option.broadcast_address": (IP, "Broadcast"),
    "dhcp.option.ntp_server": (IP, "NTP server"), "dhcp.option.tftp_server_address": (IP, "TFTP server (option 150)"),
    "dhcp.option.ip_address_lease_time": (INT, "Lease time"), "dhcp.option.hostname": (TEXT, "Host name"),
    "dhcp.option.domain_name": (TEXT, "Domain name"), "dhcp.option.vendor_class_id": (TEXT, "Vendor class"),
    "dhcp.option.tftp_server_name": (TEXT, "TFTP server (option 66)"),
    "dhcp.option.bootfile_name": (TEXT, "Boot file"), "dhcpv6.msgtype": (INT, "DHCPv6 message type"),
    "tftp.opcode": (INT, "Opcode"), "tftp.source_file": (TEXT, "File read"),
    "tftp.destination_file": (TEXT, "File written"), "tftp.block": (INT, "Block"), "tftp.error.code": (INT, "Error"),
    "tftp.error.message": (TEXT, "Error message"), "ntp.flags.vn": (INT, "Version"), "ntp.flags.mode": (INT, "Mode"),
    "ntp.stratum": (INT, "Stratum"), "syslog.facility": (INT, "Facility"),
    "syslog.level": (INT, "Severity (0 emergency .. 7 debug)"), "syslog.msg": (TEXT, "Message"),
    "snmp.version": (INT, "0 v1, 1 v2c, 3 v3"), "snmp.community": (TEXT, "Community"),
    "snmp.pdu_type": (INT, "PDU type"), "snmp.request_id": (INT, "Request ID"),
    "snmp.error_status": (INT, "Error status"), "snmp.name": (TEXT, "Object ID"), "nbns.name": (TEXT, "NetBIOS name"),
    "radius.code": (INT, "1 Access-Request, 2 Accept, 3 Reject"), "radius.id": (INT, "Identifier"),
    "radius.User_Name": (TEXT, "User-Name"), "radius.Calling_Station_Id": (TEXT, "Calling-Station-Id"),
    "radius.Called_Station_Id": (TEXT, "Called-Station-Id"), "radius.NAS_IP_Address": (TEXT, "NAS-IP-Address"),
    "radius.NAS_Identifier": (TEXT, "NAS-Identifier"), "radius.NAS_Port_Id": (TEXT, "NAS-Port-Id"),
    "radius.Reply_Message": (TEXT, "Reply-Message"), "radius.Framed_IP_Address": (TEXT, "Framed-IP-Address"),
    "radius.NAS_Port": (TEXT, "NAS-Port"), "radius.Service_Type": (TEXT, "Service-Type"),
    "radius.Session_Timeout": (TEXT, "Session-Timeout"), "radius.Acct_Session_Id": (TEXT, "Acct-Session-Id"),
    "radius.NAS_Port_Type": (TEXT, "NAS-Port-Type"), "radius.Tunnel_Type": (TEXT, "Tunnel-Type"),
    "radius.Tunnel_Private_Group_Id": (TEXT, "Tunnel-Private-Group-Id (VLAN)"),
    "tacplus.type": (INT, "1 authentication, 2 authorization, 3 accounting"),
    "tls.record.content_type": (INT, "Record type (22 handshake, 23 data)"), "tls.record.version": (INT, "Version"),
    "tls.handshake.type": (INT, "Handshake type (1 Client Hello)"),
    "tls.handshake.extensions_server_name": (TEXT, "Server name asked for (SNI)"),
    "tls.handshake.version": (INT, "Hello version"), "tls.handshake.ciphersuite": (INT, "Cipher suite chosen"),
    "tls.alert_message.desc": (INT, "Alert"), "http.request": (INT, "A request"), "http.response": (INT, "A response"),
    "http.request.method": (TEXT, "Method"), "http.request.uri": (TEXT, "URI"), "http.host": (TEXT, "Host"),
    "http.user_agent": (TEXT, "User-Agent"), "http.response.code": (INT, "Status code"),
    "ssh.protocol": (TEXT, "SSH version banner"), "smb2.cmd": (INT, "SMB2 command"),
    "smb2.nt_status": (INT, "NT status"), "smb2.flags.response": (INT, "A response"), "bgp.type": (INT, "Message type"),
    "bgp.notify.major_error": (INT, "Notification error"), "esp.spi": (INT, "SPI"),
    "hsrp.group": (INT, "Group"), "hsrp.state": (INT, "State (16 active, 8 standby)"), "hsrp.priority": (INT, "Priority"),
    "hsrp.opcode": (INT, "Opcode"), "hsrp.virt_ip": (IP, "Virtual IP"), "vrrp.virt_rtr_id": (INT, "Virtual router ID"),
    "vrrp.prio": (INT, "Priority"), "vrrp.ip_addr": (IP, "Virtual IP"), "ospf.msg": (INT, "Message type (1 hello)"),
    "ospf.srcrouter": (IP, "Router ID"), "ospf.area_id": (IP, "Area"), "ospf.hello.network_mask": (IP, "Hello mask"),
    "ospf.hello.hello_interval": (INT, "Hello interval"), "ospf.hello.router_dead_interval": (INT, "Dead interval"),
    "eigrp.opcode": (INT, "Opcode (5 hello)"), "eigrp.as": (INT, "Autonomous system"), "pim.type": (INT, "PIM type"),
    "bfd.sta": (INT, "State (3 up)"),
    # Tunnels
    "gre.proto": (INT, "Protocol inside"), "gre.key": (INT, "Key"), "gre.sequence_number": (INT, "Sequence"),
    "erspan.spanid": (INT, "ERSPAN session ID"), "erspan.vlan": (INT, "Original VLAN"), "vxlan.vni": (INT, "VNI"),
    # Layer 2
    "stp.version": (INT, "0 STP, 2 RSTP, 3 MSTP"), "stp.type": (INT, "BPDU type"), "stp.tcn": (INT, "Topology change "
                                                                                                     "notification"),
    "stp.flags": (INT, "Flags"), "stp.flags.tc": (INT, "Topology change"), "stp.flags.tcack": (INT, "TC acknowledgment"),
    "stp.root.hw": (MAC, "Root bridge MAC"), "stp.root.prio": (INT, "Root priority"),
    "stp.root.ext": (INT, "Root system ID extension (VLAN)"), "stp.root.cost": (INT, "Root path cost"),
    "stp.bridge.hw": (MAC, "Sending bridge MAC"), "stp.bridge.prio": (INT, "Bridge priority"),
    "stp.bridge.ext": (INT, "Bridge system ID extension"), "stp.port": (INT, "Port identifier"),
    "stp.pvst.origvlan": (INT, "PVST+ VLAN"), "cdp.deviceid": (TEXT, "Device ID"), "cdp.portid": (TEXT, "Port ID"),
    "cdp.platform": (TEXT, "Platform"), "cdp.native_vlan": (INT, "Native VLAN"), "cdp.duplex": (TEXT, "Duplex"),
    "cdp.address": (IP, "Address"), "cdp.vtp_management_domain": (TEXT, "VTP domain"),
    "lldp.chassis.id": (TEXT, "Chassis ID"), "lldp.port.id": (TEXT, "Port ID"),
    "lldp.port.desc": (TEXT, "Port description"), "lldp.tlv.system.name": (TEXT, "System name"),
    "lldp.tlv.system.desc": (TEXT, "System description"), "lldp.ieee.802_1.port_vlan.id": (INT, "Port VLAN"),
    "lldp.mgn.addr.ip4": (IP, "Management address"), "vtp.version": (INT, "Version"), "vtp.code": (INT, "Message"),
    "vtp.md": (TEXT, "Domain"), "vtp.conf_rev_num": (INT, "Configuration revision"), "dtp.tos": (INT, "Status"),
    "lacp.actor.sysid": (MAC, "Actor system"), "lacp.actor.key": (INT, "Actor key"), "lacp.actor.port": (INT,
                                                                                                         "Actor port"),
    "lacp.actor.state": (INT, "Actor state"), "lacp.actor.sys_priority": (INT, "Actor system priority"),
    "lacp.partner.sysid": (MAC, "Partner system"), "lacp.partner.key": (INT, "Partner key"),
    "lacp.partner.port": (INT, "Partner port"), "lacp.partner.state": (INT, "Partner state"),
    "lacp.partner.sys_priority": (INT, "Partner system priority"), "eapol.type": (INT, "EAPOL type"),
    "eap.code": (INT, "1 request, 2 response, 3 success, 4 failure"), "eap.type": (INT, "Method"),
    "eap.identity": (TEXT, "Identity"),
    # Other
    "data.len": (INT, "Undecoded data length"), "data.data": (BYTES, "Undecoded data"),
}
PROTOCOLS = {"eth", "vlan", "llc", "arp", "ip", "ipv6", "icmp", "icmpv6", "igmp", "tcp", "udp", "dns", "mdns",
             "llmnr", "dhcp", "dhcpv6", "tftp", "ntp", "snmp", "syslog", "nbns", "nbdgm", "radius", "hsrp", "vrrp",
             "ospf", "eigrp", "pim", "bfd", "tls", "http", "ssh", "smb", "smb2", "bgp", "tacplus", "gre", "erspan",
             "vxlan", "stp", "cdp", "lldp", "vtp", "dtp", "udld", "lacp", "slow", "eapol", "eap", "mpls", "wol",
             "esp", "loop", "sll", "data", "ssdp", "ftp", "ftp-data", "telnet", "smtp", "kerberos", "pop", "dcerpc",
             "netbios", "imap", "ldap", "tds", "pptp", "skinny", "mysql", "rdp", "sip", "iperf3", "winrm", "printer",
             "quic", "isakmp", "rip", "l2tp", "netflow", "glbp", "stun", "wsdiscovery", "ipfix", "capwap", "sflow",
             "traceroute", "netconf", "_ws.malformed", "malformed"}
FAST_FIELDS = {"eth.addr", "eth.src", "eth.dst", "ip.addr", "ip.src", "ip.dst", "ipv6.addr", "ipv6.src", "ipv6.dst",
               "tcp.port", "tcp.srcport", "tcp.dstport", "tcp.stream", "udp.port", "udp.srcport", "udp.dstport",
               "udp.stream", "tcp.flags", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
               "tcp.flags.push", "tcp.flags.urg", "tcp.analysis.flags", "frame.protocols"} | \
    {"tcp.analysis." + flag for flag in ("retransmission", "fast_retransmission", "spurious_retransmission",
                                         "out_of_order", "lost_segment", "ack_lost_segment", "duplicate_ack",
                                         "zero_window", "keep_alive", "keep_alive_ack", "window_update",
                                         "reused_ports")}
TCP_FLAG_BITS = {"tcp.flags.syn": 0x002, "tcp.flags.ack": 0x010, "tcp.flags.fin": 0x001, "tcp.flags.reset": 0x004,
                 "tcp.flags.push": 0x008, "tcp.flags.urg": 0x020}
FRAME_ONLY = {"frame.number", "frame.len", "frame.cap_len", "frame.time_relative", "frame.time_delta",
              "frame.time_epoch", "frame.interface_name", "frame"}
OPERATORS = {"==": "==", "eq": "==", "!=": "!=", "ne": "!=", ">": ">", "gt": ">", "<": "<", "lt": "<", ">=": ">=",
             "ge": ">=", "<=": "<=", "le": "<=", "contains": "contains", "matches": "matches", "~": "matches",
             "in": "in"}
TOKEN = re.compile(r'\s*(?:(?P<string>"(?:[^"\\]|\\.)*")|(?P<op>==|!=|>=|<=|&&|\|\||[()!<>{},~])|'
                   r'(?P<word>[A-Za-z0-9_.:/\-\[\]]+))')
MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}([:\-.]?[0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")


class FilterError(ValueError):
    def __init__(self, message, position=0):
        super().__init__(message)
        self.position = position


class Filter:
    """A compiled display filter: test(dissection, packet) -> bool."""

    def __init__(self, text, test, fields):
        self.text = text
        self.test = test
        self.fields = fields  # Field and protocol names it looks at
        self.frame_only = bool(fields) and fields <= FRAME_ONLY
        self.fast = all(name in FAST_FIELDS or name in FRAME_ONLY or name in PROTOCOLS for name in fields)

    def matches(self, packet):
        """Whether packet (a capfile.Packet) passes (decoding it if the filter looks past what was kept)."""
        return self.test(self.view(packet), packet)

    def view(self, packet):
        if self.frame_only:
            return None
        if self.fast and packet.fast is not None:
            return Quick(packet)
        return packet.dissect()


class Quick:
    """Stands in for a packet's dissection when a filter only looks at what the first decoding kept."""
    __slots__ = ("packet", "protocols")

    def __init__(self, packet):
        self.packet = packet
        self.protocols = packet.chain

    def get(self, name):
        packet = self.packet
        source_mac, destination_mac, source, destination, transport, source_port, destination_port, flags = \
            packet.fast
        family, _, rest = name.partition(".")
        if family == "eth":
            return {"addr": (source_mac, destination_mac), "src": (source_mac,), "dst": (destination_mac,)}[rest]
        if family in ("ip", "ipv6"):
            if source is None or (len(source) == 4) != (family == "ip"):
                return ()
            return {"addr": (source, destination), "src": (source,), "dst": (destination,)}[rest]
        if family != transport:
            return ()
        if rest == "stream":
            return (packet.stream,) if packet.stream >= 0 else ()
        if rest == "port":
            return source_port, destination_port
        if rest == "srcport":
            return (source_port,)
        if rest == "dstport":
            return (destination_port,)
        if rest == "flags":
            return (flags,)
        if name in TCP_FLAG_BITS:
            return (int(bool(flags & TCP_FLAG_BITS[name])),)
        if rest == "analysis.flags":
            return (1,) if packet.analysis else ()
        return (1,) if rest[9:] in packet.analysis else ()


def compile_filter(text):
    """A Filter, or None for an empty one. Raises FilterError."""
    text = (text or "").strip()
    if not text:
        return None
    shortcut = shortcut_for(text)
    if shortcut:
        text = shortcut
    parser = Parser(text)
    test = parser.parse()
    return Filter(text, test, parser.fields)


def shortcut_for(text):
    """A whole filter that's just an address, a subnet, a MAC address or a port number."""
    if " " in text:
        return ""
    if text.isdigit() and 0 < int(text) < 65536:
        return f"tcp.port == {text} || udp.port == {text}"
    if MAC_PATTERN.match(text):
        return f"eth.addr == {text}"
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return ""
    if "/" not in text and not re.match(r"^[0-9a-fA-F:.]+$", text):
        return ""
    if "." not in text and ":" not in text:
        return ""
    return f"{'ipv6' if network.version == 6 else 'ip'}.addr == {text}"


def combine(current, expression, how="and"):
    """The filter current with expression added to it: how is "and" (packets matching both), "or" (either) or "not"
    (current's, leaving out those matching expression)."""
    current = (current or "").strip()
    current = shortcut_for(current) or current
    if how == "not":
        expression = f"!{expression}" if is_one_word(expression) else f"!({expression})"
    elif how == "and" and current and has_or(expression):
        expression = f"({expression})"
    if not current:
        return expression
    if how == "or":
        return f"{current} || {expression}"
    return f"({current}) && {expression}" if has_or(current) else f"{current} && {expression}"


def is_one_word(text):
    match = TOKEN.fullmatch(text)
    return bool(match) and match.lastgroup == "word"


def has_or(text):
    """Whether text has an or outside any parentheses (so needs them around it to be and-ed with more)."""
    depth, position = 0, 0
    while position < len(text):
        match = TOKEN.match(text, position)
        if not match or match.end() == position:
            return text[position:].strip() != ""  # Text the parser won't understand either: bracket it anyway
        kind, value = match.lastgroup, match.group(match.lastgroup)
        if value == "(":
            depth += 1
        elif value == ")":
            depth -= 1
        elif depth == 0 and (value == "||" or (kind == "word" and value.lower() == "or")):
            return True
        position = match.end()
    return False


def packet_filters(d, packet=None):
    """Filters for what a packet list row shows: [(what, filter)], what being "source", "destination" (addresses,
    either way), "source port", "destination port", "vlan", "protocol" or "stream" (its TCP or UDP conversation).
    d: the packet's Dissection."""
    found = []
    if d.ips:
        family = "ip" if d.ips[0].version == 4 else "ipv6"
        found.append(("source", f"{family}.addr == {d.ips[0]}"))
        if d.ips[1] != d.ips[0]:
            found.append(("destination", f"{family}.addr == {d.ips[1]}"))
    elif d.macs:
        found.append(("source", f"eth.addr == {d.macs[0]}"))
        if d.macs[1] != d.macs[0]:
            found.append(("destination", f"eth.addr == {d.macs[1]}"))
    if d.ports:
        kind, source, destination = d.ports
        found.append(("source port", f"{kind}.port == {source}"))
        if destination != source:
            found.append(("destination port", f"{kind}.port == {destination}"))
    vlans = d.get("vlan.id")
    if vlans:
        found.append(("vlan", f"vlan.id == {vlans[0]}"))
    protocols = [name for name in d.protocols if name not in ("data", "_ws.malformed")]
    if protocols:
        found.append(("protocol", protocols[-1]))
    if packet is not None and packet.kind and packet.stream >= 0:
        found.append(("stream", f"{packet.kind}.stream == {packet.stream}"))
    return found


class Parser:
    def __init__(self, text):
        self.text = text
        self.tokens = []  # (kind, value, position)
        self.index = 0
        self.fields = set()
        position = 0
        while position < len(text):
            match = TOKEN.match(text, position)
            if not match or match.end() == position:
                if text[position:].strip() == "":
                    break
                raise FilterError(f"Didn't understand \"{text[position:].strip()[:20]}\".", position)
            kind = match.lastgroup
            value = match.group(kind)
            self.tokens.append((kind, value, match.start(kind)))
            position = match.end()

    def peek(self):
        return self.tokens[self.index] if self.index < len(self.tokens) else (None, None, len(self.text))

    def take(self):
        token = self.peek()
        self.index += 1
        return token

    def word_is(self, *words):
        kind, value, _ = self.peek()
        return (kind == "word" and value.lower() in words) or (kind == "op" and value in words)

    def parse(self):
        test = self.parse_or()
        kind, value, position = self.peek()
        if kind is not None:
            raise FilterError(f"Didn't expect \"{value}\" here.", position)
        return test

    def parse_or(self):
        tests = [self.parse_and()]
        while self.word_is("or", "||"):
            self.take()
            tests.append(self.parse_and())
        if len(tests) == 1:
            return tests[0]
        return lambda d, packet: any(test(d, packet) for test in tests)

    def parse_and(self):
        tests = [self.parse_not()]
        while self.word_is("and", "&&"):
            self.take()
            tests.append(self.parse_not())
        if len(tests) == 1:
            return tests[0]
        return lambda d, packet: all(test(d, packet) for test in tests)

    def parse_not(self):
        if self.word_is("not", "!"):
            self.take()
            test = self.parse_not()
            return lambda d, packet: not test(d, packet)
        return self.parse_primary()

    def parse_primary(self):
        kind, value, position = self.take()
        if kind is None:
            raise FilterError("The filter ends too soon.", position)
        if kind == "op" and value == "(":
            test = self.parse_or()
            kind, value, position = self.take()
            if value != ")":
                raise FilterError("Missing \")\".", position)
            return test
        if kind != "word":
            raise FilterError(f"Expected a field or protocol, not \"{value}\".", position)
        return self.parse_test(value, position)

    def parse_test(self, name, position):
        lower = name.lower()
        if lower in FIELDS:
            name = lower
        elif lower in PROTOCOLS:
            if self.is_operator():
                raise FilterError(f"{name} is a protocol: compare one of its fields, such as {name}.port.", position)
            name = "_ws.malformed" if lower == "malformed" else lower
            self.fields.add(name)
            return lambda d, packet: name in d.protocols
        else:
            raise FilterError(f"\"{name}\" isn't a field or protocol NOMAD knows.{suggestion(lower)}", position)
        self.fields.add(name)
        kind = FIELDS[name][0]
        if not self.is_operator():
            return lambda d, packet: bool(field_values(name, d, packet))
        _, operator, op_position = self.take()
        operator = OPERATORS[operator.lower()] if operator.lower() in OPERATORS else operator
        if operator == "in":
            values = self.parse_set(name, kind)
            return lambda d, packet: any(compare(value, "==", wanted, kind)
                                         for value in field_values(name, d, packet) for wanted in values)
        token_kind, raw, value_position = self.take()
        if token_kind not in ("word", "string"):
            raise FilterError(f"Expected a value after {operator}.", value_position)
        wanted = literal(raw, token_kind, kind, operator, name, value_position)
        if operator == "!=":
            return lambda d, packet: not any(compare(value, "==", wanted, kind)
                                             for value in field_values(name, d, packet))
        return lambda d, packet: any(compare(value, operator, wanted, kind) for value in field_values(name, d, packet))

    def is_operator(self):
        kind, value, _ = self.peek()
        return value is not None and (value.lower() in OPERATORS) and (kind == "op" or value.lower() in OPERATORS)

    def parse_set(self, name, kind):
        _, value, position = self.take()
        if value != "{":
            raise FilterError("Expected \"{\" after in, as in tcp.port in {80 443}.", position)
        values = []
        while True:
            token_kind, raw, position = self.take()
            if raw == "}":
                break
            if raw == ",":
                continue
            if token_kind not in ("word", "string"):
                raise FilterError("Missing \"}\".", position)
            values.append(literal(raw, token_kind, kind, "==", name, position))
        if not values:
            raise FilterError("The set is empty.", position)
        return values


def suggestion(name):
    close = [field for field in FIELDS if field.startswith(name)] or \
        [field for field in FIELDS if name in field]
    return f" Did you mean {close[0]}?" if close else ""


def literal(raw, token_kind, kind, operator, name, position):
    text = raw[1:-1].encode().decode("unicode_escape") if token_kind == "string" else raw
    if operator == "matches":
        try:
            return re.compile(text, re.IGNORECASE)
        except re.error as error:
            raise FilterError(f"\"{text}\" isn't a regular expression: {error}.", position) from None
    if operator == "contains" or kind == BYTES:
        if kind in (BYTES, TEXT):
            if token_kind == "word" and re.fullmatch(r"[0-9A-Fa-f]{2}([:\-][0-9A-Fa-f]{2})+", text):
                return bytes.fromhex(re.sub(r"[:\-]", "", text))
            return text.encode() if kind == BYTES else text.lower()
        raise FilterError(f"{name} is a {kind_name(kind)}: contains works on text and bytes fields.", position)
    if kind == INT:
        try:
            return int(text, 0)
        except ValueError:
            raise FilterError(f"{name} needs a number, not \"{text}\".", position) from None
    if kind == FLOAT:
        try:
            return float(text)
        except ValueError:
            raise FilterError(f"{name} needs a number, not \"{text}\".", position) from None
    if kind == IP:
        try:
            if "/" in text:
                network = ipaddress.ip_network(text, strict=False)
                return Subnet(network.packed if hasattr(network, "packed") else network.network_address.packed,
                              network.prefixlen)
            return Address.parse(text)
        except ValueError:
            raise FilterError(f"{name} needs an IP address or subnet, not \"{text}\".", position) from None
    if kind == MAC:
        digits = oui.normalize_mac(text)
        if len(digits) != 12:
            raise FilterError(f"{name} needs a MAC address, not \"{text}\".", position)
        return ":".join(digits[at:at + 2] for at in range(0, 12, 2)).lower()
    return text.lower()


class Subnet:
    """An IPv4 or IPv6 subnet a filter compares addresses with (ip.addr == 10.1.0.0/16)."""

    def __init__(self, packed, prefix):
        self.size = len(packed)
        bits = self.size * 8
        self.mask = ((1 << bits) - 1) ^ ((1 << (bits - prefix)) - 1)
        self.network = int.from_bytes(packed, "big") & self.mask

    def __contains__(self, address):
        return len(address) == self.size and int.from_bytes(address, "big") & self.mask == self.network


def kind_name(kind):
    return {INT: "number", FLOAT: "number", IP: "address", MAC: "MAC address", TEXT: "text", BYTES: "bytes"}[kind]


def field_values(name, d, packet):
    if name.startswith("frame"):
        if name == "frame.number":
            return [packet.number]
        if name == "frame.len":
            return [packet.wire_length]
        if name == "frame.cap_len":
            return [len(packet.data)]
        if name == "frame.time_relative":
            return [packet.time]
        if name == "frame.time_delta":
            return [packet.delta]
        if name == "frame.time_epoch":
            return [packet.epoch]
        if name == "frame.interface_name":
            return [packet.interface] if packet.interface else []
        if name == "frame.protocols":
            return [":".join(d.protocols)]
        if name == "frame":
            return [packet.data]
    return d.get(name)


def compare(value, operator, wanted, kind):
    if operator == "matches":
        return bool(wanted.search(value if isinstance(value, str) else str(value)))
    if operator == "contains":
        if kind == BYTES:
            return bytes(value).find(wanted) >= 0
        return wanted in str(value).lower()
    if kind == IP:
        if isinstance(wanted, Subnet):
            return operator == "==" and value in wanted
        if len(value) != len(wanted):
            return False
    elif kind == TEXT:
        value = str(value).lower()
    elif kind == BYTES:
        value = bytes(value)
    try:
        if operator == "==":
            return value == wanted
        if operator == ">":
            return value > wanted
        if operator == "<":
            return value < wanted
        if operator == ">=":
            return value >= wanted
        if operator == "<=":
            return value <= wanted
    except TypeError:
        return False
    return False


def apply(filter_, packets, should_stop=None, progress=None):
    """Indexes of the packets the filter shows (all of them for None)."""
    if filter_ is None:
        return list(range(len(packets)))
    shown = []
    test, view = filter_.test, filter_.view
    total = len(packets) or 1
    for index, packet in enumerate(packets):
        if index % 2000 == 0:
            if should_stop is not None and should_stop():
                return None
            if progress:
                progress(index / total)
        if test(view(packet), packet):
            shown.append(index)
    return shown
