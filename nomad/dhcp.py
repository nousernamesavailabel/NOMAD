"""Rogue DHCP test: ask the network for DHCP offers and list every server that answers.

Only a DISCOVER is sent, so no address is ever leased: servers make an offer and forget it when nothing
follows. Two different servers answering usually means one of them shouldn't be there (often a home router
plugged in the wrong way round).
"""
import ipaddress
import os
import socket
import struct
import time
from dataclasses import dataclass, field

from .oui import normalize_mac
from .system import run_powershell_json

CLIENT_PORT, SERVER_PORT = 68, 67
MAGIC_COOKIE = b"\x63\x82\x53\x63"
BOOTREQUEST, BOOTREPLY = 1, 2
DISCOVER, OFFER = 1, 2
BROADCAST_FLAG = 0x8000
OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_LEASE, OPT_TYPE, OPT_SERVER_ID = 1, 3, 6, 15, 51, 53, 54
OPT_PARAMS, OPT_CLIENT_ID, OPT_TFTP_SERVER, OPT_BOOTFILE, OPT_END, OPT_PAD = 55, 61, 66, 67, 255, 0
OPT_OVERLOAD = 52  # The file and/or sname header fields hold more options
# Servers mostly send only what the client asks for, so ask for everything commonly configured
REQUESTED = [1, 2, 3, 4, 5, 6, 7, 12, 15, 26, 28, 31, 33, 40, 41, 42, 43, 44, 46, 47, 51, 54, 58, 59, 60, 66, 67, 69,
             70, 72, 100, 101, 119, 120, 121, 138, 150, 176, 242, 249, 252]
HEADER = struct.Struct("!BBBB4sHH4s4s4s4s16s64s128s")

LEASE_SCRIPT = r"""
$config = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=%(index)s"
[ordered]@{ dhcp = [bool]$config.DHCPEnabled; server = "$($config.DHCPServer)" } | ConvertTo-Json -Compress
"""


@dataclass
class Offer:
    server: str  # Server identifier (option 54), or the sender if missing
    sender: str  # Where the packet came from: the server, or a relay (router) forwarding for it
    address: str  # Address offered
    subnet_mask: str = ""
    routers: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    domain: str = ""
    lease_seconds: int = 0
    tftp_server: str = ""
    boot_file: str = ""
    relay: str = ""  # giaddr, when a relay agent forwarded the offer
    rtt: float = 0.0  # Milliseconds after the first DISCOVER
    options: list = field(default_factory=list)  # Every option as (code, raw bytes), in the order sent
    next_server: str = ""  # siaddr: the server to boot from (PXE, phones)
    server_name: str = ""  # sname header field
    header_boot_file: str = ""  # file header field

    @property
    def lease_text(self):
        return format_seconds(self.lease_seconds) if self.lease_seconds else ""

    def details(self):
        """[(option code or "", name, value)] for the header fields and every option, for display."""
        rows = [("", "Offered address (yiaddr)", self.address)]
        for label, value in (("Next server (siaddr)", self.next_server), ("Server host name (sname)", self.server_name),
                             ("Boot file (file)", self.header_boot_file), ("Relay agent (giaddr)", self.relay)):
            if value:
                rows.append(("", label, value))
        rows += [(code, *describe_option(code, raw)) for code, raw in self.options]
        return rows


def format_seconds(seconds):
    if seconds == 0xFFFFFFFF:
        return "Infinite"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)
    return (f"{days}d " if days else "") + f"{hours}h {minutes}m" + (f" {seconds}s" if seconds else "")


def build_discover(mac, transaction_id):
    """A DHCPDISCOVER asking servers to broadcast their offers."""
    chaddr = bytes.fromhex(normalize_mac(mac)).ljust(16, b"\0")
    header = HEADER.pack(BOOTREQUEST, 1, 6, 0, transaction_id, 0, BROADCAST_FLAG, bytes(4), bytes(4), bytes(4),
                         bytes(4), chaddr, b"", b"")
    options = bytes([OPT_TYPE, 1, DISCOVER, OPT_PARAMS, len(REQUESTED)] + REQUESTED)
    options += bytes([OPT_CLIENT_ID, 7, 1]) + chaddr[:6] + bytes([OPT_END])
    return header + MAGIC_COOKIE + options


def _addresses(raw):
    return [socket.inet_ntoa(raw[i:i + 4]) for i in range(0, len(raw) - 3, 4)]


def parse_options(data):
    """[(code, value)] in the order sent. An option split into several pieces (RFC 3396) is joined together."""
    options = {}
    offset = 0
    while offset < len(data):
        code = data[offset]
        if code == OPT_END:
            break
        if code == OPT_PAD:
            offset += 1
            continue
        if offset + 1 >= len(data):
            break
        length = data[offset + 1]
        options[code] = options.get(code, b"") + data[offset + 2:offset + 2 + length]
        offset += 2 + length
    return list(options.items())


# ----------------------------------------------------------------- Describing options

def _ip(raw):
    return socket.inet_ntoa(raw) if len(raw) == 4 else raw.hex(" ")


def _ips(raw):
    return ", ".join(_addresses(raw)) if raw and len(raw) % 4 == 0 else raw.hex(" ")


def _text(raw):
    text = raw.decode("utf-8", "replace").rstrip("\0\r\n ")  # Some servers end text with a newline or a zero
    return text if text.isprintable() else raw.hex(" ")


def _hex_or_text(raw):
    """Vendor data and the like: text when it's readable, hex otherwise."""
    try:
        text = raw.decode("ascii").rstrip("\0")
        if text and text.isprintable():
            return text
    except UnicodeDecodeError:
        pass
    return raw.hex(" ")


def _uint(raw):
    return str(int.from_bytes(raw, "big")) if raw else ""


def _seconds(raw):
    return format_seconds(int.from_bytes(raw, "big")) if len(raw) == 4 else raw.hex(" ")


def _signed_seconds(raw):
    if len(raw) != 4:
        return raw.hex(" ")
    value = int.from_bytes(raw, "big", signed=True)
    return f"{value:+d} seconds (UTC{value / 3600:+g}h)"


def _flag(raw):
    return ("Yes" if raw[0] else "No") if raw else ""


def _message_type(raw):
    names = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
    return names.get(raw[0], str(raw[0])) if raw else ""


def _node_type(raw):
    names = {1: "B-node (broadcast)", 2: "P-node (WINS only)", 4: "M-node (broadcast, then WINS)",
             8: "H-node (WINS, then broadcast)"}
    return names.get(raw[0], str(raw[0])) if raw else ""


def _static_routes(raw):
    """Option 33: pairs of (destination, router)."""
    pairs = [(raw[i:i + 4], raw[i + 4:i + 8]) for i in range(0, len(raw) - 7, 8)]
    return "; ".join(f"{_ip(destination)} via {_ip(router)}" for destination, router in pairs)


def _classless_routes(raw):
    """Options 121 and 249 (RFC 3442): each route is a prefix length, the significant octets, then the router."""
    routes, offset = [], 0
    try:
        while offset < len(raw):
            width = raw[offset]
            octets = (width + 7) // 8
            destination = raw[offset + 1:offset + 1 + octets].ljust(4, b"\0")
            router = raw[offset + 1 + octets:offset + 5 + octets]
            if width > 32 or len(router) != 4:
                return raw.hex(" ")
            routes.append(f"{socket.inet_ntoa(destination)}/{width} via {socket.inet_ntoa(router)}")
            offset += 5 + octets
    except IndexError:
        return raw.hex(" ")
    return "; ".join(routes)


def _domain_search(raw):
    """Option 119 (RFC 3397): DNS-style names, which may point back at earlier ones."""
    names, offset = [], 0

    def read_name(position):
        labels, jumps = [], 0
        while position < len(raw):
            length = raw[position]
            if length == 0:
                return ".".join(labels), position + 1
            if length & 0xC0 == 0xC0:
                jumps += 1
                if jumps > 16 or position + 1 >= len(raw):
                    raise ValueError("bad pointer")
                name, _ = read_name(((length & 0x3F) << 8) | raw[position + 1])
                return ".".join(labels + [name]) if name else ".".join(labels), position + 2
            labels.append(raw[position + 1:position + 1 + length].decode("ascii", "replace"))
            position += 1 + length
        raise ValueError("truncated")

    try:
        while offset < len(raw):
            name, offset = read_name(offset)
            names.append(name)
    except (ValueError, RecursionError):
        return raw.hex(" ")
    return ", ".join(names)


def _sip_servers(raw):
    """Option 120 (RFC 3361): a first byte saying whether names (0) or addresses (1) follow."""
    if not raw:
        return ""
    if raw[0] == 1:
        return _ips(raw[1:])
    if raw[0] == 0:
        return _domain_search(raw[1:])
    return raw.hex(" ")


def _relay_info(raw):
    """Option 82: the relay agent's sub-options, such as the switch port (circuit ID) the client is on."""
    names = {1: "Circuit ID", 2: "Remote ID", 5: "Link selection", 6: "Subscriber ID", 11: "Server ID override"}
    parts, offset = [], 0
    while offset + 1 < len(raw):
        code, length = raw[offset], raw[offset + 1]
        parts.append(f"{names.get(code, f'Sub-option {code}')}: {_hex_or_text(raw[offset + 2:offset + 2 + length])}")
        offset += 2 + length
    return "; ".join(parts)


def _parameter_list(raw):
    return ", ".join(str(code) for code in raw)


OPTIONS = {
    1: ("Subnet mask", _ip), 2: ("Time offset", _signed_seconds), 3: ("Router (default gateway)", _ips),
    4: ("Time servers", _ips), 5: ("Name servers (IEN 116)", _ips), 6: ("DNS servers", _ips),
    7: ("Log servers", _ips), 9: ("LPR servers", _ips), 12: ("Host name", _text), 13: ("Boot file size", _uint),
    15: ("Domain name", _text), 17: ("Root path", _text), 19: ("IP forwarding", _flag), 23: ("Default IP TTL", _uint),
    26: ("Interface MTU", _uint), 28: ("Broadcast address", _ip), 31: ("Perform router discovery", _flag),
    33: ("Static routes", _static_routes), 35: ("ARP cache timeout", _seconds), 37: ("Default TCP TTL", _uint),
    40: ("NIS domain", _text), 41: ("NIS servers", _ips), 42: ("NTP servers", _ips),
    43: ("Vendor-specific information", _hex_or_text), 44: ("NetBIOS name servers (WINS)", _ips),
    45: ("NetBIOS datagram distribution servers", _ips), 46: ("NetBIOS node type", _node_type),
    47: ("NetBIOS scope", _text), 50: ("Requested IP address", _ip), 51: ("Lease time", _seconds),
    52: ("Option overload", _uint), 53: ("DHCP message type", _message_type), 54: ("DHCP server identifier", _ip),
    55: ("Parameter request list", _parameter_list), 56: ("Message", _text), 57: ("Maximum message size", _uint),
    58: ("Renewal time (T1)", _seconds), 59: ("Rebinding time (T2)", _seconds),
    60: ("Vendor class identifier", _hex_or_text), 61: ("Client identifier", lambda raw: raw.hex(":")),
    64: ("NIS+ domain", _text), 65: ("NIS+ servers", _ips), 66: ("TFTP server name", _text),
    67: ("Boot file name", _text), 69: ("SMTP servers", _ips), 70: ("POP3 servers", _ips),
    72: ("Default web (WWW) servers", _ips), 81: ("Client FQDN", _hex_or_text),
    82: ("Relay agent information", _relay_info), 100: ("Time zone (POSIX)", _text),
    101: ("Time zone (tz database)", _text), 108: ("IPv6-only preferred", _seconds),
    114: ("Captive portal URL", _text), 119: ("Domain search list", _domain_search), 120: ("SIP servers", _sip_servers),
    121: ("Classless static routes", _classless_routes), 125: ("Vendor-identifying vendor information", _hex_or_text),
    138: ("CAPWAP access controllers", _ips), 150: ("TFTP server addresses (Cisco)", _ips),
    176: ("Avaya IP phone settings", _text), 242: ("Avaya IP phone settings", _text),
    249: ("Classless static routes (Microsoft)", _classless_routes), 252: ("Proxy auto-discovery (WPAD) URL", _text),
}


def describe_option(code, raw):
    """(name, readable value) for an option. Anything unrecognized is shown as text or hex, never dropped."""
    name, formatter = OPTIONS.get(code, (f"Option {code}", _hex_or_text))
    try:
        return name, formatter(raw)
    except (IndexError, ValueError, OSError):
        return name, raw.hex(" ")


def parse_offer(data, transaction_id, sender=""):
    """Returns an Offer, or None if the packet isn't an offer for our DISCOVER."""
    if len(data) < HEADER.size + 4 or data[HEADER.size:HEADER.size + 4] != MAGIC_COOKIE:
        return None
    fields = HEADER.unpack_from(data)
    op, xid, yiaddr, siaddr, giaddr, sname, boot_file = fields[0], fields[4], fields[8], fields[9], fields[10], \
        fields[12], fields[13]
    if op != BOOTREPLY or xid != transaction_id:
        return None
    options = dict(parse_options(data[HEADER.size + 4:]))
    # Option overload: the file (1), sname (2) or both (3) header fields carry more options instead of text
    overload = options.get(OPT_OVERLOAD, b"\0")[0] if options.get(OPT_OVERLOAD) else 0
    for flag, extra in ((1, boot_file), (2, sname)):
        if overload & flag:
            for code, value in parse_options(extra):
                options[code] = options.get(code, b"") + value
    option_list = list(options.items())
    if options.get(OPT_TYPE) != bytes([OFFER]):
        return None
    server = options.get(OPT_SERVER_ID)
    offer = Offer(server=socket.inet_ntoa(server) if server and len(server) == 4 else sender, sender=sender,
                  address=socket.inet_ntoa(yiaddr))
    if len(options.get(OPT_SUBNET, b"")) == 4:
        offer.subnet_mask = socket.inet_ntoa(options[OPT_SUBNET])
    offer.routers = _addresses(options.get(OPT_ROUTER, b""))
    offer.dns = _addresses(options.get(OPT_DNS, b""))
    offer.domain = options.get(OPT_DOMAIN, b"").decode("ascii", "replace").rstrip("\0")
    if len(options.get(OPT_LEASE, b"")) == 4:
        offer.lease_seconds = struct.unpack("!I", options[OPT_LEASE])[0]
    offer.tftp_server = options.get(OPT_TFTP_SERVER, b"").decode("ascii", "replace").rstrip("\0")
    offer.boot_file = options.get(OPT_BOOTFILE, b"").decode("ascii", "replace").rstrip("\0")
    if giaddr != bytes(4):
        offer.relay = socket.inet_ntoa(giaddr)
    if siaddr != bytes(4):
        offer.next_server = socket.inet_ntoa(siaddr)
    if not overload & 2:
        offer.server_name = sname.split(b"\0", 1)[0].decode("ascii", "replace")
    if not overload & 1:
        offer.header_boot_file = boot_file.split(b"\0", 1)[0].decode("ascii", "replace")
    offer.options = option_list
    return offer


def current_dhcp_server(interface_index):
    """The DHCP server this adapter's current lease came from, or "" (static address, or unknown)."""
    try:
        data = run_powershell_json(LEASE_SCRIPT % {"index": int(interface_index)}, timeout=30) or {}
    except Exception:  # Only used to label results; the test works without it
        return ""
    server = (data.get("server") or "").strip()
    try:
        ipaddress.IPv4Address(server)
    except ValueError:
        return ""
    return server if data.get("dhcp") and server != "255.255.255.255" else ""


def discover_servers(source_address, mac, listen_seconds=6.0, sends=3, should_stop=lambda: False,
                     found=lambda offer: None):
    """Broadcast DISCOVERs from source_address (the adapter's IPv4 address) and collect every offer.

    The DISCOVER is repeated a few times in case one is lost. Returns [Offer], one per server.
    Raises OSError if the DHCP client port can't be used.
    """
    transaction_id = os.urandom(4)
    packet = build_discover(mac, transaction_id)
    offers = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind((source_address, CLIENT_PORT))
        except OSError as error:
            raise OSError(f"Couldn't listen on the DHCP client port ({CLIENT_PORT}) on {source_address}: "
                          f"{error.strerror or error}") from None
        started = time.monotonic()
        send_times = [started + index * listen_seconds / (sends + 1) for index in range(sends)]
        deadline = started + listen_seconds
        while not should_stop():
            now = time.monotonic()
            if now >= deadline:
                break
            while send_times and send_times[0] <= now:
                send_times.pop(0)
                sock.sendto(packet, ("255.255.255.255", SERVER_PORT))
            wait_until = min([deadline] + send_times)
            sock.settimeout(max(0.05, min(0.5, wait_until - time.monotonic())))
            try:
                data, sender = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue
            offer = parse_offer(data, transaction_id, sender[0])
            if offer is None or offer.server in offers:
                continue
            offer.rtt = (time.monotonic() - started) * 1000
            offers[offer.server] = offer
            found(offer)
    return list(offers.values())


def assess(offers, expected_server):
    """A (kind, message) verdict: "success", "warning" or "error"."""
    servers = [offer.server for offer in offers]
    if not offers:
        return "warning", ("No DHCP server answered. If this network should have one, check that it's running and "
                           "reachable (and that Windows Firewall lets DHCP replies in).")
    unexpected = [server for server in servers if expected_server and server != expected_server]
    if unexpected:
        return "error", (f"Found {len(unexpected)} DHCP server{'' if len(unexpected) == 1 else 's'} besides "
                         f"{expected_server} (where this adapter's lease came from): {', '.join(unexpected)}. "
                         "Unless it's meant to be there, that's a rogue DHCP server handing out addresses.")
    if len(offers) > 1:
        return "error", (f"{len(offers)} DHCP servers answered: {', '.join(servers)}. A network normally has one; "
                         "unless they're a deliberate pair, one of them is a rogue.")
    return "success", f"Only one DHCP server answered ({servers[0]}). No rogue DHCP servers found."
