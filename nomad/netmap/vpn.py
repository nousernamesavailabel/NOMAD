"""VPNs between Cisco IOS / IOS-XE routers: GRE, GRE over IPsec, static VTI, crypto maps (IKEv1 and IKEv2) and DMVPN
(phases 1, 2 and 3; one hub or two; a second cloud is a second VPN), with pre-shared keys or certificates.

A Vpn is the design: its kind, its members (each a router with its WAN interface and tunnel), the crypto, how the
routers authenticate, and how routes cross it. From it, each member's configuration is made as a footprint: the
blocks of configuration it needs (an IKEv2 proposal, an IPsec profile, a tunnel interface, network statements in a
routing process...). Some blocks are the VPN's own (whole) and go when it goes; some are shared with whatever else the
router has (partial: a routing process, the WAN interface's crypto map line, an IKEv2 policy), and only the VPN's own
lines in them come and go.

Changes are planned against the router's running-config as read (a tree of blocks): what the router would have once
the footprint is in place, and the fewest lines that get it there. What undoes a change is planned the same way, from
after back to before, so it's exact. Lines go in an order IOS accepts: what's used before what uses it, and anything
in use taken off what uses it before it's removed (IOS refuses to remove an IPsec profile a tunnel uses, or a crypto
map an interface has).

Pre-shared keys and NHRP passwords are kept out of what's shown and logged (mask()); the lines sent have them.

Qt-free, so it can be tested without a network.
"""
import copy
import ipaddress
import json
import logging
import re
import secrets
import string
import uuid
from dataclasses import asdict, dataclass, field

log = logging.getLogger(__name__)

GRE, GRE_IPSEC, VTI, CRYPTO_MAP, DMVPN = "gre", "gre-ipsec", "vti", "crypto-map", "dmvpn"
KINDS = [VTI, GRE_IPSEC, GRE, CRYPTO_MAP, DMVPN]
KIND_NAMES = {GRE: "GRE", GRE_IPSEC: "GRE over IPsec", VTI: "IPsec VTI", CRYPTO_MAP: "Crypto Map (policy-based)",
              DMVPN: "DMVPN"}
POINT_TO_POINT = (GRE, GRE_IPSEC, VTI)
PEER, HUB, SPOKE = "peer", "hub", "spoke"
ROLE_NAMES = {PEER: "Peer", HUB: "Hub", SPOKE: "Spoke"}
IKEV1, IKEV2 = "ikev1", "ikev2"
PSK, CERT = "psk", "cert"
NO_ROUTING, STATIC, EIGRP, OSPF, BGP = "none", "static", "eigrp", "ospf", "bgp"
ROUTING_NAMES = {NO_ROUTING: "None (I'll route it)", STATIC: "Static routes", EIGRP: "EIGRP", OSPF: "OSPF",
                 BGP: "BGP"}
TUNNEL, TRANSPORT = "tunnel", "transport"
FILE_NAME = "vpns.json"
KEEP_HISTORY = 200
MASK = "********"
TUNNEL_POOL = ipaddress.IPv4Network("172.31.0.0/16")  # Where tunnel subnets are suggested from

# Crypto choices. IKEv2 proposals take these keywords; IKEv1 policies take the "aes 256" forms.
IKEV2_ENCRYPTION = ["aes-gcm-256", "aes-gcm-128", "aes-cbc-256", "aes-cbc-192", "aes-cbc-128", "3des", "des"]
IKEV2_INTEGRITY = ["sha512", "sha384", "sha256", "sha1", "md5"]
IKEV2_PRF = ["sha512", "sha384", "sha256", "sha1", "md5"]
IKEV1_ENCRYPTION = ["aes 256", "aes 192", "aes", "3des", "des"]
IKEV1_HASH = ["sha512", "sha384", "sha256", "sha", "md5"]
DH_GROUPS = [21, 20, 19, 24, 16, 15, 14, 5, 2, 1]
ESP_CHOICES = ["esp-gcm 256", "esp-gcm 128", "esp-aes 256 esp-sha256-hmac", "esp-aes 256 esp-sha384-hmac",
               "esp-aes 256 esp-sha512-hmac", "esp-aes 256 esp-sha-hmac", "esp-aes 128 esp-sha256-hmac",
               "esp-3des esp-sha-hmac", "esp-des esp-md5-hmac"]
PFS_GROUPS = [0, 21, 20, 19, 24, 16, 15, 14, 5, 2, 1]
MODERN, COMPATIBLE, LEGACY, CUSTOM = "modern", "compatible", "legacy", "custom"
PRESET_NAMES = {MODERN: "Modern IKEv2 (AES-GCM-256, DH 20/19)", COMPATIBLE: "Compatible IKEv2 (AES-256 + SHA-256, "
                "DH 14)", LEGACY: "IKEv1 (AES-256 + SHA-256, DH 14)", CUSTOM: "Custom"}


# ----------------------------------------------------------------- Configuration as a tree of blocks

@dataclass
class Block:
    """A configuration line and the lines under it (a mode). In a footprint, partial means only the lines under it
    are the VPN's (the block itself is shared), and sticky means it stays when the VPN goes."""
    line: str
    children: list = field(default_factory=list)
    partial: bool = False
    sticky: bool = False

    def render(self, depth=0):
        lines = [" " * depth + self.line]
        for child in self.children:
            lines += child.render(depth + 1)
        return lines

    def child(self, line):
        """The child block whose line is line (or whose key is line's), or None."""
        wanted = key_of(line, self.line)
        return next((item for item in self.children if key_of(item.line, self.line) == wanted), None)

    def copy(self):
        return copy.deepcopy(self)


SKIPPED_LINES = re.compile(r"^(?:!|end$|Building configuration|Current configuration|exit-[a-z-]+$|exit$)")


def parse_tree(text):
    """[Block] of a running-config (or a section of one), by indentation."""
    root = Block("")
    stack = [(-1, root)]
    for raw in (text or "").splitlines():
        line = raw.replace("\t", " ").rstrip()
        stripped = line.strip()
        if not stripped or SKIPPED_LINES.match(stripped):
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack:
            stack = [(-1, root)]
        block = Block(collapse(stripped))
        stack[-1][1].children.append(block)
        stack.append((indent, block))
    return root.children


def collapse(line):
    """A line with runs of spaces made one (IOS pads some with trailing and doubled spaces)."""
    return " ".join(line.split())


def render(blocks):
    lines = []
    for block in blocks:
        lines += block.render()
    return lines


# What kind of mode a block is, from its line (for which of its lines replace each other)
def parent_type(line):
    words = line.split()
    if not words:
        return "top"
    if words[0] == "interface":
        return "interface"
    if words[:3] == ["crypto", "ikev2", "proposal"]:
        return "ikev2-proposal"
    if words[:3] == ["crypto", "ikev2", "policy"]:
        return "ikev2-policy"
    if words[:3] == ["crypto", "ikev2", "keyring"]:
        return "ikev2-keyring"
    if words[:3] == ["crypto", "ikev2", "profile"]:
        return "ikev2-profile"
    if words[:3] == ["crypto", "isakmp", "policy"]:
        return "isakmp-policy"
    if words[:3] == ["crypto", "isakmp", "profile"]:
        return "isakmp-profile"
    if words[:2] == ["crypto", "keyring"]:
        return "keyring"
    if words[:3] == ["crypto", "ipsec", "transform-set"]:
        return "transform-set"
    if words[:3] == ["crypto", "ipsec", "profile"]:
        return "ipsec-profile"
    if words[:2] == ["crypto", "map"]:
        return "crypto-map"
    if words[:3] == ["crypto", "pki", "trustpoint"]:
        return "trustpoint"
    if words[:3] == ["crypto", "pki", "server"]:
        return "pki-server"
    if words[:4] == ["crypto", "pki", "certificate", "map"]:
        return "certificate-map"
    if words[0] == "peer":
        return "keyring-peer"
    if words[:2] == ["ip", "access-list"]:
        return "acl"
    if words[:2] == ["router", "bgp"]:
        return "bgp"
    if words[:2] == ["router", "ospf"]:
        return "ospf"
    if words[:2] == ["router", "eigrp"]:
        return "eigrp"
    if words[0] == "address-family":
        return "address-family"
    if words[0] == "af-interface":
        return "af-interface"
    return "other"


# Lines that replace each other in a mode (typing a new one takes the old one's place): the start of the line, for
# each kind of mode. Anything else is a line of its own (removed with no, added as it is).
SLOTS = {
    "interface": ["description", "ip address", "ip mtu", "ip tcp adjust-mss", "tunnel source", "tunnel destination",
                  "tunnel mode", "tunnel key", "tunnel protection", "ip nhrp network-id", "ip nhrp holdtime",
                  "ip nhrp authentication", "ip ospf network", "ip ospf priority", "keepalive", "bandwidth",
                  "crypto map", "ip ospf cost", "delay"],
    "ikev2-proposal": ["encryption", "integrity", "prf", "group"],
    "ikev2-profile": ["identity local", "authentication local", "keyring local", "dpd", "lifetime", "description"],
    "isakmp-policy": ["encryption", "hash", "authentication", "group", "lifetime"],
    "isakmp-profile": ["keyring", "keepalive", "self-identity", "description"],
    "keyring-peer": ["address", "pre-shared-key local", "pre-shared-key remote", "pre-shared-key", "identity",
                     "description"],
    "transform-set": ["mode"],
    "ipsec-profile": ["set transform-set", "set ikev2-profile", "set isakmp-profile", "set pfs",
                      "set security-association lifetime seconds", "set security-association lifetime kilobytes"],
    "crypto-map": ["description", "set transform-set", "set ikev2-profile", "set isakmp-profile", "set pfs",
                   "match address", "set security-association lifetime seconds"],
    "trustpoint": ["enrollment", "subject-name", "revocation-check", "rsakeypair", "fqdn", "serial-number",
                   "ip-address", "auto-enroll", "source interface"],
    "pki-server": ["database level", "database url", "issuer-name", "lifetime certificate", "lifetime ca-certificate",
                   "lifetime crl", "grant"],
    "ospf": ["router-id"],
    "eigrp": ["eigrp router-id"],
    "bgp": ["bgp router-id"],
}
# Lines whose IOS default is hidden from running-config (so they're never written, or they'd always look changed)
HIDDEN_DEFAULTS = {("interface", "tunnel mode gre ip"), ("isakmp-policy", "lifetime 86400"),
                   ("ipsec-profile", "set security-association lifetime seconds 3600"),
                   ("crypto-map", "set security-association lifetime seconds 3600")}
# Lines that IOS XE hides as defaults (classic IOS shows them)
XE_HIDDEN_DEFAULTS = {("interface", "ip nhrp shortcut"), ("interface", "ip nhrp map multicast dynamic")}


def slot_of(line, parent_line):
    """The slot a line fills in its mode (lines with one replace each other), or "" for a line of its own."""
    kind = parent_type(parent_line)
    if kind == "interface" and line.startswith("ip address ") and line.endswith(" secondary"):
        return ""
    if kind == "keyring" and line.startswith("pre-shared-key address "):  # One key per peer address (and mask)
        return " ".join(line.split()[:4] if len(line.split()) > 4 and line.split()[3] != "key" else
                        line.split()[:3])
    for prefix in SLOTS.get(kind, ()):
        if line == prefix or line.startswith(prefix + " "):
            return prefix
    return ""


def key_of(line, parent_line=""):
    """What identifies a line among its siblings: its slot, a mode's name, or the line itself."""
    slot = slot_of(line, parent_line) if parent_line else ""
    if slot:
        return slot
    words = line.split()
    kind = parent_type(line)
    if kind == "crypto-map" and len(words) >= 4:
        return " ".join(words[:4])  # crypto map NAME SEQ (ipsec-isakmp...)
    if kind == "transform-set" and len(words) >= 4:
        return " ".join(words[:4])  # Its transforms can change in place
    if parent_type(parent_line) == "acl" and words and words[0].isdigit():
        return " ".join(words[1:])  # 10 permit ...: the rule, whatever its number
    if not parent_line and words[:3] == ["crypto", "isakmp", "key"] and "address" in words:
        return "crypto isakmp key address " + " ".join(words[words.index("address") + 1:])
    return line


def no_form(line, parent_line=""):
    """What removes a line (or a mode with everything in it)."""
    words = line.split()
    if line.startswith("no "):
        return line[3:]
    kind = parent_type(line)
    if not parent_line:
        if kind == "crypto-map" and len(words) >= 4:
            return "no " + " ".join(words[:4])
        if kind == "transform-set" and len(words) >= 4:
            return "no " + " ".join(words[:4])
        if kind == "certificate-map" and len(words) >= 5:
            return "no " + " ".join(words[:5])
    if parent_type(parent_line) == "acl" and words and words[0].isdigit():
        return f"no {words[0]}"
    return "no " + line


def index(blocks, parent_line=""):
    """{key: block} of sibling blocks."""
    return {key_of(block.line, parent_line): block for block in blocks}


# ----------------------------------------------------------------- Secrets kept out of what's shown

SECRET_PATTERNS = [
    re.compile(r"(\bpre-shared-key\s+(?:address|hostname)\s+\S+(?:\s+\d+\.\d+\.\d+\.\d+)?\s+key(?:\s+[0-9])?\s+)"
               r"(\S+)"),
    re.compile(r"(\bpre-shared-key(?:\s+(?:local|remote))?(?:\s+[0-9](?=\s))?\s+)(?!address\b|hostname\b)(\S+)"),
    re.compile(r"(\bcrypto\s+isakmp\s+key(?:\s+[0-9](?=\s))?\s+)(\S+)"),
    re.compile(r"(\bip\s+nhrp\s+authentication\s+)(\S+)"),
    re.compile(r"(\bkey\s+config-key\s+password-encrypt\s+)(\S+)"),
    re.compile(r"(^ ?password(?:\s+[0-9](?=\s))?\s+)(\S+)\s*$", re.MULTILINE),
]


def mask(text):
    """text with the keys and passwords in it made ********."""
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda found: found.group(1) + MASK, text)
    return text


def new_key(length=24):
    """A random pre-shared key: letters and digits (no characters IOS or a terminal treats specially)."""
    alphabet = string.ascii_letters + string.digits
    while True:
        key = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.isdigit() for c in key) and any(c.islower() for c in key) and any(c.isupper() for c in key):
            return key


def safe_name(text, limit=20):
    """A name IOS takes for crypto objects: letters, digits, - and _."""
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", (text or "").strip()).strip("-")
    return (name or "VPN")[:limit]


# ----------------------------------------------------------------- The design

@dataclass
class Crypto:
    preset: str = MODERN
    ike: str = IKEV2
    encryption: list = field(default_factory=lambda: ["aes-gcm-256"])  # IKEv2 keywords, or one IKEv1 ("aes 256")
    integrity: list = field(default_factory=list)  # IKEv2 (not with GCM), or IKEv1's hash (one)
    prf: list = field(default_factory=lambda: ["sha384"])  # IKEv2 only
    groups: list = field(default_factory=lambda: [20, 19])
    ike_lifetime: int = 86400
    esp: str = "esp-gcm 256"
    mode: str = ""  # "" = the usual for the kind (transport for GRE/DMVPN, tunnel otherwise)
    pfs: int = 0
    sa_lifetime: int = 3600
    dpd: int = 10  # Seconds (0: off)
    dpd_retry: int = 3
    dpd_periodic: bool = True
    nat_keepalive: int = 20  # Seconds (0: off): keeps NAT mappings open when a peer is behind NAT

    def gcm(self):
        return any("gcm" in item for item in self.encryption)


def preset(name):
    """A Crypto with a preset's settings."""
    if name == COMPATIBLE:
        return Crypto(preset=COMPATIBLE, ike=IKEV2, encryption=["aes-cbc-256"], integrity=["sha256"], prf=[],
                      groups=[14], esp="esp-aes 256 esp-sha256-hmac")
    if name == LEGACY:
        return Crypto(preset=LEGACY, ike=IKEV1, encryption=["aes 256"], integrity=["sha256"], prf=[], groups=[14],
                      esp="esp-aes 256 esp-sha256-hmac", pfs=14)
    return Crypto()


@dataclass
class Auth:
    method: str = PSK
    psk: str = ""
    trustpoint: str = ""  # The trustpoint holding each router's certificate (the same name on each)
    ca_name: str = ""  # The CA's common name (what certificate maps match the issuer on)
    ca_kind: str = ""  # "router" (an IOS CA NOMAD sets up), "scep" (another CA's SCEP URL) or "paste"
    ca_device: str = ""  # The member key of the router that is the CA (ca_kind router)
    ca_url: str = ""  # The SCEP URL (ca_kind scep; for router, made from the CA's address)
    ca_fingerprint: str = ""  # The CA certificate's fingerprint, checked before it's trusted
    revocation: str = "none"  # Trustpoint revocation-check: "none" or "crl"


@dataclass
class Routing:
    kind: str = STATIC
    process: str = ""  # EIGRP AS / OSPF process ("" = picked)
    area: str = "0"  # OSPF
    eigrp_name: str = ""  # Named EIGRP (the name), or "" for classic
    guard: bool = True  # BGP: keep the VPN's LANs from the router's other eBGP neighbors (its ISP)


@dataclass
class Dmvpn:
    phase: int = 3
    network_id: int = 0  # 0 = the tunnel number
    auth: str = ""  # NHRP authentication (at most 8 characters)
    holdtime: int = 300
    tunnel_key: int = 0  # 0 = none (unless another mGRE tunnel shares the WAN interface)


@dataclass
class Member:
    key: str  # Device key (the page's)
    label: str = ""
    address: str = ""  # Where NOMAD logs in to it
    role: str = PEER
    wan: str = ""  # WAN interface (tunnel source / crypto map interface)
    local_ip: str = ""  # Its address on the WAN interface (its IKE identity)
    public_ip: str = ""  # Where the others reach it, when NAT changes it ("" = local_ip)
    tunnel: int = 0
    tunnel_ip: str = ""  # Address on the tunnel (the prefix length is the VPN subnet's)
    lans: list = field(default_factory=list)  # Prefixes ("10.1.1.0/24") it carries across
    bgp_as: str = ""  # Its BGP AS (BGP routing; read from the router when it has BGP)
    hub_order: int = 0  # Dual hub: 1 (preferred) or 2
    names: dict = field(default_factory=dict)  # The names of its objects when they aren't the VPN's usual ones
    psk: str = ""  # The key it sends (IKEv2 pre-shared-key local) when it isn't the VPN's ("" = auth.psk)
    psk_remote: str = ""  # The key it expects back, as read, when it isn't the others' own ("" = theirs)
    by_hand: bool = False  # A far end typed in (key "peer:..."): nothing is sent to it, its lines are shown to copy

    @property
    def reached_at(self):
        return self.public_ip or self.local_ip

    def title(self):
        return self.label or self.address or self.key


@dataclass
class Vpn:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = "VPN"
    kind: str = VTI
    members: list = field(default_factory=list)
    crypto: Crypto = field(default_factory=Crypto)
    auth: Auth = field(default_factory=Auth)
    routing: Routing = field(default_factory=Routing)
    dmvpn: Dmvpn = field(default_factory=Dmvpn)
    subnet: str = ""  # The tunnel subnet ("172.31.0.0/30"); not for crypto maps
    mtu: int = 1400
    mss: int = 1360
    keepalive: int = 0  # GRE keepalive seconds (plain GRE only)
    description: str = ""
    found: bool = False  # Read from routers (not built in NOMAD)
    differences: list = field(default_factory=list)  # As read: where one router's side isn't like the others'
    template: bool = False  # No routers: each member is a slot ("slot:...") whose details are <PLACEHOLDERS>

    @property
    def protected(self):
        return self.kind != GRE

    @property
    def base(self):
        return safe_name(self.name)

    def member(self, key):
        return next((item for item in self.members if item.key == key), None)

    def hubs(self):
        return sorted((item for item in self.members if item.role == HUB), key=lambda item: item.hub_order or 9)

    def spokes(self):
        return [item for item in self.members if item.role == SPOKE]

    def others(self, member):
        return [item for item in self.members if item.key != member.key]

    def prefix_length(self):
        try:
            return ipaddress.IPv4Network(self.subnet, strict=False).prefixlen
        except ValueError:
            return 30 if self.kind in POINT_TO_POINT else 24

    def netmask(self):
        return str(ipaddress.IPv4Network(f"0.0.0.0/{self.prefix_length()}").netmask)

    def copy(self):
        return copy.deepcopy(self)

    def to_dict(self, with_secrets=False):
        data = asdict(self)
        if not with_secrets:
            data["auth"]["psk"] = ""
            data["dmvpn"]["auth"] = ""
            for member in data["members"]:
                member["psk"] = member["psk_remote"] = ""
        return data

    def own_keys(self):
        """Whether any member has keys of its own (asymmetric keys, as read)."""
        return any(member.psk or member.psk_remote for member in self.members)

    def one_key(self, psk):
        """The same key on every router (the members' own ones dropped)."""
        self.auth.psk = psk
        for member in self.members:
            member.psk = member.psk_remote = ""
        self.differences = [text for text in self.differences if "pre-shared key" not in text]

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data["members"] = [Member(**item) for item in data.get("members", [])]
        data["crypto"] = Crypto(**data.get("crypto", {}))
        data["auth"] = Auth(**data.get("auth", {}))
        data["routing"] = Routing(**data.get("routing", {}))
        data["dmvpn"] = Dmvpn(**data.get("dmvpn", {}))
        known = set(cls.__dataclass_fields__)
        return cls(**{key: value for key, value in data.items() if key in known})


def most_common(values):
    """The value given most often (the first of those tied), or "" for none."""
    values = [value for value in values if value]
    return max(values, key=values.count) if values else ""


def own_key(vpn, member):
    """The pre-shared key a member sends (its local key)."""
    return member.psk or vpn.auth.psk


def remote_key(vpn, member):
    """The pre-shared key a member expects from the others (its remote key): as read, else the one they send (on a
    DMVPN cloud the hubs', or for a hub the spokes')."""
    if member.psk_remote:
        return member.psk_remote
    peers = vpn.others(member)
    if vpn.kind == DMVPN:
        peers = [item for item in (vpn.spokes() if member.role == HUB else vpn.hubs())
                 if item.key != member.key] or peers
    return most_common([own_key(vpn, item) for item in peers]) or vpn.auth.psk


def ikev2_key_lines(local, remote):
    """An IKEv2 keyring peer's key lines: one key, or a local and a remote one when they differ."""
    if not remote or local == remote:
        return [f"pre-shared-key {local}"]
    return [f"pre-shared-key local {local}", f"pre-shared-key remote {remote}"]


def kind_text(vpn):
    if vpn.kind == DMVPN:
        return f"DMVPN phase {vpn.dmvpn.phase}"
    if vpn.kind == CRYPTO_MAP:
        return f"Crypto Map ({'IKEv1' if vpn.crypto.ike == IKEV1 else 'IKEv2'})"
    return KIND_NAMES.get(vpn.kind, vpn.kind)


# ----------------------------------------------------------------- What NOMAD reads from a router

@dataclass
class Route:
    prefix: str  # "10.1.1.0/24"
    protocol: str  # "C", "S", "O", "B", "D"...
    distance: int = 0
    next_hops: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)


@dataclass
class DeviceVpns:
    """A router as read for VPNs: its running-config as blocks, its interfaces and ACLs (acl.DeviceAcls), routes,
    and what its show commands say about the VPNs up now (vpnstatus.Status)."""
    read: bool = False
    problem: str = ""
    hostname: str = ""
    when: str = ""
    tree: list = field(default_factory=list)
    acls: object = None  # acl.DeviceAcls
    xe: bool = True
    version: str = ""
    routes: list = field(default_factory=list)  # [Route]
    status: object = None  # vpnstatus.Status
    toward_pc: str = ""  # The interface this PC is reached through
    pc_ip: str = ""  # This PC's address as NOMAD sees it from the router

    def block(self, line):
        """The top-level block whose key is line's, or None."""
        wanted = key_of(line)
        return next((item for item in self.tree if key_of(item.line) == wanted), None)

    def blocks(self, prefix):
        """Top-level blocks whose line is prefix or starts with its words (a prefix ending in a space, or "interface
        Tunnel": any line starting with it)."""
        if prefix.endswith(" ") or prefix == "interface Tunnel":
            return [item for item in self.tree if item.line.startswith(prefix)]
        return [item for item in self.tree if item.line == prefix or item.line.startswith(prefix + " ")]

    def interfaces(self):
        return self.acls.interfaces if self.acls is not None else {}

    def interface_address(self, name):
        """(address, prefix length) of an interface's primary IPv4 address, or ("", 0)."""
        interface = self.interfaces().get(name) or self.interfaces().get(full_interface(name))
        if interface is None or not interface.addresses:
            return "", 0
        return interface.addresses[0]

    def interface_with(self, address):
        """The interface with an address (or "")."""
        for name, interface in self.interfaces().items():
            if any(item == address for item, _ in interface.addresses):
                return name
        return ""

    def interface_in(self, prefix):
        """The interface with an address in a prefix (the interface for a LAN), or ("", "")."""
        try:
            network = ipaddress.IPv4Network(prefix, strict=False)
        except ValueError:
            return "", ""
        for name, interface in self.interfaces().items():
            for address, _ in interface.addresses:
                if ipaddress.IPv4Address(address) in network:
                    return name, address
        return "", ""

    def networks(self):
        """[IPv4Interface] of every interface address."""
        found = []
        for interface in self.interfaces().values():
            for address, length in interface.addresses:
                found.append(ipaddress.IPv4Interface(f"{address}/{length}"))
        return found

    def tunnel_numbers(self):
        numbers = set()
        for name in self.interfaces():
            found = re.match(r"(?i)tunnel(\d+)$", name)
            if found:
                numbers.add(int(found.group(1)))
        return numbers

    def bgp_as(self):
        block = next(iter(self.blocks("router bgp")), None)
        return block.line.split()[2] if block is not None and len(block.line.split()) > 2 else ""

    def processes(self, protocol):
        """The numbers (or names) of its routing processes of a protocol ("eigrp", "ospf")."""
        return [block.line.split()[2] for block in self.blocks(f"router {protocol}") if len(block.line.split()) > 2]

    def route_to(self, address):
        """The most specific Route covering an address, or None."""
        try:
            target = ipaddress.IPv4Address(address)
        except ValueError:
            return None
        best, best_length = None, -1
        for route in self.routes:
            try:
                network = ipaddress.IPv4Network(route.prefix, strict=False)
            except ValueError:
                continue
            if target in network and network.prefixlen > best_length:
                best, best_length = route, network.prefixlen
        return best


INTERFACE_ABBREVIATIONS = [("Gi", "GigabitEthernet"), ("Te", "TenGigabitEthernet"), ("Fa", "FastEthernet"),
                           ("Et", "Ethernet"), ("Tu", "Tunnel"), ("Lo", "Loopback"), ("Se", "Serial"),
                           ("Po", "Port-channel"), ("Vl", "Vlan"), ("Di", "Dialer"), ("Mu", "Multilink"),
                           ("Fo", "FortyGigabitEthernet"), ("Hu", "HundredGigE"), ("Twe", "TwentyFiveGigE")]


def full_interface(name):
    """An interface name as running-config writes it ("Gi1" -> "GigabitEthernet1")."""
    found = re.match(r"([A-Za-z-]+)(\d.*)$", name or "")
    if not found:
        return name
    letters, rest = found.groups()
    for short, full in sorted(INTERFACE_ABBREVIATIONS, key=lambda item: -len(item[0])):
        if full.lower().startswith(letters.lower()) and letters.lower().startswith(short.lower()):
            return full + rest
    return name


ROUTE_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9*+%& ]{0,6}?)\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?(?=[\s,\[]|$)(.*)$")
SUBNETTED = re.compile(r"^\s+\d+\.\d+\.\d+\.\d+/(\d+) is (variably )?subnetted")
DISTANCE = re.compile(r"\[(\d+)/\d+\]")


def classful(address):
    first = int(address.split(".")[0])
    return 8 if first < 128 else 16 if first < 192 else 24


def parse_routes(text):
    """[Route] from show ip route (a "subnetted" heading gives the length its routes leave out)."""
    routes, current, uniform = [], None, None
    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        heading = SUBNETTED.match(line)
        if heading:
            uniform = None if heading.group(2) else int(heading.group(1))
            current = None
            continue
        found = ROUTE_LINE.match(line) if not line[0].isspace() else None
        if found:
            code, address, length, rest = found.groups()
            if length is None:
                length = uniform if uniform is not None else classful(address)
            letters = re.match(r"[A-Za-z]+", code.split("*")[0].strip())
            current = Route(f"{address}/{length}", letters.group(0) if letters else code.strip())
            route_details(current, rest)
            routes.append(current)
            if code.strip()[:1] in ("C", "L"):
                current.distance = 0
        elif line[0].isspace() and current is not None:
            route_details(current, line)
        else:
            current = None
    return routes


def route_details(route, text):
    distance = DISTANCE.search(text)
    if distance and not route.distance:
        route.distance = int(distance.group(1))
    for hop in re.findall(r"via (\d+\.\d+\.\d+\.\d+)", text):
        if hop not in route.next_hops:
            route.next_hops.append(hop)
    port = re.search(r"directly connected, (\S+)", text) or \
        re.search(r"via \d+\.\d+\.\d+\.\d+(?:,\s*[\dwdhms:.]+)?,\s*([A-Za-z][\w./:-]*\d)\s*$", text)
    if port and port.group(1) not in route.interfaces:
        route.interfaces.append(port.group(1))


def parse_device(running, routes_text="", version=""):
    """DeviceVpns from show running-config (and show ip route, show version)."""
    from . import acl
    device = DeviceVpns(read=True, tree=parse_tree(running), acls=acl.parse_running(running), version=version)
    device.hostname = device.acls.hostname
    device.routes = parse_routes(routes_text)
    device.xe = is_xe(version) if version else True
    return device


def is_xe(version):
    text = version or ""
    if re.search(r"IOS[ -]XE", text):
        return True
    found = re.search(r"Version (\d+)\.", text)
    return bool(found and int(found.group(1)) >= 16)


# ----------------------------------------------------------------- Suggestions for a new VPN

def suggest_subnet(vpn, devices, taken=()):
    """A tunnel subnet (/30 point-to-point, /24 DMVPN) from 172.31.0.0/16 that no member has an address in, and that
    isn't one of taken (other VPNs' subnets)."""
    length = 30 if vpn.kind in POINT_TO_POINT else 24
    used = []
    for device in devices:
        if device is not None:
            used += [item.network for item in device.networks()]
            for route in device.routes:
                try:
                    network = ipaddress.IPv4Network(route.prefix, strict=False)
                except ValueError:
                    continue
                if network.prefixlen > 0 and network.overlaps(TUNNEL_POOL):
                    used.append(network)
    for item in taken:
        try:
            used.append(ipaddress.IPv4Network(item, strict=False))
        except ValueError:
            pass
    for candidate in TUNNEL_POOL.subnets(new_prefix=length):
        if not any(candidate.overlaps(item) for item in used):
            return str(candidate)
    return ""


def suggest_tunnel(devices, start=10):
    """A tunnel number free on every device (so the VPN has the same number everywhere)."""
    taken = set()
    for device in devices:
        if device is not None:
            taken |= device.tunnel_numbers()
    number = start
    while number in taken:
        number += 1
    return number


def assign_addresses(vpn):
    """Give members without a tunnel address the next free ones in the subnet (hubs first)."""
    try:
        network = ipaddress.IPv4Network(vpn.subnet, strict=False)
    except ValueError:
        return
    taken = {member.tunnel_ip for member in vpn.members if member.tunnel_ip}
    hosts = (str(host) for host in network.hosts())
    ordered = vpn.hubs() + [member for member in vpn.members if member.role != HUB]
    for member in ordered:
        if member.tunnel_ip:
            continue
        for host in hosts:
            if host not in taken:
                member.tunnel_ip = host
                taken.add(host)
                break


def wan_choices(device):
    """[(interface, address)] that could be a WAN interface (an address, not a tunnel or loopback)."""
    found = []
    for name, interface in (device.interfaces() if device is not None else {}).items():
        if re.match(r"(?i)(tunnel|loopback|nve|vasi)", name) or not interface.addresses:
            continue
        found.append((name, interface.addresses[0][0]))
    return found


def wan_toward(device, address):
    """The interface a router reaches an address through (its WAN toward a peer), or ""."""
    route = device.route_to(address) if device is not None else None
    if route is None:
        return ""
    if route.interfaces:
        return full_interface(route.interfaces[0])
    for hop in route.next_hops:
        for name, interface in device.interfaces().items():
            for own, length in interface.addresses:
                if ipaddress.IPv4Address(hop) in ipaddress.IPv4Interface(f"{own}/{length}").network:
                    return name
    return ""


def wan_between(device, others):
    """A router's WAN interface toward the other routers: the one its most specific route to any of their WAN
    addresses goes out of (a default route only when nothing better is known), or ""."""
    best, best_length = "", -1
    for other in others:
        for _, address in wan_choices(other):
            route = device.route_to(address) if device is not None else None
            if route is None:
                continue
            length = ipaddress.IPv4Network(route.prefix, strict=False).prefixlen
            interface = wan_toward(device, address)
            if interface and length > best_length and \
                    not interface.lower().startswith(("loopback", "tunnel", "null")):
                best, best_length = interface, length
    return best


# ----------------------------------------------------------------- Names

def names(vpn, member):
    """The names of a member's objects: its own (found on the router) over the VPN's usual ones."""
    base = vpn.base
    usual = {"proposal": f"{base}-PROP", "policy": f"{base}-POL", "keyring": f"{base}-KEYS",
             "ike_profile": f"{base}-IKE", "transform": f"{base}-TS", "ipsec_profile": f"{base}-IPSEC",
             "map": f"{base}-MAP", "map_seq": "10", "acl": f"{base}-ACL", "isakmp_policy": "",
             "cert_map": f"{base}-CMAP", "prefix_list": f"{base}-OUT", "peer_group": f"{base}-SPOKES",
             "trustpoint": vpn.auth.trustpoint or f"{base}-TP"}
    usual.update({key: value for key, value in member.names.items() if value})
    return usual


def crypto_map_for(vpn, member, device):
    """(map name, sequence, shared) for a member's crypto map entry: the map its WAN interface has already (an
    interface takes one map, so another VPN's entries share it), at a free number, else the VPN's own map. shared:
    other entries are in the map (so the interface keeps it when this VPN goes)."""
    usual = names(vpn, member)
    if member.names.get("map"):
        name, seq = member.names["map"], str(member.names.get("map_seq") or "10")
        return name, seq, any(block.line.split()[3] != seq for block in (device.blocks(f"crypto map {name}")
                                                                          if device is not None else [])
                              if len(block.line.split()) > 3 and block.line.split()[3].isdigit())
    interface = device.block(f"interface {full_interface(member.wan)}") if device is not None and member.wan else None
    applied = next((child.line.split()[2] for child in interface.children
                    if child.line.startswith("crypto map ") and len(child.line.split()) > 2), "") \
        if interface is not None else ""
    name = applied or usual["map"]
    taken, mine = set(), ""
    for block in device.blocks(f"crypto map {name}") if device is not None else []:
        words = block.line.split()
        if len(words) > 3 and words[3].isdigit():
            taken.add(int(words[3]))
            if f"description {vpn.description or vpn.name} (NOMAD)" in [child.line for child in block.children]:
                mine = words[3]  # This VPN's entry already
    if mine:
        return name, mine, len(taken) > 1
    number = 10
    while number in taken:
        number += 10
    return name, str(number), bool(taken)


def peer_name(member):
    return safe_name(member.label or member.address or member.key, 30)


# ----------------------------------------------------------------- Each member's footprint

def mask_of(length):
    return str(ipaddress.IPv4Network(f"0.0.0.0/{length}").netmask)


def wildcard_of(length):
    return str(ipaddress.IPv4Address(int(ipaddress.IPv4Network(f"0.0.0.0/{length}").hostmask)))


def network_words(prefix):
    """("10.1.1.0", "255.255.255.0") of a prefix (of a placeholder "<A-LAN>": "<A-LAN-NETWORK>", "<A-LAN-MASK>")."""
    if is_placeholder(prefix):
        return derived(prefix, "NETWORK"), derived(prefix, "MASK")
    network = ipaddress.IPv4Network(prefix, strict=False)
    return str(network.network_address), str(network.netmask)


def network_wildcard(prefix):
    """("10.1.1.0", "0.0.0.255") of a prefix (of a placeholder: its -NETWORK and -WILDCARD)."""
    if is_placeholder(prefix):
        return derived(prefix, "NETWORK"), derived(prefix, "WILDCARD")
    network = ipaddress.IPv4Network(prefix, strict=False)
    return str(network.network_address), str(network.hostmask)


def esp_mode(vpn):
    if vpn.crypto.mode:
        return vpn.crypto.mode
    return TRANSPORT if vpn.kind in (GRE_IPSEC, DMVPN) else TUNNEL


def proposal_block(vpn, name):
    crypto = vpn.crypto
    block = Block(f"crypto ikev2 proposal {name}")
    block.children.append(Block("encryption " + " ".join(crypto.encryption)))
    if crypto.gcm():
        block.children.append(Block("prf " + " ".join(crypto.prf or ["sha384"])))
    else:
        block.children.append(Block("integrity " + " ".join(crypto.integrity or ["sha256"])))
    block.children.append(Block("group " + " ".join(str(group) for group in crypto.groups)))
    return block


def isakmp_policy_children(vpn):
    crypto = vpn.crypto
    children = [Block("encryption " + (crypto.encryption[0] if crypto.encryption else "aes 256")),
                Block("hash " + (crypto.integrity[0] if crypto.integrity else "sha256")),
                Block("authentication " + ("rsa-sig" if vpn.auth.method == CERT else "pre-share")),
                Block("group " + str(crypto.groups[0] if crypto.groups else 14))]
    if crypto.ike_lifetime != 86400:
        children.append(Block(f"lifetime {crypto.ike_lifetime}"))
    return children


def isakmp_policy_number(vpn, device):
    """An IKEv1 policy for the VPN's crypto: (number, whether it's there already). One with the same settings is
    used as it is."""
    wanted = {child.line for child in isakmp_policy_children(vpn)}
    numbers = []
    for block in device.blocks("crypto isakmp policy") if device is not None else []:
        words = block.line.split()
        if len(words) > 3 and words[3].isdigit():
            numbers.append(int(words[3]))
            have = {child.line for child in block.children if child.line != "lifetime 86400"}
            if have == wanted:
                return int(words[3]), True
    number = 10
    while number in numbers:
        number += 10
    return number, False


def ikev2_policy_for(device, local_ip):
    """An IKEv2 policy already on the router that a negotiation on local_ip uses (its line), or ""."""
    catch_all = ""
    for block in device.blocks("crypto ikev2 policy") if device is not None else []:
        matches = [child.line for child in block.children if child.line.startswith("match address local ")]
        if local_ip and any(line.split()[-1] == local_ip for line in matches):
            return block.line
        if not [child for child in block.children if child.line.startswith("match ")] and \
                block.line.split()[-1] != "default":
            catch_all = catch_all or block.line
    return catch_all


def tunnel_ip_line(vpn, member):
    return f"ip address {member.tunnel_ip} {vpn.netmask()}" if member.tunnel_ip else ""


def shares_source(vpn, member, device, extra=()):
    """Whether another multipoint GRE tunnel on the router has the same tunnel source (so this one needs a key)."""
    wanted = {member.wan.lower(), full_interface(member.wan).lower(), member.local_ip}
    mine = f"interface Tunnel{member.tunnel}".lower()
    candidates = list(device.blocks("interface Tunnel")) if device is not None else []
    candidates += list(extra)
    for block in candidates:
        if block.line.lower() == mine:
            continue
        lines = [child.line for child in block.children]
        if "tunnel mode gre multipoint" not in lines:
            continue
        source = next((line.split(None, 2)[2] for line in lines if line.startswith("tunnel source ")), "")
        if source.lower() in wanted or full_interface(source).lower() in wanted:
            return True
    return False


def routing_signature(vpn, member):
    """What a member's routing lines are made from (when it's unchanged, the lines found on the router are kept as
    they are, however they were written)."""
    return json.dumps([vpn.kind, vpn.routing.kind, vpn.routing.process, vpn.routing.area, vpn.routing.eigrp_name,
                       vpn.dmvpn.phase, member.role, member.tunnel_ip,
                       sorted([item.key, item.role, item.tunnel_ip, item.reached_at, sorted(item.lans)]
                              for item in vpn.members)])


def routing_for(vpn, member, device):
    """(blocks, interface lines): the member's routing configuration, and lines for its tunnel interface."""
    kept = member.names.get("routing_lines")
    if kept is not None and member.names.get("routing_sig") == routing_signature(vpn, member):
        blocks = parse_tree("\n".join(kept))
        for block in blocks:
            block.partial = block.line.startswith("router ")
            for child in block.children:
                child.partial = bool(child.children) and child.line.startswith("address-family")
        if vpn.routing.kind == BGP and vpn.routing.guard and device is not None:
            local_as = device.bgp_as()
            process = next((block for block in blocks if block.line == f"router bgp {local_as}"), None)
            if process is not None:
                target = next((child for child in process.children if child.line == "address-family ipv4"),
                              process)
                blocks = bgp_guard(vpn, member, device, local_as, process, target) + blocks
        return blocks, list(member.names.get("routing_tunnel_lines") or [])
    kind = vpn.routing.kind
    blocks, tunnel_lines = [], []
    tunnel_name = f"Tunnel{member.tunnel}"
    others = vpn.others(member)
    hub_ips = [hub.tunnel_ip for hub in vpn.hubs() if hub.key != member.key and hub.tunnel_ip]
    if kind == STATIC:
        for other in others:
            if vpn.kind == CRYPTO_MAP:
                hop = wan_next_hop(device, other.reached_at)
                if not hop:
                    continue
                for prefix in other.lans:
                    address, netmask = network_words(prefix)
                    if not covered_by_route(device, prefix, hop):
                        blocks.append(Block(f"ip route {address} {netmask} {hop}"))
                continue
            if vpn.kind == DMVPN and member.role == SPOKE and other.role == SPOKE and vpn.dmvpn.phase != 2:
                hops = hub_ips  # Phase 1 and 3: through the hub (phase 3 then shortcuts it)
            elif vpn.kind == DMVPN and member.role == SPOKE and other.role == SPOKE:
                hops = [other.tunnel_ip]
            else:
                hops = [other.tunnel_ip]
            for prefix in other.lans:
                address, netmask = network_words(prefix)
                for number, hop in enumerate(hop for hop in hops if hop):
                    distance = "" if number == 0 else f" {number + 1}"  # A second hub as a floating route
                    blocks.append(Block(f"ip route {address} {netmask} {hop}{distance}"))
        return blocks, tunnel_lines
    if kind in (EIGRP, OSPF) and vpn.kind == CRYPTO_MAP:
        return blocks, tunnel_lines  # Routing protocols don't cross a crypto map (no tunnel interface)
    own = [f"{member.tunnel_ip} 0.0.0.0"] if member.tunnel_ip else []  # "address wildcard" network statements
    for prefix in member.lans:
        if device is not None:
            address = device.interface_in(prefix)[1]
            if address:
                own.append(f"{address} 0.0.0.0")
        else:  # A router NOMAD doesn't read (lines to copy): the LAN itself
            own.append(" ".join(network_wildcard(prefix)))
    if kind == EIGRP:
        number = vpn.routing.process or "100"
        if vpn.routing.eigrp_name:
            af = Block(f"address-family ipv4 unicast autonomous-system {number}", partial=True)
            af.children += [Block(f"network {item}") for item in own]
            if vpn.kind == DMVPN and member.role == HUB:
                af_if = Block(f"af-interface {tunnel_name}")
                af_if.children.append(Block("no split-horizon"))
                if vpn.dmvpn.phase == 2:
                    af_if.children.append(Block("no next-hop-self"))
                af.children.append(af_if)
            blocks.append(Block(f"router eigrp {vpn.routing.eigrp_name}", [af], partial=True))
        else:
            blocks.append(Block(f"router eigrp {number}", [Block(f"network {item}") for item in own],
                                partial=True))
            if vpn.kind == DMVPN and member.role == HUB:
                tunnel_lines.append(f"no ip split-horizon eigrp {number}")
                if vpn.dmvpn.phase == 2:
                    tunnel_lines.append(f"no ip next-hop-self eigrp {number}")
    elif kind == OSPF:
        number = vpn.routing.process or "100"
        area = vpn.routing.area or "0"
        blocks.append(Block(f"router ospf {number}", [Block(f"network {item} area {area}") for item in own],
                            partial=True))
        if vpn.kind == DMVPN:
            if vpn.dmvpn.phase == 2:
                tunnel_lines.append("ip ospf network broadcast")
                tunnel_lines.append(f"ip ospf priority {(256 - (member.hub_order or 1)) if member.role == HUB else 0}")
            else:
                tunnel_lines.append("ip ospf network point-to-multipoint")
    elif kind == BGP:
        blocks += bgp_blocks(vpn, member, device)
    return blocks, tunnel_lines


def wan_next_hop(device, peer):
    """The next hop a router sends a peer's traffic to (for routes to the far LANs out of a crypto map), or ""."""
    route = device.route_to(peer) if device is not None else None
    if route is not None and route.next_hops:
        return route.next_hops[0]
    return ""


def covered_by_route(device, prefix, hop):
    """Whether a router already sends a prefix to hop (so no static route is needed)."""
    if device is None:
        return False
    network = ipaddress.IPv4Network(prefix, strict=False)
    route = device.route_to(str(network.network_address))
    return route is not None and hop in route.next_hops and \
        ipaddress.IPv4Network(route.prefix, strict=False).prefixlen <= network.prefixlen


GUARD_LIST = "NOMAD-VPN-GUARD"


def bgp_neighbors(process):
    """{neighbor: {"remote-as", "peer-group", "out": [filter lines]}} of a router bgp block (and its IPv4 address
    family), peer groups' settings included in their members'."""
    found = {}
    lines = [child.line for child in process.children]
    for child in process.children:
        if child.line.startswith("address-family ipv4") and "vrf" not in child.line:
            lines += [item.line for item in child.children]
    for line in lines:
        words = line.split()
        if len(words) < 3 or words[0] != "neighbor":
            continue
        entry = found.setdefault(words[1], {"remote-as": "", "peer-group": "", "out": [], "group": False})
        if words[2] == "remote-as" and len(words) > 3:
            entry["remote-as"] = words[3]
        elif words[2] == "peer-group":
            if len(words) > 3:
                entry["peer-group"] = words[3]
            else:
                entry["group"] = True
        elif words[-1] == "out" and words[2] in ("prefix-list", "route-map", "filter-list", "distribute-list"):
            entry["out"].append(line)
    for entry in found.values():
        group = found.get(entry["peer-group"]) if entry["peer-group"] else None
        if group is not None:
            entry["remote-as"] = entry["remote-as"] or group["remote-as"]
            entry["out"] = entry["out"] or group["out"]
    return found


def bgp_guard(vpn, member, device, local_as, process, target):
    """Blocks keeping the VPN's LANs from the router's other eBGP neighbors (an ISP would otherwise be told them):
    deny entries in each one's outbound prefix list, or NOMAD's guard list put on it. Neighbors filtered with a
    route map or filter list are left (vpncheck says so)."""
    existing = device.block(f"router bgp {local_as}") if device is not None else None
    if existing is None:
        return []
    lans = []
    for item in vpn.members:
        lans += [prefix for prefix in item.lans if prefix not in lans]
    if not lans:
        return []
    tunnel_peers = {item.tunnel_ip for item in vpn.members if item.tunnel_ip}
    blocks = []
    lists = {}
    for neighbor, entry in bgp_neighbors(existing).items():
        if entry["group"] or neighbor in tunnel_peers or not entry["remote-as"] or entry["remote-as"] == local_as:
            continue
        if not ipaddress_like(neighbor) or in_subnet(neighbor, vpn.subnet):
            continue
        out = entry["out"]
        if any(" route-map " in line or " filter-list " in line or " distribute-list " in line for line in out):
            continue
        prefix_out = next((line.split()[3] for line in out if " prefix-list " in line), "")
        if prefix_out:
            lists.setdefault(prefix_out, False)
        else:
            lists.setdefault(GUARD_LIST, False)
            who = entry["peer-group"] or neighbor  # IOS takes a peer group member's filters only on its group
            line = f"neighbor {who} prefix-list {GUARD_LIST} out"
            if not any(child.line == line for child in target.children):
                target.children.insert(0, Block(line, sticky=True))
    for name in lists:
        entries = [block.line for block in device.blocks(f"ip prefix-list {name} seq")]
        taken = sorted(int(line.split()[4]) for line in entries if len(line.split()) > 4 and line.split()[4].isdigit())
        there = {}  # A LAN already denied (by this VPN before): keeps its number
        for line in entries:
            words = line.split()
            if len(words) >= 7 and words[5] == "deny":
                there[words[6]] = line
        missing = [prefix for prefix in lans if prefix not in there]
        low = min([int(line.split()[4]) for line in entries if " permit " in line] or [1000])
        seqs = free_below(low, len(missing), taken)
        for prefix in lans:
            if prefix in there:
                blocks.append(Block(there[prefix]))
        for seq, prefix in zip(seqs, missing):
            longer = " le 32" if not prefix.endswith("/32") else ""  # IOS refuses le 32 on a /32
            blocks.append(Block(f"ip prefix-list {name} seq {seq} deny {prefix}{longer}"))
        if name == GUARD_LIST and not any(" permit " in line for line in entries):
            blocks.append(Block(f"ip prefix-list {GUARD_LIST} seq 1000 permit 0.0.0.0/0 le 32", sticky=True))
    return blocks


def free_below(low, count, taken):
    """Up to count free sequence numbers just below low (so the denies come before the list's first entry)."""
    numbers = [number for number in range(low - 1, 0, -1) if number not in taken][:count]
    return sorted(numbers)


def ipaddress_like(text):
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def in_subnet(address, subnet):
    try:
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return False


def bgp_blocks(vpn, member, device):
    """The member's BGP: neighbors over the tunnel, its LANs as network statements, a prefix list so only the VPN's
    LANs go over it, and (vpn.routing.guard) the VPN's LANs kept from its other eBGP neighbors."""
    name = names(vpn, member)
    local_as = (device.bgp_as() if device is not None else "") or member.bgp_as
    if not local_as:
        return []
    plist = name["prefix_list"]
    advertise = list(member.lans)
    if member.role == HUB:
        for other in vpn.members:
            advertise += [prefix for prefix in other.lans if prefix not in advertise]
    blocks = [Block(f"ip prefix-list {plist} seq {5 * (number + 1)} permit {prefix}")
              for number, prefix in enumerate(advertise)]
    if not blocks:
        blocks.append(Block(f"ip prefix-list {plist} seq 5 deny 0.0.0.0/0 le 32"))
    process = Block(f"router bgp {local_as}", partial=True)
    target = process
    existing = device.block(f"router bgp {local_as}") if device is not None else None
    if existing is not None and existing.child("address-family ipv4") is not None:
        target = Block("address-family ipv4", partial=True)
        process.children.append(target)
    if vpn.routing.guard:
        blocks += bgp_guard(vpn, member, device, local_as, process, target)
    neighbor_lines, af_lines = [], []
    if vpn.kind == DMVPN and member.role == HUB:
        group = name["peer_group"]
        spokes = [spoke for spoke in vpn.spokes() if spoke.bgp_as]
        ases = sorted({spoke.bgp_as for spoke in spokes}, key=lambda value: (len(value), value))
        neighbor_lines.append(f"neighbor {group} peer-group")
        if ases:
            remote = f"neighbor {group} remote-as {ases[0]}"
            if len(ases) > 1:
                remote += " alternate-as " + " ".join(ases[1:6])
            neighbor_lines.append(remote)
        neighbor_lines.append(f"bgp listen range {vpn.subnet} peer-group {group}")
        if ases == [local_as]:
            af_lines.append(f"neighbor {group} route-reflector-client")
        af_lines.append(f"neighbor {group} prefix-list {plist} out")
        for hub in vpn.hubs():
            if hub.key != member.key and hub.tunnel_ip and hub.bgp_as:
                neighbor_lines.append(f"neighbor {hub.tunnel_ip} remote-as {hub.bgp_as}")
                af_lines.append(f"neighbor {hub.tunnel_ip} prefix-list {plist} out")
    else:
        peers = vpn.hubs() if vpn.kind == DMVPN else vpn.others(member)
        for other in peers:
            if other.key == member.key or not other.tunnel_ip or not other.bgp_as:
                continue
            neighbor_lines.append(f"neighbor {other.tunnel_ip} remote-as {other.bgp_as}")
            af_lines.append(f"neighbor {other.tunnel_ip} prefix-list {plist} out")
            if target is not process:
                af_lines.insert(len(af_lines) - 1, f"neighbor {other.tunnel_ip} activate")
    networks = []
    for prefix in member.lans:
        address, netmask = network_words(prefix)
        networks.append(f"network {address} mask {netmask}")
    at = len([child for child in process.children if child.sticky])
    process.children[at:at] = [Block(line) for line in neighbor_lines]
    target.children += [Block(line) for line in networks + af_lines]
    return blocks + [process]


def footprint(vpn, member, device, siblings=(), xe=None):
    """[Block]: everything a member needs for the VPN (partial and sticky set on what's shared). siblings: tunnel
    interface blocks of other VPNs being made on the same router (for the tunnel key a shared source needs). xe:
    whether it runs IOS XE (None: as read; True without a router)."""
    name = names(vpn, member)
    if xe is None:
        xe = device.xe if device is not None else True
    blocks = []
    crypto = vpn.crypto
    certificates = vpn.auth.method == CERT
    others = vpn.others(member)
    if vpn.protected:
        if crypto.ike == IKEV2:
            if name["proposal"] != "default":  # "default": found using IOS's default proposal (left as it is)
                blocks.append(proposal_block(vpn, name["proposal"]))
                existing = ikev2_policy_for(device, member.local_ip)
                policy = Block(existing or f"crypto ikev2 policy {name['policy']}", partial=True)
                if not existing and member.local_ip:
                    policy.children.append(Block(f"match address local {member.local_ip}", sticky=True))
                policy.children.append(Block(f"proposal {name['proposal']}"))
                blocks.append(policy)
            if certificates:
                blocks.append(Block(f"crypto pki certificate map {name['cert_map']} 10",
                                    [Block(f"issuer-name co cn = {vpn.auth.ca_name.lower()}")]))
            else:
                keyring = Block(f"crypto ikev2 keyring {name['keyring']}")
                local = own_key(vpn, member)
                if vpn.kind == DMVPN:
                    keyring.children.append(Block(f"peer {name.get('peer:*') or 'ANY'}", [
                        Block("address 0.0.0.0 0.0.0.0")] + [
                        Block(line) for line in ikev2_key_lines(local, remote_key(vpn, member))]))
                else:
                    for other in others:
                        remote = member.psk_remote or own_key(vpn, other)
                        keyring.children.append(Block(f"peer {name.get('peer:' + other.key) or peer_name(other)}", [
                            Block(f"address {other.reached_at}")] + [
                            Block(line) for line in ikev2_key_lines(local, remote)]))
                blocks.append(keyring)
            profile = Block(f"crypto ikev2 profile {name['ike_profile']}")
            if not vpn.found:  # Only on what NOMAD builds (one found keeps its own, if any)
                profile.children.append(Block(f"description {vpn.description or vpn.name} (NOMAD)"))
            if certificates:
                profile.children.append(Block(f"match certificate {name['cert_map']}"))
                profile.children.append(Block("identity local dn"))
            elif vpn.kind == DMVPN:
                profile.children.append(Block("match identity remote address 0.0.0.0"))
                if member.local_ip:  # Any peer: tell this profile from another cloud's by the address it's on
                    profile.children.append(Block(f"match address local {member.local_ip}"))
            else:
                for other in others:
                    profile.children.append(Block(f"match identity remote address {other.local_ip or other.reached_at}"
                                                  f" 255.255.255.255"))
            method = "rsa-sig" if certificates else "pre-share"
            profile.children.append(Block(f"authentication remote {method}"))
            profile.children.append(Block(f"authentication local {method}"))
            if certificates:
                profile.children.append(Block(f"pki trustpoint {name['trustpoint']}"))
            else:
                profile.children.append(Block(f"keyring local {name['keyring']}"))
            if crypto.dpd:
                profile.children.append(Block(f"dpd {crypto.dpd} {crypto.dpd_retry} "
                                              f"{'periodic' if crypto.dpd_periodic else 'on-demand'}"))
            blocks.append(profile)
            if crypto.nat_keepalive:
                blocks.append(Block(f"crypto ikev2 nat keepalive {crypto.nat_keepalive}", sticky=True))
        else:
            if name["isakmp_policy"] != "default":  # "default": found using IOS's default policies
                number, there = isakmp_policy_number(vpn, device)
                name["isakmp_policy"] = name["isakmp_policy"] or str(number)
                policy = Block(f"crypto isakmp policy {name['isakmp_policy']}", isakmp_policy_children(vpn))
                policy.sticky = there  # One with the same settings already there stays
                blocks.append(policy)
            if certificates:
                blocks.append(Block(f"crypto pki certificate map {name['cert_map']} 10",
                                    [Block(f"issuer-name co cn = {vpn.auth.ca_name.lower()}")]))
            elif name["ike_profile"] == "-":  # Found with global keys and no ISAKMP profile: kept that way
                targets = ["0.0.0.0"] if vpn.kind == DMVPN else [other.reached_at for other in others]
                blocks += [Block(f"crypto isakmp key {own_key(vpn, member)} address {target}") for target in targets]
            else:
                keyring = Block(f"crypto keyring {name['keyring']}")
                if vpn.kind == DMVPN:
                    keyring.children.append(Block(f"pre-shared-key address 0.0.0.0 0.0.0.0 key "
                                                  f"{own_key(vpn, member)}"))
                else:
                    for other in others:
                        keyring.children.append(Block(f"pre-shared-key address {other.reached_at} key "
                                                      f"{own_key(vpn, member)}"))
                blocks.append(keyring)
            profile = Block(f"crypto isakmp profile {name['ike_profile']}")
            if name["ike_profile"] == "-":
                profile = None
            elif certificates:
                profile.children.append(Block(f"ca trust-point {name['trustpoint']}"))
                profile.children.append(Block(f"match certificate {name['cert_map']}"))
            else:
                profile.children.append(Block(f"keyring {name['keyring']}"))
                if vpn.kind == DMVPN:
                    profile.children.append(Block("match identity address 0.0.0.0"))
                    if member.wan:
                        profile.children.append(Block(f"local-address {full_interface(member.wan)}"))
                else:
                    for other in others:
                        profile.children.append(Block(f"match identity address {other.local_ip or other.reached_at}"
                                                      f" 255.255.255.255"))
            if profile is not None:
                if crypto.dpd:
                    profile.children.append(Block(f"keepalive {crypto.dpd} retry {crypto.dpd_retry}"))
                blocks.append(profile)
            if crypto.nat_keepalive:
                blocks.append(Block(f"crypto isakmp nat keepalive {crypto.nat_keepalive}", sticky=True))
        defaults = name["transform"] == "default"  # Found using IOS's default transform sets: left as they are
        if not defaults:
            blocks.append(Block(f"crypto ipsec transform-set {name['transform']} {crypto.esp}",
                                [Block(f"mode {esp_mode(vpn)}")]))
        profile_word = "ikev2-profile" if crypto.ike == IKEV2 else "isakmp-profile"
        if vpn.kind != CRYPTO_MAP:
            ipsec = Block(f"crypto ipsec profile {name['ipsec_profile']}", [
                Block(f"set transform-set {name['transform']}")] if not defaults else [])
            if crypto.pfs:
                ipsec.children.append(Block(f"set pfs group{crypto.pfs}"))
            if name["ike_profile"] != "-":
                ipsec.children.append(Block(f"set {profile_word} {name['ike_profile']}"))
            if crypto.sa_lifetime != 3600:
                ipsec.children.append(Block(f"set security-association lifetime seconds {crypto.sa_lifetime}"))
            blocks.append(ipsec)
    if vpn.kind == CRYPTO_MAP:
        name["map"], name["map_seq"], shared_map = crypto_map_for(vpn, member, device)
        acl = Block(f"ip access-list extended {name['acl']}")
        number = 10
        for prefix in member.lans:
            for other in others:
                for far in other.lans:
                    source, source_wildcard = network_wildcard(prefix)
                    target, target_wildcard = network_wildcard(far)
                    acl.children.append(Block(f"{number} permit ip {source} {source_wildcard} {target} "
                                              f"{target_wildcard}"))
                    number += 10
        blocks.append(acl)
        entry = Block(f"crypto map {name['map']} {name['map_seq']} ipsec-isakmp")
        if not vpn.found:
            entry.children.append(Block(f"description {vpn.description or vpn.name} (NOMAD)"))
        for other in others:
            entry.children.append(Block(f"set peer {other.reached_at}"))
        if name["transform"] != "default":
            entry.children.append(Block(f"set transform-set {name['transform']}"))
        if crypto.pfs:
            entry.children.append(Block(f"set pfs group{crypto.pfs}"))
        if name["ike_profile"] != "-":
            entry.children.append(Block(f"set {'ikev2-profile' if crypto.ike == IKEV2 else 'isakmp-profile'} "
                                        f"{name['ike_profile']}"))
        if crypto.sa_lifetime != 3600:
            entry.children.append(Block(f"set security-association lifetime seconds {crypto.sa_lifetime}"))
        entry.children.append(Block(f"match address {name['acl']}"))
        blocks.append(entry)
        if member.wan:
            blocks.append(Block(f"interface {full_interface(member.wan)}", [Block(f"crypto map {name['map']}",
                                                                                 sticky=shared_map)], partial=True))
    else:
        blocks.append(tunnel_block(vpn, member, device, xe, name, siblings))
    routing, tunnel_lines = routing_for(vpn, member, device)
    if tunnel_lines:
        tunnel = next(block for block in blocks if block.line == f"interface Tunnel{member.tunnel}")
        insert_at = next((at for at, child in enumerate(tunnel.children) if child.line.startswith("tunnel ")),
                         len(tunnel.children))
        tunnel.children[insert_at:insert_at] = [Block(line) for line in tunnel_lines]
    blocks += routing
    shared = set(member.names.get("shared") or ())
    if shared:  # Objects other VPNs use too: a keyring or ACL loses only this VPN's entries; the rest stay put
        partial = {key_of(f"crypto ikev2 keyring {name['keyring']}"), key_of(f"crypto keyring {name['keyring']}"),
                   key_of(f"ip access-list extended {name['acl']}")}
        kinds = {"proposal": f"crypto ikev2 proposal {name['proposal']}",
                 "transform": f"crypto ipsec transform-set {name['transform']}",
                 "ipsec_profile": f"crypto ipsec profile {name['ipsec_profile']}",
                 "cert_map": f"crypto pki certificate map {name['cert_map']} 10"}
        sticky = {key_of(line) for kind, line in kinds.items() if kind in shared}
        if "ike_profile" in shared:
            sticky |= {key_of(f"crypto ikev2 profile {name['ike_profile']}"),
                       key_of(f"crypto isakmp profile {name['ike_profile']}")}
        partial = {key for key in partial if any(word in key for word in ("keyring", "access-list")) and
                   (("keyring" in key and "keyring" in shared) or ("access-list" in key and "acl" in shared))}
        for block in blocks:
            if key_of(block.line) in sticky:
                block.sticky = True
            elif key_of(block.line) in partial:
                block.partial = True
    return blocks


def tunnel_block(vpn, member, device, xe, name, siblings=()):
    block = Block(f"interface Tunnel{member.tunnel}")
    add = block.children.append
    if not vpn.found:
        add(Block(f"description {vpn.description or vpn.name} {KIND_NAMES[vpn.kind]} (NOMAD)"))
    if member.tunnel_ip:
        add(Block(tunnel_ip_line(vpn, member)))
    if vpn.kind == DMVPN:
        add(Block("no ip redirects"))
    if vpn.mtu:
        add(Block(f"ip mtu {vpn.mtu}"))
    if vpn.kind == DMVPN:
        settings = vpn.dmvpn
        if settings.auth:
            add(Block(f"ip nhrp authentication {settings.auth[:8]}"))
        if member.role == HUB:
            add(Block("ip nhrp map multicast dynamic"))
        add(Block(f"ip nhrp network-id {settings.network_id or member.tunnel}"))
        if settings.holdtime:
            add(Block(f"ip nhrp holdtime {settings.holdtime}"))
        for hub in vpn.hubs():
            if hub.key == member.key or not hub.tunnel_ip:
                continue
            if member.role == SPOKE or settings.phase != 1:
                add(Block(f"ip nhrp nhs {hub.tunnel_ip} nbma {hub.reached_at} multicast"))
        if settings.phase == 3:
            if member.role == HUB:
                add(Block("ip nhrp redirect"))
            if member.role == SPOKE or len(vpn.hubs()) > 1:
                if not xe:
                    add(Block("ip nhrp shortcut"))
    if vpn.mss:
        add(Block(f"ip tcp adjust-mss {vpn.mss}"))
    if member.wan:
        add(Block(f"tunnel source {full_interface(member.wan)}"))
    if vpn.kind == VTI:
        add(Block("tunnel mode ipsec ipv4"))
    elif vpn.kind == DMVPN and not (vpn.dmvpn.phase == 1 and member.role == SPOKE):
        add(Block("tunnel mode gre multipoint"))
    if vpn.kind in POINT_TO_POINT:
        other = next(iter(vpn.others(member)), None)
        if other is not None and other.reached_at:
            add(Block(f"tunnel destination {other.reached_at}"))
    elif vpn.kind == DMVPN and vpn.dmvpn.phase == 1 and member.role == SPOKE:
        hub = next(iter(vpn.hubs()), None)
        if hub is not None and hub.reached_at:
            add(Block(f"tunnel destination {hub.reached_at}"))
    if vpn.kind == DMVPN:
        if vpn.dmvpn.tunnel_key:  # Set (keyed()) when a router's WAN has another cloud's tunnel on it
            add(Block(f"tunnel key {vpn.dmvpn.tunnel_key}"))
    if vpn.kind == GRE and vpn.keepalive:
        add(Block(f"keepalive {vpn.keepalive} 3"))
    if vpn.protected:
        add(Block(f"tunnel protection ipsec profile {name['ipsec_profile']}"))
    return block


# ----------------------------------------------------------------- Planning the change

# The order objects go in (and, reversed, the order they're removed): what something uses first
RANKS = [("crypto ikev2 nat", 0), ("crypto isakmp nat", 0), ("crypto ikev2 proposal", 1),
         ("crypto isakmp policy", 1), ("crypto ikev2 policy", 2), ("crypto ikev2 keyring", 3),
         ("crypto keyring", 3), ("crypto pki certificate map", 3), ("ip access-list", 3), ("ip prefix-list", 3),
         ("crypto ikev2 profile", 4), ("crypto isakmp profile", 4), ("crypto ipsec transform-set", 5),
         ("crypto ipsec profile", 6), ("crypto map", 7), ("interface Tunnel", 8), ("interface", 9),
         ("router", 10), ("ip route", 10)]
# Shared blocks removed once nothing of theirs is left
EMPTY_GOES = ("crypto ikev2 policy", "router eigrp", "router ospf")


def rank(line):
    return next((value for prefix, value in RANKS if line.startswith(prefix)), 5)


def hidden(line, parent_line, xe=True):
    kind = parent_type(parent_line)
    return (kind, line) in HIDDEN_DEFAULTS or (xe and (kind, line) in XE_HIDDEN_DEFAULTS)


def prune_hidden(blocks, xe=True, parent_line=""):
    """Footprint blocks without the lines IOS wouldn't show (so they don't always look changed)."""
    kept = []
    for block in blocks:
        if parent_line and hidden(block.line, parent_line, xe):
            continue
        item = Block(block.line, prune_hidden(block.children, xe, block.line), block.partial, block.sticky)
        kept.append(item)
    return kept


def without(device_block, before):
    """A router's block less the VPN's lines in before (a footprint block as it was): its own lines go, partial
    blocks inside lose the VPN's lines in them, sticky lines stay."""
    children = []
    for child in device_block.children:
        mine = before.child(child.line) if before is not None else None
        if mine is None or mine.sticky:
            children.append(child.copy())
        elif mine.partial and child.children:
            kept = without(child, mine)
            if kept.children or not goes_when_empty(kept):
                children.append(kept)
    return Block(device_block.line, children)


def goes_when_empty(block):
    """Whether a shared block is removed once nothing is left in it (a routing process NOMAD's network statements
    were all of, an IKEv2 policy with no proposal left)."""
    if block.line.startswith("crypto ikev2 policy"):
        return not any(child.line.startswith("proposal ") for child in block.children)
    return not block.children and any(block.line.startswith(prefix) for prefix in EMPTY_GOES + ("address-family",))


def merge(device_block, before, after):
    """What a router's block becomes: its lines, less the VPN's as they were (before's), plus the VPN's as they'll be
    (after's). None when it goes."""
    if after is None:
        if device_block is None:
            return None
        if before is None or before.sticky:
            return device_block.copy()
        if not before.partial:
            return None  # The VPN's own: it goes
        result = without(device_block, before)
        return None if goes_when_empty(result) else result
    if device_block is None:
        return strip_flags(after)
    result = without(device_block, before) if before is not None else device_block.copy()
    if not after.partial:
        result.line = after.line  # A transform set's transforms, say, change in place
    for child in after.children:
        at = next((number for number, item in enumerate(result.children)
                   if key_of(item.line, result.line) == key_of(child.line, result.line)), None)
        if at is None:
            result.children.append(strip_flags(child))
        elif child.partial:
            result.children[at] = merge(result.children[at], None, child)
        else:
            result.children[at] = strip_flags(child)
    return result


def strip_flags(block):
    return Block(block.line, [strip_flags(child) for child in block.children])


def child_lines(before, after, parent_line, depth):
    """The lines that turn a mode's children from before's into after's: removals first (so a tunnel destination
    goes before the tunnel turns multipoint, and an ACL rule's number is free again), then additions and replacements
    in after's order."""
    pad = " " * depth
    before_index = index(before, parent_line)
    after_index = index(after, parent_line)
    removing, adding = [], []
    for key, block in reversed(list(before_index.items())):  # Last in, first out (a peer group's settings first)
        if key not in after_index:
            removing.append(pad + no_form(block.line, parent_line))
    for child in after:
        old = before_index.get(key_of(child.line, parent_line))
        if old is None:
            adding += child.render(depth)
        elif same(old, child):
            continue
        elif not child.children and not old.children:
            adding.append(pad + child.line)  # Replaces the old one in its slot
        else:
            adding.append(pad + child.line)
            adding += child_lines(old.children, child.children, child.line, depth + 1)
    return removing + adding


def same(a, b):
    if a is None or b is None:
        return a is b
    if a.line != b.line or len(a.children) != len(b.children):
        return False
    b_index = index(b.children, b.line)
    return all(same(child, b_index.get(key_of(child.line, a.line))) for child in a.children)


def object_lines(before, after):
    """("make" or "remove", lines) for one top-level object ((None, []) when it's the same)."""
    if before is None and after is None or same(before, after):
        return None, []
    if before is None:
        return "make", after.render()
    if after is None:
        return "remove", [no_form(before.line)]
    lines = child_lines(before.children, after.children, after.line, 1)
    if before.line != after.line or lines:
        return "make", [after.line] + lines
    return None, []


def plan(before_objects, after_objects):
    """Configuration lines turning before_objects ({key: Block or None}) into after_objects: made and changed in
    rank order (what's used before what uses it), then removed in reverse."""
    making, removing = [], []
    keys = list(dict.fromkeys(list(before_objects) + list(after_objects)))
    for order, key in enumerate(keys):
        before, after = before_objects.get(key), after_objects.get(key)
        what, lines = object_lines(before, after)
        if not lines:
            continue
        item = (rank((after or before).line), order, lines)
        (making if what == "make" else removing).append(item)
    making.sort(key=lambda item: (item[0], item[1]))
    removing.sort(key=lambda item: (-item[0], item[1]))
    lines = []
    for _, _, part in making + removing:
        lines += part
    return lines


def states(device, before_footprint, after_footprint):
    """({key: Block or None} before, {key: Block or None} after) of the router's objects a change touches."""
    xe = device.xe if device is not None else True
    before_footprint = prune_hidden(before_footprint, xe)
    after_footprint = prune_hidden(after_footprint, xe)
    before_index = {key_of(block.line): block for block in before_footprint}
    after_index = {key_of(block.line): block for block in after_footprint}
    before_objects, after_objects = {}, {}
    for key in list(dict.fromkeys(list(before_index) + list(after_index))):
        existing = device.block((after_index.get(key) or before_index[key]).line) if device is not None else None
        before_objects[key] = existing
        after_objects[key] = merge(existing, before_index.get(key), after_index.get(key))
    return before_objects, after_objects


@dataclass
class MemberChange:
    """One router's part of a VPN change: the lines, and the lines that undo them (in configuration mode)."""
    key: str
    title: str = ""
    lines: list = field(default_factory=list)
    undo: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def __bool__(self):
        return bool(self.lines)

    def text(self, revert_minutes=0):
        first = f"configure terminal revert timer {revert_minutes}" if revert_minutes else "configure terminal"
        return "\n".join([first] + self.lines + ["end"])

    def undo_text(self):
        return "\n".join(["configure terminal"] + self.undo + ["end"])


def member_change(device, before_footprint, after_footprint, key="", title="", peers=()):
    """MemberChange from a router's footprint as it was to as it'll be. peers: the far ends' addresses (an IKE
    profile in use by a live session can't be removed: they're cleared first)."""
    before_objects, after_objects = states(device, before_footprint, after_footprint)
    change = MemberChange(key, title)
    change.lines = clear_before_removing(plan(before_objects, after_objects), peers)
    change.undo = clear_before_removing(plan(after_objects, before_objects), peers)
    return change


PROFILE_REMOVALS = ("no crypto isakmp profile ", "no crypto ikev2 profile ", "no crypto keyring ",
                    "no crypto ikev2 keyring ")


def clear_before_removing(lines, peers):
    """lines with the far ends' crypto sessions cleared (do clear crypto session remote X) before an IKE profile or
    keyring a session still uses is removed (IOS refuses: "Profile ... is still in use"), once what used it (a crypto
    map entry, a tunnel) is gone."""
    at = next((number for number, line in enumerate(lines) if line.startswith(PROFILE_REMOVALS)), None)
    if at is None or not peers:
        return lines
    clears = [f"do clear crypto session remote {peer}" for peer in peers if peer and peer != "0.0.0.0"]
    return lines[:at] + clears + lines[at:]


def applied(device, before_footprint, after_footprint):
    """The router as it would be read once a change is in (a new DeviceVpns: what checks look at, and what tests
    compare)."""
    _, after_objects = states(device, before_footprint, after_footprint)
    tree = [block.copy() for block in device.tree]
    for key, block in after_objects.items():
        at = next((number for number, item in enumerate(tree) if key_of(item.line) == key), None)
        if block is None:
            if at is not None:
                del tree[at]
        elif at is None:
            tree.append(block.copy())
        else:
            tree[at] = block.copy()
    text = "\n".join(render(tree))
    result = parse_device(text, version=device.version)
    result.routes, result.xe, result.status = device.routes, device.xe, device.status
    result.toward_pc, result.pc_ip = device.toward_pc, device.pc_ip
    return result


def vpn_changes(before, after, devices, siblings=None):
    """{member key: MemberChange} turning VPN before into after (either None: made from nothing, or taken away).
    devices: {member key: DeviceVpns}."""
    keys = []
    for vpn in (before, after):
        if vpn is not None:
            keys += [member.key for member in vpn.members if member.key not in keys]
    changes = {}
    for key, old_footprint, new_footprint, title in footprints(before, after, devices, siblings):
        peers = []
        for vpn in (before, after):
            mine = vpn.member(key) if vpn is not None else None
            if mine is not None:
                peers += [other.reached_at for other in vpn.others(mine) if other.reached_at not in peers]
        changes[key] = member_change(devices[key], old_footprint, new_footprint, key, title, peers)
    return changes


def footprints(before, after, devices, siblings=None):
    """[(member key, footprint before, footprint after, title)] of the members whose routers were read (one that
    wasn't, such as the far end of a tunnel found on one side, isn't changed)."""
    keys = []
    for vpn in (before, after):
        if vpn is not None:
            keys += [member.key for member in vpn.members if member.key not in keys]
    after = keyed(after, devices, siblings)
    found = []
    for key in keys:
        device = devices.get(key)
        if device is None or not device.read:
            continue
        old = before.member(key) if before is not None else None
        new = after.member(key) if after is not None else None
        extra = (siblings or {}).get(key, ())
        old_footprint = footprint(before, old, device, extra) if old is not None else []
        new_footprint = footprint(after, new, device, extra) if new is not None else []
        found.append((key, old_footprint, new_footprint, (new or old).title()))
    return found


def keyed(design, devices, siblings=None):
    """A DMVPN whose routers' WAN interfaces have another multipoint GRE tunnel on them (a second cloud) needs a tunnel
    key, and the same one on every router in the cloud: design with it set (its network ID), or design as it is."""
    if design is None or design.kind != DMVPN or design.dmvpn.tunnel_key:
        return design
    if any(devices.get(member.key) is not None and f"Tunnel{member.tunnel}" in devices[member.key].interfaces()
           for member in design.members):
        return design  # A cloud already there works as it is (one without a key next to one with a key is fine)
    if not any(shares_source(design, member, devices.get(member.key), (siblings or {}).get(member.key, ()))
               for member in design.members if devices.get(member.key) is not None):
        return design
    design = design.copy()
    design.dmvpn.tunnel_key = design.dmvpn.network_id or (design.members[0].tunnel if design.members else 1)
    return design


def devices_after(before, after, devices, siblings=None):
    """{member key: DeviceVpns} as the routers would be once the change is in."""
    result = dict(devices)
    for key, old_footprint, new_footprint, _ in footprints(before, after, devices, siblings):
        result[key] = applied(devices[key], old_footprint, new_footprint)
    return result


# ----------------------------------------------------------------- What a router says when it refuses

REFUSAL = re.compile(r"^\s*%|^\s*Error\b|\bis (?:still )?in use\b|\bPlease remove\b|\bcan ?not be (?:deleted|removed|"
                     r"configured|changed)\b|^\s*Conflict between|Invalid input|Incomplete command|Ambiguous command",
                     re.IGNORECASE)
# What crypto and PKI commands say that looks like a refusal but isn't (notes, prompts, what an undo finds gone)
NOTES = [
    r"deemed incomplete", r"will remain disabled", r"database url was changed", r"existing database to the",
    r"keypair does not exist", r"Removing an enrolled trustpoint", r"ask the CA administrator", r"Keys to be removed",
    r"All router certs issued", r"will destroy all certificates", r"will show the fingerprint", r"Can.t find policy",
    r"rollback", r"backing up", r"archive", r"confirmed change", r"^\s*%[A-Z0-9_]+-\d+-[A-Z0-9_]+:",
    r"^\s*%\s*(?:Warning|Note|Info|Applying|Generating|The subject name|The fully-qualified|Start certificate|"
    r"Certificate request sent|Create a challenge|For security|Please make a note|Enrollment|Certificate has the "
    r"following|Fingerprint|You will need|Key .* already exists|The key modulus|Exporting|Some server|Please enter a "
    r"passphrase|or type Return|Certificate Server enabled|Do you accept|Include an IP|Include the router|Request "
    r"certificate|The subject|Re-enter|Password)",
]
NOT_REFUSAL = re.compile("|".join(NOTES), re.IGNORECASE)


def refusals(answer):
    """The lines of a router's answer to a VPN line that say it refused it (crypto refusals don't always start with %;
    some % lines are only notes)."""
    found = []
    for line in (answer or "").splitlines():
        if REFUSAL.search(line) and not NOT_REFUSAL.search(line):
            found.append(line.strip())
    return found


# ----------------------------------------------------------------- What a change leaves to check

def verify_commands(vpn, member, devices):
    """[(command, what success looks like (a regex), what it means)] to run on a member once its change is in."""
    checks = []
    if vpn.kind == CRYPTO_MAP:
        device = devices.get(member.key)
        for other in vpn.others(member):
            far = devices.get(other.key)
            for prefix in member.lans:
                interface, source = device.interface_in(prefix) if device is not None else ("", "")
                for far_prefix in other.lans:
                    _, target = far.interface_in(far_prefix) if far is not None else ("", "")
                    if source and target:
                        checks.append((f"ping {target} source {source} repeat 5 timeout 1", r"Success rate is "
                                       r"(?:[4-9]\d|100) percent", f"{target} answers through the VPN"))
            checks.append((f"show crypto session remote {other.reached_at}", r"Session status: UP-ACTIVE",
                           f"the IPsec session to {other.title()} is up"))
        return checks
    others = vpn.hubs() if vpn.kind == DMVPN and member.role == SPOKE else vpn.others(member)
    if vpn.kind == DMVPN and member.role == HUB:
        others = [hub for hub in vpn.hubs() if hub.key != member.key]  # Spokes are checked from their side
    for other in others:
        if other.tunnel_ip:
            checks.append((f"ping {other.tunnel_ip} source Tunnel{member.tunnel} repeat 5 timeout 1",
                           r"Success rate is (?:[4-9]\d|100) percent",
                           f"{other.title()} answers across the tunnel"))
    if vpn.routing.kind != NO_ROUTING:  # The LANs reach each other (the routing across it works)
        device = devices.get(member.key)
        far_members = vpn.others(member) if member.role != HUB else vpn.spokes()[:1] + \
            [hub for hub in vpn.hubs() if hub.key != member.key]
        for other in far_members:
            far = devices.get(other.key)
            for prefix in member.lans[:1]:
                _, source = device.interface_in(prefix) if device is not None else ("", "")
                for far_prefix in other.lans[:1]:
                    _, target = far.interface_in(far_prefix) if far is not None else ("", "")
                    if source and target:
                        checks.append((f"ping {target} source {source} repeat 5 timeout 1",
                                       r"Success rate is (?:[4-9]\d|100) percent",
                                       f"{other.title()}'s LAN answers from {member.title()}'s LAN"))
    return checks


# ----------------------------------------------------------------- Templates, and far ends set up by hand

PLACEHOLDER = re.compile(r"^<[A-Z0-9][A-Z0-9-]*>$")
SLOT_WORDS = {"A": "side A", "B": "side B", "HUB": "the hub", "HUB2": "the second hub", "SPOKE": "each spoke"}
PLACEHOLDER_MEANINGS = [  # (ending, what it stands for: {who} is whose)
    ("-WAN-INTERFACE", "{who}'s WAN interface (the tunnel source, GigabitEthernet1)"),
    ("-WAN-IP", "{who}'s WAN address (where the others reach it)"),
    ("-TUNNEL-IP", "{who}'s address on the tunnel"),
    ("-AS", "{who}'s BGP AS"),
    ("-IP", "{who}'s address"),
]


def is_placeholder(text):
    return bool(PLACEHOLDER.match(text or ""))


def derived(token, what):
    """"<A-LAN>", "MASK" -> "<A-LAN-MASK>"."""
    return f"{token[:-1]}-{what}>"


def placeholders(text):
    """The <PLACEHOLDERS> in some lines, in the order they first come."""
    return list(dict.fromkeys(re.findall(r"<[A-Z0-9][A-Z0-9-]*>", text or "")))


def placeholder_meaning(token):
    """What a placeholder stands for ("<SPOKE-LAN>" -> "a LAN behind each spoke (10.1.1.0/24)")."""
    words = token.strip("<>").split("-")
    who = SLOT_WORDS.get(words[0], "this router") if len(words) > 1 and words[0] in SLOT_WORDS else "this router"
    body = "-" + "-".join(words[1:] if words[0] in SLOT_WORDS else words)
    if re.search(r"-LAN\d*$", body):
        return f"a LAN behind {who} (a prefix, 10.1.1.0/24)"
    part = re.search(r"-LAN\d*-(NETWORK|MASK|WILDCARD)$", body)
    if part:
        return {"NETWORK": f"a LAN behind {who}: its network address (10.1.1.0)",
                "MASK": f"a LAN behind {who}: its mask (255.255.255.0)",
                "WILDCARD": f"a LAN behind {who}: its wildcard mask (0.0.0.255)"}[part.group(1)]
    for ending, meaning in PLACEHOLDER_MEANINGS:
        if body.endswith(ending):
            return meaning.format(who=who)
    return "fill in"


def legend(text):
    """"!" comment lines saying what each placeholder in text stands for (IOS ignores them when pasted)."""
    found = placeholders(text)
    if not found:
        return []
    width = max(len(token) for token in found)
    return ["! Replace before pasting:"] + [f"!   {token.ljust(width)}  {placeholder_meaning(token)}"
                                            for token in found]


def filled(vpn, member):
    """A copy of a member NOMAD doesn't read, with placeholders where something its lines need is unknown."""
    item = copy.deepcopy(member)
    item.wan = item.wan or "<WAN-INTERFACE>"
    item.local_ip = item.local_ip or "<WAN-IP>"
    if vpn.kind != CRYPTO_MAP:
        item.tunnel_ip = item.tunnel_ip or "<TUNNEL-IP>"
    if vpn.routing.kind == BGP:
        item.bgp_as = item.bgp_as or "<BGP-AS>"
    return item


def removal_lines(blocks, parent_line="", depth=0):
    """Lines taking a footprint away from a router NOMAD hasn't read: its own objects go, shared (partial) blocks lose
    only the VPN's lines in them, sticky ones stay."""
    pad = " " * depth
    lines = []
    ordered = sorted(blocks, key=lambda block: -rank(block.line)) if not depth else list(reversed(blocks))
    for block in ordered:
        if block.sticky:
            continue
        left = Block(block.line, [child for child in block.children if child.sticky])
        if block.partial and block.children and not (block.line.startswith("crypto ikev2 policy") and
                                                     goes_when_empty(left)):
            inner = removal_lines(block.children, block.line, depth + 1)
            if inner:
                lines += [pad + block.line] + inner
        else:
            lines.append(pad + no_form(block.line, parent_line))
    return lines


def side_change(vpn, member, xe=False):
    """MemberChange with all of a router's lines for a VPN, for a router NOMAD doesn't read (a template's slot, a
    far end set up by hand): to copy and paste. xe False keeps the lines IOS XE takes as defaults (they're harmless
    there, and classic IOS needs them)."""
    item = member if vpn.template else filled(vpn, member)
    blocks = prune_hidden(footprint(vpn, item, None, xe=xe), xe)
    after = {}
    for block in blocks:
        after.setdefault(key_of(block.line), strip_flags(block))
    change = MemberChange(member.key, member.title())
    change.lines = plan({}, after)
    change.undo = removal_lines(blocks)
    return change


def side_text(change, undo=False):
    """A side's lines to paste, with a legend of its placeholders first."""
    text = change.undo_text() if undo else change.text()
    return "\n".join(legend(text) + [text])


TEMPLATE_SUBNETS = {True: "172.31.0.0/30", False: "172.31.0.0/24"}


def slot(kind, word, role, tunnel, hub_order=0):
    """A template's member: its details are placeholders named for it (<A-WAN-IP>, <SPOKE-LAN>...)."""
    label = {"A": "Side A", "B": "Side B", "HUB": "Hub", "HUB2": "Hub 2", "SPOKE": "Spoke"}.get(word, word.title())
    member = Member(f"slot:{word.lower()}", label, "", role, f"<{word}-WAN-INTERFACE>", f"<{word}-WAN-IP>",
                    tunnel=tunnel, lans=[f"<{word}-LAN>"], bgp_as=f"<{word}-AS>", hub_order=hub_order)
    if role == SPOKE:
        member.tunnel_ip = f"<{word}-TUNNEL-IP>"  # Every spoke has its own
    return member


def make_template(name, kind, hubs=1, base=None):
    """A VPN with no routers: slots (two sides, or hubs and a spoke) whose lines have placeholders. base: a VPN whose
    settings it takes (a library entry)."""
    design = base.copy() if base is not None else Vpn(name=name, kind=kind)
    design.id = Vpn().id
    design.name, design.kind, design.found, design.template = name, kind, False, True
    design.differences = []
    tunnel = 100 if kind == DMVPN else 10
    if kind == DMVPN:
        design.members = [slot(kind, "HUB" if number == 1 else f"HUB{number}", HUB, tunnel, number)
                          for number in range(1, max(1, min(hubs, 2)) + 1)]
        design.members.append(slot(kind, "SPOKE", SPOKE, tunnel))
    else:
        design.members = [slot(kind, "A", PEER, tunnel), slot(kind, "B", PEER, tunnel)]
    if kind == CRYPTO_MAP:
        design.subnet = ""
        if base is None:
            design.crypto = preset(COMPATIBLE)
        design.routing.kind = STATIC
    else:
        design.subnet = TEMPLATE_SUBNETS[kind in POINT_TO_POINT]
        assign_addresses(design)
    design.auth.psk = design.auth.psk or new_key()
    if kind == DMVPN and not design.dmvpn.auth:
        design.dmvpn.auth = new_key(8)
    return design


# ----------------------------------------------------------------- Kept on this PC

@dataclass
class LibraryEntry:
    id: str
    name: str
    design: dict  # Vpn.to_dict() (without secrets)
    saved: str = ""
    notes: str = ""


@dataclass
class HistoryEntry:
    id: str
    when: str
    vpn: str  # Its name
    device: str
    address: str
    lines: str  # Masked
    undo: str  # Masked
    how: str
    outcome: str
    secret: str = ""  # The unmasked lines and undo, protected for this Windows account (for Undo)


class VpnStore:
    """VPN designs (the library), the changes sent from this PC, and the pre-shared keys of VPNs built here (each
    protected for this Windows account), in a JSON file in the app's folder."""

    def __init__(self, path=None, protect=None, unprotect=None):
        self.path = path
        self.library, self.history = [], []
        self.keys = {}  # VPN id -> protected key text
        self.designs = {}  # VPN id -> Vpn.to_dict() of VPNs built here (so their names and choices are kept)
        if protect is None or unprotect is None:
            from ..terminal import credentials
            protect, unprotect = credentials.protect, credentials.unprotect
        self.protect, self.unprotect = protect, unprotect

    @classmethod
    def default(cls):
        from ..system import app_data_dir
        store = cls(app_data_dir() / FILE_NAME)
        store.load()
        return store

    def load(self):
        self.library, self.history, self.keys, self.designs = [], [], {}, {}
        if self.path is None:
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
            self.library = [LibraryEntry(**item) for item in data.get("library", [])]
            self.history = [HistoryEntry(**item) for item in data.get("history", [])]
            self.keys = dict(data.get("keys", {}))
            self.designs = dict(data.get("designs", {}))
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as error:
            log.warning("Couldn't read the VPNs from %s: %s", self.path, error)

    def save(self):
        if self.path is None:
            return
        from ..system import replace_file
        self.history = self.history[:KEEP_HISTORY]
        temporary = f"{self.path}.tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump({"version": 1, "library": [asdict(item) for item in self.library],
                       "history": [asdict(item) for item in self.history], "keys": self.keys,
                       "designs": self.designs}, file, indent=1)
        replace_file(temporary, self.path)

    def remember(self, vpn):
        """Keep a VPN's design and keys (protected)."""
        self.designs[vpn.id] = vpn.to_dict()
        secrets_kept = {"psk": vpn.auth.psk, "nhrp": vpn.dmvpn.auth,
                        "members": {member.key: [member.psk, member.psk_remote] for member in vpn.members
                                    if member.psk or member.psk_remote}}
        if any(secrets_kept.values()):
            try:
                self.keys[vpn.id] = self.protect(json.dumps(secrets_kept))
            except Exception as error:  # A key that can't be protected isn't kept (it's still on the routers)
                log.warning("Couldn't protect the VPN's keys: %s", error)
        self.save()

    def forget(self, vpn_id):
        self.designs.pop(vpn_id, None)
        self.keys.pop(vpn_id, None)
        self.save()

    def secrets_of(self, vpn_id):
        stored = self.keys.get(vpn_id)
        if not stored:
            return {}
        try:
            return json.loads(self.unprotect(stored))
        except Exception as error:
            log.warning("Couldn't read the VPN's keys: %s", error)
            return {}

    def design(self, vpn_id):
        data = self.designs.get(vpn_id)
        if not data:
            return None
        vpn = Vpn.from_dict(data)
        kept = self.secrets_of(vpn_id)
        vpn.auth.psk = kept.get("psk", "") or vpn.auth.psk
        vpn.dmvpn.auth = kept.get("nhrp", "") or vpn.dmvpn.auth
        for key, (psk, psk_remote) in (kept.get("members") or {}).items():
            member = vpn.member(key)
            if member is not None:
                member.psk, member.psk_remote = psk, psk_remote
        return vpn

    def add_to_library(self, vpn, notes=""):
        entry = LibraryEntry(uuid.uuid4().hex, vpn.name, vpn.to_dict(), now_text(), notes)
        self.library.insert(0, entry)
        self.save()
        return entry

    def remove_from_library(self, entry_id):
        self.library = [item for item in self.library if item.id != entry_id]
        self.save()

    def record(self, vpn_name, device, address, lines, undo, how, outcome):
        secret = ""
        if lines != mask(lines) or undo != mask(undo):
            try:
                secret = self.protect(json.dumps({"lines": lines, "undo": undo}))
            except Exception as error:
                log.warning("Couldn't protect the change's keys: %s", error)
        entry = HistoryEntry(uuid.uuid4().hex, now_text(), vpn_name, device, address, mask(lines), mask(undo), how,
                             outcome, secret)
        self.history.insert(0, entry)
        self.save()
        return entry

    def update(self, entry):
        self.save()

    def unmasked(self, entry):
        """(lines, undo) of a history entry with its keys (masked if they can't be read)."""
        if entry.secret:
            try:
                data = json.loads(self.unprotect(entry.secret))
                return data.get("lines", entry.lines), data.get("undo", entry.undo)
            except Exception as error:
                log.warning("Couldn't read the change's keys: %s", error)
        return entry.lines, entry.undo


def now_text():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
