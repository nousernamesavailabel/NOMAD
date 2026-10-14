"""Finding the VPNs already on routers (built by NOMAD or by hand), as vpn.Vpn designs that can be edited.

From each router's running-config: its tunnel interfaces (GRE, IPsec VTI, multipoint GRE with NHRP) and the crypto
map entries on its interfaces, with the IPsec profiles, transform sets, IKE profiles, keyrings and proposals they
use, and the routing that crosses them. Then across routers: point-to-point tunnels are paired by their addresses
(one's destination is the other's source), DMVPN tunnels are grouped into clouds by NHRP network ID and tunnel
subnet (hubs are the ones that take registrations, spokes the ones with an NHS), and crypto map entries are paired
by peer address. A tunnel or entry whose far end wasn't read is a VPN with one member, still editable on its side.

The names each router uses (its proposal, keyring, profile, keyring peer names, crypto map and sequence...) go in
each member's names, so a VPN read and changed keeps them; lines NOMAD doesn't model stay as they are; objects used
by more than one VPN are marked shared, so taking one VPN away leaves them for the others.

Qt-free.
"""
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from . import vpn as V


@dataclass
class TunnelInfo:
    key: str  # Device key
    number: int
    block: object
    ip: str = ""
    length: int = 0
    source: str = ""  # As written (an interface or an address)
    wan: str = ""  # The source interface
    local_ip: str = ""
    destination: str = ""
    mode: str = "gre"  # gre, ipsec, mgre, other
    protection: str = ""
    shared: bool = False
    tunnel_key: int = 0
    mtu: int = 0
    mss: int = 0
    keepalive: int = 0
    description: str = ""
    network_id: int = 0
    nhrp_auth: str = ""
    holdtime: int = 0
    dynamic: bool = False  # ip nhrp map multicast dynamic (it takes registrations: a hub)
    nhs: list = field(default_factory=list)  # [(tunnel address, nbma)]
    redirect: bool = False
    shortcut: bool = False
    lines: list = field(default_factory=list)

    @property
    def subnet(self):
        if not self.ip or not self.length:
            return ""
        return str(ipaddress.IPv4Interface(f"{self.ip}/{self.length}").network)

    @property
    def nhrp(self):
        return bool(self.network_id or self.nhs or self.dynamic)


def tunnels_of(key, device):
    """[TunnelInfo] of a router's tunnel interfaces."""
    found = []
    for block in device.blocks("interface Tunnel"):
        number = re.match(r"interface Tunnel(\d+)$", block.line)
        if not number:
            continue
        info = TunnelInfo(key, int(number.group(1)), block, lines=[child.line for child in block.children])
        maps = {}
        multicast = []
        for line in info.lines:
            words = line.split()
            if words[:2] == ["ip", "address"] and len(words) >= 4 and words[-1] != "secondary":
                try:
                    info.ip, info.length = words[2], ipaddress.IPv4Network(f"0.0.0.0/{words[3]}").prefixlen
                except ValueError:
                    pass
            elif words[:2] == ["tunnel", "source"] and len(words) > 2:
                info.source = words[2]
            elif words[:2] == ["tunnel", "destination"] and len(words) > 2:
                info.destination = words[2]
            elif words[:2] == ["tunnel", "mode"]:
                rest = " ".join(words[2:])
                info.mode = {"ipsec ipv4": "ipsec", "gre multipoint": "mgre", "gre ip": "gre"}.get(rest, "other")
            elif words[:4] == ["tunnel", "protection", "ipsec", "profile"] and len(words) > 4:
                info.protection = words[4]
                info.shared = "shared" in words[5:]
            elif words[:2] == ["tunnel", "key"] and len(words) > 2 and words[2].isdigit():
                info.tunnel_key = int(words[2])
            elif words[:2] == ["ip", "mtu"] and len(words) > 2 and words[2].isdigit():
                info.mtu = int(words[2])
            elif words[:3] == ["ip", "tcp", "adjust-mss"] and len(words) > 3 and words[3].isdigit():
                info.mss = int(words[3])
            elif words[0] == "keepalive" and len(words) > 1 and words[1].isdigit():
                info.keepalive = int(words[1])
            elif words[0] == "description":
                info.description = line[len("description "):]
            elif words[:3] == ["ip", "nhrp", "network-id"] and len(words) > 3 and words[3].isdigit():
                info.network_id = int(words[3])
            elif words[:3] == ["ip", "nhrp", "authentication"] and len(words) > 3:
                info.nhrp_auth = words[3]
            elif words[:3] == ["ip", "nhrp", "holdtime"] and len(words) > 3 and words[3].isdigit():
                info.holdtime = int(words[3])
            elif words[:5] == ["ip", "nhrp", "map", "multicast", "dynamic"]:
                info.dynamic = True
            elif words[:4] == ["ip", "nhrp", "map", "multicast"] and len(words) > 4:
                multicast.append(words[4])
            elif words[:3] == ["ip", "nhrp", "map"] and len(words) > 4:
                maps[words[3]] = words[4]
            elif words[:3] == ["ip", "nhrp", "nhs"] and len(words) > 3:
                nbma = words[words.index("nbma") + 1] if "nbma" in words[:-1] else ""
                info.nhs.append((words[3], nbma))
            elif words[:3] == ["ip", "nhrp", "redirect"]:
                info.redirect = True
            elif words[:3] == ["ip", "nhrp", "shortcut"]:
                info.shortcut = True
        info.nhs = [(address, nbma or maps.get(address, "")) for address, nbma in info.nhs]
        if V.ipaddress_like(info.source):
            info.local_ip = info.source
            info.wan = device.interface_with(info.source)
        elif info.source:
            info.wan = V.full_interface(info.source)
            info.local_ip = device.interface_address(info.wan)[0]
        found.append(info)
    return found


# ----------------------------------------------------------------- Crypto pieces

def block_of(device, line):
    return device.block(line) if device is not None else None


def children(block):
    return [child.line for child in block.children] if block is not None else []


def value(lines, prefix):
    """The rest of the first line starting with prefix ("" if none)."""
    for line in lines:
        if line == prefix:
            return ""
        if line.startswith(prefix + " "):
            return line[len(prefix) + 1:]
    return ""


def read_crypto(device, ipsec_profile="", transform="", ike_profile="", ike="", local_ip=""):
    """(vpn.Crypto, vpn.Auth, names {}, ike version) from the objects a tunnel or crypto map entry uses."""
    crypto, auth, names = V.Crypto(preset=V.CUSTOM), V.Auth(), {}
    if ipsec_profile:
        names["ipsec_profile"] = ipsec_profile
        lines = children(block_of(device, f"crypto ipsec profile {ipsec_profile}"))
        transform = transform or value(lines, "set transform-set").split(" ")[0]
        if not transform:
            names["transform"] = "default"  # IOS's default transform sets: left as they are
        if value(lines, "set ikev2-profile"):
            ike_profile, ike = value(lines, "set ikev2-profile"), V.IKEV2
        elif value(lines, "set isakmp-profile"):
            ike_profile, ike = value(lines, "set isakmp-profile"), V.IKEV1
        pfs = value(lines, "set pfs")
        crypto.pfs = int(pfs[5:]) if pfs.startswith("group") and pfs[5:].isdigit() else 0
        lifetime = value(lines, "set security-association lifetime seconds")
        crypto.sa_lifetime = int(lifetime) if lifetime.isdigit() else 3600
    if transform:
        names["transform"] = transform
        block = next(iter(device.blocks(f"crypto ipsec transform-set {transform}")), None)
        if block is not None:
            crypto.esp = " ".join(block.line.split()[4:])
            crypto.mode = value(children(block), "mode").split(" ")[0] or V.TUNNEL
    if not ike:
        ike = V.IKEV2 if device.blocks("crypto ikev2 profile") and not device.blocks("crypto isakmp policy") \
            else V.IKEV1 if device.blocks("crypto isakmp") or device.blocks("crypto keyring") else V.IKEV2
    crypto.ike = ike
    if ike == V.IKEV2:
        read_ikev2(device, crypto, auth, names, ike_profile, local_ip)
    else:
        read_ikev1(device, crypto, auth, names, ike_profile)
    return crypto, auth, names


def read_ikev2(device, crypto, auth, names, profile_name, local_ip):
    if profile_name:
        names["ike_profile"] = profile_name
        lines = children(block_of(device, f"crypto ikev2 profile {profile_name}"))
        names["keyring"] = value(lines, "keyring local")
        auth.method = V.CERT if value(lines, "authentication local") == "rsa-sig" else V.PSK
        auth.trustpoint = value(lines, "pki trustpoint").split(" ")[0]
        if auth.trustpoint:
            names["trustpoint"] = auth.trustpoint
        cert_map = value(lines, "match certificate")
        if cert_map:
            names["cert_map"] = cert_map
            issuer = value(children(block_of(device, f"crypto pki certificate map {cert_map} 10")), "issuer-name co")
            auth.ca_name = issuer.split("=", 1)[-1].strip() if "=" in issuer else issuer
        dpd = value(lines, "dpd").split()
        if len(dpd) >= 2 and dpd[0].isdigit() and dpd[1].isdigit():
            crypto.dpd, crypto.dpd_retry = int(dpd[0]), int(dpd[1])
            crypto.dpd_periodic = dpd[2:] == ["periodic"]
        else:
            crypto.dpd = 0
    policy_line = V.ikev2_policy_for(device, local_ip)
    proposal = ""
    if policy_line:
        names["policy"] = policy_line.split()[3] if len(policy_line.split()) > 3 else ""
        proposals = [line.split()[1] for line in children(block_of(device, policy_line))
                     if line.startswith("proposal ")]
        # A policy several VPNs share lists each one's proposal: this VPN's is named like its profile (NAME-PROP
        # beside NAME-IKE); else the first
        base = profile_name[:-len("-IKE")] if profile_name.endswith("-IKE") else ""
        proposal = f"{base}-PROP" if base and f"{base}-PROP" in proposals else proposals[0] if proposals else ""
    if proposal:
        names["proposal"] = proposal
        lines = children(block_of(device, f"crypto ikev2 proposal {proposal}"))
        crypto.encryption = value(lines, "encryption").split() or crypto.encryption
        crypto.integrity = value(lines, "integrity").split()
        crypto.prf = value(lines, "prf").split()
        groups = [int(item) for item in value(lines, "group").split() if item.isdigit()]
        crypto.groups = groups or crypto.groups
    else:
        names["proposal"] = "default"  # IOS's default proposal: left as it is
    keepalive = next((block.line.split()[-1] for block in device.blocks("crypto ikev2 nat keepalive")), "")
    crypto.nat_keepalive = int(keepalive) if keepalive.isdigit() else 0
    crypto.preset = matching_preset(crypto)


def read_ikev1(device, crypto, auth, names, profile_name):
    if profile_name:
        names["ike_profile"] = profile_name
        lines = children(block_of(device, f"crypto isakmp profile {profile_name}"))
        names["keyring"] = value(lines, "keyring")
        trustpoint = value(lines, "ca trust-point")
        if trustpoint:
            auth.method, auth.trustpoint, names["trustpoint"] = V.CERT, trustpoint, trustpoint
        cert_map = value(lines, "match certificate")
        if cert_map:
            names["cert_map"] = cert_map
        keepalive = value(lines, "keepalive").split()
        if len(keepalive) >= 3 and keepalive[0].isdigit():
            crypto.dpd, crypto.dpd_retry = int(keepalive[0]), int(keepalive[2]) if keepalive[2].isdigit() else 3
        else:
            crypto.dpd = 0
    else:
        names["ike_profile"] = "-"  # Global crypto isakmp key lines, no profile
        crypto.dpd = 0
    method = "rsa-sig" if auth.method == V.CERT else "pre-share"
    policies = []
    for block in device.blocks("crypto isakmp policy"):
        lines = children(block)
        if value(lines, "authentication") in (method, "") or (method == "rsa-sig" and not value(lines,
                                                                                                "authentication")):
            policies.append(block)
    if policies:
        block = sorted(policies, key=lambda item: int(item.line.split()[3]) if item.line.split()[3].isdigit()
                       else 0)[0]
        lines = children(block)
        names["isakmp_policy"] = block.line.split()[3]
        crypto.encryption = [value(lines, "encryption") or "des"]
        crypto.integrity = [value(lines, "hash") or "sha"]
        group = value(lines, "group")
        crypto.groups = [int(group)] if group.isdigit() else [1]
        lifetime = value(lines, "lifetime")
        crypto.ike_lifetime = int(lifetime) if lifetime.isdigit() else 86400
    else:
        names["isakmp_policy"] = "default"
    crypto.prf = []
    keepalive = next((block.line.split()[-1] for block in device.blocks("crypto isakmp nat keepalive")), "")
    crypto.nat_keepalive = int(keepalive) if keepalive.isdigit() else 0
    crypto.preset = matching_preset(crypto)


def matching_preset(crypto):
    for name in (V.MODERN, V.COMPATIBLE, V.LEGACY):
        wanted = V.preset(name)
        if (wanted.ike, wanted.encryption, wanted.integrity if not wanted.gcm() else [], wanted.prf if wanted.gcm()
                else [], wanted.groups, wanted.esp) == (crypto.ike, crypto.encryption, crypto.integrity
                                                        if not crypto.gcm() else [], crypto.prf if crypto.gcm()
                                                        else [], crypto.groups, crypto.esp):
            return name
    return V.CUSTOM


def ikev2_psk(device, keyring, address=None):
    """(the key for a peer address (None: the 0.0.0.0 one), the keyring peer's name)."""
    block = block_of(device, f"crypto ikev2 keyring {keyring}") if keyring else None
    for peer in block.children if block is not None else []:
        lines = children(peer)
        found = value(lines, "address").split()
        if not found:
            continue
        if (address is None and found[0] == "0.0.0.0") or found[0] == address or \
                (address and len(found) > 1 and address_in(address, found[0], found[1])):
            key = value(lines, "pre-shared-key")
            return key, peer.line.split(" ", 1)[1] if " " in peer.line else ""
    return "", ""


def ikev1_psk(device, keyring, address):
    """The IKEv1 key for an address: from a keyring, else a global crypto isakmp key line."""
    if keyring:
        for line in children(block_of(device, f"crypto keyring {keyring}")):
            words = line.split()
            if words[:2] == ["pre-shared-key", "address"] and "key" in words:
                target = words[2]
                key = " ".join(words[words.index("key") + 1:])
                if target == (address or "0.0.0.0") or (address and target == "0.0.0.0"):
                    return key
        return ""
    for block in device.blocks("crypto isakmp key"):
        words = block.line.split()
        if "address" in words:
            target = words[words.index("address") + 1] if words.index("address") + 1 < len(words) else ""
            key = " ".join(words[3:words.index("address")])
            if target == (address or "0.0.0.0") or (address and target == "0.0.0.0"):
                return key
    return ""


def address_in(address, network, mask):
    try:
        return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
    except ValueError:
        return False


# ----------------------------------------------------------------- Routing across a VPN

def covers(statement_words, address):
    """Whether a network statement (network A W [area N]) takes in an address."""
    try:
        network, wildcard = statement_words[1], statement_words[2] if len(statement_words) > 2 and \
            V.ipaddress_like(statement_words[2]) else "0.0.0.0"
        if len(statement_words) == 2 or not V.ipaddress_like(statement_words[2]):
            mask = ipaddress.IPv4Network(f"{network}/{V.classful(network)}", strict=False)
            return ipaddress.IPv4Address(address) in mask
        target = int(ipaddress.IPv4Address(address))
        base = int(ipaddress.IPv4Address(network))
        wild = int(ipaddress.IPv4Address(wildcard))
        return (target & ~wild) == (base & ~wild)
    except (ValueError, IndexError):
        return False


def routing_of(device, tunnel_ips, own_tunnel_ip, tunnel_name, others_tunnel_ips):
    """(kind, process, area, eigrp name, lans, lines found, tunnel lines) of what routes a member's side of a VPN."""
    lines_found, tunnel_lines = [], []
    connected = []
    for name, interface in device.interfaces().items():
        if name.lower().startswith("tunnel"):
            continue
        for address, length in interface.addresses:
            connected.append((name, address, length))
    # EIGRP and OSPF: the process with a network statement taking in the tunnel's address
    for block in device.blocks("router eigrp") + device.blocks("router ospf"):
        protocol = block.line.split()[1]
        number = block.line.split()[2] if len(block.line.split()) > 2 else ""
        scopes = [(block, None)]
        named = ""
        for child in block.children:
            if child.line.startswith("address-family ipv4"):
                scopes.append((child, child))
        for scope, af in scopes:
            statements = [child.line for child in scope.children if child.line.startswith("network ")]
            if not own_tunnel_ip or not any(covers(line.split(), own_tunnel_ip) for line in statements):
                continue
            if af is not None:
                named = number
                found_as = re.search(r"autonomous-system (\d+)", af.line)
                number = found_as.group(1) if found_as else number
            lans, used = [], []
            for line in statements:
                words = line.split()
                if covers(words, own_tunnel_ip):
                    used.append(line)
                    continue
                for name, address, length in connected:
                    if covers(words, address):
                        prefix = str(ipaddress.IPv4Interface(f"{address}/{length}").network)
                        if prefix not in lans:
                            lans.append(prefix)
                        if line not in used:
                            used.append(line)
            if af is not None:
                af_block = V.Block(af.line, [V.Block(line) for line in used])
                af_if = next((child for child in af.children if child.line == f"af-interface {tunnel_name}"), None)
                if af_if is not None:
                    af_block.children.append(V.Block(af_if.line, [V.Block(item.line) for item in af_if.children]))
                lines_found = V.render([V.Block(block.line, [af_block])])
            else:
                lines_found = V.render([V.Block(block.line, [V.Block(line) for line in used])])
            kind = V.EIGRP if protocol == "eigrp" else V.OSPF
            area = ""
            if kind == V.OSPF:
                own = next((line for line in used if covers(line.split(), own_tunnel_ip)), "")
                area = own.split()[-1] if " area " in own else "0"
            return kind, number, area, named, lans, lines_found, tunnel_lines, {}
    # BGP: a neighbor at another member's tunnel address (or a listen range over the tunnel subnet)
    for block in device.blocks("router bgp"):
        all_lines = [child.line for child in block.children]
        af = next((child for child in block.children if child.line == "address-family ipv4"), None)
        if af is not None:
            all_lines += [child.line for child in af.children]
        peers = [ip for ip in others_tunnel_ips if any(line.startswith(f"neighbor {ip} ") for line in all_lines)]
        groups = []
        for line in all_lines:
            words = line.split()
            if words[:3] == ["bgp", "listen", "range"] and len(words) > 5 and own_tunnel_ip and \
                    V.in_subnet(own_tunnel_ip, words[3]):
                groups.append(words[5])
        if not peers and not groups:
            continue
        mine = [line for line in all_lines if any(line.startswith(f"neighbor {peer} ") for peer in peers + groups)
                or (line.startswith("bgp listen range ") and line.split()[-1] in groups)]
        out_lists = {line.split()[3] for line in mine if " prefix-list " in line and line.endswith(" out")}
        allowed = []
        for name in out_lists:
            for entry in device.blocks(f"ip prefix-list {name} seq"):
                words = entry.line.split()
                if len(words) > 6 and words[5] == "permit":
                    allowed.append(words[6])
        networks = [line for line in all_lines if line.startswith("network ") and " mask " in line]
        lans, kept = [], []
        for line in networks:
            words = line.split()
            prefix = str(ipaddress.IPv4Network(f"{words[1]}/{words[3]}", strict=False))
            if out_lists and prefix not in allowed:
                continue
            lans.append(prefix)
            kept.append(line)
        process = V.Block(block.line, [V.Block(line) for line in mine if line in [c.line for c in block.children]])
        if af is not None:
            process.children.append(V.Block(af.line, [V.Block(line) for line in kept + [
                line for line in mine if line in [c.line for c in af.children]]]))
        else:
            process.children += [V.Block(line) for line in kept]
        plist_lines = [entry.line for name in out_lists for entry in device.blocks(f"ip prefix-list {name} seq")]
        lines_found = plist_lines + V.render([process])
        return V.BGP, block.line.split()[2], "", "", lans, lines_found, tunnel_lines, {}
    # Static routes through the tunnel
    statics, far = [], {}
    for block in device.blocks("ip route "):
        words = block.line.split()
        if len(words) < 5 or not V.ipaddress_like(words[2]) or not V.ipaddress_like(words[3]):
            continue
        hop = words[4]
        through_tunnel = hop.lower() in (tunnel_name.lower(), f"tu{tunnel_name[6:]}".lower())
        if hop in others_tunnel_ips or through_tunnel:
            statics.append(block.line)
            prefix = str(ipaddress.IPv4Network(f"{words[2]}/{words[3]}", strict=False))
            if through_tunnel:  # Out of the tunnel interface: the far end's (one far end on a point-to-point)
                if len(others_tunnel_ips) != 1:
                    continue
                hop = others_tunnel_ips[0]
            far.setdefault(hop, []).append(prefix)
    if statics:
        return V.STATIC, "", "", "", [], statics, tunnel_lines, far
    return V.NO_ROUTING, "", "", "", [], [], tunnel_lines, {}


# ----------------------------------------------------------------- Putting it together

@dataclass
class Read:
    """A router as given to find(): its key, label, management address and what was read."""
    key: str
    label: str
    address: str
    device: object


def find(reads):
    """[vpn.Vpn] on the routers read ([Read])."""
    infos = {}
    for read in reads:
        if read.device is not None and read.device.read:
            infos[read.key] = tunnels_of(read.key, read.device)
    by_key = {read.key: read for read in reads}
    vpns = []
    used = set()
    # DMVPN clouds
    clouds = {}
    for key, tunnels in infos.items():
        for info in tunnels:
            if info.mode == "mgre" or info.nhrp:
                clouds.setdefault((info.network_id or info.number, info.subnet), []).append(info)
    for (network_id, subnet), members in clouds.items():
        vpns.append(dmvpn_vpn(network_id, subnet, members, by_key))
        used |= {(info.key, info.number) for info in members}
    # Point-to-point tunnels, paired by address
    singles = [info for tunnels in infos.values() for info in tunnels
               if (info.key, info.number) not in used and info.mode in ("gre", "ipsec") and info.destination]
    paired = set()
    for info in singles:
        if (info.key, info.number) in paired:
            continue
        partner = next((other for other in singles if other.key != info.key and info.subnet and
                        (other.key, other.number) not in paired and other.subnet == info.subnet), None)
        paired.add((info.key, info.number))
        if partner is not None:
            paired.add((partner.key, partner.number))
        vpns.append(p2p_vpn(info, partner, by_key))
    # Crypto map entries, paired by peer address
    entries = []
    for read in reads:
        if read.device is not None and read.device.read:
            entries += map_entries(read.key, read.device)
    taken = set()
    for entry in entries:
        if id(entry) in taken:
            continue
        taken.add(id(entry))
        partner = next((other for other in entries if id(other) not in taken and other["key"] != entry["key"] and
                        other["local_ip"] in entry["peers"] and entry["local_ip"] in other["peers"]), None)
        if partner is not None:
            taken.add(id(partner))
        vpns.append(map_vpn(entry, partner, by_key))
    mark_shared(vpns)
    return vpns


def stable_id(*parts):
    return "found-" + hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()[:16]


def name_from(description, fallback):
    found = re.match(r"^(.*?)(?: (?:IPsec VTI|GRE over IPsec|GRE|DMVPN|Crypto Map \(policy-based\)))? \(NOMAD\)$",
                     description or "")
    return found.group(1).strip() if found and found.group(1).strip() else fallback


def member_of(read, info, role=V.PEER):
    member = V.Member(read.key, read.label or (read.device.hostname if read.device else ""), read.address, role)
    member.wan, member.local_ip = info.wan, info.local_ip
    member.tunnel, member.tunnel_ip = info.number, info.ip
    member.bgp_as = read.device.bgp_as() if read.device is not None else ""
    return member


def p2p_vpn(info, partner, by_key):
    read = by_key[info.key]
    kind = V.VTI if info.mode == "ipsec" else V.GRE_IPSEC if info.protection else V.GRE
    vpn = V.Vpn(id=stable_id("p2p", info.key, info.number, partner.key if partner else info.destination,
                             partner.number if partner else ""), kind=kind, found=True)
    vpn.name = name_from(info.description, f"Tunnel{info.number}")
    vpn.subnet = info.subnet
    vpn.mtu, vpn.mss, vpn.keepalive = info.mtu, info.mss, info.keepalive
    members = [(info, read)]
    if partner is not None:
        members.append((partner, by_key[partner.key]))
    for item, item_read in members:
        vpn.members.append(member_of(item_read, item))
    if partner is None:  # The far end wasn't read: a member that stands for it
        far = V.Member(f"peer:{info.destination}", info.destination, info.destination, local_ip=info.destination)
        vpn.members.append(far)
    for item, item_read in members:
        member = vpn.member(item_read.key)
        other = next(iter(vpn.others(member)))
        if item.destination and item.destination != other.local_ip and other.key.startswith("peer:") is False:
            other.public_ip = item.destination  # The far end is reached at an address it doesn't have (NAT)
    fill_crypto(vpn, members, by_key)
    fill_routing(vpn, members, by_key)
    return vpn


def dmvpn_vpn(network_id, subnet, infos, by_key):
    first = infos[0]
    vpn = V.Vpn(id=stable_id("dmvpn", network_id, subnet), kind=V.DMVPN, found=True)
    named_hubs = {address for info in infos for address, _ in info.nhs}
    for info in infos:  # A hub takes registrations: the others name it as their NHS (IOS XE hides "map multicast
        # dynamic"), or it names none itself
        info.dynamic = info.dynamic or info.redirect or info.ip in named_hubs or (info.mode == "mgre" and
                                                                                 not info.nhs)
    hub_info = next((info for info in infos if info.dynamic), first)
    vpn.name = name_from(hub_info.description, f"DMVPN {network_id}")
    vpn.subnet = subnet
    vpn.mtu, vpn.mss = hub_info.mtu, hub_info.mss
    vpn.dmvpn.network_id = network_id if network_id != hub_info.number else 0
    vpn.dmvpn.auth = hub_info.nhrp_auth
    vpn.dmvpn.holdtime = hub_info.holdtime
    keys = {info.tunnel_key for info in infos}
    vpn.dmvpn.tunnel_key = keys.pop() if len(keys) == 1 else 0
    spokes_p2p = any(info.mode == "gre" and not info.dynamic for info in infos)
    vpn.dmvpn.phase = 3 if any(info.redirect for info in infos) else 1 if spokes_p2p else 2
    members = []
    hub_order = {}
    for info in infos:
        for number, (address, _) in enumerate(info.nhs):
            hub_order.setdefault(address, number + 1)
    for info in infos:
        read = by_key[info.key]
        role = V.HUB if info.dynamic else V.SPOKE
        member = member_of(read, info, role)
        if role == V.HUB:
            member.hub_order = hub_order.get(info.ip, 1)
        vpn.members.append(member)
        members.append((info, read))
    # A hub only known from the spokes' NHS lines (not read): a member standing for it
    for info in infos:
        for address, nbma in info.nhs:
            if not any(member.tunnel_ip == address for member in vpn.members):
                far = V.Member(f"peer:{nbma or address}", nbma or address, nbma, V.HUB, local_ip=nbma,
                               tunnel_ip=address, hub_order=hub_order.get(address, 1))
                vpn.members.append(far)
    for member in vpn.members:  # A hub reached at an address it doesn't have (NAT): what the spokes say
        if member.role != V.HUB or member.key.startswith("peer:"):
            continue
        for info in infos:
            for address, nbma in info.nhs:
                if address == member.tunnel_ip and nbma and nbma != member.local_ip:
                    member.public_ip = nbma
    fill_crypto(vpn, members, by_key)
    fill_routing(vpn, members, by_key)
    return vpn


def fill_crypto(vpn, members, by_key):
    """Crypto, auth and each member's names, from the tunnels' IPsec profiles."""
    first = True
    for info, read in members:
        member = vpn.member(read.key)
        if not info.protection:
            continue
        crypto, auth, names = read_crypto(read.device, ipsec_profile=info.protection, local_ip=info.local_ip)
        if first:
            vpn.crypto, vpn.auth = crypto, auth
            first = False
        if auth.method == V.PSK:
            psk, peer_names = find_psks(vpn, member, read.device, crypto.ike, names.get("keyring", ""))
            if psk and not vpn.auth.psk:
                vpn.auth.psk = psk
            names.update(peer_names)
        member.names.update(names)


def find_psks(vpn, member, device, ike, keyring):
    """(the key this member has for the others, {"peer:<key>": keyring peer name})."""
    found, peer_names = "", {}
    if vpn.kind == V.DMVPN:
        if ike == V.IKEV2:
            found, name = ikev2_psk(device, keyring, None)
            if name:
                peer_names["peer:*"] = name
        else:
            found = ikev1_psk(device, keyring, None)
        return found, peer_names
    for other in vpn.others(member):
        if ike == V.IKEV2:
            key, name = ikev2_psk(device, keyring, other.reached_at)
            if name:
                peer_names[f"peer:{other.key}"] = name
        else:
            key = ikev1_psk(device, keyring, other.reached_at)
        found = found or key
    return found, peer_names


def fill_routing(vpn, members, by_key):
    """The routing across the VPN and each member's LANs, from what routes through its tunnel on each router."""
    tunnel_ips = [member.tunnel_ip for member in vpn.members if member.tunnel_ip]
    far_lans = {}  # Static routes: tunnel address -> the prefixes sent to it
    vpn.routing.kind = V.NO_ROUTING
    for info, read in members:
        member = vpn.member(read.key)
        others = [ip for ip in tunnel_ips if ip != member.tunnel_ip]
        kind, process, area, named, lans, lines, _, far = routing_of(read.device, tunnel_ips, member.tunnel_ip,
                                                                     f"Tunnel{info.number}", others)
        if kind == V.NO_ROUTING:
            continue
        if vpn.routing.kind in (V.NO_ROUTING, V.STATIC):
            vpn.routing.kind = kind
        if kind == V.STATIC:
            for hop, prefixes in far.items():
                far_lans.setdefault(hop, [])
                far_lans[hop] += [prefix for prefix in prefixes if prefix not in far_lans[hop]]
        else:
            vpn.routing.process = process or vpn.routing.process
            vpn.routing.area = area or vpn.routing.area
            vpn.routing.eigrp_name = named or vpn.routing.eigrp_name
            member.lans = lans
        member.names["routing_lines"] = lines
        member.names["routing_tunnel_lines"] = [line for line in info.lines if line.startswith((
            "no ip split-horizon eigrp", "no ip next-hop-self eigrp", "ip ospf network", "ip ospf priority"))]
    if vpn.routing.kind == V.STATIC:
        for member in vpn.members:
            if member.tunnel_ip in far_lans and not member.lans:
                member.lans = far_lans[member.tunnel_ip]
    for info, read in members:  # Now the LANs are known, what those lines stand for
        member = vpn.member(read.key)
        if "routing_lines" in member.names:
            member.names["routing_sig"] = V.routing_signature(vpn, member)


# ----------------------------------------------------------------- Crypto maps

def acl_pairs(device, name):
    """[(source prefix, destination prefix)] of an extended ACL's permit ip rules."""
    pairs = []
    block = block_of(device, f"ip access-list extended {name}")
    lines = children(block)
    if block is None:
        lines = [" ".join(item.line.split()[2:]) for item in device.blocks(f"access-list {name} ")]
    for line in lines:
        words = line.split()
        if words and words[0].isdigit():
            words = words[1:]
        if words[:2] != ["permit", "ip"]:
            continue
        rest = words[2:]
        source, rest = read_address(rest)
        target, rest = read_address(rest)
        if source and target:
            pairs.append((source, target))
    return pairs


def read_address(words):
    if not words:
        return "", []
    if words[0] == "any":
        return "0.0.0.0/0", words[1:]
    if words[0] == "host" and len(words) > 1:
        return f"{words[1]}/32", words[2:]
    if len(words) > 1 and V.ipaddress_like(words[0]) and V.ipaddress_like(words[1]):
        try:
            wildcard = int(ipaddress.IPv4Address(words[1]))
            length = 32 - bin(wildcard).count("1")
            return str(ipaddress.IPv4Network(f"{words[0]}/{length}", strict=False)), words[2:]
        except ValueError:
            return "", words[2:]
    return "", words[1:]


def map_entries(key, device):
    """[{...}] of a router's crypto map entries that are on an interface."""
    applied = {}
    for name, interface in device.interfaces().items():
        block = device.block(f"interface {name}")
        for line in children(block):
            if line.startswith("crypto map ") and len(line.split()) > 2:
                applied.setdefault(line.split()[2], name)
    entries = []
    for block in device.blocks("crypto map "):
        words = block.line.split()
        if len(words) < 5 or not words[3].isdigit() or words[4] != "ipsec-isakmp" or words[2] not in applied:
            continue
        lines = children(block)
        wan = applied[words[2]]
        entries.append({
            "key": key, "map": words[2], "seq": words[3], "block": block, "wan": wan,
            "local_ip": device.interface_address(wan)[0],
            "peers": [line.split()[2] for line in lines if line.startswith("set peer ")],
            "transform": value(lines, "set transform-set").split(" ")[0],
            "ike_profile": value(lines, "set ikev2-profile") or value(lines, "set isakmp-profile"),
            "ike": V.IKEV2 if value(lines, "set ikev2-profile") else V.IKEV1,
            "pfs": value(lines, "set pfs"), "acl": value(lines, "match address"),
            "description": value(lines, "description"),
            "lifetime": value(lines, "set security-association lifetime seconds"),
        })
    return entries


def map_vpn(entry, partner, by_key):
    read = by_key[entry["key"]]
    vpn = V.Vpn(id=stable_id("map", entry["key"], entry["map"], entry["seq"]), kind=V.CRYPTO_MAP, found=True)
    vpn.name = name_from(entry["description"], f"{entry['map']} {entry['seq']}")
    pairs = acl_pairs(read.device, entry["acl"]) if entry["acl"] else []
    sides = [(entry, read)]
    if partner is not None:
        sides.append((partner, by_key[partner["key"]]))
    for side, side_read in sides:
        member = V.Member(side_read.key, side_read.label or side_read.device.hostname, side_read.address)
        member.wan, member.local_ip = side["wan"], side["local_ip"]
        member.bgp_as = side_read.device.bgp_as()
        member.names.update({"map": side["map"], "map_seq": side["seq"], "acl": side["acl"]})
        side_pairs = acl_pairs(side_read.device, side["acl"]) if side["acl"] else []
        member.lans = list(dict.fromkeys(source for source, _ in side_pairs))
        vpn.members.append(member)
    if partner is None:
        peer = entry["peers"][0] if entry["peers"] else "?"
        far = V.Member(f"peer:{peer}", peer, peer, local_ip=peer)
        far.lans = list(dict.fromkeys(target for _, target in pairs))
        vpn.members.append(far)
    first = True
    for side, side_read in sides:
        member = vpn.member(side_read.key)
        crypto, auth, names = read_crypto(side_read.device, transform=side["transform"],
                                          ike_profile=side["ike_profile"], ike=side["ike"],
                                          local_ip=side["local_ip"])
        pfs = side["pfs"]
        crypto.pfs = int(pfs[5:]) if pfs.startswith("group") and pfs[5:].isdigit() else 0
        crypto.sa_lifetime = int(side["lifetime"]) if side["lifetime"].isdigit() else 3600
        if first:
            vpn.crypto, vpn.auth = crypto, auth
            first = False
        if auth.method == V.PSK:
            psk, peer_names = find_psks(vpn, member, side_read.device, crypto.ike, names.get("keyring", ""))
            vpn.auth.psk = vpn.auth.psk or psk
            names.update(peer_names)
        member.names.update(names)
        # Routes to the far LANs out of the WAN interface (kept as they are)
        statics = []
        for other in vpn.others(member):
            for prefix in other.lans:
                address, netmask = V.network_words(prefix)
                statics += [block.line for block in side_read.device.blocks(f"ip route {address} {netmask} ")]
        if statics:
            vpn.routing.kind = V.STATIC
            member.names["routing_lines"] = statics
    if vpn.routing.kind != V.STATIC:
        vpn.routing.kind = V.NO_ROUTING
    for member in vpn.members:
        if "routing_lines" in member.names:
            member.names["routing_sig"] = V.routing_signature(vpn, member)
    return vpn


def mark_shared(vpns):
    """Objects more than one VPN on a router uses: marked shared in each (so one going leaves them)."""
    users = {}
    for vpn in vpns:
        for member in vpn.members:
            for kind in ("proposal", "keyring", "ike_profile", "transform", "ipsec_profile", "acl", "cert_map"):
                name = member.names.get(kind)
                if name and name not in ("-", "default"):
                    users.setdefault((member.key, kind, name), set()).add(vpn.id)
    for vpn in vpns:
        for member in vpn.members:
            shared = [kind for kind in ("proposal", "keyring", "ike_profile", "transform", "ipsec_profile", "acl",
                                        "cert_map")
                      if len(users.get((member.key, kind, member.names.get(kind)), ())) > 1]
            if shared:
                member.names["shared"] = shared
