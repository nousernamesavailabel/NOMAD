"""Checks on a VPN design against the routers as read, before anything is sent: what would stop it working, what
would make it work badly or unsafely, and what the routers would do that isn't obvious.

Findings are vpnstatus.Finding (error: it won't work or isn't safe to send; warning: it'll work, but look; info).

Qt-free.
"""
import ipaddress
import re

from . import aclcheck, vpn as V
from .vpnstatus import ERROR, INFO, WARNING, Finding

WEAK_IKE = {"des", "3des", "md5", "sha1", "sha", "aes-cbc-128"}
WEAK_GROUPS = {1, 2, 5}
ADMIN_DISTANCE = {V.STATIC: 1, V.EIGRP: 90, V.OSPF: 110}
PROTOCOL_DISTANCE = {"C": 0, "L": 0, "S": 1, "D": 90, "O": 110, "B": 20, "i": 115, "R": 120}
UDP, ESP, GRE_PROTOCOL = 17, 50, 47


def network(prefix):
    try:
        return ipaddress.IPv4Network(prefix, strict=False)
    except ValueError:
        return None


def check(vpn, devices, others=(), pc_ip=""):
    """[Finding] for a VPN design. devices: {member key: DeviceVpns}; others: the other VPNs found on the routers."""
    found = []
    say = lambda severity, text, member="": found.append(Finding(severity, text, member))  # noqa: E731
    members(vpn, devices, say)
    addresses(vpn, devices, say, others)
    secrets(vpn, say)
    crypto(vpn, say)
    routing(vpn, devices, say)
    reach(vpn, devices, say)
    nat(vpn, devices, say)
    wan_acls(vpn, devices, say)
    certificates(vpn, devices, say)
    lockout(vpn, devices, say, pc_ip)
    other_clouds(vpn, devices, say, others)
    shared(vpn, say, others)
    order = {ERROR: 0, WARNING: 1, INFO: 2}
    return sorted(found, key=lambda item: order.get(item.severity, 3))


def members(vpn, devices, say):
    if vpn.kind in V.POINT_TO_POINT + (V.CRYPTO_MAP,) and len(vpn.members) != 2:
        say(ERROR, f"A {V.KIND_NAMES[vpn.kind]} VPN joins exactly two routers ({len(vpn.members)} chosen).")
    if vpn.kind == V.DMVPN:
        if not vpn.hubs():
            say(ERROR, "A DMVPN needs a hub.")
        if len(vpn.hubs()) > 2:
            say(WARNING, "More than two hubs in one cloud: spokes register with each (that's fine, but unusual).")
        if vpn.dmvpn.phase == 1 and len(vpn.hubs()) > 1:
            say(ERROR, "DMVPN phase 1 spokes have a point-to-point tunnel to one hub: use phase 2 or 3 for two hubs.")
        if not vpn.spokes():
            say(WARNING, "The DMVPN has no spokes yet.")
    keys = [member.key for member in vpn.members]
    if len(set(keys)) != len(keys):
        say(ERROR, "A router is in the VPN twice.")
    for member in vpn.members:
        device = devices.get(member.key)
        if member.key.startswith("peer:"):
            say(INFO, f"{member.title()} wasn't read (only its address is known): nothing is sent to it, so its side "
                      f"has to match by hand.", member.key)
            continue
        if device is None or not device.read:
            say(ERROR, f"{member.title()} hasn't been read yet: read it first.", member.key)
            continue
        if not member.wan:
            say(ERROR, f"{member.title()} has no WAN interface chosen.", member.key)
        elif not member.local_ip:
            say(ERROR, f"{member.title()}'s WAN interface {member.wan} has no IPv4 address.", member.key)
        elif member.wan not in device.interfaces() and V.full_interface(member.wan) not in device.interfaces():
            say(ERROR, f"{member.title()} has no interface {member.wan}.", member.key)
        else:
            interface = device.interfaces().get(V.full_interface(member.wan))
            if interface is not None and interface.shutdown:
                say(ERROR, f"{member.title()}'s WAN interface {member.wan} is shut down.", member.key)
        if vpn.kind == V.CRYPTO_MAP and not member.lans:
            say(ERROR, f"{member.title()} has no LANs: a crypto map only protects traffic between the LANs.",
                member.key)
        if vpn.kind == V.CRYPTO_MAP and any(prefix in ("0.0.0.0/0",) for prefix in member.lans):
            say(WARNING, f"{member.title()}'s LAN is 0.0.0.0/0: everything it sends out of {member.wan} would go "
                         f"into the VPN (management included).", member.key)


def addresses(vpn, devices, say, others):
    if vpn.kind == V.CRYPTO_MAP:
        return
    subnet = network(vpn.subnet)
    if subnet is None:
        say(ERROR, "The tunnel subnet isn't a subnet.")
        return
    if vpn.kind in V.POINT_TO_POINT and subnet.prefixlen < 29:
        say(INFO, f"{vpn.subnet} is bigger than a point-to-point tunnel needs (/30 or /31).")
    seen = {}
    for member in vpn.members:
        if member.key.startswith("peer:"):
            continue
        if not member.tunnel:
            say(ERROR, f"{member.title()} has no tunnel number.", member.key)
        if not member.tunnel_ip:
            say(ERROR, f"{member.title()} has no tunnel address.", member.key)
            continue
        try:
            address = ipaddress.IPv4Address(member.tunnel_ip)
        except ValueError:
            say(ERROR, f"{member.title()}'s tunnel address {member.tunnel_ip} isn't an address.", member.key)
            continue
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address) and \
                subnet.prefixlen < 31:
            say(ERROR, f"{member.title()}'s tunnel address {member.tunnel_ip} isn't a host in {vpn.subnet}.",
                member.key)
        if member.tunnel_ip in seen:
            say(ERROR, f"{member.title()} and {seen[member.tunnel_ip]} have the same tunnel address.", member.key)
        seen[member.tunnel_ip] = member.title()
        device = devices.get(member.key)
        if device is None or not device.read:
            continue
        own = f"Tunnel{member.tunnel}".lower()
        for name, interface in device.interfaces().items():
            if name.lower() == own:
                continue
            for item, length in interface.addresses:
                taken = ipaddress.IPv4Interface(f"{item}/{length}").network
                if taken.overlaps(subnet):
                    say(ERROR, f"{member.title()}'s {name} ({item}/{length}) overlaps the tunnel subnet {vpn.subnet}.",
                        member.key)
        if not vpn.found and f"Tunnel{member.tunnel}" in device.interfaces() and \
                not any(item.member(member.key) and item.member(member.key).tunnel == member.tunnel
                        for item in others if item.id == vpn.id):
            say(ERROR, f"{member.title()} already has Tunnel{member.tunnel}: pick another number.", member.key)


def secrets(vpn, say):
    if vpn.protected and vpn.auth.method == V.PSK:
        key = vpn.auth.psk
        if not key:
            say(ERROR, "There's no pre-shared key.")
        elif any(character in key for character in " ?\"'\t"):
            say(ERROR, "The pre-shared key has a space, quote or ? in it (IOS takes ? as help): use letters and "
                       "digits.")
        elif len(key) < 16 and not key.startswith(("6 ", "7 ", "0 ")):
            say(WARNING, f"The pre-shared key is short ({len(key)} characters): use 16 or more (Generate makes 24).")
    if vpn.kind == V.DMVPN and vpn.dmvpn.auth and len(vpn.dmvpn.auth) > 8:
        say(ERROR, "NHRP authentication takes at most 8 characters.")
    if vpn.kind == V.DMVPN and vpn.protected and vpn.auth.method == V.PSK:
        say(INFO, "Every DMVPN router uses the same key for any peer (spokes talk to each other directly).")


def crypto(vpn, say):
    if not vpn.protected:
        say(WARNING, "Plain GRE isn't encrypted: anything on the path can read it. Use GRE over IPsec unless "
                     "something else encrypts it.")
        return
    settings = vpn.crypto
    if settings.ike == V.IKEV2:
        if settings.gcm() and settings.integrity:
            say(ERROR, "An IKEv2 proposal with AES-GCM takes a PRF, not an integrity algorithm.")
        if not settings.gcm() and not settings.integrity:
            say(ERROR, "The IKEv2 proposal needs an integrity algorithm (or use AES-GCM).")
        if not settings.encryption:
            say(ERROR, "The IKEv2 proposal has no encryption.")
    weak = [item for item in settings.encryption + settings.integrity if item.split()[0] in WEAK_IKE]
    if weak:
        say(WARNING, f"Weak IKE algorithms: {', '.join(weak)}.")
    groups = [group for group in settings.groups if group in WEAK_GROUPS]
    if groups:
        say(WARNING, f"Weak Diffie-Hellman groups: {', '.join(map(str, groups))} (use 14, 19, 20 or 21).")
    if settings.pfs in WEAK_GROUPS:
        say(WARNING, f"PFS group {settings.pfs} is weak.")
    if any(word in settings.esp for word in ("esp-des", "esp-3des", "md5")):
        say(WARNING, f"The IPsec transform ({settings.esp}) is weak.")
    if settings.ike == V.IKEV1:
        say(INFO, "IKEv1 is old (and gone from newer IOS XE): use IKEv2 unless the far end can't.")
    if vpn.kind == V.VTI and V.esp_mode(vpn) == V.TRANSPORT:
        say(ERROR, "An IPsec VTI needs tunnel mode.")
    if vpn.mtu and vpn.protected and vpn.mtu > 1440:
        say(WARNING, f"IP MTU {vpn.mtu} leaves too little room for the GRE and IPsec headers on a 1500-byte "
                     f"path: 1400 is usual.")
    if vpn.mss and vpn.mtu and vpn.mss > vpn.mtu - 40:
        say(WARNING, f"TCP MSS {vpn.mss} is more than the MTU ({vpn.mtu}) less 40: big TCP segments get fragmented.")
    if not vpn.mtu and vpn.kind != V.CRYPTO_MAP:
        say(WARNING, "No tunnel IP MTU: big packets get fragmented after encryption (slow, and some paths drop "
                     "fragments).")


def distance(vpn, member):
    kind = vpn.routing.kind
    if kind == V.BGP:
        far = [other for other in vpn.others(member) if other.bgp_as]
        return 200 if far and all(other.bgp_as == member.bgp_as for other in far) else 20
    return ADMIN_DISTANCE.get(kind, 1)


def routing(vpn, devices, say):
    kind = vpn.routing.kind
    if kind == V.NO_ROUTING:
        if vpn.kind != V.CRYPTO_MAP:
            say(INFO, "No routing across it: route the far LANs into the tunnel yourself.")
        return
    lans_all = {member.key: [network(prefix) for prefix in member.lans if network(prefix)] for member in vpn.members}
    for member in vpn.members:
        device = devices.get(member.key)
        if device is None or not device.read:
            continue
        far_members = vpn.others(member)
        # Recursive routing: a far end's public address inside what goes over the VPN
        for other in far_members:
            for prefix in [item for key, items in lans_all.items() if key != member.key for item in items]:
                if other.reached_at and ipaddress.IPv4Address(other.reached_at) in prefix:
                    say(ERROR, f"{other.title()}'s address {other.reached_at} is inside {prefix}, which "
                               f"{member.title()} would send over the VPN: the tunnel would be routed through itself "
                               f"(recursive routing) and flap.", member.key)
        # LANs that cover its own WAN network
        wan_address, wan_length = device.interface_address(V.full_interface(member.wan)) if member.wan else ("", 0)
        if wan_address:
            wan = ipaddress.IPv4Interface(f"{wan_address}/{wan_length}").network
            for prefix in lans_all.get(member.key, []):
                if wan.overlaps(prefix):
                    say(ERROR, f"{member.title()}'s LAN {prefix} covers its WAN network {wan}: advertising it over the "
                               f"tunnel breaks the tunnel.", member.key)
        # LANs a dynamic protocol can't advertise
        if kind in (V.EIGRP, V.OSPF, V.BGP):
            for prefix in member.lans:
                interface, _ = device.interface_in(prefix)
                if kind != V.BGP and not interface:
                    say(WARNING, f"{prefix} isn't on an interface of {member.title()}: {V.ROUTING_NAMES[kind]} won't "
                                 f"advertise it (use static routing, or redistribute it).", member.key)
                connected = any(item.network == network(prefix) for item in device.networks())
                if kind == V.BGP and not connected and \
                        not any(route.prefix == str(network(prefix)) for route in device.routes):
                    say(WARNING, f"{member.title()} has no route exactly matching {prefix}: BGP won't advertise "
                                 f"its network statement.", member.key)
        # Far LANs it already reaches some better way (the VPN's routes would lose)
        mine = distance(vpn, member)
        for other in far_members:
            for prefix in other.lans:
                route = next((item for item in device.routes if item.prefix == str(network(prefix))), None)
                if route is None:
                    continue
                if any(hop in [item.tunnel_ip for item in vpn.members] for hop in route.next_hops) or \
                        any(item.lower().startswith(f"tunnel{member.tunnel}") or
                            item.lower() == f"tu{member.tunnel}" for item in route.interfaces):
                    continue
                theirs = route.distance if route.distance or route.protocol in ("C", "L") else \
                    PROTOCOL_DISTANCE.get(route.protocol, 255)
                if theirs < mine:
                    via = f" via {', '.join(route.next_hops)}" if route.next_hops else ""
                    say(WARNING, f"{member.title()} already reaches {prefix} by {route.protocol} (distance "
                                 f"{theirs}){via}: that beats the VPN's route ({mine}), so traffic would keep going "
                                 f"that way (in the clear if it's the internet).", member.key)
        if kind == V.BGP:
            bgp_checks(vpn, member, device, say)
        if kind == V.OSPF and vpn.kind == V.DMVPN and vpn.dmvpn.phase == 2 and member.role == V.SPOKE:
            say(INFO, f"{member.title()} gets OSPF priority 0 (only hubs can be the DR on a phase 2 cloud).",
                member.key)
    if vpn.kind == V.DMVPN and vpn.dmvpn.phase == 2 and kind == V.BGP:
        hubs = vpn.hubs()
        if any(spoke.bgp_as != hub.bgp_as for spoke in vpn.spokes() for hub in hubs):
            say(INFO, "eBGP on a phase 2 cloud: the hub passes routes on with the spokes' tunnel addresses as next "
                      "hops only because they share the tunnel subnet. Phase 3 doesn't depend on that.")


def must_reach(vpn, member, other):
    """How bad it is when a router has no route to another's WAN address: ERROR when the tunnel can't come up
    without it, WARNING when only some traffic suffers (spoke to spoke), None when they never talk directly."""
    if vpn.kind != V.DMVPN:
        return ERROR
    if member.role == V.HUB and other.role == V.HUB:
        return None
    if member.role == V.SPOKE and other.role == V.SPOKE:
        return WARNING if vpn.dmvpn.phase in (2, 3) else None
    return ERROR


def reach(vpn, devices, say):
    """Each router needs a route (outside the VPN) to the far ends' WAN addresses (IKE and GRE go there) and to the
    CA it enrolls with. A route out of another interface than the tunnel's source is worth a look too."""
    for member in vpn.members:
        device = devices.get(member.key)
        if device is None or not device.read or not device.routes:
            continue
        for other in vpn.others(member):
            severity = must_reach(vpn, member, other)
            if severity is None or not other.reached_at:
                continue
            route = device.route_to(other.reached_at)
            if route is None:
                say(severity, f"{member.title()} has no route to {other.title()}'s address {other.reached_at} "
                              f"({other.wan or 'its WAN'}), so the tunnel can't reach it. If that's the wrong "
                              f"interface for {other.title()}, pick the one it's reached through (Edit...); "
                              f"otherwise give {member.title()} a route to it.", member.key)
                continue
            out = V.wan_toward(device, other.reached_at)
            if out and member.wan and V.full_interface(out).lower() != V.full_interface(member.wan).lower() and                     not out.lower().startswith("tunnel"):
                say(WARNING, f"{member.title()} reaches {other.title()} ({other.reached_at}) out of {out}, not the "
                             f"tunnel's source {member.wan}: its packets would leave by another way than their "
                             f"address says (an ISP may drop them). Check {member.title()}'s WAN interface.",
                    member.key)
        if vpn.protected and vpn.auth.method == V.CERT:
            ca_host = ca_address(vpn)
            ca = vpn.member(vpn.auth.ca_device) if vpn.auth.ca_kind == "router" else None
            if ca_host and (ca is None or ca.key != member.key) and device.route_to(ca_host) is None:
                say(ERROR, f"{member.title()} has no route to the CA at {ca_host}: it can't fetch the CA's "
                           f"certificate or enroll.", member.key)


def ca_address(vpn):
    """The address the members enroll with (the CA router's, or the host in the SCEP URL if it's an address)."""
    if vpn.auth.ca_kind == "router":
        ca = vpn.member(vpn.auth.ca_device)
        return ca.reached_at if ca is not None else ""
    host = re.sub(r"^\w+://", "", vpn.auth.ca_url or "").split("/")[0].split(":")[0]
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return ""


def bgp_checks(vpn, member, device, say):
    local_as = device.bgp_as() or member.bgp_as
    if not local_as:
        say(ERROR, f"{member.title()} has no BGP process: give it an AS number.", member.key)
        return
    if member.bgp_as and device.bgp_as() and member.bgp_as != device.bgp_as():
        say(WARNING, f"{member.title()} runs BGP AS {device.bgp_as()}, not {member.bgp_as}: AS {device.bgp_as()} is "
                     f"used.", member.key)
    process = device.block(f"router bgp {local_as}")
    if process is None:
        return
    tunnel_peers = {item.tunnel_ip for item in vpn.members if item.tunnel_ip}
    unguarded = []
    for neighbor, entry in V.bgp_neighbors(process).items():
        if entry["group"] or neighbor in tunnel_peers or not entry["remote-as"] or entry["remote-as"] == local_as:
            continue
        if not V.ipaddress_like(neighbor):
            continue
        out = entry["out"]
        if any(" route-map " in line or " filter-list " in line or " distribute-list " in line for line in out):
            say(WARNING, f"{member.title()}'s BGP neighbor {neighbor} (AS {entry['remote-as']}) has an outbound route "
                         f"map or filter list: check it keeps the VPN's LANs from it (NOMAD only adds to prefix "
                         f"lists).", member.key)
        elif not vpn.routing.guard:
            unguarded.append(f"{neighbor} (AS {entry['remote-as']})")
    if unguarded:
        say(ERROR, f"Routes learned over the VPN would be passed on to {member.title()}'s other eBGP neighbors: "
                   f"{', '.join(unguarded)}. Tick Keep the VPN's LANs from other BGP neighbors.", member.key)
    elif vpn.routing.guard and any(V.ipaddress_like(neighbor) and entry["remote-as"] != local_as
                                   for neighbor, entry in V.bgp_neighbors(process).items()):
        say(INFO, f"{member.title()}'s other eBGP neighbors get a prefix list keeping the VPN's LANs from them.",
            member.key)
    for child in process.children:
        words = child.line.split()
        if words[:1] == ["redistribute"] and "route-map" not in words:
            say(WARNING, f"{member.title()} redistributes {' '.join(words[1:3])} into BGP with no route map: check "
                         f"that doesn't hand the VPN's routes to its ISP.", member.key)


def nat(vpn, devices, say):
    for member in vpn.members:
        if member.public_ip and member.public_ip != member.local_ip:
            say(INFO, f"{member.title()} is behind NAT ({member.local_ip} reached at {member.public_ip}): IKE moves to "
                      f"UDP 4500 (NAT-T); the others use {member.public_ip} to reach it and {member.local_ip} as its "
                      f"identity.", member.key)
            if vpn.protected and not vpn.crypto.nat_keepalive:
                say(WARNING, "NAT keepalives are off: a NAT mapping that times out drops the tunnel until the far "
                             "end re-keys.")
            if vpn.kind == V.DMVPN and member.role == V.HUB:
                say(INFO, f"Hub {member.title()} is behind NAT: spokes use its NBMA address {member.public_ip} "
                          f"(a static NAT on the hub's side is needed).", member.key)
        device = devices.get(member.key)
        if device is None or not device.read or vpn.kind != V.CRYPTO_MAP:
            continue
        for block in device.blocks("ip nat inside source"):
            words = block.line.split()
            if "overload" not in words or "list" not in words:
                continue
            name = words[words.index("list") + 1]
            acl = device.acls.acl(aclcheck.V4, name)
            if acl is None:
                continue
            for prefix in member.lans:
                for other in vpn.others(member):
                    for far in other.lans:
                        source = network(prefix)
                        target = network(far)
                        if source is None or target is None:
                            continue
                        packet = aclcheck.Packet(str(source.network_address + 1), str(target.network_address + 1),
                                                 protocol=0)
                        verdict = aclcheck.evaluate(acl, packet, device.acls.groups, device.acls.ranges)
                        if verdict.permitted:
                            say(ERROR, f"{member.title()}'s NAT (list {name}) would translate {prefix} -> {far} "
                                       f"before the crypto map sees it, so it never matches: add 'deny ip "
                                       f"{source.network_address} {V.wildcard_of(source.prefixlen)} "
                                       f"{target.network_address} {V.wildcard_of(target.prefixlen)}' at the top of "
                                       f"{name} (the ACLs page).", member.key)


def wan_acls(vpn, devices, say):
    """An ACL in on a WAN interface that drops what the VPN needs from its peers."""
    for member in vpn.members:
        device = devices.get(member.key)
        if device is None or not device.read or not member.wan:
            continue
        applied = [item for item in device.acls.applied if item.where == "interface" and item.direction == "in" and
                   V.full_interface(item.target) == V.full_interface(member.wan) and item.family == aclcheck.V4]
        for item in applied:
            acl = device.acls.acl(aclcheck.V4, item.acl)
            for other in vpn.others(member):
                if not other.reached_at or not member.local_ip:
                    continue
                needs = []
                if vpn.protected:
                    needs = [("IKE (UDP 500)", aclcheck.Packet(other.reached_at, member.local_ip, UDP, 500, 500)),
                             ("NAT-T (UDP 4500)", aclcheck.Packet(other.reached_at, member.local_ip, UDP, 4500, 4500)),
                             ("ESP", aclcheck.Packet(other.reached_at, member.local_ip, ESP))]
                    if not (other.public_ip or member.public_ip):
                        needs = [need for need in needs if "4500" not in need[0]]
                else:
                    needs = [("GRE", aclcheck.Packet(other.reached_at, member.local_ip, GRE_PROTOCOL))]
                for label, packet in needs:
                    verdict = aclcheck.evaluate(acl, packet, device.acls.groups, device.acls.ranges)
                    if not verdict.permitted:
                        say(ERROR, f"ACL {item.acl} in on {member.title()}'s {member.wan} drops {label} from "
                                   f"{other.title()} ({other.reached_at}): {verdict.text}", member.key)


def certificates(vpn, devices, say):
    if not vpn.protected or vpn.auth.method != V.CERT:
        return
    if not vpn.auth.ca_name:
        say(ERROR, "Certificates need the CA's name (its certificates' issuer) for the certificate maps.")
    if not vpn.auth.ca_kind:
        say(ERROR, "Choose where the certificates come from (a CA on one of the routers, a CA's SCEP URL, or "
                   "pasting them).")
    for member in vpn.members:
        device = devices.get(member.key)
        if device is None or device.status is None:
            continue
        status = device.status
        trustpoint = V.names(vpn, member)["trustpoint"]
        identity = next((item for item in status.certificates if trustpoint in item.trustpoints and
                         item.kind == "identity"), None)
        if identity is None:
            say(INFO, f"{member.title()} has no certificate in {trustpoint} yet: it's enrolled before the VPN is "
                      f"sent.", member.key)
        if not status.clock_set:
            say(WARNING, f"{member.title()}'s clock isn't authoritative (no NTP): IOS won't use certificates "
                         f"(PKI-2-NON_AUTHORITATIVE_CLOCK). Keep the clocks in step with NTP (the certificate step "
                         f"can set it up from the CA router).", member.key)


def lockout(vpn, devices, say, pc_ip):
    """Whether sending this could cut NOMAD (this PC) off from a router."""
    if not pc_ip:
        return
    try:
        pc = ipaddress.IPv4Address(pc_ip)
    except ValueError:
        return
    for member in vpn.members:
        for other in vpn.others(member):
            for prefix in other.lans:
                carried = network(prefix)
                if carried is not None and pc in carried:
                    say(ERROR, f"This PC ({pc_ip}) is in {prefix}, which {member.title()} would send over the VPN: "
                               f"NOMAD's own connection to {member.title()} would go into it.", member.key)
        device = devices.get(member.key)
        if device is None or not device.read:
            continue
        if vpn.kind == V.CRYPTO_MAP and device.toward_pc and member.wan and \
                V.full_interface(device.toward_pc) == V.full_interface(member.wan):
            say(INFO, f"NOMAD reaches {member.title()} through {member.wan}, where the crypto map goes: only traffic "
                      f"between the LANs is encrypted, so that's fine unless this PC is in one.", member.key)
    hubs_or_first = vpn.hubs() or vpn.members[:1]
    reached = [member for member in vpn.members if member.address and member.address == member.local_ip]
    if reached and hubs_or_first:
        names = ", ".join(member.title() for member in reached)
        say(INFO, f"NOMAD reaches {names} at {'its' if len(reached) == 1 else 'their'} WAN address: if a change cut "
                  f"that off, the revert timer puts it back.")


def other_clouds(vpn, devices, say, others):
    """Another VPN on a router taking IKE from any peer on the same address (a second DMVPN cloud on a spoke's one
    WAN link): IOS can't tell which profile a peer that connects is for, so their keys have to match."""
    if vpn.kind != V.DMVPN or not vpn.protected:
        return
    for other in others:
        if other.id == vpn.id or other.kind != V.DMVPN or not other.protected:
            continue
        for member in vpn.members:
            mine = other.member(member.key)
            if mine is None or not member.local_ip or mine.local_ip != member.local_ip:
                continue
            if vpn.auth.method == V.PSK and other.auth.method == V.PSK and other.auth.psk and \
                    other.auth.psk != vpn.auth.psk:
                say(ERROR, f"{member.title()} is in {other.name} on the same address ({member.local_ip}): IOS can't "
                           f"tell which cloud a peer connecting there is for, so the two need the same key (use "
                           f"{other.name}'s).", member.key)
                return


def shared(vpn, say, others):
    for member in vpn.members:
        for kind in member.names.get("shared") or ():
            name = member.names.get(kind)
            users = [item.name for item in others if item.id != vpn.id and item.member(member.key) and
                     item.member(member.key).names.get(kind) == name]
            if users:
                say(INFO, f"{member.title()}'s {kind.replace('_', ' ')} {name} is also used by {', '.join(users)}: "
                          f"changing it changes them too, and it stays if this VPN goes.", member.key)


def explain_refusal(line, error):
    """Plain words for a line a router refused, when NOMAD knows why."""
    text = f"{line} {error}".lower()
    if "invalid input" in text and line.strip().startswith("crypto"):
        return ("The router doesn't know this crypto command: its image or license has no crypto (a C8000V or "
                "CSR1000V needs a boot level license such as network-advantage; ISRs need securityk9).")
    if "is in use" in text or "please remove" in text:
        return "Something still uses it (a tunnel, crypto map or live session)."
    if "peer-group member" in text:
        return "That BGP neighbor is in a peer group: its filters go on the group."
    if "shared" in text and "tunnel source" in text:
        return "Two tunnels with the same source and IPsec profile need the 'shared' keyword (or separate profiles)."
    return ""
