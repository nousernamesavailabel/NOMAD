"""VPNs: the configuration made for each kind, the change planned against what a router has (and its exact undo), and
VPNs found on routers coming back as the same design (so an unchanged VPN plans no lines)."""
import pytest

from nomad.netmap import vpn, vpnfind
from nomad.netmap.vpn import BGP, CRYPTO_MAP, DMVPN, EIGRP, GRE, GRE_IPSEC, HUB, IKEV1, NO_ROUTING, OSPF, SPOKE, \
    STATIC, VTI, Member, Vpn

HUB_RUNNING = """hostname R5
!
interface Loopback0
 ip address 10.18.0.15 255.255.255.255
!
interface Loopback250
 ip address 10.250.5.1 255.255.255.0
!
interface GigabitEthernet1.172
 encapsulation dot1Q 172
 ip address 172.18.0.15 255.255.255.0
!
interface GigabitEthernet2
 ip address 8.0.0.18 255.255.255.252
!
interface GigabitEthernet3
 ip address 8.0.0.2 255.255.255.252
!
router ospf 1
 router-id 10.18.0.15
 network 10.18.0.15 0.0.0.0 area 1
 network 172.18.0.0 0.0.0.255 area 1
!
router bgp 18
 bgp log-neighbor-changes
 network 8.0.0.0 mask 255.255.255.252
 network 8.0.0.16 mask 255.255.255.252
 redistribute ospf 1 route-map BGP-TO-ISP
 neighbor 8.0.0.1 remote-as 28
 neighbor 8.0.0.17 remote-as 27
!
ip prefix-list BGP-TO-ISP seq 10 permit 192.168.5.0/24
"""

SPOKE_RUNNING = """hostname {name}
!
interface Loopback250
 ip address 10.250.{n}.1 255.255.255.0
!
interface GigabitEthernet1
 ip address {wan} 255.255.255.252
!
router bgp {asn}
 bgp log-neighbor-changes
 network {net} mask 255.255.255.252
 neighbor ISP peer-group
 neighbor {isp} remote-as 30
 neighbor {isp} peer-group ISP
!
"""

ROUTES = """Gateway of last resort is not set

      8.0.0.0/8 is variably subnetted, 8 subnets, 2 masks
B        8.0.0.0/30 [20/0] via {hop}, 00:15:38
B        8.0.0.16/30 [20/0] via {hop}, 00:15:38
B        8.0.0.20/30 [20/0] via {hop}, 00:15:38
B        8.0.0.24/30 [20/0] via {hop}, 00:15:38
"""


def devices():
    r5 = vpn.parse_device(HUB_RUNNING, ROUTES.format(hop="8.0.0.17"), "Cisco IOS XE Software, Version 17.04.02")
    r6 = vpn.parse_device(SPOKE_RUNNING.format(name="R6C8K", n=6, wan="8.0.0.22", asn=180, net="8.0.0.20",
                                               isp="8.0.0.21"), ROUTES.format(hop="8.0.0.21"),
                          "Cisco IOS XE Software, Version 17.04.02")
    r7 = vpn.parse_device(SPOKE_RUNNING.format(name="R7C8K", n=7, wan="8.0.0.26", asn=181, net="8.0.0.24",
                                               isp="8.0.0.25"), ROUTES.format(hop="8.0.0.25"),
                          "Cisco IOS XE Software, Version 17.04.02")
    return {"R5": r5, "R6": r6, "R7": r7}


WANS = {"R5": ("GigabitEthernet2", "8.0.0.18", "18"), "R6": ("GigabitEthernet1", "8.0.0.22", "180"),
        "R7": ("GigabitEthernet1", "8.0.0.26", "181")}


def member(key, role=vpn.PEER):
    wan, ip, asn = WANS[key]
    return Member(key, key, ip, role, wan, ip, lans=[f"10.250.{key[1]}.0/24"], bgp_as=asn)


def design(kind, routing=STATIC, keys=("R6", "R7"), crypto=vpn.MODERN):
    item = Vpn(name=f"T-{kind}", kind=kind, crypto=vpn.preset(crypto))
    item.auth.psk = "Secr3tKeyABC"
    if kind == DMVPN:
        item.members = [member("R5", HUB), member("R6", SPOKE), member("R7", SPOKE)]
        item.dmvpn.auth = "nh5ecret"
    else:
        item.members = [member(key) for key in keys]
    item.routing.kind = routing
    found = devices()
    item.subnet = vpn.suggest_subnet(item, [found[m.key] for m in item.members])
    number = vpn.suggest_tunnel([found[m.key] for m in item.members], 100 if kind == DMVPN else 10)
    for m in item.members:
        m.tunnel = number
    vpn.assign_addresses(item)
    return item, found


def reads(found):
    return [vpnfind.Read(key, key, WANS[key][1], device) for key, device in found.items()]


def test_vti_lines_in_the_order_ios_takes_them():
    item, found = design(VTI, EIGRP)
    change = vpn.vpn_changes(None, item, found)["R6"]
    text = change.text()
    order = ["crypto ikev2 proposal", "crypto ikev2 policy", "crypto ikev2 keyring", "crypto ikev2 profile",
             "crypto ipsec transform-set", "crypto ipsec profile", "interface Tunnel10", "router eigrp 100"]
    positions = [text.index(item) for item in order]
    assert positions == sorted(positions)
    assert " tunnel mode ipsec ipv4" in text and " tunnel destination 8.0.0.26" in text
    assert " match identity remote address 8.0.0.26 255.255.255.255" in text
    assert " network 172.31.0.1 0.0.0.0" in text and " network 10.250.6.1 0.0.0.0" in text
    assert " mode tunnel" in text
    undo = change.undo_text()
    assert undo.index("no router eigrp 100") < undo.index("no interface Tunnel10") < \
        undo.index("no crypto ipsec profile") < undo.index("no crypto ikev2 proposal")


def test_keys_are_masked_in_what_is_shown():
    item, found = design(DMVPN, EIGRP)
    text = vpn.vpn_changes(None, item, found)["R5"].text()
    assert "Secr3tKeyABC" in text and "nh5ecret" in text
    shown = vpn.mask(text)
    assert "Secr3tKeyABC" not in shown and "nh5ecret" not in shown
    assert "pre-shared-key ********" in shown and "ip nhrp authentication ********" in shown
    assert vpn.mask("crypto isakmp key 6 abcdef address 1.2.3.4") == "crypto isakmp key 6 ******** address 1.2.3.4"
    assert vpn.mask(" pre-shared-key address 1.2.3.4 key s3cret") == " pre-shared-key address 1.2.3.4 key ********"


@pytest.mark.parametrize("kind,routing", [(VTI, STATIC), (VTI, EIGRP), (VTI, OSPF), (VTI, BGP), (GRE, STATIC),
                                          (GRE_IPSEC, OSPF), (CRYPTO_MAP, STATIC), (DMVPN, EIGRP), (DMVPN, OSPF),
                                          (DMVPN, BGP), (DMVPN, STATIC)])
def test_a_vpn_read_back_plans_nothing_and_its_undo_restores_the_routers(kind, routing):
    item, found = design(kind, routing, keys=("R5", "R7") if kind == CRYPTO_MAP else ("R6", "R7"))
    after = vpn.devices_after(None, item, found)
    vpns = vpnfind.find(reads(after))
    assert len(vpns) == 1, [v.name for v in vpns]
    again = vpns[0]
    assert again.kind == kind and again.name == item.name
    assert again.routing.kind == routing
    assert sorted(m.key for m in again.members) == sorted(m.key for m in item.members)
    assert again.auth.psk == ("" if kind == GRE else "Secr3tKeyABC")
    for key, change in vpn.vpn_changes(again, again, after).items():
        assert not change.lines, (key, change.lines)
    # Taking it away (as found) gives back the routers as they were, but for what other VPNs may share (NAT
    # keepalives, an IKEv1 policy, the BGP guard)
    gone = vpn.devices_after(again, None, after)
    for key, device in found.items():
        left, right = vpn.render(gone[key].tree), vpn.render(device.tree)
        assert not [line for line in right if line not in left], key
        assert all(shared(line) for line in left if line not in right), (key, [l for l in left if l not in right])


def shared(line):
    return line.startswith(("crypto ikev2 nat keepalive", "crypto isakmp nat keepalive", "crypto isakmp policy",
                            " encryption", " hash", " authentication", " group")) or \
        "NOMAD-VPN-GUARD" in line and (" permit 0.0.0.0/0" in line or line.startswith(" neighbor"))


def test_dmvpn_phase_and_roles_found():
    item, found = design(DMVPN, EIGRP)
    item.dmvpn.phase = 2
    after = vpn.devices_after(None, item, found)
    again = vpnfind.find(reads(after))[0]
    assert again.dmvpn.phase == 2
    assert [m.key for m in again.hubs()] == ["R5"] and sorted(m.key for m in again.spokes()) == ["R6", "R7"]
    hub = vpn.vpn_changes(None, item, found)["R5"].text()
    assert " no ip split-horizon eigrp 100" in hub and " no ip next-hop-self eigrp 100" in hub
    assert " ip nhrp map multicast dynamic" not in hub  # IOS XE's default (hidden from running-config)
    found["R5"].xe = False
    assert " ip nhrp map multicast dynamic" in vpn.vpn_changes(None, item, found)["R5"].text()
    spoke = vpn.vpn_changes(None, item, found)["R6"].text()
    assert " ip nhrp nhs 172.31.0.1 nbma 8.0.0.18 multicast" in spoke and "ip nhrp redirect" not in spoke


def test_editing_changes_only_what_changed():
    item, found = design(VTI, EIGRP)
    after = vpn.devices_after(None, item, found)
    again = vpnfind.find(reads(after))[0]
    edited = again.copy()
    edited.crypto = vpn.preset(vpn.COMPATIBLE)
    edited.mtu = 1380
    change = vpn.vpn_changes(again, edited, after)["R6"]
    assert change.lines == ["crypto ikev2 proposal T-vti-PROP", " encryption aes-cbc-256", " integrity sha256",
                            " group 14", "crypto ipsec transform-set T-vti-TS esp-aes 256 esp-sha256-hmac",
                            "interface Tunnel10", " ip mtu 1380"] or "prf" in " ".join(change.lines)
    assert any(line.strip() == "no prf sha384" for line in change.lines)
    assert any(line.strip() == "ip mtu 1380" for line in change.lines)
    # Undo puts it back exactly
    done = vpn.devices_after(again, edited, after)
    undone = vpn.applied(done["R6"], vpn.footprint(edited, edited.member("R6"), done["R6"]),
                         vpn.footprint(again, again.member("R6"), done["R6"]))
    assert vpn.render(undone.tree) == vpn.render(after["R6"].tree)


def test_bgp_keeps_the_vpn_lans_from_the_isp():
    item, found = design(DMVPN, BGP)
    text = vpn.vpn_changes(None, item, found)["R6"].text()
    assert "ip prefix-list NOMAD-VPN-GUARD seq 997 deny 10.250.5.0/24 le 32" in text
    assert "ip prefix-list NOMAD-VPN-GUARD seq 1000 permit 0.0.0.0/0 le 32" in text
    assert " neighbor ISP prefix-list NOMAD-VPN-GUARD out" in text  # Its ISP neighbor is in a peer group
    hub = vpn.vpn_changes(None, item, found)["R5"].text()
    assert " neighbor 8.0.0.1 prefix-list NOMAD-VPN-GUARD out" in hub
    assert hub.index("neighbor T-dmvpn-SPOKES peer-group") < hub.index("bgp listen range")
    assert " neighbor T-dmvpn-SPOKES remote-as 180 alternate-as 181" in hub


def test_a_single_address_lan_is_kept_from_the_isp_without_le_32():
    item, found = design(DMVPN, BGP)
    item.member("R5").lans = ["10.18.0.15/32"]
    lines = vpn.vpn_changes(None, item, found)["R6"].lines
    assert "ip prefix-list NOMAD-VPN-GUARD seq 997 deny 10.18.0.15/32" in lines  # IOS refuses le 32 on a /32
    assert "ip prefix-list NOMAD-VPN-GUARD seq 998 deny 10.250.6.0/24 le 32" in lines


def test_a_wan_with_a_crypto_map_gets_an_entry_in_it_not_a_new_map():
    item, found = design(CRYPTO_MAP, STATIC, keys=("R5", "R7"))
    after = vpn.devices_after(None, item, found)
    second = Vpn(name="Second", kind=CRYPTO_MAP, crypto=vpn.preset(vpn.LEGACY))
    second.auth.psk = "An0therKey99"
    second.members = [member("R5"), Member("far", "far", "9.9.9.9", local_ip="9.9.9.9", lans=["10.9.0.0/16"])]
    change = vpn.vpn_changes(None, second, after)["R5"]
    text = change.text()
    assert "crypto map T-crypto-map-MAP 20 ipsec-isakmp" in text
    assert "interface GigabitEthernet2" not in text  # Its map is already on it
    # Taking the second away leaves the map on the interface (the first VPN's entry is still in it)
    both = vpn.devices_after(None, second, after)
    found_both = vpnfind.find(reads({"R5": both["R5"], "R7": after["R7"]}))
    entry = next(v for v in found_both if v.name == "Second")
    lines = vpn.vpn_changes(entry, None, {"R5": both["R5"]})["R5"].lines
    assert "no crypto map T-crypto-map-MAP 20" in lines
    assert not any("interface GigabitEthernet2" in line for line in lines)


def test_ikev1_crypto_map_reuses_an_identical_policy():
    item, found = design(CRYPTO_MAP, STATIC, keys=("R5", "R7"), crypto=vpn.LEGACY)
    assert item.crypto.ike == IKEV1
    after = vpn.devices_after(None, item, found)
    again = vpnfind.find(reads(after))[0]
    assert again.member("R5").names["isakmp_policy"] == "10"
    lines = vpn.vpn_changes(again, None, after)["R5"].lines
    assert "no crypto isakmp policy 10" not in lines  # Policies are shared by every IKEv1 peer: left


def test_found_without_far_end_read():
    item, found = design(VTI, STATIC)
    after = vpn.devices_after(None, item, found)
    vpns = vpnfind.find([vpnfind.Read("R6", "R6", "8.0.0.22", after["R6"])])
    assert len(vpns) == 1 and len(vpns[0].members) == 2
    far = next(m for m in vpns[0].members if m.key.startswith("peer:"))
    assert far.local_ip == "8.0.0.26"
    changes = vpn.vpn_changes(vpns[0], vpns[0], {"R6": after["R6"]})
    assert list(changes) == ["R6"] and not changes["R6"].lines


def test_routes_parsed():
    routes = vpn.parse_routes("""Gateway of last resort is 172.18.0.1 to network 0.0.0.0

O*E2  0.0.0.0/0 [110/10] via 172.18.0.1, 00:30:29, GigabitEthernet1.172
      8.0.0.0/8 is variably subnetted, 9 subnets, 2 masks
C        8.0.0.0/30 is directly connected, GigabitEthernet3
L        8.0.0.2/32 is directly connected, GigabitEthernet3
O        10.18.0.111/32
           [110/12] via 172.18.0.11, 00:30:29, GigabitEthernet1.172
      27.0.0.0/32 is subnetted, 1 subnets
B        27.27.27.27 [20/0] via 8.0.0.17, 00:29:46
B     192.168.5.0/24 [20/0] via 8.0.0.21, 00:15:38
""")
    by = {route.prefix: route for route in routes}
    assert by["0.0.0.0/0"].protocol == "O" and by["0.0.0.0/0"].next_hops == ["172.18.0.1"]
    assert by["8.0.0.0/30"].interfaces == ["GigabitEthernet3"] and by["8.0.0.0/30"].distance == 0
    assert by["10.18.0.111/32"].next_hops == ["172.18.0.11"] and by["10.18.0.111/32"].distance == 110
    assert by["27.27.27.27/32"].distance == 20
    assert "192.168.5.0/24" in by


def test_no_routing_and_shared_source_key():
    item, found = design(DMVPN, NO_ROUTING)
    second = item.copy()
    second.id, second.name = "second", "Cloud2"
    second.subnet = "172.31.1.0/24"
    for m in second.members:
        m.tunnel, m.tunnel_ip = 101, ""
    hub = second.member("R5")
    hub.wan, hub.local_ip = "GigabitEthernet3", "8.0.0.2"  # The hub's other WAN link: no other tunnel on it
    vpn.assign_addresses(second)
    after = vpn.devices_after(None, item, found)
    changes = vpn.vpn_changes(None, second, after)
    assert " tunnel key 101" in changes["R6"].text()  # Two multipoint tunnels on one source need keys...
    assert " tunnel key 101" in changes["R5"].text()  # ...and every router in the cloud the same one


def test_a_crypto_map_vpn_clears_its_sessions_before_its_profile_goes():
    item, found = design(CRYPTO_MAP, STATIC, keys=("R5", "R7"), crypto=vpn.LEGACY)
    after = vpn.devices_after(None, item, found)
    again = vpnfind.find(reads(after))[0]
    lines = vpn.vpn_changes(again, None, after)["R5"].lines
    assert lines.index("no crypto map T-crypto-map-MAP 10") < \
        lines.index("do clear crypto session remote 8.0.0.26") < lines.index("no crypto isakmp profile T-crypto-map-IKE")


def test_two_clouds_sharing_a_policy_each_keep_their_own_proposal():
    item, found = two_clouds()
    after = vpn.devices_after(None, item[0], found)
    after = vpn.devices_after(None, item[1], after)
    policy = after["R6"].block("crypto ikev2 policy T-dmvpn-POL")
    assert [child.line for child in policy.children if child.line.startswith("proposal")] == \
        ["proposal T-dmvpn-PROP", "proposal Cloud2-PROP"]
    clouds = {v.name: v for v in vpnfind.find(reads(after))}
    assert clouds["Cloud2"].member("R6").names["proposal"] == "Cloud2-PROP"
    gone = vpn.devices_after(clouds["Cloud2"], None, after)
    gone = vpn.devices_after(clouds["T-dmvpn"], None, gone)
    assert not [block.line for block in gone["R6"].tree if block.line.startswith(("crypto ikev2 proposal",
                                                                                   "crypto ikev2 policy"))]


def two_clouds():
    first, found = design(DMVPN, EIGRP)
    second = first.copy()
    second.id, second.name, second.subnet = "two", "Cloud2", "172.31.1.0/24"
    for m in second.members:
        m.tunnel, m.tunnel_ip = 101, ""
    vpn.assign_addresses(second)
    return (first, second), found
