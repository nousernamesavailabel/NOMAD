"""VPNs built by hand, found on routers: keys of their own on each end (pre-shared-key local/remote), and tunnels
numbered alike on many routers (Tunnel1 everywhere) found as the VPNs they are, each router's side read."""
from nomad.netmap import vpn, vpncheck, vpnfind
from nomad.netmap.vpn import DMVPN, HUB, SPOKE, VTI

XE = "Cisco IOS XE Software, Version 17.04.02"

VTI_RUNNING = """hostname {name}
!
interface GigabitEthernet1
 ip address {wan} 255.255.255.0
!
interface Tunnel1
 ip address {tip} 255.255.255.252
 ip mtu {mtu}
 ip tcp adjust-mss 1360
 tunnel source GigabitEthernet1
 tunnel mode ipsec ipv4
 tunnel destination {peer}
 tunnel protection ipsec profile PROF
!
crypto ikev2 proposal PROP
 encryption {encryption}
 integrity sha256
 group 14
!
crypto ikev2 policy POL
 proposal PROP
!
crypto ikev2 keyring KR
 peer FAR
  address {peer}
{keys}
!
crypto ikev2 profile IKE
 match identity remote address {peer} 255.255.255.255
 authentication remote pre-share
 authentication local pre-share
 keyring local KR
!
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
 mode tunnel
!
crypto ipsec profile PROF
 set transform-set TS
 set ikev2-profile IKE
!
"""


def vti_router(name, wan, peer, tip, keys, mtu=1400, encryption="aes-cbc-256"):
    text = VTI_RUNNING.format(name=name, wan=wan, peer=peer, tip=tip, mtu=mtu, encryption=encryption,
                              keys="\n".join(f"  {line}" for line in keys))
    return vpn.parse_device(text, "", XE)


def reads(found):
    return [vpnfind.Read(key, key, device.interface_address("GigabitEthernet1")[0], device)
            for key, device in found.items()]


def asymmetric_pair():
    return {"A": vti_router("A", "1.1.1.1", "2.2.2.2", "10.0.0.1",
                            ["pre-shared-key local KeyFromAaaaaaaa1", "pre-shared-key remote KeyFromBbbbbbbb2"]),
            "B": vti_router("B", "2.2.2.2", "1.1.1.1", "10.0.0.2",
                            ["pre-shared-key local KeyFromBbbbbbbb2", "pre-shared-key remote KeyFromAaaaaaaa1"])}


def test_local_and_remote_keys_are_read_as_keys():
    assert vpnfind.key_lines(["address 2.2.2.2", "pre-shared-key local Abc", "pre-shared-key remote Xyz"]) == \
        ("Abc", "Xyz")
    assert vpnfind.key_lines(["pre-shared-key Same"]) == ("Same", "Same")
    assert vpnfind.key_lines(["pre-shared-key local 6 Enc==", "pre-shared-key remote 6 Other=="]) == \
        ("6 Enc==", "6 Other==")


def test_a_vpn_with_keys_of_its_own_on_each_end_reads_back_unchanged():
    found = asymmetric_pair()
    vpns = vpnfind.find(reads(found))
    assert len(vpns) == 1 and vpns[0].kind == VTI
    item = vpns[0]
    keys = {member.key: (vpn.own_key(item, member), vpn.remote_key(item, member)) for member in item.members}
    assert keys == {"A": ("KeyFromAaaaaaaa1", "KeyFromBbbbbbbb2"), "B": ("KeyFromBbbbbbbb2", "KeyFromAaaaaaaa1")}
    assert not any("local" in key or "remote" in key for pair in keys.values() for key in pair)
    assert not item.differences
    for key, change in vpn.vpn_changes(item, item, found).items():
        assert not change.lines, (key, change.lines)  # The remote key isn't lost
    edited = item.copy()
    edited.mtu = 1380
    for change in vpn.vpn_changes(item, edited, found).values():
        assert not [line for line in change.lines if "pre-shared-key" in line]
    findings = [finding.text for finding in vpncheck.check(item, found)]
    assert any("Keys of their own" in text for text in findings)


def test_a_key_typed_puts_one_key_on_both_ends():
    found = asymmetric_pair()
    item = vpnfind.find(reads(found))[0]
    edited = item.copy()
    edited.one_key("OneKeyForBothEnds99")
    lines = vpn.vpn_changes(item, edited, found)["A"].lines
    assert "  no pre-shared-key local KeyFromAaaaaaaa1" in lines
    assert "  no pre-shared-key remote KeyFromBbbbbbbb2" in lines
    assert "  pre-shared-key OneKeyForBothEnds99" in lines
    after = vpn.devices_after(item, edited, found)
    again = vpnfind.find(reads(after))[0]
    assert again.auth.psk == "OneKeyForBothEnds99" and not again.own_keys()


def test_keys_that_dont_match_are_told():
    found = asymmetric_pair()
    found["B"] = vti_router("B", "2.2.2.2", "1.1.1.1", "10.0.0.2",
                            ["pre-shared-key local KeyFromBbbbbbbb2", "pre-shared-key remote NotWhatAsends333"])
    item = vpnfind.find(reads(found))[0]
    assert any("expects another pre-shared key" in text for text in item.differences)
    for key, change in vpn.vpn_changes(item, item, found).items():
        assert not change.lines, (key, change.lines)


def test_each_routers_settings_are_read_not_just_the_firsts():
    found = asymmetric_pair()
    found["B"] = vti_router("B", "2.2.2.2", "1.1.1.1", "10.0.0.2",
                            ["pre-shared-key local KeyFromBbbbbbbb2", "pre-shared-key remote KeyFromAaaaaaaa1"],
                            mtu=1300, encryption="aes-cbc-128")
    item = vpnfind.find(reads(found))[0]
    texts = " ".join(item.differences)
    assert "IKE encryption (aes-cbc-128)" in texts and "IP MTU is 1300" in texts
    findings = [finding.text for finding in vpncheck.check(item, found)]
    assert any(text.startswith("As read: ") for text in findings)


def test_tunnel1_on_many_routers_pairs_by_address():
    # Two VTIs with the same tunnel number and even the same tunnel subnet, between different routers
    found = {
        "A": vti_router("A", "1.1.1.1", "2.2.2.2", "10.0.0.1", ["pre-shared-key KeyAaaaaaaaaaaaaa"]),
        "B": vti_router("B", "2.2.2.2", "1.1.1.1", "10.0.0.2", ["pre-shared-key KeyAaaaaaaaaaaaaa"]),
        "C": vti_router("C", "3.3.3.3", "4.4.4.4", "10.0.0.1", ["pre-shared-key KeyCccccccccccccc"]),
        "D": vti_router("D", "4.4.4.4", "3.3.3.3", "10.0.0.2", ["pre-shared-key KeyCccccccccccccc"]),
    }
    reads_list = reads(found)
    reads_list = [reads_list[0], reads_list[3], reads_list[2], reads_list[1]]  # The read order doesn't matter
    vpns = vpnfind.find(reads_list)
    pairs = sorted(sorted(member.key for member in item.members) for item in vpns)
    assert pairs == [["A", "B"], ["C", "D"]]
    assert {item.auth.psk for item in vpns} == {"KeyAaaaaaaaaaaaaa", "KeyCccccccccccccc"}
    assert len({item.name for item in vpns}) == 2  # Told apart by their routers
    assert len({item.id for item in vpns}) == 2


def test_spokes_to_a_hub_not_read_arent_paired_with_each_other():
    found = {
        "A": vti_router("A", "1.1.1.1", "9.9.9.9", "10.0.0.2", ["pre-shared-key KeyAaaaaaaaaaaaaa"]),
        "B": vti_router("B", "2.2.2.2", "9.9.9.9", "10.0.0.2", ["pre-shared-key KeyBbbbbbbbbbbbbb"]),
    }
    vpns = vpnfind.find(reads(found))
    assert len(vpns) == 2
    for item in vpns:
        assert len(item.members) == 2 and any(member.key == "peer:9.9.9.9" for member in item.members)


DMVPN_RUNNING = """hostname {name}
!
interface GigabitEthernet1
 ip address {wan} 255.255.255.0
!
interface Tunnel1
 ip address {tip} 255.255.255.0
 ip mtu 1400
 ip tcp adjust-mss 1360
 ip nhrp network-id 1
{nhrp}
 tunnel source GigabitEthernet1
 tunnel mode gre multipoint
 tunnel protection ipsec profile PROF
!
crypto ikev2 proposal PROP
 encryption aes-cbc-256
 integrity sha256
 group 14
!
crypto ikev2 policy POL
 proposal PROP
!
crypto ikev2 keyring KR
 peer ANY
  address 0.0.0.0 0.0.0.0
  pre-shared-key {key}
!
crypto ikev2 profile IKE
 match identity remote address 0.0.0.0
 authentication remote pre-share
 authentication local pre-share
 keyring local KR
!
crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac
 mode transport
!
crypto ipsec profile PROF
 set transform-set TS
 set ikev2-profile IKE
!
"""


def dmvpn_router(name, wan, tip, hub=None, key="CloudKeyAaaaaaaaa"):
    nhrp = " ip nhrp map multicast dynamic" if hub is None else \
        f" ip nhrp nhs {hub[1]} nbma {hub[0]} multicast"
    text = DMVPN_RUNNING.format(name=name, wan=wan, tip=tip, nhrp=nhrp, key=key)
    return vpn.parse_device(text, "", XE)


def test_clouds_alike_but_for_their_hubs_are_separate():
    # Two regions built from one template: Tunnel1, NHRP network-id 1 and 172.16.0.0/24 in each
    found = {
        "H1": dmvpn_router("H1", "1.1.1.1", "172.16.0.1", key="RegionOneKeyAaaaa"),
        "S1": dmvpn_router("S1", "3.3.3.3", "172.16.0.11", hub=("1.1.1.1", "172.16.0.1"), key="RegionOneKeyAaaaa"),
        "H2": dmvpn_router("H2", "2.2.2.2", "172.16.0.1", key="RegionTwoKeyBbbbb"),
        "S2": dmvpn_router("S2", "4.4.4.4", "172.16.0.12", hub=("2.2.2.2", "172.16.0.1"), key="RegionTwoKeyBbbbb"),
    }
    vpns = vpnfind.find(reads(found))
    clouds = sorted(sorted(member.key for member in item.members) for item in vpns)
    assert clouds == [["H1", "S1"], ["H2", "S2"]]
    for item in vpns:
        assert item.kind == DMVPN
        assert [member.role for member in item.hubs()] == [HUB] and len(item.spokes()) == 1
        assert item.auth.psk == ("RegionOneKeyAaaaa" if item.member("H1") else "RegionTwoKeyBbbbb")
    assert len({item.id for item in vpns}) == 2


def test_spokes_of_one_unread_hub_are_one_cloud():
    found = {
        "S1": dmvpn_router("S1", "3.3.3.3", "172.16.0.11", hub=("1.1.1.1", "172.16.0.1")),
        "S2": dmvpn_router("S2", "4.4.4.4", "172.16.0.12", hub=("1.1.1.1", "172.16.0.1")),
    }
    vpns = vpnfind.find(reads(found))
    assert len(vpns) == 1
    assert sorted(member.key for member in vpns[0].members) == ["S1", "S2", "peer:1.1.1.1"]
    assert [member.role for member in vpns[0].members if member.key.startswith("peer:")] == [HUB]
    assert {member.role for member in vpns[0].spokes()} == {SPOKE}


def test_a_dmvpn_hub_with_its_own_key():
    found = {
        "H1": dmvpn_router("H1", "1.1.1.1", "172.16.0.1", key="local HubSendsThis11111\n  pre-shared-key remote "
                                                               "SpokesSendThis2222"),
        "S1": dmvpn_router("S1", "3.3.3.3", "172.16.0.11", hub=("1.1.1.1", "172.16.0.1"),
                           key="local SpokesSendThis2222\n  pre-shared-key remote HubSendsThis11111"),
        "S2": dmvpn_router("S2", "4.4.4.4", "172.16.0.12", hub=("1.1.1.1", "172.16.0.1"),
                           key="local SpokesSendThis2222\n  pre-shared-key remote HubSendsThis11111"),
    }
    item = vpnfind.find(reads(found))[0]
    assert item.auth.psk == "SpokesSendThis2222" and item.member("H1").psk == "HubSendsThis11111"
    assert not item.differences
    for key, change in vpn.vpn_changes(item, item, found).items():
        assert not [line for line in change.lines if "pre-shared-key" in line], (key, change.lines)
    assert not [finding for finding in vpncheck.check(item, found) if finding.severity == vpncheck.ERROR and
                "key" in finding.text]


def test_secrets_kept_for_keys_of_their_own():
    found = asymmetric_pair()
    item = vpnfind.find(reads(found))[0]
    assert not any(member["psk"] or member["psk_remote"] for member in item.to_dict()["members"])
    store = vpn.VpnStore(None, protect=lambda text: text[::-1], unprotect=lambda text: text[::-1])
    store.remember(item)
    kept = store.design(item.id)
    assert {member.key: member.psk for member in kept.members} == {member.key: member.psk for member in item.members}
