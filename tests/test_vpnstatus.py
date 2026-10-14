"""What routers say about their VPNs (as IOS XE 17.4 says it), and the checks on a VPN design before it's sent."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import test_vpn as T  # noqa: E402

from nomad.netmap import vpn, vpncheck, vpnfind, vpnstatus  # noqa: E402
from nomad.netmap.vpn import BGP, CRYPTO_MAP, DMVPN, EIGRP, STATIC, VTI  # noqa: E402
from nomad.netmap.vpnstatus import ERROR, WARNING  # noqa: E402

SESSION = """Crypto session current status

Code: C - IKE Configuration mode, D - Dead Peer Detection
K - Keepalives, N - NAT-traversal, T - cTCP encapsulation
X - IKE Extended Authentication, F - IKE Fragmentation
R - IKE Auto Reconnect, U - IKE Dynamic Route Update
S - SIP VPN

Interface: Tunnel10
Profile: LAB-VTI-IKE
Uptime: 00:00:22
Session status: UP-ACTIVE
Peer: 8.0.0.26 port 500 fvrf: (none) ivrf: (none)
      Desc: LAB-VTI (NOMAD)
      Phase1_id: 8.0.0.26
  Session ID: 2
  IKEv2 SA: local 8.0.0.22/500 remote 8.0.0.26/500 Active
          Capabilities:DU connid:1 lifetime:23:59:38
  IPSEC FLOW: permit ip 0.0.0.0/0.0.0.0 0.0.0.0/0.0.0.0
        Active SAs: 2, origin: crypto map
        Inbound:  #pkts dec'ed 5 drop 0 life (KB/Sec) 4607999/3578
        Outbound: #pkts enc'ed 7 drop 1 life (KB/Sec) 4608000/3578
"""
IKEV2 = """ IPv4 Crypto IKEv2  SA

Tunnel-id Local                 Remote                fvrf/ivrf            Status
1         8.0.0.22/500          8.0.0.26/500          none/none            READY
      Encr: AES-GCM, keysize: 256, PRF: SHA384, Hash: None, DH Grp:20, Auth sign: PSK, Auth verify: PSK
      Life/Active Time: 86400/22 sec
"""
ISAKMP = """IPv4 Crypto ISAKMP SA
dst             src             state          conn-id status
8.0.0.26        8.0.0.18        MM_KEY_EXCH       1001 ACTIVE
"""
DMVPN_HUB = """Legend: Attrb --> S - Static, D - Dynamic, I - Incomplete
==========================================================================

Interface: Tunnel100, IPv4 NHRP Details
Type:Hub, NHRP Peers:2,

 # Ent  Peer NBMA Addr Peer Tunnel Add State  UpDn Tm Attrb
 ----- --------------- --------------- ----- -------- -----
     1 8.0.0.22             172.31.0.2    UP 00:00:59     D
     1 8.0.0.26             172.31.0.3    UP 00:00:42     D
"""
CERTIFICATES = """Certificate
  Status: Available
  Certificate Serial Number (hex): 02
  Issuer:
    cn=LAB-CA
  Subject:
    Name: R6
    cn=R6
  Validity Date:
    start date: 02:10:00 UTC Oct 14 2026
    end   date: 02:10:00 UTC Oct 14 2028
  Associated Trustpoints: LAB-PKI-TP

CA Certificate
  Status: Available
  Issuer:
    cn=LAB-CA
  Subject:
    cn=LAB-CA
  Validity Date:
    start date: 02:00:00 UTC Oct 14 2026
    end   date: 02:00:00 UTC Oct 13 2036
  Associated Trustpoints: LAB-PKI-TP
"""


def test_parse_what_the_router_says():
    status = vpnstatus.parse({"show clock": "*01:38:57.046 UTC Wed Oct 14 2026", "show ntp status":
                              "%NTP is not enabled.", "show crypto session detail": SESSION,
                              "show crypto ikev2 sa": IKEV2, "show crypto isakmp sa": ISAKMP,
                              "show dmvpn": DMVPN_HUB, "show crypto pki certificates": CERTIFICATES,
                              "show ip interface brief | include Tunnel":
                                  "Tunnel10               172.31.0.1      YES manual up                    up"})
    assert status.clock is not None and status.clock.hour == 1 and not status.clock_set and status.ntp is None
    session, = status.sessions
    assert session.interface == "Tunnel10" and session.up and session.peer == "8.0.0.26"
    assert (session.encaps, session.decaps, session.encap_drops) == (7, 5, 1) and session.ike == "IKEv2"
    assert [(sa.version, sa.remote, sa.state) for sa in status.ike] == [("IKEv2", "8.0.0.26", "READY"),
                                                                        ("IKEv1", "8.0.0.26", "MM_KEY_EXCH")]
    assert [(peer.nbma, peer.tunnel_ip, peer.state) for peer in status.dmvpn] == [
        ("8.0.0.22", "172.31.0.2", "UP"), ("8.0.0.26", "172.31.0.3", "UP")]
    assert status.dmvpn_types == {"Tunnel100": "Hub"}
    identity, ca = status.certificates
    assert identity.kind == "identity" and identity.issuer == "LAB-CA" and identity.trustpoints == ["LAB-PKI-TP"]
    assert ca.kind == "ca" and identity.end.year == 2028
    assert status.tunnels == {"Tunnel10": ("up", "up")}


def test_diagnosis_in_words():
    item, found = T.design(CRYPTO_MAP, STATIC, keys=("R5", "R7"))
    found["R5"].status = vpnstatus.parse({"show crypto isakmp sa": ISAKMP})
    findings = vpnstatus.diagnose(item, item.member("R5"), found["R5"], found)
    assert any("MM_KEY_EXCH" in finding.text and "pre-shared keys" in finding.text for finding in findings)
    found["R5"].status = vpnstatus.parse({})
    findings = vpnstatus.diagnose(item, item.member("R5"), found["R5"], found)
    assert any(finding.severity == ERROR and "No IKE with R7" in finding.text for finding in findings)
    meanings = vpnstatus.explain_log(["*Oct 14 01:02:03: %IKEV2-5-SA_DOWN: ... Auth exchange failed"])
    assert meanings and "pre-shared keys don't match" in meanings[0][0]


def errors(item, found, **options):
    return [finding.text for finding in vpncheck.check(item, found, **options) if finding.severity == ERROR]


def warnings(item, found, **options):
    return [finding.text for finding in vpncheck.check(item, found, **options) if finding.severity == WARNING]


def test_a_good_design_has_no_errors():
    item, found = T.design(VTI, EIGRP)
    assert errors(item, found) == []


def test_a_hub_on_an_address_the_spokes_cant_reach():
    item, found = T.design(DMVPN, EIGRP)
    assert errors(item, found) == []
    hub = item.member("R5")
    hub.wan, hub.local_ip = "GigabitEthernet1.172", "172.18.0.15"  # Its management VLAN, unknown to the ISP
    found_errors = errors(item, found)
    assert any(text.startswith("R6 has no route to R5's address 172.18.0.15") for text in found_errors)
    assert any(text.startswith("R7 has no route to R5's address 172.18.0.15") for text in found_errors)
    assert any("R5 reaches R6 (8.0.0.22) out of GigabitEthernet2, not the tunnel's source GigabitEthernet1.172"
               in text for text in warnings(item, found))
    item.auth.method, item.auth.ca_kind, item.auth.ca_device, item.auth.ca_name = vpn.CERT, "router", "R5", "CA"
    assert any("R6 has no route to the CA at 172.18.0.15" in text for text in errors(item, found))
    found["R6"].status = vpnstatus.parse({})
    findings = vpnstatus.diagnose(item, item.member("R6"), found["R6"], found)
    assert any("R6 has no route to 172.18.0.15" in finding.text for finding in findings)


def test_recursive_routing_and_wan_covering_lans():
    item, found = T.design(VTI, EIGRP)
    item.member("R7").lans.append("8.0.0.0/24")  # Covers R6's WAN and R7's own address
    found_errors = errors(item, found)
    assert any("recursive routing" in text for text in found_errors)
    assert any("covers its WAN network" in text for text in found_errors)


def test_a_better_route_elsewhere():
    item, found = T.design(VTI, EIGRP)
    found["R6"].routes.append(vpn.Route("10.250.7.0/24", "B", 20, ["8.0.0.21"]))
    assert any("already reaches 10.250.7.0/24 by B (distance 20)" in text for text in warnings(item, found))


def test_bgp_without_the_guard_leaks_to_the_isp():
    item, found = T.design(DMVPN, BGP)
    item.routing.guard = False
    assert any("passed on to" in text and "8.0.0.21 (AS 30)" in text for text in errors(item, found))


def test_keys_ids_and_this_pc():
    item, found = T.design(VTI, STATIC)
    item.auth.psk = "bad key?"
    assert any("space, quote or ?" in text for text in errors(item, found))
    item.auth.psk = "Secr3tKeyABCdefGH"
    item.member("R7").lans = ["192.168.5.0/24"]
    assert any("This PC (192.168.5.25)" in text for text in errors(item, found, pc_ip="192.168.5.25"))


def test_a_wan_acl_dropping_ike():
    item, found = T.design(VTI, STATIC)
    running = T.SPOKE_RUNNING.format(name="R6C8K", n=6, wan="8.0.0.22", asn=180, net="8.0.0.20", isp="8.0.0.21")
    running = running.replace("interface GigabitEthernet1\n ip address 8.0.0.22 255.255.255.252\n",
                              "interface GigabitEthernet1\n ip address 8.0.0.22 255.255.255.252\n"
                              " ip access-group WAN-IN in\n") + \
        "ip access-list extended WAN-IN\n 10 permit tcp any any eq 22\n 20 permit tcp any any eq bgp\n"
    found["R6"] = vpn.parse_device(running, T.ROUTES.format(hop="8.0.0.21"), "Version 17.04.02")
    texts = errors(item, found)
    assert any("drops IKE (UDP 500) from R7" in text for text in texts)
    assert any("drops ESP from R7" in text for text in texts)


def test_nat_catching_crypto_map_traffic():
    item, found = T.design(CRYPTO_MAP, STATIC, keys=("R5", "R7"))
    running = T.HUB_RUNNING + "ip nat inside source list NAT interface GigabitEthernet2 overload\n" \
                              "ip access-list extended NAT\n 10 permit ip 10.250.5.0 0.0.0.255 any\n"
    found["R5"] = vpn.parse_device(running, T.ROUTES.format(hop="8.0.0.17"), "Version 17.04.02")
    assert any("NAT (list NAT) would translate 10.250.5.0/24 -> 10.250.7.0/24" in text
               for text in errors(item, found))


def test_a_second_cloud_needs_the_first_ones_key():
    item, found = T.design(DMVPN, EIGRP)
    after = vpn.devices_after(None, item, found)
    first = vpnfind.find(T.reads(after))[0]
    second = item.copy()
    second.id, second.name, second.subnet = "two", "Cloud2", "172.31.1.0/24"
    second.auth.psk = "AnotherKeyAltogether9"
    for m in second.members:
        m.tunnel, m.tunnel_ip = 101, ""
    vpn.assign_addresses(second)
    assert any("need the same key" in text for text in errors(second, after, others=[first]))
    second.auth.psk = first.auth.psk
    assert not any("need the same key" in text for text in errors(second, after, others=[first]))


def test_refusals_explained():
    assert "license" in vpncheck.explain_refusal("crypto ikev2 proposal X", "% Invalid input detected")
    assert vpn.refusals("% A profile is deemed incomplete until it has match identity statements") == []
    assert vpn.refusals("Crypto-map X is in use by interface(s): Gi1\nPlease remove the crypto map") != []
    assert vpn.refusals("Error: All Tunnel interfaces having the same Tunnel Source ... shared") != []
    assert vpn.refusals("*Oct 14 01:02:03: %LINEPROTO-5-UPDOWN: Line protocol on Interface Tunnel10, changed "
                        "state to up") == []
