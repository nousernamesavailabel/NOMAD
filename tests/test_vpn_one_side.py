"""VPNs with only one side built (the far end set up by hand: nothing sent to it, its lines shown to copy), and
templates (no routers: each side's lines with <PLACEHOLDERS>)."""
import re

import pytest

from nomad.netmap import vpn, vpncheck
from nomad.netmap.vpn import BGP, CRYPTO_MAP, DMVPN, EIGRP, HUB, KINDS, NO_ROUTING, OSPF, PEER, SPOKE, STATIC, VTI, \
    Member
from nomad.netmap.vpnstatus import ERROR, INFO
from tests.test_vpn import design
from tests.test_vpn_tab import FakeVpnShell, page, read_both, wait  # noqa: F401 (page: a fixture)
from tests.test_vpn_tab import app  # noqa: F401


def by_hand(item, key, role=PEER):
    """item with member key's router swapped for a far end typed in (same details, but nothing read)."""
    real = item.member(key)
    far = Member(f"peer:{real.local_ip}", real.label, "", role, local_ip=real.local_ip, tunnel=real.tunnel,
                 tunnel_ip=real.tunnel_ip, lans=list(real.lans), bgp_as=real.bgp_as, hub_order=real.hub_order,
                 by_hand=True)
    item.members[item.members.index(real)] = far
    return far


def test_one_side_of_a_vti_changes_only_that_router():
    item, found = design(VTI, STATIC)
    by_hand(item, "R7")
    changes = vpn.vpn_changes(None, item, found)
    assert list(changes) == ["R6"]
    lines = changes["R6"].lines
    assert "tunnel destination 8.0.0.26" in [line.strip() for line in lines]
    assert "ip route 10.250.7.0 255.255.255.0 172.31.0.2" in lines


def test_the_far_ends_lines_match_what_nomad_would_send_it():
    both, found = design(VTI, OSPF)
    sent = vpn.vpn_changes(None, both, found)["R7"].lines
    item, _ = design(VTI, OSPF)
    far = by_hand(item, "R7")
    far.wan = "GigabitEthernet1"
    lines = vpn.side_change(item, far).lines
    # The same objects; only the LAN's network statement differs (NOMAD can't see which address R7 has on it)
    assert [line for line in lines if "network 10.250" not in line] == \
        [line for line in sent if "network 10.250" not in line]
    assert " network 10.250.7.0 0.0.0.255 area 0" in lines


def test_a_far_end_without_its_interface_gets_placeholders_and_a_legend():
    item, _ = design(VTI, BGP)
    far = by_hand(item, "R7")
    far.bgp_as = ""
    text = vpn.side_text(vpn.side_change(item, far))
    assert "tunnel source <WAN-INTERFACE>" in text and "router bgp <BGP-AS>" in text
    assert text.startswith("! Replace before pasting:")
    assert re.search(r"^!\s+<WAN-INTERFACE>\s+this router's WAN interface", text, re.MULTILINE)


def test_spokes_built_with_the_hub_set_up_by_hand():
    item, found = design(DMVPN, EIGRP)
    hub = by_hand(item, "R5", HUB)
    changes = vpn.vpn_changes(None, item, found)
    assert set(changes) == {"R6", "R7"}
    assert f" ip nhrp nhs {hub.tunnel_ip} nbma 8.0.0.18 multicast" in changes["R6"].lines
    hub_lines = vpn.side_change(item, hub).lines
    assert " ip nhrp map multicast dynamic" in hub_lines  # Kept (IOS XE hides it, classic IOS needs it)
    assert " ip nhrp redirect" in hub_lines and " no ip split-horizon eigrp 100" in hub_lines


def test_checks_say_the_far_end_is_by_hand_and_still_check_its_tunnel_address():
    item, found = design(VTI, STATIC)
    far = by_hand(item, "R7")
    far.tunnel_ip = item.member("R6").tunnel_ip
    findings = vpncheck.check(item, found)
    assert any(finding.severity == INFO and "set up by hand" in finding.text for finding in findings)
    assert any(finding.severity == ERROR and "same tunnel address" in finding.text for finding in findings)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("routing", [NO_ROUTING, STATIC, EIGRP, OSPF, BGP])
def test_every_template_renders_with_its_placeholders_explained(kind, routing):
    item = vpn.make_template("TPL", kind, hubs=2)
    item.routing.kind = routing if kind != CRYPTO_MAP or routing in (NO_ROUTING, STATIC) else STATIC
    for member in item.members:
        for undo in (False, True):
            text = vpn.side_text(vpn.side_change(item, member), undo)
            explained = re.findall(r"^!\s+(<[A-Z0-9-]+>)\s", text, re.MULTILINE)
            body = text.split("configure terminal", 1)[1]
            assert set(explained) == set(vpn.placeholders(body))
            assert "fill in" not in text  # Every placeholder has a meaning


def test_a_dmvpn_template_spoke():
    item = vpn.make_template("TPL", DMVPN)
    item.routing.kind = OSPF
    spoke = item.members[-1]
    assert [member.role for member in item.members] == [HUB, SPOKE]
    lines = vpn.side_change(item, spoke).lines
    assert " ip address <SPOKE-TUNNEL-IP> 255.255.255.0" in lines
    assert " ip nhrp nhs 172.31.0.1 nbma <HUB-WAN-IP> multicast" in lines
    assert " ip nhrp shortcut" in lines  # Classic IOS spokes need it for phase 3
    assert " network <SPOKE-LAN-NETWORK> <SPOKE-LAN-WILDCARD> area 0" in lines
    assert " match address local <SPOKE-WAN-IP>" in lines


def test_a_crypto_map_template_protects_lan_to_lan():
    item = vpn.make_template("TPL", CRYPTO_MAP)
    lines = vpn.side_change(item, item.members[0]).lines
    assert " 10 permit ip <A-LAN-NETWORK> <A-LAN-WILDCARD> <B-LAN-NETWORK> <B-LAN-WILDCARD>" in lines
    assert " set peer <B-WAN-IP>" in lines and "interface <A-WAN-INTERFACE>" in lines


def test_a_templates_undo_leaves_a_shared_routing_process():
    item = vpn.make_template("TPL", VTI)
    item.routing.kind = EIGRP
    undo = vpn.side_change(item, item.members[0]).undo
    assert "router eigrp 100" in undo and " no network 172.31.0.1 0.0.0.0" in undo
    assert "no router eigrp 100" not in undo
    assert "no crypto ikev2 policy TPL-POL" in undo  # Its own policy goes whole
    assert undo.index("no interface Tunnel10") < undo.index("no crypto ipsec profile TPL-IPSEC")


def test_a_template_is_checked_only_for_its_settings():
    item = vpn.make_template("TPL", DMVPN)
    findings = vpncheck.check(item, {})
    assert not [finding for finding in findings if finding.severity == ERROR], findings
    assert any("A template" in finding.text for finding in findings)
    item.crypto.groups = [2]
    assert any("group" in finding.text.lower() for finding in vpncheck.check(item, {}))


def test_a_hub_alone_with_bgp_needs_the_spokes_as():
    item, found = design(DMVPN, BGP)
    item.members = item.members[:1]
    assert any(finding.severity == ERROR and "spokes' AS" in finding.text
               for finding in vpncheck.check(item, found))


def test_templates_survive_the_store():
    item = vpn.make_template("TPL", DMVPN, hubs=2)
    again = vpn.Vpn.from_dict(item.to_dict())
    assert again.template and [member.key for member in again.members] == ["slot:hub", "slot:hub2", "slot:spoke"]


# ----------------------------------------------------------------- The page

def test_page_builds_one_side_and_sends_only_to_it(page):  # noqa: F811
    read_both(page)
    page.make_new("HALF", VTI, [("map:R6", PEER)], far="8.0.0.26")
    design_ = page.editable()
    far = design_.member("peer:8.0.0.26")
    assert far is not None and far.by_hand and far.tunnel_ip == "172.31.0.1"
    assert design_.member("map:R6").wan == "GigabitEthernet1"  # Its WAN toward the far end
    far.lans = ["10.250.7.0/24"]
    page.show_design()
    keys = [page.preview_combo.itemData(row) for row in range(page.preview_combo.count())]
    assert keys == ["map:R6", "side:peer:8.0.0.26"]
    page.preview_combo.setCurrentIndex(1)
    text = page.preview.toPlainText()
    assert "tunnel destination 8.0.0.22" in text and "tunnel source <WAN-INTERFACE>" in text
    assert "pre-shared-key ********" in text  # Keys hidden here too
    page.verify_check.setChecked(False)
    assert page.send_button.isEnabled(), page.blocked(design_.id)
    page.send()
    wait(page)
    r6, r7 = FakeVpnShell.channels["8.0.0.22"], FakeVpnShell.channels["8.0.0.26"]
    assert "tunnel destination 8.0.0.26" in [line.strip() for line in r6.sent] and r6.confirms == 1
    assert not any("tunnel" in line for line in r7.sent) and r7.confirms == 0
    found = next(item for item in page.found if item.name == "HALF")  # Read back: the same VPN
    assert found.id == design_.id and found.member("peer:8.0.0.26").by_hand
    assert not page.changes_for(found.id)


def test_page_template_shows_every_side_and_sends_nothing(page):  # noqa: F811
    page.make_template("SPOKES", DMVPN)
    design_ = page.design()
    assert design_.template
    assert "[template]" in page.vpn_tree.currentItem().text(0)
    text = page.preview.toPlainText()
    assert "! Hub" in text and "! Spoke" in text and "<SPOKE-TUNNEL-IP>" in text
    assert not page.send_button.isEnabled() and "template" in page.blocked(design_.id)
    assert page.add_far_button.text() == "Add Second Hub"
    page.add_far_end()
    assert [member.key for member in page.design().members] == ["slot:hub", "slot:hub2", "slot:spoke"]
    page.kind_combo.setCurrentIndex(page.kind_combo.findData(VTI))
    assert [member.key for member in page.design().members] == ["slot:a", "slot:b"]
    assert page.design().id == design_.id and page.design().auth.psk == design_.auth.psk
