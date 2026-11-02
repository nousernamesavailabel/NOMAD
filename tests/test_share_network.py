"""Sharing a Local network with the tribe when a map of it is shared: the whole network and its VLAN domains go, all or
nothing, the rule that laptops can't otherwise add networks stays, and a tribe map never carries a link to a network
of one computer's own."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QMessageBox  # noqa: E402
from test_integration import app, key, pages  # noqa: E402,F401 (fixtures)
from test_ipam_server import plan as import_plan, server, team_store, tribe_maps  # noqa: E402,F401 (fixture)
from test_placement import lab  # noqa: E402

from nomad.ipam.network_move import plan_network, share_network, share_problems  # noqa: E402
from nomad.ipam.placement import LOCAL, PlacementStore  # noqa: E402
from nomad.ipam.server import ADMIN  # noqa: E402
from nomad.ipam.store import IpamError, IpamStore, RESERVED  # noqa: E402
from nomad.ipam.vlans import VlanStore  # noqa: E402
from nomad.netmap import shared, store as map_store  # noqa: E402
from nomad.netmap.model import NetworkMap  # noqa: E402
from nomad.ui.integration import TribeNetworkDialog  # noqa: E402


@pytest.fixture
def mine(tmp_path):
    store = IpamStore(str(tmp_path / "mine.db"), user="alice")
    network = store.add_network("Planning", "A new site", {"Unit": "11AB"})
    store.add_subnet(network.id, "10.5.0.0/22", "Block", "10.5.0.1")
    store.add_subnet(network.id, "10.5.1.0/24", "Inside", "10.5.1.1")
    store.set_address(network.id, "10.5.0.10", name="printer", mac="aa-bb-cc-dd-ee-ff")
    store.set_address(network.id, "10.5.1.20", RESERVED, "held")
    store.set_address(network.id, "10.9.9.9", name="in no subnet")
    placements = PlacementStore(store)
    placements.set_role(network.id, "10.5.1.0/24", "routed")
    placements.set_placement(network.id, "10.5.0.0/22", LOCAL, note="reused")
    vlans = VlanStore(store)
    domain = vlans.add_domain("Planning switches", network.id, "VTP1", "Core", [dict(first=1, last=99, name="Users")])
    vlans.set_vlan(domain.id, 20, "USERS", subnets=["10.5.1.0/24"], description="Floor 1")
    vlans.add_domain("Unrelated", "")
    yield store, network
    store.close()


def test_a_whole_network_goes_to_the_tribe(server, mine, tmp_path):
    store, network = mine
    alice = team_store(server, tmp_path, "alice")
    shared_network = share_network(store, alice, network.id, "  Site A  ")
    assert shared_network.name == "Site A" and shared_network.description == "A new site"
    assert shared_network.fields == {"Unit": "11AB"}

    bob = team_store(server, tmp_path, "bob")  # On the server, for everyone
    assert [subnet.cidr for subnet in bob.subnets(shared_network.id)] == ["10.5.0.0/22", "10.5.1.0/24"]
    addresses = {address.ip: address for address in bob.addresses(shared_network.id)}
    assert set(addresses) == {"10.5.0.10", "10.5.1.20", "10.9.9.9"}  # Even the one in no subnet
    assert addresses["10.5.0.10"].mac == "aa-bb-cc-dd-ee-ff" and addresses["10.5.1.20"].status == RESERVED
    placements = PlacementStore(bob.copy)
    assert placements.role(shared_network.id, "10.5.1.0/24").role == "routed"
    assert placements.placement(shared_network.id, "10.5.0.0/22").note == "reused"
    vlans = VlanStore(bob.copy)
    domain = vlans.domain_named("Planning switches")
    assert domain.network_id == shared_network.id and (domain.vtp_domain, domain.description) == ("VTP1", "Core")
    assert domain.ranges == [dict(first=1, last=99, name="Users")]
    vlan = vlans.vlan(domain.id, 20)
    assert (vlan.name, vlan.subnets, vlan.description) == ("USERS", ["10.5.1.0/24"], "Floor 1")

    assert store.networks() == []  # It left this computer, and only what was its
    assert [domain.name for domain in VlanStore(store).domains()] == ["Unrelated"]
    assert PlacementStore(store).roles(network.id) == {}


def test_laptops_still_cant_add_networks_any_other_way(server, tmp_path):
    alice = team_store(server, tmp_path, "alice")
    with pytest.raises(IpamError, match="Only the server"):
        alice.add_network("Mine")
    with pytest.raises(IpamError, match="imported on the server"):
        alice.import_networks([import_plan()])


def test_refused_whole_with_nothing_changed(server, mine, tmp_path):
    store, network = mine
    admin = team_store(server, tmp_path, "admin", ADMIN)
    admin.add_network("Site A")
    alice = team_store(server, tmp_path, "alice")
    assert share_problems(store, alice, network.id, "site a") == ["The tribe already has a network called site a."]
    assert share_problems(store, alice, network.id, " ") == ["Give the network a name."]
    with pytest.raises(IpamError, match="already has a network"):
        share_network(store, alice, network.id, "Site A")

    admin._send("add_vlan_domain", name="Planning switches", network_id="")
    alice.sync()
    assert "already has a VLAN domain called Planning switches" in share_problems(store, alice, network.id, "B")[0]
    with pytest.raises(IpamError, match="VLAN domain"):
        share_network(store, alice, network.id, "B")

    # The server has the last word: its refusal undoes everything it had done
    bob = team_store(server, tmp_path, "bob")
    data_network = store.add_network("Clash")
    domain = VlanStore(store).add_domain("Taken here", data_network.id)
    bob._send("add_vlan_domain", name="Taken here", network_id="")  # Alice's copy hasn't heard of this one
    with pytest.raises(IpamError, match="already a VLAN domain"):
        share_network(store, alice, data_network.id, "Half")
    alice.sync()
    assert alice.copy.network_named("Half") is None
    assert store.network(data_network.id).name == "Clash" and VlanStore(store).domain(domain.id)  # Still here


def test_needs_the_server_and_a_new_enough_one(server, mine, tmp_path):
    store, network = mine
    assert share_problems(store, None, network.id, "A") == ["This computer isn't connected to the tribe's IPAM server."]
    alice = team_store(server, tmp_path, "alice")
    alice.online = False
    assert "can't be reached" in share_problems(store, alice, network.id, "A")[0]
    alice.online = True
    alice.copy.set_meta("server_api", 14)
    assert "needs updating" in share_problems(store, alice, network.id, "A")[0]
    with pytest.raises(IpamError, match="needs updating"):
        share_network(store, alice, network.id, "A")
    assert store.network(network.id).name == "Planning"


def test_not_while_a_subnet_is_being_moved(server, mine, tmp_path):
    store, network = mine
    alice = team_store(server, tmp_path, "alice")
    placements = PlacementStore(store)
    planned = placements.plan_move(network.id, "10.5.1.0/24", to_domain_id=VlanStore(store).domains()[0].id, to_vlan=30)
    placements.update_move(planned.id, status="in progress")
    assert "being moved on the Subnet Placement page" in share_problems(store, alice, network.id, "A")[0]
    assert plan_network(store, network.id).move.problems


def test_a_big_network_arrives_whole(server, tmp_path):
    store = IpamStore(str(tmp_path / "mine.db"), user="alice")
    network = store.add_network("Big")
    store.add_subnet(network.id, "10.40.0.0/18", "Block")
    with store.transaction():
        for number in range(1, 5200):
            store.set_address(network.id, f"10.40.{number // 250}.{number % 250 + 1}", name=f"host{number}")
    alice = team_store(server, tmp_path, "alice")
    shared_network = share_network(store, alice, network.id, "Big")
    assert len(alice.addresses(shared_network.id)) == 5199  # In the reply, before any sync
    store.close()


def test_a_tribe_map_never_carries_a_local_link():
    network_map = NetworkMap(seeds=["10.0.0.1"], ipam_network="local:abc")
    items = shared.flatten(network_map, {})
    assert (shared.META, shared.IPAM) not in items
    items[(shared.META, shared.IPAM)] = {"network": "local:abc"}  # As shared by an older NOMAD
    assert shared.build(items).ipam_network == ""
    items[(shared.META, shared.IPAM)] = {"network": "team:abc"}
    assert shared.build(items).ipam_network == "team:abc"


def test_a_link_already_shared_mends_itself(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("Lab", NetworkMap(seeds=["10.0.0.1"]), {}, {})
    alice.client.map_request("push", map_id=map_id, changes=[{"section": shared.META, "key": shared.IPAM,
                                                              "data": {"network": "local:abc"}}])
    bob.sync()
    network_map, settings, seen = bob.snapshot(map_id)
    assert network_map.ipam_network == ""  # So Bob is asked
    assert bob.save(map_id, network_map, settings, seen) == 1  # And the bad link goes for everyone
    bob.sync()
    alice.sync()
    assert (shared.META, shared.IPAM) not in alice.items(map_id)
    alice.close()
    bob.close()


def accept_as_shown(dialog):
    """OK clicked on the dialog as it opened."""
    dialog.result_item = dialog.apply()
    return True


@pytest.fixture
def tribe_pages(pages, server, tmp_path, monkeypatch):
    window, store, lab_network, other, domain = pages
    alice = team_store(server, tmp_path, "alice")
    window.ipam_tab.team = alice
    monkeypatch.setattr(window.ipam_tab, "sync_now", lambda: None)
    monkeypatch.setattr(window.ipam_tab, "open_store", lambda: True)
    monkeypatch.setattr(TribeNetworkDialog, "exec_", accept_as_shown)
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    maps = tribe_maps(server, tmp_path, "alice-maps")
    window.netmap_tab.tribe.maps = maps
    yield window, store, lab_network, other, domain, alice, maps
    window.netmap_tab.tribe.maps = None
    maps.close()


def test_sharing_a_map_can_share_its_local_network(tribe_pages, tmp_path):
    window, store, lab_network, other, domain, alice, maps = tribe_pages
    page = window.netmap_tab
    second = tmp_path / "second.nomadmap"
    map_store.save(NetworkMap(started="2026-10-01T09:00:00", ipam_network=key(lab_network)), second)
    window.ipam_tab.fill_networks(key(lab_network))
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    page.set_ipam_network(key(lab_network))

    page.share_with_tribe()

    network = alice.copy.network_named("Lab")
    assert network is not None and page.tribe_map_id is not None
    new_key = f"team:{network.id}"
    assert page.network_map.ipam_network == new_key
    assert maps.items(page.tribe_map_id)[(shared.META, shared.IPAM)] == {"network": new_key}  # For everyone
    assert map_store.load(second).ipam_network == new_key  # Another map of it here comes along
    assert [item.name for item in store.networks()] == ["Other"]
    assert VlanStore(alice.copy).domain_named("Lab switches").network_id == network.id
    assert window.integration.network == new_key and window.ipam_tab.network_id == network.id  # The pages followed
    assert (window.ipam_tab.source, window.integration.network_name(new_key)) == ("team", "Lab")


def test_sharing_a_map_with_no_network_moves_nothing(tribe_pages, tmp_path):
    window, store, _, _, _, _, _ = tribe_pages
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    dialog = TribeNetworkDialog(page, window.integration, page.network_map, "Share", "Lab", ["lab"])
    dialog.combo.setCurrentIndex(0)
    with pytest.raises(IpamError, match="already a tribe map"):
        dialog.apply()
    dialog.name_input.setText("Fresh")
    assert dialog.apply() == ""  # None chosen: nothing moves
    assert [item.name for item in store.networks()] == ["Lab", "Other"]


def test_a_network_only_goes_once_confirmed(tribe_pages, tmp_path, monkeypatch):
    window, store, lab_network, _, _, alice, _ = tribe_pages
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    dialog = TribeNetworkDialog(page, window.integration, page.network_map, "Share", "Lab map", [])
    asked = []

    def answer(_parent, _title, text, *args):
        asked.append(text)
        return QMessageBox.No
    monkeypatch.setattr(QMessageBox, "question", answer)
    dialog.save()
    assert not dialog.result_item and "nothing was moved" in dialog.error_label.text()  # Stays open to choose again
    assert "Share Lab with the tribe as Lab?" in asked[0] and "only the tribe server can delete it" in asked[0]
    assert "Moves 3 subnets" in asked[0]
    assert store.network(lab_network.id).name == "Lab" and alice.copy.network_named("Lab") is None

    alice.online = False  # What would be refused isn't asked about
    asked.clear()
    dialog.save()
    assert asked == [] and "can't be reached" in dialog.error_label.text()
    alice.online = True

    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    dialog.save()
    assert dialog.result_item == f"team:{alice.copy.network_named('Lab').id}"


def test_the_dialog_says_what_goes_and_what_stops_it(tribe_pages, tmp_path):
    window, _, lab_network, _, _, alice, _ = tribe_pages
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    dialog = TribeNetworkDialog(page, window.integration, page.network_map, "IPAM Network of the Map")
    assert dialog.combo.currentData() == key(lab_network)  # Suggested: it holds the map's subnets
    assert "share it with the tribe" in dialog.combo.currentText()
    assert dialog.network_name_input.text() == "Lab" and not dialog.network_name_input.isHidden()
    assert "Moves 3 subnets, 0 recorded addresses and 1 VLAN domain into" in dialog.summary.text()
    alice.online = False
    dialog.show_summary()
    assert "can't be reached" in dialog.summary.text()
    with pytest.raises(IpamError, match="can't be reached"):
        dialog.apply()
    alice.online = True
    dialog.combo.setCurrentIndex(0)
    assert dialog.network_name_input.isHidden() and dialog.summary.text() == ""
