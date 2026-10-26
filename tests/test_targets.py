"""Software targets: comparing versions, which target counts for a model, keeping them (here and through the tribe
server), what the Assets page's Problems column says of devices off target, the map's Software Targets overlay, and
the watch log's lines for upgrades and swapped hardware."""
import pytest
from test_ipam_server import offline_store, server, team_store  # noqa: F401 (fixture)

from nomad.ipam.assets import IN_SERVICE, RETIRED, AssetStore, all_asset_history, problems
from nomad.ipam.client import ServerUnreachable
from nomad.ipam.store import IpamError, IpamStore
from nomad.ipam.target_team import TeamTargetStore
from nomad.ipam.targets import AHEAD, BEHIND, NO_SOFTWARE, NO_TARGET, ON_TARGET, OTHER, TargetStore, \
    compare_versions, compliance, counts, newest_first, suggestions, target_for


def test_versions_compare_the_way_their_numbers_read():
    cases = [("17.9.4a", "17.9.4a", 0), ("17.9.4", "17.9.4a", -1), ("17.9.4a", "17.9.4b", -1),
             ("17.9.4a", "17.12.1", -1), ("17.12.1", "17.9.4a", 1), ("17.09.04a", "17.9.4a", 0),
             ("15.2(7)E4", "15.2(7)E10", -1), ("15.2(7)E4", "15.2(7)M4", None), ("9.3(8)", "9.3(10)", -1),
             ("10.2.4-h3", "10.2.4-h12", -1), ("v7.2.5", "7.2.6", -1),
             ("sip8845_65.14-1-1-0001-136", "sip8845_65.14-2-1-0001-11", -1), ("", "17.9.4a", None)]
    for first, second, expected in cases:
        assert compare_versions(first, second) == expected, (first, second)
    assert newest_first(["17.9.4", "17.12.1", "17.9.4a"]) == ["17.12.1", "17.9.4a", "17.9.4"]


@pytest.fixture
def ipam(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="alice")
    yield store
    store.close()


def test_the_most_exact_target_counts(ipam):
    targets = TargetStore(ipam)
    family = targets.set_target(model="C9300-*", target="17.9.4a")
    exact = targets.set_target(model="c9300-48p", target="17.12.1", allowed="17.9.4a, 17.9.5")
    assert exact.model == "c9300-48p" and exact.allowed == "17.9.4a, 17.9.5"
    listed = targets.targets()
    assert target_for(listed, "C9300-48P").id == exact.id  # Without case
    assert target_for(listed, "C9300-24T").id == family.id
    assert target_for(listed, "C9200L-24P") is None
    with pytest.raises(IpamError, match="There's a target for c9300-48p already"):
        targets.set_target(model="C9300-48P", target="17.9.4a")
    with pytest.raises(IpamError, match="Say which software"):
        targets.set_target(model="C9500-24Y4C", target="")
    targets.set_target(family.id, model="C9300-*", target="17.9.5")
    assert targets.target(family.id).target == "17.9.5" and targets.target(family.id).version == 2
    targets.delete_target(exact.id)
    assert target_for(targets.targets(), "C9300-48P").id == family.id


def test_devices_on_behind_and_ahead_of_their_target(ipam):
    assets, targets = AssetStore(ipam), TargetStore(ipam)
    made = {name: assets.set_asset(None, serial=name, kind="switch", model="C9300-48P", hostname=name.lower(),
                                   software=software)
            for name, software in (("ON1", "17.9.4a"), ("OK1", "17.9.5"), ("OLD1", "17.6.5"), ("NEW1", "17.15.1"),
                                   ("ODD1", "16.12.4(EFT)x"), ("NONE1", ""))}
    assets.set_asset(None, serial="RET1", kind="switch", model="C9300-48P", software="16.9.1", status=RETIRED)
    target = targets.set_target(model="C9300-48P", target="17.9.4a", allowed="17.9.5")
    states = {name: compliance(asset, targets.targets())[0] for name, asset in made.items()}
    assert states == {"ON1": ON_TARGET, "OK1": ON_TARGET, "OLD1": BEHIND, "NEW1": AHEAD, "ODD1": BEHIND,
                      "NONE1": NO_SOFTWARE}
    psu = assets.set_asset(None, serial="LIT1", kind="power supply", model="C9300-48P", parent_id=made["ON1"].id)
    assert compliance(psu, targets.targets()) == (NO_TARGET, None)  # A part runs its chassis' software
    found = problems(assets.assets(), targets=targets.targets())
    assert "Behind target: runs 17.6.5, the target for C9300-48P is 17.9.4a" in found[made["OLD1"].id]
    assert any(line.startswith("Ahead of target") for line in found[made["NEW1"].id])
    assert made["ON1"].id not in found
    assert not any("most C9300-48P run" in line for lines in found.values() for line in lines)  # The target says
    assert counts(assets.assets(), targets.targets())[target.id] == {ON_TARGET: 2, BEHIND: 2, AHEAD: 1,
                                                                     NO_SOFTWARE: 1}  # Not the retired one
    assert "Software target for C9300-48P" in [event.subject for event in all_asset_history(ipam)]


def test_other_trains_are_other_software_and_suggestions(ipam):
    assets, targets = AssetStore(ipam), TargetStore(ipam)
    old = assets.set_asset(None, serial="A1", kind="switch", model="WS-C2960X-48FPD-L", software="15.2(7)M4")
    assets.set_asset(None, serial="A2", kind="switch", model="WS-C2960X-48FPD-L", software="15.2(7)E4")
    assets.set_asset(None, serial="A3", kind="switch", model="WS-C2960X-48FPD-L", software="15.2(7)E4")
    assets.set_asset(None, serial="B1", kind="router", model="C8000V", software="17.9.4a", status=IN_SERVICE)
    assert suggestions(assets.assets(), []) == [("C8000V", "17.9.4a", {"17.9.4a": 1}),
                                                ("WS-C2960X-48FPD-L", "15.2(7)E4", {"15.2(7)M4": 1, "15.2(7)E4": 2})]
    targets.set_target(model="WS-C2960X-*", target="15.2(7)E10")
    assert compliance(assets.find(old.id), targets.targets())[0] == OTHER
    assert [model for model, _, _ in suggestions(assets.assets(), targets.targets())] == ["C8000V"]


def test_targets_shared_through_the_server(server, tmp_path):
    alice = TeamTargetStore(team_store(server, tmp_path, "alice"))
    bob = TeamTargetStore(team_store(server, tmp_path, "bob"))
    assert alice.can_change
    target = alice.set_target(model="C9300-*", target="17.9.4a", note="Approved in CAB 41")
    assert target.model == "C9300-*" and target.modified_by == "alice (PC)"
    bob.team.sync()
    assert [item.target for item in bob.targets()] == ["17.9.4a"]
    bob.set_target(target.id, model="C9300-*", target="17.9.5")
    with pytest.raises(IpamError, match="changed by bob"):  # Alice hasn't synced since
        alice.set_target(target.id, model="C9300-*", target="17.12.1")
    with pytest.raises(IpamError, match="bob .* set a target for C9300-\\*"):
        alice.set_target(None, model="c9300-*", target="17.12.1")
    alice.team.sync()
    alice.delete_target(target.id)
    bob.team.sync()
    assert bob.targets() == []


def test_targets_wait_for_the_server(server, tmp_path):
    team_store(server, tmp_path, "alice").close()
    laptop = TeamTargetStore(offline_store(server, tmp_path))
    laptop.team.online = False
    assert not laptop.can_change and "can't be reached" in laptop.why_not
    with pytest.raises(ServerUnreachable):
        laptop.set_target(model="C9300-*", target="17.9.4a")
    old = TeamTargetStore(team_store(server, tmp_path, "bob"))
    old.team.copy.set_meta("server_api", 11)
    assert "doesn't keep software targets" in old.why_not


# --------------------------------------------------------------------- On the map, and in the watch log

def test_the_software_overlay_colors_devices_against_their_target(ipam):
    from test_assets import map_with, switch_device

    from nomad.netmap import overlays
    targets = TargetStore(ipam)
    old = switch_device(key="sw1", name="sw1", serials=("FOC1", "FOC2"), software="17.6.5")
    new = switch_device(key="sw2", name="sw2", serials=("FOC3",), software="17.9.4a")
    network_map = map_with(old, new)
    overlay = overlays.build(network_map, overlays.SOFTWARE, [])
    assert "no software targets set yet" in overlay.summary[0]
    assert {mark.color for mark in overlay.devices.values()} == {overlays.OTHER}
    targets.set_target(model="C9300-*", target="17.9.4a")
    overlay = overlays.build(network_map, overlays.SOFTWARE, targets.targets())
    assert overlay.devices["sw1"].color == "warning" and "behind target" in overlay.devices["sw1"].note
    assert overlay.devices["sw2"].color == "success"
    assert overlay.tone == "warning" and overlay.summary == ["1 of 2 devices with a target on it", "1 behind"]
    assert overlays.attribute_value(network_map, old, "version") == "17.6.5"  # Color By reads the crawl's too


def test_the_watch_log_says_what_was_upgraded_swapped_added_and_taken_out():
    from netmap_fakes import FakeNetwork, string
    from test_assets import crawl, entity, stack_switch

    from nomad.netmap import collect, watch
    network = FakeNetwork()
    switch = network.add("10.0.0.11", stack_switch())
    network_map = crawl(network)
    switch.set(collect.SYS_DESCR, string("Cisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), "
                                         "Version 17.12.1, RELEASE SOFTWARE (fc5)"))
    entity(switch, 2000, 3, 1, "FOC9999Z9ZZ", "C9300-48P", "Switch 2", 2)  # Member 2 swapped (an RMA)
    entity(switch, 1011, 6, 1005, "LIT3333", "PWR-C1-1100WAC", "Switch 1 - Power Supply B")  # Added
    entity(switch, 1101, 10, 1100, "", "", "Te1/1/1 Module")  # The transceiver taken out: no serial now
    crawled = watch.crawl_from(network_map, watch.WatchOptions(), ["10.0.0.11"], network.client, network.ping)
    result = watch.apply_refresh(network_map, crawled, by="tester")
    assert result.hardware == ["acc1"] and bool(result)
    lines = "\n".join(result.lines)
    assert "Software changed on acc1.corp.example: 17.9.4a → 17.12.1" in lines
    assert "Hardware swapped on acc1.corp.example Switch 2: FOC2222B2BB → FOC9999Z9ZZ (C9300-48P)" in lines
    assert "Parts added on acc1.corp.example: Power supply LIT3333 (PWR-C1-1100WAC)" in lines
    assert "Parts taken out of acc1.corp.example: Transceiver AVM1111 (SFP-10G-SR)" in lines
    again = watch.apply_refresh(network_map, watch.crawl_from(network_map, watch.WatchOptions(), ["10.0.0.11"],
                                                              network.client, network.ping), by="tester")
    assert not again.hardware  # Nothing changed since
