import pytest

from netmap_fakes import CISCO_SWITCH, PALO_ALTO, PHONE_MAC, Device as FakeDevice, FakeNetwork, number, string
from test_ipam_server import offline_store, online_again, server, team_store  # noqa: F401 (fixture)

from nomad.ipam import asset_compare
from nomad.ipam.asset_compare import CONFLICT, NEW, REPLACE, SAME, UPDATE, apply, plan, sightings
from nomad.ipam.asset_team import TeamAssetStore
from nomad.ipam.assets import IN_SERVICE, REPLACED, RETIRED, SPARE, AssetStore, all_asset_history, asset_history
from nomad.ipam.store import IpamError, IpamStore
from nomad.netmap import collect, hardware
from nomad.netmap.crawl import CrawlSettings, Crawler, apply_inventory, read_inventory_of
from nomad.netmap.model import PHONE, ROUTER, SNMP, SWITCH, Device, Host, NetworkMap

ENTRY = hardware.ENT_PHYSICAL_ENTRY


def entity(device, index, kind, contained=0, serial="", model="", name="", position=0, software="", descr=""):
    """An entPhysicalTable row on a fake device."""
    device.set(ENTRY, hardware.CLASS, index, number(kind))
    device.set(ENTRY, hardware.CONTAINED_IN, index, number(contained))
    device.set(ENTRY, hardware.SERIAL, index, string(serial))
    device.set(ENTRY, hardware.MODEL, index, string(model))
    device.set(ENTRY, hardware.NAME, index, string(name))
    device.set(ENTRY, hardware.DESCR, index, string(descr or name))
    device.set(ENTRY, hardware.POSITION, index, number(position))
    device.set(ENTRY, hardware.SOFTWARE_REV, index, string(software))
    for column in (hardware.HARDWARE_REV, hardware.FIRMWARE_REV, hardware.MAKER):
        device.set(ENTRY, column, index, string(""))


def stack_switch():
    """A two-switch Catalyst stack, each member with a power supply, one with a transceiver, and the sensors and
    plain ports a real one lists."""
    switch = FakeDevice("acc1.corp.example", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
                        "(CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)", CISCO_SWITCH)
    switch.interface(1, "GigabitEthernet1/0/1")
    switch.address("10.0.0.11", 1)
    entity(switch, 1, 11, name="c93xx Stack")
    entity(switch, 1000, 3, 1, "FOC1111A1AA", "C9300-48P", "Switch 1", 1)
    entity(switch, 2000, 3, 1, "FOC2222B2BB", "C9300-48P", "Switch 2", 2)
    entity(switch, 1005, 5, 1000, name="Switch 1 - Power Supply Bay A")
    entity(switch, 1010, 6, 1005, "LIT1111", "PWR-C1-715WAC", "Switch 1 - Power Supply A")
    entity(switch, 2010, 6, 2000, "LIT2222", "PWR-C1-715WAC", "Switch 2 - Power Supply A")
    entity(switch, 1020, 8, 1010, name="Switch 1 - Power Supply A Temp Sensor")
    entity(switch, 1100, 10, 1000, name="GigabitEthernet1/0/1")
    entity(switch, 1101, 10, 1100, "AVM1111", "SFP-10G-SR", "Te1/1/1 Module")
    return switch


# --------------------------------------------------------------------- Reading the hardware

def test_software_versions_from_system_descriptions():
    cases = {
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE": "17.9.4a",
        "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE": "15.2(7)E4",
        "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(8), RELEASE SOFTWARE": "9.3(8)",
        "Cisco Adaptive Security Appliance Version 9.16(3)19": "9.16(3)19",
        "Cisco IOS XR Software (Cisco ASR9K Series), Version 6.5.3[Default]": "6.5.3",
        "Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel JUNOS 21.4R3-S1.5, Build date": "21.4R3-S1.5",
        "Arista Networks EOS version 4.28.3M running on an Arista Networks DCS-7050SX3": "4.28.3M",
        "Aruba JL322A 2930M-48G-PoE+ Switch, revision WC.16.10.0012, ROM WC.16.01.0008": "WC.16.10.0012",
        "Palo Alto Networks PA-3220 series firewall": "",
    }
    for descr, version in cases.items():
        assert hardware.software_version(descr) == version, descr
    assert hardware.neighbor_software("sip88xx.14-1-1-0001-136") == "sip88xx.14-1-1-0001-136"  # A phone's
    assert hardware.device_software("", vendor_version="v7.2.5,build1517,230606 (GA.F)") == "7.2.5"
    assert hardware.serial_in_name("core-sw1(FOC1234X0YZ)") == "FOC1234X0YZ"
    assert hardware.serial_in_name("sw1") == ""


def test_stack_members_and_parts_from_entity_mib():
    switch = stack_switch()
    rows = sorted(switch.mib.items())
    found = hardware.parts(rows, rows, rows, rows)
    chassis = hardware.chassis(found)
    assert [(part["serial"], part["name"], part["position"]) for part in chassis] == [
        ("FOC1111A1AA", "Switch 1", 1), ("FOC2222B2BB", "Switch 2", 2)]
    others = {part["serial"]: part for part in found if part["class"] != hardware.CHASSIS}
    assert set(others) == {"LIT1111", "LIT2222", "AVM1111"}  # Not the sensor, the container or the plain port
    assert others["LIT1111"]["class"] == hardware.POWER and others["LIT1111"]["chassis"] == 1000
    assert others["LIT2222"]["chassis"] == 2000
    assert others["AVM1111"]["class"] == hardware.TRANSCEIVER and others["AVM1111"]["chassis"] == 1000


def test_a_table_without_a_chassis_has_its_outermost_part_stand_in():
    device = FakeDevice("r1", "", CISCO_SWITCH)
    entity(device, 1, 9, 0, "9ABCDEF1234", "C8000V", "Chassis-ish module")
    entity(device, 2, 9, 1, "SUB1", "Submodule")
    rows = sorted(device.mib.items())
    found = hardware.parts(rows, rows, rows, rows)
    assert [(part["class"], part["serial"]) for part in found] == [(hardware.CHASSIS, "9ABCDEF1234"),
                                                                   (hardware.MODULE, "SUB1")]


def crawl(network, seeds=("10.0.0.11",), **options):
    return Crawler(CrawlSettings(seeds=list(seeds), trace=False, **options), client_factory=network.client,
                   pinger=network.ping).run()


def test_crawl_reads_each_devices_hardware_and_software():
    network = FakeNetwork()
    network.add("10.0.0.11", stack_switch())
    network_map = crawl(network)
    [device] = network_map.devices.values()
    assert device.inventory_read and device.software == "17.9.4a"
    assert [part["serial"] for part in hardware.chassis(device.parts)] == ["FOC1111A1AA", "FOC2222B2BB"]
    assert len(device.parts) == 5  # Not the sensor, the container or the plain port
    # Saved and opened again with the map
    again = NetworkMap.from_json(network_map.to_json())
    assert again.devices[device.key].parts == device.parts and again.devices[device.key].software == "17.9.4a"


def test_crawl_without_inventory_and_read_inventory_again():
    network = FakeNetwork()
    network.add("10.0.0.11", stack_switch())
    network_map = crawl(network, read_inventory=False)
    [device] = network_map.devices.values()
    assert not device.inventory_read and not device.parts
    assert device.software == "17.9.4a"  # sysDescr still says it
    tables, community = read_inventory_of(CrawlSettings(seeds=["10.0.0.11"]), "10.0.0.11", network.client)
    assert community == "public"
    apply_inventory(device, tables)
    assert device.inventory_read and len(hardware.chassis(device.parts)) == 2


def test_palo_alto_serial_and_version_from_its_own_mib():
    network = FakeNetwork()
    firewall = network.add("10.0.0.5", FakeDevice("pa-fw1", "Palo Alto Networks PA-3220 series firewall", PALO_ALTO))
    firewall.interface(1, "ethernet1/1")
    firewall.address("10.0.0.5", 1)
    firewall.set(hardware.PAN_SW_VERSION, string("10.2.4-h3"))
    firewall.set(hardware.PAN_SERIAL, string("012801012345"))
    network_map = crawl(network, seeds=("10.0.0.5",))
    [device] = network_map.devices.values()
    assert device.software == "10.2.4-h3"
    assert [part["serial"] for part in hardware.chassis(device.parts)] == ["012801012345"]


def test_phones_say_their_serial_and_firmware_through_the_switch():
    network = FakeNetwork()
    switch = network.add("10.0.0.11", FakeDevice("acc1", "Cisco IOS Software, Version 17.9.4a", CISCO_SWITCH))
    switch.interface(5, "GigabitEthernet1/0/5")
    switch.address("10.0.0.11", 5)
    switch.cdp(5, 2, "SEP00AABBCCDDEE", "Port 1", "10.10.0.22", "Cisco IP Phone 8845", 0x90)
    switch.set(collect.CDP_CACHE_ENTRY, 5, 5, 2, string("sip8845_65.14-1-1-0001-136"))
    switch.lldp(5, "Gi1/0/5", 3, "SEP00AABBCCDDEE", "Port 1", chassis_mac=PHONE_MAC, capabilities=0x04)
    switch.set(hardware.LLDP_MED_INVENTORY_ENTRY, 4, (0, 5, 3), string("FCH2222ABCD"))
    switch.set(hardware.LLDP_MED_INVENTORY_ENTRY, 6, (0, 5, 3), string("CP-8845"))
    switch.learned(PHONE_MAC, 5, 5, vlan=None)
    network_map = crawl(network)
    [phone] = [host for host in network_map.hosts if host.mac == PHONE_MAC]
    assert phone.software == "sip8845_65.14-1-1-0001-136" and phone.platform == "Cisco IP Phone 8845"
    found = {sighting.mac: sighting for sighting in sightings(network_map)}
    assert found[PHONE_MAC].kind == PHONE and found[PHONE_MAC].slot == "acc1 Gi1/0/5"


# --------------------------------------------------------------------- The asset list

@pytest.fixture
def store(tmp_path):
    ipam = IpamStore(str(tmp_path / "ipam.db"), user="alice")
    yield AssetStore(ipam)
    ipam.close()


def test_assets_are_unique_by_serial(store):
    switch = store.set_asset(None, serial=" foc 1234 ", kind=SWITCH, model="C9300-48P", hostname="sw1")
    assert switch.serial == "FOC1234" and switch.status == IN_SERVICE
    with pytest.raises(IpamError, match="already recorded, as sw1"):
        store.set_asset(None, serial="FOC1234", kind=SWITCH)
    store.set_asset(switch.id, hostname="sw1-core", software="17.9.4a")
    assert store.by_serial("foc1234").hostname == "sw1-core"
    with pytest.raises(IpamError, match="Unknown asset status"):
        store.set_asset(switch.id, status="lost")
    with pytest.raises(IpamError, match="Write dates like"):
        store.set_asset(switch.id, warranty_end="next year")
    with pytest.raises(IpamError, match="isn't a MAC"):
        store.set_asset(None, mac="nope")
    phone = store.set_asset(None, kind=PHONE, mac="00aa.bbcc.ddee")
    assert phone.mac == "00-AA-BB-CC-DD-EE"
    store.delete_asset(switch.id)
    assert store.deleted_serials() == {"FOC1234"}
    assert store.set_asset(None, serial="FOC1234", kind=SWITCH).serial == "FOC1234"  # Recorded again
    assert store.deleted_serials() == set()


def test_history_leaves_out_changes_that_only_say_when_it_was_seen(store):
    switch = store.set_asset(None, serial="FOC1", kind=SWITCH, hostname="sw1", last_seen="2026-10-01")
    store.set_asset(switch.id, last_seen="2026-10-02", seen_by="bob")
    store.set_asset(switch.id, hostname="sw1-core")
    events = asset_history(store.store, switch.id)
    assert [event.op for event in events] == ["update", "create"]
    assert "Hostname: sw1 → sw1-core" in events[0].details
    assert len(asset_history(store.store, switch.id, include_seen=True)) == 3
    assert [event.entity_id for event in all_asset_history(store.store)] == [switch.id, switch.id]


# --------------------------------------------------------------------- Bringing in a map's hardware

def map_with(*devices, hosts=()):
    network_map = NetworkMap()
    for device in devices:
        network_map.devices[device.key] = device
    network_map.hosts = list(hosts)
    return network_map


def chassis_part(serial, model="C9300-48P", name="", position=0, index=1000):
    return dict(hardware.blank_chassis(serial, model), name=name, position=position, index=index)


def switch_device(key="sw1", name="sw1", serials=("FOC1",), software="17.9.4a", parts=()):
    device = Device(key=key, name=name, mgmt_ip="10.0.0.11", kind=SWITCH, source=SNMP, software=software,
                    inventory_read=True)
    if len(serials) == 1:
        device.parts = [chassis_part(serials[0])]
    else:
        device.parts = [chassis_part(serial, name=f"Switch {number}", position=number, index=number * 1000)
                        for number, serial in enumerate(serials, start=1)]
    device.parts += list(parts)
    return device


def test_new_hardware_is_brought_in_with_its_parts(store):
    psu = dict(chassis_part("LIT1", "PWR-C1-715WAC", "Switch 2 - Power Supply A", index=2010),
               **{"class": hardware.POWER, "chassis": 2000})
    network_map = map_with(switch_device(serials=("FOC1", "FOC2"), parts=[psu]))
    network_map.groups, network_map.group_of = [], {}
    site = network_map.new_group("HQ")
    network_map.set_group(["sw1"], site.key)
    changes = plan(store, sightings(network_map))
    assert [(change.action, change.sighting.serial) for change in changes] == [
        (NEW, "FOC1"), (NEW, "FOC2"), (NEW, "LIT1")]
    apply(store, changes, user="alice", when="2026-10-23")
    members = {asset.serial: asset for asset in store.assets()}
    assert members["FOC2"].slot == "Switch 2" and members["FOC2"].location == "HQ"
    assert members["FOC1"].first_seen == "2026-10-23" and members["FOC1"].seen_by == "alice"
    assert members["LIT1"].parent_id == members["FOC2"].id and members["LIT1"].kind == hardware.POWER
    assert [change.sighting.serial for change in plan(store, sightings(network_map, track_parts=False))] == [
        "FOC1", "FOC2"]  # Parts aren't tracked when that's turned off
    assert {change.action for change in plan(store, sightings(network_map))} == {SAME}


def test_renamed_upgraded_and_replaced_hardware(store):
    apply(store, plan(store, sightings(map_with(switch_device(serials=("FOC1", "FOC2"))))), when="2026-10-01")
    old = store.by_serial("FOC2")
    store.set_asset(old.id, owner="Network team", asset_tag="A-77")
    # Renamed, upgraded, and member 2 swapped for new hardware (RMA)
    later = map_with(switch_device(key="sw1-core", name="sw1-core", serials=("FOC1", "FOC9"), software="17.12.1"))
    changes = {change.sighting.serial: change for change in plan(store, sightings(later))}
    assert changes["FOC1"].action == UPDATE
    assert changes["FOC1"].changes["hostname"] == ("sw1", "sw1-core")
    assert changes["FOC1"].changes["software"] == ("17.9.4a", "17.12.1")
    assert changes["FOC9"].action == REPLACE and changes["FOC9"].asset.serial == "FOC2"
    apply(store, list(changes.values()), when="2026-10-20")
    replaced, new = store.by_serial("FOC2"), store.by_serial("FOC9")
    assert replaced.status == REPLACED and replaced.replaced_by == new.id
    assert new.owner == "Network team" and new.asset_tag == "" and new.slot == "Switch 2"  # The tag is the old box's
    assert store.by_serial("FOC1").hostname == "sw1-core" and store.by_serial("FOC1").last_seen == "2026-10-20"
    assert "replaced by C9300-48P FOC9" in changes["FOC9"].describe()


def test_a_module_with_its_chassis_serial_is_one_asset(store):
    route_processor = dict(chassis_part("FOC1", "C8000V", "module R0", index=2), **{"class": hardware.MODULE,
                                                                                   "chassis": 1000})
    again = dict(chassis_part("FOC5", "NIM-ES2-4", "NIM subslot 0/1", index=3), **{"class": hardware.MODULE,
                                                                                  "chassis": 1000})
    router = switch_device("r1", "r1", ("FOC1",), parts=[route_processor, again, dict(again, index=4)])
    changes = plan(store, sightings(map_with(router)))
    assert sorted((change.action, change.sighting.serial) for change in changes) == [(NEW, "FOC1"), (NEW, "FOC5")]
    apply(store, changes)
    assert store.count() == 2


def test_the_same_serial_twice_is_a_conflict_not_brought_in(store):
    lab = map_with(switch_device("r1", "r1", ("ABC123",)), switch_device("r2", "r2", ("ABC123",)))
    [change] = plan(store, sightings(lab))
    assert change.action == CONFLICT and not change.can_apply and "r1, r2" in change.note
    assert apply(store, [change]) == [] and store.count() == 0


def test_what_the_list_says_by_hand_is_kept(store):
    apply(store, plan(store, sightings(map_with(switch_device()))))
    asset = store.by_serial("FOC1")
    store.set_asset(asset.id, location="Closet 2", status=SPARE)
    network_map = map_with(switch_device())
    site = network_map.new_group("HQ")
    network_map.set_group(["sw1"], site.key)
    [change] = plan(store, sightings(network_map))
    assert change.action == UPDATE and not change.chosen  # Asked, not done by itself
    assert "the map has it in HQ" in change.note and "recorded as spare" in change.note
    apply(store, [change], when="2026-10-23")
    assert store.by_serial("FOC1").location == "Closet 2" and store.by_serial("FOC1").last_seen == "2026-10-23"


def test_deleted_hardware_is_offered_back_unticked(store):
    apply(store, plan(store, sightings(map_with(switch_device()))))
    store.delete_asset(store.by_serial("FOC1").id)
    [change] = plan(store, sightings(map_with(switch_device())))
    assert change.action == NEW and not change.chosen and "deleted" in change.note


def test_phones_are_known_by_mac_until_their_serial_is():
    ipam = IpamStore(":memory:", user="alice")
    store = AssetStore(ipam)
    switch = switch_device()
    phone = Host(mac=PHONE_MAC, device="sw1", port="Gi1/0/5", ip="10.10.0.22", name="SEP00AABBCCDDEE",
                 platform="Cisco IP Phone 8845", software="sip8845.14-1")
    apply(store, plan(store, sightings(map_with(switch, hosts=[phone]))))
    [recorded] = [asset for asset in store.assets() if asset.kind == PHONE]
    assert recorded.mac == PHONE_MAC and recorded.serial == "" and recorded.slot == "sw1 Gi1/0/5"
    moved = Host(mac=PHONE_MAC, device="sw1", port="Gi1/0/9", ip="10.10.0.23", name="SEP00AABBCCDDEE",
                 platform="Cisco IP Phone 8845", software="sip8845.14-2", serial="FCH2222ABCD")
    changes = [change for change in plan(store, sightings(map_with(switch, hosts=[moved])))
               if change.sighting.kind == PHONE]
    assert [change.action for change in changes] == [UPDATE]
    assert changes[0].changes["serial"] == ("", "FCH2222ABCD")
    assert changes[0].changes["slot"] == ("sw1 Gi1/0/5", "sw1 Gi1/0/9")
    apply(store, changes)
    assert store.by_serial("FCH2222ABCD").id == recorded.id


def test_a_device_read_with_its_serial_for_the_first_time_is_the_same_asset(store):
    seen = Device(key="ap1", name="ap1", kind="ap", platform="cisco AIR-AP2802I-B-K9", mgmt_ip="10.0.0.40")
    apply(store, plan(store, sightings(map_with(seen))))
    seen.serial = "FGL2222X1"
    [change] = plan(store, sightings(map_with(seen)))
    assert change.action == UPDATE and change.changes["serial"] == ("", "FGL2222X1")


def test_summary_counts_what_is_ticked(store):
    changes = plan(store, sightings(map_with(switch_device(serials=("FOC1", "FOC2")))))
    changes[1].chosen = False
    assert asset_compare.summary(changes) == "1 new"


def test_kind_said_by_hand_is_kept(store):
    apply(store, plan(store, sightings(map_with(switch_device()))))
    store.set_asset(store.by_serial("FOC1").id, kind=ROUTER)
    [change] = plan(store, sightings(map_with(switch_device())))
    assert change.action == SAME


# --------------------------------------------------------------------- Shared through the tribe's server

def tribe_assets(server, tmp_path, user):
    return TeamAssetStore(team_store(server, tmp_path, user))


def test_assets_shared_through_the_server(server, tmp_path):
    alice = tribe_assets(server, tmp_path, "alice")
    switch = alice.set_asset(None, serial="FOC1", kind=SWITCH, hostname="sw1")
    alice.set_assets([{"serial": "FOC2", "kind": SWITCH, "hostname": "sw2"},
                      {"serial": "LIT1", "kind": hardware.POWER, "parent_id": switch.id}])
    bob = tribe_assets(server, tmp_path, "bob")
    assert sorted(asset.serial for asset in bob.assets()) == ["FOC1", "FOC2", "LIT1"]
    assert bob.by_serial("FOC1").modified_by == "alice (PC)"
    assert [asset.serial for asset in bob.parts_of(switch.id)] == ["LIT1"]
    bob.set_asset(switch.id, hostname="sw1-core")
    with pytest.raises(IpamError, match="changed by bob"):  # Alice hasn't synced since
        alice.set_asset(switch.id, owner="Alice")
    with pytest.raises(IpamError, match="Serial number FOC2 was recorded as sw2 by alice"):
        bob.set_asset(None, serial="FOC2", kind=SWITCH)
    alice.team.sync()
    assert alice.by_serial("FOC1").hostname == "sw1-core"
    # A map's hardware brought in through the server, in one go
    apply(alice, plan(alice, sightings(map_with(switch_device(serials=("FOC1", "FOC3"))))), user="alice")
    bob.team.sync()
    assert bob.by_serial("FOC3") is not None and bob.by_serial("FOC1").hostname == "sw1"


def test_offline_asset_changes_wait_then_reach_the_server(server, tmp_path):
    alice = tribe_assets(server, tmp_path, "alice")
    switch = alice.set_asset(None, serial="FOC1", kind=SWITCH, hostname="sw1")
    alice.team.close()
    laptop = TeamAssetStore(offline_store(server, tmp_path))
    new = laptop.set_asset(None, serial="FOC2", kind=SWITCH, hostname="sw2")
    laptop.set_asset(new.id, owner="Field team")  # Merged with the change before
    laptop.set_asset(switch.id, location="Closet 1")
    temp = laptop.set_asset(None, serial="TEMP", kind=SWITCH)
    laptop.delete_asset(temp.id)  # Recorded and deleted offline: nothing to send
    assert laptop.by_serial("FOC2").owner == "Field team"  # Usable straight away
    assert laptop.pending_count() == 2 and laptop.pending_ids() == {new.id, switch.id}
    laptop.team.close()

    laptop = TeamAssetStore(online_again(server, tmp_path))
    assert laptop.flush() == (2, 0)
    bob = tribe_assets(server, tmp_path, "bob")
    assert bob.by_serial("FOC2").owner == "Field team" and bob.by_serial("FOC2").id == new.id
    assert bob.by_serial("FOC1").location == "Closet 1"


def test_offline_asset_changes_someone_beat_are_refused(server, tmp_path):
    alice = tribe_assets(server, tmp_path, "alice")
    switch = alice.set_asset(None, serial="FOC1", kind=SWITCH, hostname="sw1")
    alice.team.close()
    laptop = TeamAssetStore(offline_store(server, tmp_path))
    laptop.set_asset(None, serial="FOC2", kind=SWITCH, hostname="alice-sw2")
    laptop.set_asset(switch.id, status=RETIRED)
    laptop.team.close()

    bob = tribe_assets(server, tmp_path, "bob")
    bob.set_asset(None, serial="FOC2", kind=SWITCH, hostname="bob-sw2")
    bob.set_asset(switch.id, hostname="sw1-core")

    laptop = TeamAssetStore(online_again(server, tmp_path))
    assert laptop.flush() == (0, 2)
    errors = " | ".join(entry["error"] for entry in laptop.refused())
    assert "sw1-core was changed by bob" in errors and "Serial number FOC2 was recorded as bob-sw2 by bob" in errors
    assert laptop.by_serial("FOC1").status == IN_SERVICE  # Back to the server's version
    laptop.team.sync()
    assert laptop.by_serial("FOC2").hostname == "bob-sw2"


def test_older_server_without_assets(server, tmp_path):
    laptop = team_store(server, tmp_path, "alice")
    laptop.copy.set_meta("server_api", 10)
    assets = TeamAssetStore(laptop)
    with pytest.raises(IpamError, match="doesn't keep assets"):
        assets.set_asset(None, serial="FOC1", kind=SWITCH)
    assert assets.outgoing() == []


# --------------------------------------------------------------------- Base MACs

def mac_value(mac):
    return string(bytes.fromhex(mac.replace("-", "")))


def test_stack_members_each_have_their_own_base_mac():
    switch = stack_switch()
    switch.set(hardware.STACK_MAC, 1000, mac_value("70-1F-53-00-10-00"))
    switch.set(hardware.STACK_MAC, 2000, mac_value("70-1F-53-00-20-00"))
    switch.set(hardware.BRIDGE_ADDRESS, mac_value("70-1F-53-00-10-00"))  # The stack's: the active member's
    switch.interface(1, "GigabitEthernet1/0/1", mac="70-1F-53-00-10-81")
    switch.interface(2, "GigabitEthernet2/0/1", mac="70-1F-53-00-20-81")
    switch.interface(3, "Vlan10", mac="70-1F-53-00-10-C7")
    switch.interface(4, "Vlan20", mac="00-00-0C-07-AC-14")  # HSRP's: no member's
    network = FakeNetwork()
    network.add("10.0.0.11", switch)
    [device] = crawl(network).devices.values()
    one, two = hardware.chassis(device.parts)
    assert (one["mac"], one["mac_last"], two["mac"], two["mac_last"]) == (
        "70-1F-53-00-10-00", "70-1F-53-00-10-C7", "70-1F-53-00-20-00", "70-1F-53-00-20-81")
    assert device.mac == "70-1F-53-00-10-00"
    assert hardware.owns_mac(one, "70-1F-53-00-10-81") and not hardware.owns_mac(one, "70-1F-53-00-20-81")
    assert hardware.owns_mac(two, "70:1f:53:00:20:00") and not hardware.owns_mac(two, "00-00-0C-07-AC-14")
    found = {sighting.serial: sighting for sighting in sightings(NetworkMap.from_json(
        map_with(device).to_json()))}
    assert found["FOC2222B2BB"].mac == "70-1F-53-00-20-00" and found["LIT1111"].mac == ""


def test_a_stack_without_stackwise_gives_its_members_no_mac():
    switch = stack_switch()
    switch.set(hardware.BRIDGE_ADDRESS, mac_value("70-1F-53-00-10-00"))
    network = FakeNetwork()
    network.add("10.0.0.11", switch)
    [device] = crawl(network).devices.values()
    assert [part["mac"] for part in hardware.chassis(device.parts)] == ["", ""]
    assert device.mac == "70-1F-53-00-10-00"  # The stack's, shown on the map, but no one member's


def test_a_device_on_its_own_gives_its_lldp_chassis_id_or_its_management_mac():
    network = FakeNetwork()
    switch = network.add("10.0.0.11", FakeDevice("sw9", "Cisco IOS Software, Version 17.9.4a", CISCO_SWITCH))
    switch.interface(1, "Vlan1", mac="F8-7B-20-00-00-41")
    switch.address("10.0.0.11", 1)
    entity(switch, 1, 3, 0, "FOC9", "C9200L-24P")
    switch.set(hardware.LLDP_LOC_CHASSIS_SUBTYPE, number(4))
    switch.set(hardware.LLDP_LOC_CHASSIS_ID, mac_value("F8-7B-20-00-00-00"))
    switch.set(hardware.BRIDGE_ADDRESS, mac_value("F8-7B-20-00-00-80"))
    [device] = crawl(network).devices.values()
    [chassis] = hardware.chassis(device.parts)
    assert (chassis["mac"], chassis["mac_source"], chassis["mac_last"]) == ("F8-7B-20-00-00-00", hardware.BASE,
                                                                             "F8-7B-20-00-00-41")
    firewall = network.add("10.0.0.5", FakeDevice("pa-fw1", "Palo Alto Networks PA-3220 series firewall", PALO_ALTO))
    firewall.interface(1, "ethernet1/1", mac="00-1B-17-00-01-10")
    firewall.interface(2, "mgmt", mac="00-1B-17-00-01-00")
    firewall.address("10.0.0.5", 2)
    firewall.set(hardware.PAN_SERIAL, string("012801012345"))
    [device] = crawl(network, seeds=("10.0.0.5",)).devices.values()
    [chassis] = hardware.chassis(device.parts)
    assert (chassis["mac"], chassis["mac_source"]) == ("00-1B-17-00-01-00", hardware.MANAGEMENT)
    assert not hardware.owns_mac(chassis, "00-1B-17-00-01-10")  # Not a base MAC: no block


def test_base_macs_on_assets_and_a_replaced_chassis_with_another_mac(store):
    device = switch_device(serials=("FOC1", "FOC2"))
    device.parts[1]["mac"] = "70-1F-53-00-20-00"
    apply(store, plan(store, sightings(map_with(device))), when="2026-10-01")
    assert store.by_serial("FOC2").mac == "70-1F-53-00-20-00"
    later = switch_device(serials=("FOC1", "FOC9"))
    later.parts[1]["mac"] = "70-1F-53-00-90-00"
    changes = {change.sighting.serial: change for change in plan(store, sightings(map_with(later)))}
    assert changes["FOC9"].action == REPLACE and changes["FOC9"].asset.serial == "FOC2"


def test_a_chassis_without_a_serial_is_known_by_its_base_mac(store):
    device = switch_device(serials=("",))
    device.parts[0]["mac"] = "F8-7B-20-00-00-00"
    apply(store, plan(store, sightings(map_with(device))), when="2026-10-01")
    moved = switch_device(key="sw7", name="sw7", serials=("",))
    moved.parts[0]["mac"] = "F8-7B-20-00-00-00"
    [change] = plan(store, sightings(map_with(moved)))
    assert change.action == UPDATE and change.changes["hostname"] == ("sw1", "sw7")
