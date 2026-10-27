"""Aruba wireless controllers: their access points and Wi-Fi clients, read over SNMP and put on the map, the asset
list, Watch and MAC Finder."""
import datetime
from types import SimpleNamespace

import pytest

from netmap_fakes import (ACC1_MAC, AP1_MAC, AP2_MAC, AP3_MAC, LAPTOP_MAC, TABLET_MAC, WIRED_USER_MAC, WLC_SERIAL,
                          add_aruba, build_network, number)

from nomad.ipam.asset_compare import sightings
from nomad.ipam.asset_team import TeamAssetStore
from nomad.netmap import aruba, collect, macfind, overlays, watch
from nomad.netmap.crawl import CrawlSettings, Crawler
from nomad.netmap.model import AP, AP_DOWN, AP_UP, CONTROLLER, SNMP, WLC, NetworkMap

NOW = datetime.datetime(2026, 10, 27, 9, 30)


def settings(seeds=("10.0.0.1",), **options):
    return CrawlSettings(seeds=list(seeds), overrides=[("10.0.0.12/32", "secret")], trace=False, **options)


def crawl(network, **options):
    return Crawler(settings(**options), client_factory=network.client, pinger=network.ping, echo=network.echo).run()


@pytest.fixture
def network():
    network = build_network()
    add_aruba(network)
    return network


@pytest.fixture
def mapped(network):
    return crawl(network)


# --------------------------------------------------------------------- Reading a controller

def test_access_points_from_the_ap_table(network):
    rows = sorted(network.devices["10.0.0.20"].mib.items())
    aps = {ap.mac: ap for ap in aruba.access_points(rows)}
    assert set(aps) == {AP1_MAC, AP2_MAC, AP3_MAC}
    ap1 = aps[AP1_MAC]
    assert (ap1.name, ap1.ip, ap1.group, ap1.model, ap1.serial, ap1.software, ap1.up, ap1.uptime) == \
        ("ap1", "10.20.0.11", "campus", "AP-505", "CNAA000001", "8.10.0.15-FIPS", True, 3600)
    assert not aps[AP2_MAC].up and aps[AP2_MAC].software == "" and aps[AP2_MAC].model == "AP-635"


def test_clients_from_the_station_and_user_tables(network):
    rows = sorted(network.devices["10.0.0.20"].mib.items())
    aps = aruba.access_points(rows)
    clients = {client.mac: client for client in aruba.clients(rows, rows, rows, aps)}
    assert WIRED_USER_MAC not in clients  # The controller's own wired port's user
    laptop = clients[LAPTOP_MAC]
    assert (laptop.ip, laptop.name, laptop.user, laptop.ap, laptop.ap_name, laptop.ssid, laptop.vlan) == \
        ("10.30.0.5", "LAPTOP-7", "", AP1_MAC, "ap1", "Corp", 30)
    tablet = clients[TABLET_MAC]  # Only in the user table, with no address yet: its AP found by name
    assert (tablet.ip, tablet.name, tablet.user, tablet.ap, tablet.ap_name) == ("", "", "jdoe", AP3_MAC, "ap3")


def test_names_models_and_controllers():
    assert aruba.user_name("host/PC-0142") == ("PC-0142", "")
    assert aruba.user_name("CORP\\jdoe") == ("", "CORP\\jdoe")
    assert aruba.ap_model("635") == "AP-635" and aruba.ap_model("RAP-3WN") == "RAP-3WN"
    descr = "ArubaOS (MODEL: ArubaMC-VA-US), Version 8.10.0.15-FIPS LSR (91324)"
    assert aruba.controller_model(descr) == "ArubaMC-VA-US"
    assert aruba.is_controller("1.3.6.1.4.1.14823.1.1.52", descr)
    assert not aruba.is_controller("1.3.6.1.4.1.9.1.2494", "Cisco IOS Software")
    assert collect.classify("1.3.6.1.4.1.14823.1.1.52", descr) == WLC
    # As a switch's LLDP sees them: a hardware controller, and an AP (with or without the WLAN capability)
    assert collect.classify(capabilities=frozenset({"bridge", "router"}),
                            platform="ArubaOS (MODEL: Aruba7210), Version 8.10.0.15") == WLC
    assert collect.classify(capabilities=frozenset({"ap"}), platform="ArubaOS (MODEL: 505), Version Aruba AP") == AP
    assert collect.classify(platform="ArubaOS (MODEL: 505), Version Aruba AP") == AP


# --------------------------------------------------------------------- On the map

def test_controller_is_read_with_its_serial_and_software(mapped):
    wlc = mapped.devices["wlc1"]
    assert (wlc.kind, wlc.source, wlc.platform, wlc.software) == (WLC, SNMP, "Aruba7210", "8.10.0.15-FIPS")
    assert [(part["serial"], part["model"]) for part in wlc.parts] == [(WLC_SERIAL, "Aruba7210")]


def test_access_point_seen_by_lldp_gets_what_the_controller_knows(mapped):
    ap1 = mapped.devices["ap1"]
    assert (ap1.kind, ap1.source, ap1.platform, ap1.serial, ap1.software, ap1.mac) == \
        (AP, CONTROLLER, "AP-505", "CNAA000001", "8.10.0.15-FIPS", AP1_MAC)
    assert (ap1.controller, ap1.ap_group, ap1.ap_status) == ("wlc1", "campus", AP_UP)
    assert any({link.a, link.b} == {"acc1", "ap1"} for link in mapped.links)  # Still on its switch port
    assert [key for key, device in mapped.devices.items() if device.mac == AP1_MAC] == ["ap1"]  # Once


def test_access_points_on_no_switch_are_laid_out_by_their_controller(mapped):
    assert mapped.devices["ap2"].ap_status == AP_DOWN and mapped.devices["ap3"].ap_status == AP_UP
    edges = mapped.layout_edges()
    assert ("ap2", "wlc1") in edges and ("ap3", "wlc1") in edges
    assert ("ap1", "wlc1") not in edges  # It has its switch
    assert sorted(mapped.access_points_of("wlc1")) == ["ap1", "ap2", "ap3"]


def test_wifi_clients_are_hosts_on_their_access_points(mapped):
    hosts = {host.mac: host for host in mapped.hosts}
    laptop = hosts[LAPTOP_MAC]
    assert (laptop.device, laptop.port, laptop.ip, laptop.name, laptop.vlan, laptop.controller) == \
        ("ap1", "Corp", "10.30.0.5", "LAPTOP-7", 30, "wlc1")
    assert laptop.wireless
    tablet = hosts[TABLET_MAC]
    assert (tablet.device, tablet.port, tablet.ip, tablet.user) == ("ap3", aruba.WIFI, "10.30.0.6", "jdoe")  # ARP
    assert AP1_MAC not in hosts  # The AP isn't a host on the switch port it's plugged into
    assert not [host for host in mapped.hosts if host.device == "acc1" and host.port == "Gi1/0/8"]
    assert ACC1_MAC not in hosts


def test_no_clients_without_hosts(network):
    network_map = crawl(network, collect_hosts=False)
    assert not [host for host in network_map.hosts if host.wireless]
    assert network_map.devices["ap1"].ap_status == AP_UP


def test_controller_read_again_replaces_its_clients(network, mapped):
    wlc = network.devices["10.0.0.20"]
    laptop = tuple(bytes.fromhex(LAPTOP_MAC.replace("-", "")))
    for key in [key for key in wlc.mib if key[:len(aruba.USER_ENTRY.split("."))] ==
                tuple(int(part) for part in aruba.USER_ENTRY.split(".")) and key[-10:-4] == laptop]:
        del wlc.mib[key]
    for column in aruba.STATION_COLUMNS:
        del wlc.mib[tuple(int(part) for part in aruba.STATION_ENTRY.split(".")) + (column,) + laptop]
    newer = Crawler(settings(["10.0.0.20"]), client_factory=network.client, pinger=network.ping,
                    echo=network.echo, known=mapped).run()
    mapped.merge_crawl(newer)
    assert LAPTOP_MAC not in {host.mac for host in mapped.hosts}  # Gone from the controller: gone from the map
    assert TABLET_MAC in {host.mac for host in mapped.hosts}


def test_map_saves_and_loads_wireless(mapped):
    loaded = NetworkMap.from_json(mapped.to_json())
    assert loaded.devices["ap2"].ap_status == AP_DOWN and loaded.devices["ap2"].controller == "wlc1"
    assert next(host for host in loaded.hosts if host.mac == LAPTOP_MAC).wireless


def test_wireless_overlay(mapped):
    overlay = overlays.build(mapped, overlays.WIRELESS)
    assert overlay.devices["ap1"].color == "success" and overlay.devices["ap2"].color == "error"
    assert overlay.devices["wlc1"].color == "accent"
    assert {(a, b) for a, b, _ in overlay.extra_lines} == {("ap1", "wlc1"), ("ap2", "wlc1"), ("ap3", "wlc1")}
    assert "core" not in overlay.devices and overlay.tone == "error"
    assert overlay.summary == ["1 controller", "3 access points", "1 down", "2 Wi-Fi clients"]
    grouped = overlays.build(mapped, overlays.COLOR, "ap_group")
    assert set(grouped.devices) == {"ap1", "ap2", "ap3"}


# --------------------------------------------------------------------- Assets

def test_access_points_and_controller_are_assets(mapped):
    found = {item.serial: item for item in sightings(mapped)}
    assert found[WLC_SERIAL].kind == WLC and found[WLC_SERIAL].model == "Aruba7210"
    ap2 = found["CNAA000002"]
    assert (ap2.kind, ap2.model, ap2.hostname, ap2.mac, ap2.map_device) == (AP, "AP-635", "ap2", AP2_MAC, "ap2")
    assert found["CNAA000001"].software == "8.10.0.15-FIPS"


def test_old_tribe_server_gets_controllers_as_other():
    old = SimpleNamespace(team=SimpleNamespace(server_knows_wlc=False))
    new = SimpleNamespace(team=SimpleNamespace(server_knows_wlc=True))
    assert TeamAssetStore.for_server(old, {"kind": "wlc", "serial": "X"}) == {"kind": "unknown", "serial": "X"}
    assert TeamAssetStore.for_server(new, {"kind": "wlc"}) == {"kind": "wlc"}
    assert TeamAssetStore.for_server(old, {"kind": "ap"}) == {"kind": "ap"}


# --------------------------------------------------------------------- Watch

OPTIONS = watch.WatchOptions(overrides=[("10.0.0.12/32", "secret")])


def test_watch_notices_an_access_point_going_down(network, mapped):
    assert watch.controllers(mapped) == {"wlc1"}
    baseline = watch.NeighborBaseline()
    targets = watch.switches(mapped)
    first = watch.read_signatures(targets, OPTIONS, network.client, wireless=watch.controllers(mapped))
    assert ("ap", AP1_MAC, AP_UP) in first["wlc1"]
    assert "wlc1" not in baseline.changed(mapped, first)  # The APs' status isn't a neighbor not on the map
    ap1 = tuple(bytes.fromhex(AP1_MAC.replace("-", "")))
    network.devices["10.0.0.20"].set(aruba.AP_ENTRY, aruba.AP_STATUS, ap1, number(2))
    second = watch.read_signatures(targets, OPTIONS, network.client, wireless=watch.controllers(mapped))
    assert baseline.changed(mapped, second) == ["wlc1"]
    crawled = watch.crawl_from(mapped, OPTIONS, ["10.0.0.20"], network.client, network.ping, network.echo)
    result = watch.apply_refresh(mapped, crawled, NOW, by="tester")
    assert result.access_points == ["ap1"]
    assert "Access point ap1 went down (wlc1)" in result.lines
    assert mapped.devices["ap1"].ap_status == AP_DOWN
    assert not [line for line in result.lines if "LAPTOP" in line or "host" in line.lower()]  # Wi-Fi isn't news


def test_signature_of_a_switch_has_no_access_points(network, mapped):
    signatures = watch.read_signatures({"core": "10.0.0.1"}, OPTIONS, network.client)
    assert not [entry for entry in signatures["core"] if entry[0] == "ap"]


# --------------------------------------------------------------------- MAC Finder

def test_map_search_finds_wifi_clients_on_their_access_point(mapped):
    snapshot = macfind.snapshot_map(mapped)
    [location] = macfind.search_map(snapshot, macfind.parse_query(LAPTOP_MAC))
    assert (location.device, location.switch, location.port, location.ip) == ("ap1", "ap1", "Corp", "10.30.0.5")
    assert location.note == "Wi-Fi client of access point ap1 on SSID Corp (controller wlc1)."
    assert location.path[-2:] == [["acc1.corp.example", "Gi1/0/8"], ["ap1", "Corp"]]
    [by_user] = macfind.search_map(snapshot, macfind.parse_query("jdoe"))
    assert by_user.mac == TABLET_MAC and by_user.name == "jdoe"


def test_live_search_asks_the_controller_first(network, mapped):
    snapshot = macfind.snapshot_map(mapped)
    network.requests.clear()
    locator = macfind.Locator(snapshot, settings(), client_factory=network.client)
    found, problem = locator.run([macfind.parse_query(LAPTOP_MAC)])[0]
    assert problem == ""
    [location] = found
    assert (location.device, location.port, location.vlan, location.source) == ("ap1", "Corp", 30, macfind.LIVE)
    assert "access point ap1" in location.note
    assert {host for host, _ in network.requests} == {"10.0.0.20"}  # No switch needed asking


def test_live_search_of_a_wired_mac_goes_on_to_the_switches(network, mapped):
    from netmap_fakes import PRINTER_MAC
    locator = macfind.Locator(macfind.snapshot_map(mapped), settings(), client_factory=network.client)
    found, _ = locator.run([macfind.parse_query(PRINTER_MAC)])[0]
    assert [(location.device, location.port) for location in found] == [("acc1", "Gi1/0/7")]


def test_partial_mac_search_reads_the_controllers_clients(network, mapped):
    locator = macfind.Locator(macfind.snapshot_map(mapped), settings(), client_factory=network.client)
    found, problem = locator.run([macfind.parse_query("82-00-00-3")])[0]  # The laptop and the tablet
    assert problem == ""
    places = {location.mac: (location.device, location.port, location.ip, location.name) for location in found}
    assert places == {LAPTOP_MAC: ("ap1", "Corp", "10.30.0.5", "LAPTOP-7"),
                      TABLET_MAC: ("ap3", aruba.WIFI, "10.30.0.6", "jdoe")}
    assert all(location.source == macfind.LIVE and "access point" in location.note for location in found)


def test_whole_mac_from_the_tables_read_is_a_wifi_client(network, mapped):
    locator = macfind.Locator(macfind.snapshot_map(mapped), settings(), client_factory=network.client)
    locator.read_all_tables()
    [location] = locator.from_tables(LAPTOP_MAC, LAPTOP_MAC.replace("-", ""))
    assert (location.device, location.port) == ("ap1", "Corp")  # Not acc1 Gi1/0/8, where the switch learned it
