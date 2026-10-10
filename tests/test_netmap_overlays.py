"""Overlays on the network map: what a failure cuts off, single points of failure, trunk problems, VRFs, subnets
and Color By, worked out from a map and drawn on the physical view."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from netmap_fakes import CISCO_SWITCH, FakeNetwork  # noqa: E402
from netmap_fakes import Device as FakeDevice  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMenu  # noqa: E402
from test_netmap_tab import Window  # noqa: E402
from test_netmap_vlans import crawl, two_switches  # noqa: E402

from nomad.netmap import collect, counters, overlays, store  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, apply_vlans, read_vlans_of  # noqa: E402
from nomad.netmap.model import AP, ROUTER, SWITCH, Device, Host, Link, NetworkMap  # noqa: E402
from nomad.netmap.vlan_path import StpView  # noqa: E402
from nomad.snmp import COUNTER64, GAUGE32, INTEGER, Value  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.navigation import Navigator  # noqa: E402
from nomad.ui.netmap_view import FADED, DeviceItem, LinkItem  # noqa: E402


def campus():
    """core -- dist1, core -- dist2; acc1 on both (redundant); acc2 on dist1 only (two links: a port-channel), and
    an AP on acc2. Hosts on acc1 and acc2."""
    network_map = NetworkMap(root="core", seeds=["10.0.0.1"])
    for key, kind, address in (("core", ROUTER, "10.0.0.1"), ("dist1", SWITCH, "10.0.0.2"),
                               ("dist2", SWITCH, "10.0.0.3"), ("acc1", SWITCH, "10.0.0.4"),
                               ("acc2", SWITCH, "10.0.0.5"), ("ap1", AP, "")):
        network_map.devices[key] = Device(key, name=key, kind=kind, mgmt_ip=address)
    for a, a_port, b, b_port in (("core", "Gi0/1", "dist1", "Gi1/0/1"), ("core", "Gi0/2", "dist2", "Gi1/0/1"),
                                 ("dist1", "Gi1/0/2", "acc1", "Gi1/0/49"), ("dist2", "Gi1/0/2", "acc1", "Gi1/0/50"),
                                 ("dist1", "Gi1/0/3", "acc2", "Gi1/0/49"), ("dist1", "Gi1/0/4", "acc2", "Gi1/0/50"),
                                 ("acc2", "Gi1/0/1", "ap1", "Gi0")):
        network_map.links.append(Link(a, a_port, b, b_port, ["cdp"]))
    network_map.hosts = [Host("aa:00:00:00:00:01", "acc1", "Gi1/0/5", "10.1.1.10", vlan=10),
                         Host("aa:00:00:00:00:02", "acc2", "Gi1/0/5", "10.1.1.11", vlan=10),
                         Host("aa:00:00:00:00:03", "acc2", "Gi1/0/6", "10.2.2.12", vlan=20)]
    return network_map


def links_between(network_map, a, b):
    return [link for link in network_map.links if {link.a, link.b} == {a, b}]


# --------------------------------------------------------------------- Failures

def test_a_failure_cuts_off_what_has_no_other_way():
    network_map = campus()
    overlay = overlays.impact(network_map, device="dist1")
    cut = {key for key, mark in overlay.devices.items() if mark.note.startswith("Cut off")}
    assert cut == {"acc2", "ap1"}
    assert overlay.devices["dist1"].note == "Fails"
    assert overlay.devices["core"].color == "success"  # Measured from the device put at the top
    assert overlay.tone == "error"
    assert "2 devices cut off" in overlay.summary[0] and "2 hosts lose the network" in overlay.summary
    for link in network_map.links_of("dist1"):
        assert overlay.links[id(link)].style == overlays.DASH
    [ap_link] = links_between(network_map, "acc2", "ap1")
    assert overlay.links[id(ap_link)].note == "Cut off from the rest"


def test_a_redundant_device_or_one_member_of_a_bundle_cuts_nothing_off():
    network_map = campus()
    assert overlays.cut_off(network_map, device="dist2") == (set(), "")
    assert overlays.cut_off(network_map, device="core") == (set(), "")  # dist1 and dist2 still meet at acc1
    bundle = links_between(network_map, "dist1", "acc2")
    assert overlays.cut_off(network_map, links=bundle[:1])[0] == set()
    assert overlays.cut_off(network_map, links=bundle) == ({"acc2", "ap1"}, "core")
    overlay = overlays.impact(network_map, links=bundle[:1])
    assert overlay.summary[0].startswith("nothing else is cut off") and not overlay.tone


def test_without_a_top_device_the_biggest_part_stays_connected():
    network_map = campus()
    network_map.root, network_map.seeds = "", []
    lost, known_by = overlays.cut_off(network_map, device="dist1")
    assert lost == {"acc2", "ap1"} and known_by == ""


def test_single_points_of_failure():
    network_map = campus()
    devices, links = overlays.single_points(network_map)
    assert devices == {"dist1": ["acc2", "ap1"], "acc2": ["ap1"]}
    assert set(links) == {("acc2", "dist1"), ("acc2", "ap1")}
    overlay = overlays.spof(network_map)
    assert overlay.devices["dist1"].color == "error"  # Cuts off a switch
    assert overlay.devices["acc2"].color == "warning"  # Only an AP
    for link in links_between(network_map, "dist1", "acc2"):
        assert "all 2 links of it" in overlay.links[id(link)].note
    assert overlay.tone == "warning"


# --------------------------------------------------------------------- Trunks, VRFs, subnets

def test_trunk_problems_mark_the_link_and_its_switches():
    network_map = crawl(two_switches())
    overlay = overlays.trunk_problems(network_map)
    [link] = network_map.links
    mark = overlay.links[id(link)]
    assert mark.color == "error" and "native VLAN 1 on one end, 99 on the other" in mark.note
    assert "allowed only on" in mark.note  # The warning on the same link is in its tooltip too
    assert overlay.devices["sw1"].color == "error" and "VLAN 40" in overlay.devices["sw1"].note
    assert overlay.tone == "error" and "1 problem" in overlay.summary[0]


def test_vrf_overlay():
    network_map = campus()
    network_map.devices["dist1"].port_vrfs = {"Gi1/0/3": "RED", "Gi1/0/4": "RED"}
    network_map.devices["acc2"].port_vrfs = {"Gi1/0/49": "RED"}
    network_map.devices["core"].vrf_routes = {"RED": [["0.0.0.0", "10.9.9.9", "Gi0/9", "static"]]}
    assert overlays.map_vrfs(network_map) == {"RED": 3}
    overlay = overlays.vrf(network_map, "RED")
    assert set(overlay.devices) == {"dist1", "acc2", "core"}
    first, second = links_between(network_map, "dist1", "acc2")
    assert overlay.links[id(first)].color == "accent"
    assert overlay.links[id(second)].color == "warning"  # acc2's end isn't in it
    assert overlays.build(network_map, overlays.VRF, "BLUE") is None


def test_subnet_overlay_follows_its_vlan():
    network_map = campus()
    dist1, acc1 = network_map.devices["dist1"], network_map.devices["acc1"]
    dist1.interfaces_l3 = [["10.1.1.1", 24, "Vlan10"], ["10.0.0.2", 32, "Loopback0"]]
    for device, port in ((dist1, "Gi1/0/2"), (acc1, "Gi1/0/49")):
        device.vlans = [[1, "default"], [10, "USERS"]]
        device.port_vlans = {port: {"mode": "trunk", "native": 1, "allowed": "1,10"}}
    assert overlays.map_subnets(network_map) == ["10.1.1.0/24"]  # Not the loopback's /32
    overlay = overlays.subnet(network_map, "10.1.1.0/24")
    assert overlay.devices["dist1"].color == "accent" and "10.1.1.1/24 on Vlan10" in overlay.devices["dist1"].note
    [trunk] = links_between(network_map, "dist1", "acc1")
    assert overlay.links[id(trunk)].note == "Carries VLAN 10"
    assert "1 host in it" in overlay.devices["acc1"].note and "1 host in it" in overlay.devices["acc2"].note
    assert "core" not in overlay.devices
    assert overlays.build(network_map, overlays.SUBNET, "not a subnet") is None
    managed = overlays.subnet(network_map, "10.0.0.0/29")
    assert managed.devices["core"].note == "Managed at 10.0.0.1"


# --------------------------------------------------------------------- Color By

def test_color_by_model_and_software_version():
    network_map = campus()
    for key in ("dist1", "dist2", "acc1"):
        network_map.devices[key].platform = "C9300"
    network_map.devices["acc2"].platform = "C2960"
    network_map.devices["core"].sys_descr = ("Cisco IOS Software, ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), "
                                             "Version 17.3.4a, RELEASE SOFTWARE (fc3)")
    overlay = overlays.color_by(network_map, "platform")
    assert not overlay.fade
    assert overlay.devices["dist1"].color == overlays.PALETTE[0]  # The most common first
    assert overlay.devices["acc2"].color == overlays.PALETTE[1]
    assert overlay.devices["core"].color == overlays.OTHER and overlay.legend[-1][1] == "(not known) (2)"
    assert overlays.software_version(network_map.devices["core"]) == "17.3.4a"
    assert overlays.color_by(network_map, "version").devices["core"].note == "Software Version: 17.3.4a"


def test_color_by_site():
    network_map = campus()
    site = network_map.new_group("HQ")
    building = network_map.new_group("Main", "building", site.key)
    network_map.set_group(["dist1"], building.key)
    overlay = overlays.color_by(network_map, "site")
    assert overlay.devices["dist1"].note == "Site: HQ"


# --------------------------------------------------------------------- On the map page

@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def tab(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    page.resize(1200, 800)
    yield page
    page.shutdown()


def items(tab):
    found = tab.view.scene().items()
    return ({item.key: item for item in found if isinstance(item, DeviceItem)},
            [item for item in found if isinstance(item, LinkItem)])


def test_what_if_it_fails_on_the_map(tab):
    tab.show_map(campus())
    tab.show_overlay(overlays.IMPACT, "dist1")
    devices, links = items(tab)
    assert tab.vlan_bar.isVisibleTo(tab) and "If dist1 fails" in tab.vlan_label.text()
    assert devices["acc2"].mark.color == "error" and devices["acc2"].opacity() == 1.0
    assert devices["dist2"].opacity() == FADED
    assert "Cut off" in devices["ap1"].toolTip()
    bundle = next(item for item in links if len(item.links) == 2)
    assert bundle.mark is not None and "Goes down with it" in bundle.toolTip()

    tab.show_map(tab.network_map)  # Drawn again: still shown
    devices, _ = items(tab)
    assert devices["acc2"].mark is not None

    tab.highlight_vlan(10)  # One at a time
    assert tab.overlay_shown is None and tab.view.overlay is None
    devices, links = items(tab)
    assert all(item.mark is None for item in devices.values())
    assert devices["ap1"].toolTip() == devices["ap1"].base_tip
    tab.clear_vlan()
    assert not tab.vlan_bar.isVisibleTo(tab)


def test_color_by_keeps_everything_bright(tab):
    tab.show_map(campus())
    tab.show_overlay(overlays.COLOR, "kind")
    devices, links = items(tab)
    assert all(item.opacity() == 1.0 for item in devices.values())
    assert devices["core"].mark.color != devices["dist1"].mark.color
    assert "Router (1)" in tab.vlan_label.text()


def test_overlay_menu_and_stop(tab):
    tab.show_map(campus())
    tab.fill_overlay_menu()
    titles = [action.text() for action in tab.overlay_menu.actions()]
    assert titles[:3] == ["Highlight VLAN", "Highlight VRF", "Highlight Subnet"]
    assert "Single Points of Failure" in titles and "Color By" in titles and titles[-1] == "Show All (Esc)"
    spof = next(action for action in tab.overlay_menu.actions() if action.text() == "Single Points of Failure")
    spof.trigger()
    assert tab.overlay_shown == (overlays.SPOF, None)
    tab.fill_overlay_menu()  # Again: the one showing is ticked, and its old submenus are let go
    assert next(action for action in tab.overlay_menu.actions()
                if action.text() == "Single Points of Failure").isChecked()
    menu = QMenu()
    action = tab.add_stop_highlight(menu)
    assert action.text() == "Stop Showing Single points of failure (Show All)"
    tab.on_escape()
    assert tab.overlay_shown is None and not tab.vlan_bar.isVisibleTo(tab)


def test_escape_shows_all_inside_the_main_window_s_navigator(tab):
    navigator = Navigator()  # Its drawer's Escape mustn't make the map's ambiguous
    navigator.add_section("Discover")
    navigator.add_page(tab, "Network Map")
    navigator.resize(1200, 800)
    navigator.show()
    tab.show_map(campus())
    tab.show_overlay(overlays.SPOF)
    tab.view.setFocus()
    QApplication.processEvents()
    QTest.keyClick(tab.view, Qt.Key_Escape)
    assert tab.overlay_shown is None and not tab.vlan_bar.isVisibleTo(tab)
    tab.setParent(None)
    navigator.deleteLater()


def test_link_failure_from_a_link_s_menu(tab, monkeypatch):
    network_map = campus()
    tab.show_map(network_map)
    bundle = links_between(network_map, "dist1", "acc2")
    chosen = {}

    def exec_(menu, _position):
        chosen["texts"] = [action.text() for action in menu.actions()]
        return next(action for action in menu.actions() if action.text().startswith("What If"))
    monkeypatch.setattr(QMenu, "exec_", exec_)
    tab.show_link_menu(bundle, None)
    assert "What If All 2 Links Fail?" in chosen["texts"]
    assert tab.overlay_shown == (overlays.IMPACT, [link.key for link in bundle])
    assert "If the 2 links between acc2 and dist1 fail" in tab.vlan_label.text()


def test_overlay_of_something_gone_is_dropped(tab):
    tab.show_map(campus())
    tab.show_overlay(overlays.IMPACT, "dist1")
    newer = campus()
    del newer.devices["dist1"]
    newer.links = [link for link in newer.links if "dist1" not in (link.a, link.b)]
    tab.show_map(newer)
    assert tab.overlay_shown is None and not tab.vlan_bar.isVisibleTo(tab)


# --------------------------------------------------------------------- Read over SNMP: port status, STP, counters

def status_switch():
    """sw1 with an up 1G full-duplex port, an up 100M half-duplex port and a shut-down port."""
    device = FakeDevice("sw1", "Cisco IOS Software, Catalyst", CISCO_SWITCH)
    for index, name, admin, oper, speed, duplex in ((1, "GigabitEthernet1/0/1", 1, 1, 1000, 3),
                                                    (2, "GigabitEthernet1/0/2", 1, 1, 100, 2),
                                                    (3, "GigabitEthernet1/0/3", 2, 2, 1000, 1)):
        device.interface(index, name)
        device.set(collect.IF_ADMIN_STATUS, index, Value(INTEGER, admin))
        device.set(collect.IF_OPER_STATUS, index, Value(INTEGER, oper))
        device.set(collect.IF_HIGH_SPEED, index, Value(GAUGE32, speed))
        device.set(collect.DOT3_DUPLEX, index, Value(INTEGER, duplex))
    return device


def test_port_status_read_and_kept_on_the_device():
    network = FakeNetwork()
    network.add("10.0.0.1", status_switch())
    tables, _ = read_vlans_of(CrawlSettings(seeds=["10.0.0.1"]), "10.0.0.1", client_factory=network.client)
    assert tables.status_read
    device = Device("sw1", name="sw1", kind=SWITCH)
    apply_vlans(device, tables)
    assert device.port_status == {"Gi1/0/1": {"oper": "up", "speed": 1000, "duplex": "full"},
                                  "Gi1/0/2": {"oper": "up", "speed": 100, "duplex": "half"}}  # Not the shut one
    restored = NetworkMap.from_json(NetworkMap(devices={"sw1": device}).to_json())
    assert restored.devices["sw1"].port_status == device.port_status


def speed_map():
    network_map = campus()
    status = {"core": {"Gi0/1": (1000, "full"), "Gi0/2": (10000, "full")},
              "dist1": {"Gi1/0/1": (1000, "full"), "Gi1/0/2": (1000, "full"), "Gi1/0/3": (1000, "full"),
                        "Gi1/0/4": (1000, "full")},
              "dist2": {"Gi1/0/1": (10000, "full"), "Gi1/0/2": (1000, "full")},
              "acc1": {"Gi1/0/49": (100, "full"), "Gi1/0/50": (1000, "half")}}
    for key, ports in status.items():
        network_map.devices[key].port_status = {port: {"oper": "up", "speed": speed, "duplex": duplex}
                                                for port, (speed, duplex) in ports.items()}
    network_map.devices["acc2"].port_status = {"Gi1/0/50": {"oper": "down"}}
    return network_map


def test_link_speed_overlay():
    network_map = speed_map()
    overlay = overlays.link_speed(network_map)
    marks = {(link.a, link.a_port): overlay.links.get(id(link)) for link in network_map.links}
    assert marks[("core", "Gi0/1")].color == "#58a6ff" and marks[("core", "Gi0/1")].width == 3
    assert marks[("core", "Gi0/2")].color == "#4ecdc4"  # 10G
    assert marks[("dist1", "Gi1/0/2")].color == "warning" and "speeds differ" in marks[("dist1", "Gi1/0/2")].note
    assert marks[("dist2", "Gi1/0/2")].color == "error" and "Duplex mismatch" in marks[("dist2", "Gi1/0/2")].note
    assert marks[("dist1", "Gi1/0/4")].style == overlays.DASH  # Down at acc2's end
    assert marks[("acc2", "Gi1/0/1")] is None  # Nothing read at either end
    assert "1 not read" in overlay.summary[0] and overlay.tone == "error"
    assert overlays.speed_text(2500) == "2.5 Gb/s" and overlays.speed_text(100) == "100 Mb/s"


def test_link_speed_says_when_nothing_was_read():
    overlay = overlays.link_speed(campus())
    assert "not read yet" in overlay.summary[0] and not overlay.links


def test_spanning_tree_overlay():
    network_map = campus()
    views = {"dist1": StpView("rapid-pvst", 10, {"gi1/0/1": (collect.FORWARDING, "designated"),
                                                 "gi1/0/2": (collect.FORWARDING, "designated")}, root=True),
             "dist2": StpView("rapid-pvst", 10, {"gi1/0/2": (collect.FORWARDING, "designated")}, root=False),
             "acc1": StpView("rapid-pvst", 10, {"gi1/0/49": (collect.FORWARDING, "root"),
                                                "gi1/0/50": (collect.BLOCKING, "alternate")}, root=False)}
    overlay = overlays.spanning_tree(network_map, 10, views, unread=["acc2"])
    assert overlay.devices["dist1"].color == "accent" and "Root bridge of VLAN 10" in overlay.devices["dist1"].note
    assert "blocking on gi1/0/50" in overlay.devices["acc1"].note
    [blocked] = links_between(network_map, "dist2", "acc1")
    assert overlay.links[id(blocked)].color == "error"
    assert "acc1 Gi1/0/50: alternate" in overlay.links[id(blocked)].note
    [forwarding] = links_between(network_map, "dist1", "acc1")
    assert overlay.links[id(forwarding)].color == "link"
    assert overlay.summary[:2] == ["root bridge dist1", "1 link blocking, 2 forwarding"]
    assert "1 didn't answer" in overlay.summary


def test_counters_rates_and_the_utilization_overlay():
    network_map = campus()
    tracker = counters.CounterTracker()
    tracker.update("dist1", {"gi1/0/3": counters.Sample(0.0, 0, 0, 5, 0, 1000)})
    assert not tracker.rates  # One sample isn't a rate
    tracker.update("dist1", {"gi1/0/3": counters.Sample(10.0, 1_000_000_000, 125_000, 5, 2, 1000)})
    rate = tracker.rates[("dist1", "gi1/0/3")]
    assert rate.in_bps == 800_000_000 and rate.out_bps == 100_000 and rate.errors == 0 and rate.discards == 2
    tracker.update("dist1", {"gi1/0/4": counters.Sample(0.0, 0, 0, 0, 0, 1000)})
    tracker.update("dist1", {"gi1/0/4": counters.Sample(10.0, 1000, 1000, 3, 0, 1000)})
    overlay = overlays.utilization(network_map, tracker.rates)
    first, second = links_between(network_map, "dist1", "acc2")
    assert overlay.links[id(first)].color == "error" and "80% busy" in overlay.links[id(first)].note
    assert overlay.links[id(second)].style == overlays.DASH and "3 errors" in overlay.links[id(second)].note
    assert overlay.tone == "error" and "2 links measured" in overlay.summary
    tracker.update("dist1", {"gi1/0/3": counters.Sample(20.0, 5, 5, 5, 2, 1000)})  # Reloaded: counters went back
    assert ("dist1", "gi1/0/3") not in tracker.rates
    assert "turn Monitor on" in overlays.utilization(network_map, {}, monitoring=False).summary[0]


def test_counters_poll_reads_only_linked_ports():
    network = FakeNetwork()
    switch = network.add("10.0.0.1", status_switch())
    switch.set(collect.IF_HC_IN_OCTETS, 1, Value(COUNTER64, 5000))
    switch.set(collect.IF_HC_OUT_OCTETS, 1, Value(COUNTER64, 7000))
    found = counters.poll([("sw1", "10.0.0.1", "public", 2, 1000, ["Gi1/0/1", "Gi9/9/9"])], {}, network.client)
    index, samples = found["sw1"]
    assert index["gi1/0/1"] == 1 and set(samples) == {"gi1/0/1"}
    sample = samples["gi1/0/1"]
    assert (sample.in_octets, sample.out_octets, sample.speed) == (5000, 7000, 1000)
    assert counters.poll([("sw9", "10.9.9.9", "public", 2, 1000, ["Gi1"])], {}, network.client) == {}


def test_spanning_tree_overlay_from_the_menu(tab):
    network_map = campus()
    for key in ("dist1", "dist2", "acc1"):
        device = network_map.devices[key]
        device.source, device.vlans = "snmp", [[10, "USERS"]]
    tab.show_map(network_map)

    def read(settings, address, stp_vlan=None):
        tables = collect.DeviceTables(interfaces={1: "Gi1/0/50", 2: "Gi1/0/49"}, stp_mode="rapid-pvst",
                                      stp_instance=stp_vlan, stp_read=True)
        if address == "10.0.0.4":  # acc1
            tables.stp_ports = {1: (collect.BLOCKING, "alternate"), 2: (collect.FORWARDING, "root")}
            tables.stp_root = False
        elif address == "10.0.0.2":  # dist1
            tables.stp_root = True
        else:
            return None, None
        return tables, "public"
    tab.read_vlans = read
    assert tab.read_spanning_tree(10)
    tab.check_threads[-1].wait(5000)
    QApplication.processEvents()
    assert tab.stp_reading is None and tab.overlay_shown[0] == overlays.STP
    assert "root bridge dist1" in tab.vlan_label.text() and "1 didn't answer" in tab.vlan_label.text()
    _, links = items(tab)
    blocked = next(item for item in links if {item.links[0].a, item.links[0].b} == {"dist2", "acc1"})
    assert blocked.mark.color == "error"


def test_utilization_overlay_follows_monitoring(tab):
    network = FakeNetwork()
    switch = network.add("10.0.0.2", status_switch())
    network_map = NetworkMap(devices={"sw1": Device("sw1", name="sw1", kind=SWITCH, mgmt_ip="10.0.0.2",
                                                    source="snmp"),
                                      "sw2": Device("sw2", name="sw2", kind=SWITCH, mgmt_ip="10.0.0.3")},
                             links=[Link("sw1", "Gi1/0/1", "sw2", "Gi0/1", ["cdp"])])
    tab.show_map(network_map)
    tab.counters.client_factory = network.client
    tab.monitor.pinger = lambda address: 1
    tab.show_overlay(overlays.UTIL)
    assert "turn Monitor on" in tab.vlan_label.text()
    tab.monitor.timer.setInterval(3_600_000)
    tab.monitor_check.setChecked(True)
    for octets in (0, 125_000_000):  # Two polls, with 1 Gb of traffic in between
        switch.set(collect.IF_HC_IN_OCTETS, 1, Value(COUNTER64, octets))
        switch.set(collect.IF_HC_OUT_OCTETS, 1, Value(COUNTER64, 0))
        if tab.counters.thread is None:
            tab.counters.poll_now()
        tab.counters.thread.wait(5000)
        QApplication.processEvents()
    assert ("sw1", "gi1/0/1") in tab.counters.rates
    assert "1 link measured" in tab.vlan_label.text()
    _, [link] = items(tab)
    assert link.mark is not None and "busy" in link.mark.note
    tab.monitor_check.setChecked(False)
    assert not tab.counters.rates and "turn Monitor on" in tab.vlan_label.text()
