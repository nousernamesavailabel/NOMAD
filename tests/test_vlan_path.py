from netmap_fakes import CISCO_SWITCH, Device, FakeNetwork, number, string

from nomad.netmap import collect, crawl, vlan_path
from nomad.netmap.crawl import CrawlSettings
from nomad.netmap.model import FIREWALL, ROUTER, SNMP, SWITCH, Link, NetworkMap
from nomad.netmap.model import Device as MapDevice
from nomad.netmap.vlan_path import Hop, StpView, plan
from nomad.netmap.vlans import ERROR, INFO, WARNING


def trunk(allowed="1-4094", native=1):
    return {"mode": "trunk", "native": native, "allowed": allowed}


def access(vlan):
    return {"mode": "access", "vlan": vlan}


def switch(key, vlans=(1,), ports=None, vtp="transparent", domain="", stp="rapid-pvst", channels=None,
           interfaces=(), kind=SWITCH):
    return MapDevice(key, key, mgmt_ip=f"10.0.0.{abs(hash(key)) % 250 + 1}", kind=kind, source=SNMP,
                     vtp_mode=vtp, vtp_domain=domain, vlans=[[vlan, f"V{vlan}"] for vlan in vlans],
                     port_vlans=dict(ports or {}), port_channels=dict(channels or {}), stp_mode=stp,
                     interfaces_l3=[list(item) for item in interfaces])


def make_map(*devices, links=()):
    network_map = NetworkMap()
    network_map.devices = {device.key: device for device in devices}
    network_map.links = [Link(*link) for link in links]
    return network_map


def chain():
    """CORE (gateway for 20) - SW1 - SW2 - SW3: 20 reaches SW1; SW1's uplink to SW2 allows only 1; SW2 and SW3 lack
    20, and SW2 - SW3 allows everything."""
    return make_map(
        switch("CORE", (1, 20), {"Gi0/1": trunk("1,20")}, interfaces=[("10.1.20.1", 24, "Vlan20")]),
        switch("SW1", (1, 20), {"Gi0/1": trunk("1,20"), "Gi0/2": trunk("1")}),
        switch("SW2", (1,), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        switch("SW3", (1,), {"Gi0/1": trunk(), "Gi0/5": access(10)}),
        links=[("CORE", "Gi0/1", "SW1", "Gi0/1"), ("SW1", "Gi0/2", "SW2", "Gi0/1"), ("SW2", "Gi0/2", "SW3", "Gi0/1")])


def steps_of(result):
    return {(step.device, step.redundant): (step.create_vlan, list(step.trunks), [port for port, _ in step.edge])
            for step in result.changes}


# --------------------------------------------------------------------- Finding the way

def test_carries_from_the_nearest_switch_that_has_it():
    result = plan(chain(), 20, "USERS", b="SW3")
    assert result.ok and not result.already
    assert result.a == "SW1" and result.route == ["SW1", "SW2", "SW3"]
    assert steps_of(result) == {("SW1", False): (False, ["Gi0/2"], []), ("SW2", False): (True, ["Gi0/1"], []),
                                ("SW3", False): (True, [], [])}
    assert result.gateway.severity == INFO and "10.1.20.1/24 on CORE Vlan20" in result.gateway.text
    assert "reachable" in result.gateway.text


def test_already_carried_needs_only_the_edge_ports():
    network_map = chain()
    result = plan(network_map, 20, b="SW1", edge_ports=["Gi0/2"])
    assert result.already and result.route == ["SW1"]
    assert steps_of(result) == {("SW1", False): (False, ["Gi0/2"], [])}  # A trunk edge port: allowed vlan add
    network_map.devices["SW1"].port_vlans["Gi0/3"] = access(10)
    result = plan(network_map, 20, b="SW1", edge_ports=["Gi0/3"])
    assert steps_of(result) == {("SW1", False): (False, [], ["Gi0/3"])}
    assert result.changes[0].edge == [("Gi0/3", access(10))]


def test_fewest_changes_beats_fewest_hops():
    # A - B direct needs both ends changed; A - X - Y - B allows 30 everywhere and X, Y have it
    network_map = make_map(
        switch("A", (1, 30), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        switch("X", (1, 30), {"Gi0/1": trunk(), "Gi0/2": trunk()}),
        switch("Y", (1, 30), {"Gi0/1": trunk(), "Gi0/2": trunk()}),
        switch("B", (1, 30), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        links=[("A", "Gi0/1", "B", "Gi0/1"), ("A", "Gi0/2", "X", "Gi0/1"), ("X", "Gi0/2", "Y", "Gi0/1"),
               ("Y", "Gi0/2", "B", "Gi0/2")])
    result = plan(network_map, 30, a="A", b="B")
    assert result.route == ["A", "X", "Y", "B"]
    assert result.changes == []  # Nothing to change at all: it's carried already that way


def test_access_ports_are_never_crossed_or_converted():
    network_map = make_map(
        switch("A", (1, 20), {"Gi0/1": access(10)}),
        switch("B", (1,), {"Gi0/1": access(10)}),
        links=[("A", "Gi0/1", "B", "Gi0/1")])
    result = plan(network_map, 20, a="A", b="B")
    assert not result.ok and result.findings[0].severity == ERROR and "No way" in result.findings[0].text
    by_hand = plan(network_map, 20, route=["A", "B"])
    assert not by_hand.ok
    assert any("access port in VLAN 10" in finding.text for finding in by_hand.findings)


def test_routers_end_the_way_and_are_never_on_it():
    # The gateway is a router-on-a-stick: its Gi0/0.20 subinterface is on the link to SW1
    network_map = make_map(
        switch("R1", (), {}, kind=ROUTER, interfaces=[("10.1.20.1", 24, "Gi0/0.20")]),
        switch("SW1", (1,), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        switch("SW2", (1,), {"Gi0/1": trunk()}),
        links=[("R1", "Gi0/0", "SW1", "Gi0/1"), ("SW1", "Gi0/2", "SW2", "Gi0/1")])
    result = plan(network_map, 20, b="SW2")
    assert result.ok and result.route == ["R1", "SW1", "SW2"]
    assert steps_of(result) == {("SW1", False): (True, ["Gi0/1"], []), ("SW2", False): (True, [], [])}
    assert "reachable" in result.gateway.text
    # A router between two switches can't pass the VLAN on
    network_map = make_map(
        switch("SW1", (1, 20), {"Gi0/1": trunk()}),
        switch("R1", (), {}, kind=ROUTER),
        switch("SW2", (1,), {"Gi0/1": trunk()}),
        links=[("SW1", "Gi0/1", "R1", "Gi0/0"), ("R1", "Gi0/1", "SW2", "Gi0/1")])
    assert not plan(network_map, 20, a="SW1", b="SW2").ok
    by_hand = plan(network_map, 20, route=["SW1", "R1", "SW2"])
    assert any("can only be A" in finding.text for finding in by_hand.findings)


def test_port_channel_members_are_one_hop_on_the_port_channel():
    channels = {"Gi0/1": "Po1", "Gi0/2": "Po1"}
    network_map = make_map(
        switch("A", (1, 20), {"Gi0/1": trunk("1"), "Gi0/2": trunk("1"), "Po1": trunk("1")}, channels=channels),
        switch("B", (1,), {"Gi0/1": trunk("1"), "Gi0/2": trunk("1"), "Po1": trunk("1")}, channels=channels),
        links=[("A", "Gi0/1", "B", "Gi0/1"), ("A", "Gi0/2", "B", "Gi0/2")])
    graph = vlan_path.Graph(network_map)
    assert len(graph.hops) == 1 and graph.hops[0].a_port == "Po1" and len(graph.hops[0].links) == 2
    result = plan(network_map, 20, a="A", b="B")
    assert steps_of(result) == {("A", False): (False, ["Po1"], []), ("B", False): (True, ["Po1"], [])}
    assert result.redundant == []  # The members aren't redundant links: they're the port-channel
    assert "interface Gi0/1" not in vlan_path.config(result.changes[0], 20)


# --------------------------------------------------------------------- VTP

def test_vtp_clients_get_the_vlan_from_their_server():
    network_map = chain()
    network_map.devices["SW2"].vtp_mode, network_map.devices["SW2"].vtp_domain = "client", "CORP"
    network_map.devices["SW3"].vtp_mode, network_map.devices["SW3"].vtp_domain = "client", "CORP"
    network_map.devices["SRV"] = switch("SRV", (1,), vtp="server", domain="CORP")
    result = plan(network_map, 20, "USERS", b="SW3")
    assert result.changes[0].device == "SRV" and result.changes[0].create_vlan
    assert "VTP server for SW2" in result.changes[0].notes
    assert steps_of(result) == {("SRV", False): (True, [], []), ("SW1", False): (False, ["Gi0/2"], []),
                                ("SW2", False): (False, ["Gi0/1"], [])}
    del network_map.devices["SRV"]
    result = plan(network_map, 20, b="SW3")
    assert not result.ok and any("no VTP server" in finding.text for finding in result.findings)


def test_extended_vlans_warn_on_vtp_servers():
    network_map = make_map(
        switch("A", (1, 2000), {"Gi0/1": trunk()}),
        switch("B", (1,), {"Gi0/1": trunk()}, vtp="server", domain="CORP"),
        links=[("A", "Gi0/1", "B", "Gi0/1")])
    result = plan(network_map, 2000, a="A", b="B")
    assert result.ok and any(finding.severity == WARNING and "extended VLAN" in finding.text
                             for finding in result.findings)


# --------------------------------------------------------------------- Redundant links and spanning tree

def triangle(stp="rapid-pvst"):
    """SW1 (has 20) - SW2 - SW3, and SW1 - SW3 directly, which allows only 1 at both ends."""
    return make_map(
        switch("SW1", (1, 20), {"Gi0/1": trunk(), "Gi0/2": trunk("1")}, stp=stp),
        switch("SW2", (1,), {"Gi0/1": trunk(), "Gi0/2": trunk()}, stp=stp),
        switch("SW3", (1,), {"Gi0/1": trunk(), "Gi0/2": trunk("1")}, stp=stp),
        links=[("SW1", "Gi0/1", "SW2", "Gi0/1"), ("SW2", "Gi0/2", "SW3", "Gi0/1"), ("SW1", "Gi0/2", "SW3", "Gi0/2")])


def test_redundant_links_are_offered_with_spanning_tree_notes_and_go_last():
    network_map = triangle()
    result = plan(network_map, 20, a="SW1", b="SW3", route=None)
    assert result.route == ["SW1", "SW2", "SW3"]  # Creating 20 on SW2 + SW3 beats 2 trunk ends + SW3
    assert len(result.redundant) == 1
    item = result.redundant[0]
    assert {item.hop.a, item.hop.b} == {"SW1", "SW3"} and item.severity == INFO and "Rapid-PVST+" in item.note
    assert all(not step.redundant for step in result.changes)
    chosen = plan(network_map, 20, a="SW1", b="SW3", chosen=[item.hop.key])
    assert [step.redundant for step in chosen.changes][-2:] == [True, True]
    assert steps_of(chosen)[("SW1", True)] == (False, ["Gi0/2"], [])
    assert steps_of(chosen)[("SW3", True)] == (False, ["Gi0/2"], [])
    assert plan(triangle("mst"), 20, a="SW1", b="SW3").redundant[0].severity == WARNING
    unknown = plan(triangle(""), 20, a="SW1", b="SW3").redundant[0]
    assert unknown.severity == WARNING and "loop" in unknown.note
    network_map = triangle()
    network_map.devices["SW3"].stp_mode = "mst"
    assert "different spanning trees" in plan(network_map, 20, a="SW1", b="SW3").redundant[0].note


def test_parallel_links_not_in_a_port_channel_are_redundant():
    network_map = make_map(
        switch("A", (1, 20), {"Gi0/1": trunk("1"), "Gi0/2": trunk("1")}),
        switch("B", (1,), {"Gi0/1": trunk("1"), "Gi0/2": trunk("1")}),
        links=[("A", "Gi0/1", "B", "Gi0/1"), ("A", "Gi0/2", "B", "Gi0/2")])
    result = plan(network_map, 20, a="A", b="B")
    assert result.hops[0].a_port == "Gi0/1"
    assert len(result.redundant) == 1 and result.redundant[0].parallel and "port-channel" in result.redundant[0].note


def test_mst_blocked_ports_are_avoided_unless_the_route_is_set_by_hand():
    network_map = triangle("mst")
    # SW2 blocks its link to SW3 in the VLAN's MST instance
    stp = {"SW2": StpView("mst", 1, {"gi0/2": (collect.BLOCKING, "alternate")})}
    result = plan(network_map, 20, a="SW1", b="SW3", stp=stp)
    assert result.route == ["SW1", "SW3"]
    forced = plan(network_map, 20, route=["SW1", "SW2", "SW3"], stp=stp)
    assert forced.ok and forced.route == ["SW1", "SW2", "SW3"]
    assert any(finding.severity == WARNING and "blocks" in finding.text for finding in forced.findings)


# --------------------------------------------------------------------- Routes set by hand

def test_a_route_set_by_hand_is_planned_as_given():
    network_map = triangle()
    result = plan(network_map, 20, route=["SW1", "SW3"])
    assert result.by_hand and result.route == ["SW1", "SW3"]
    assert steps_of(result) == {("SW1", False): (False, ["Gi0/2"], []), ("SW3", False): (True, ["Gi0/2"], [])}
    assert result.redundant == []  # SW2 won't have VLAN 20, so its links can't close a loop


def test_routes_set_by_hand_are_checked():
    network_map = chain()
    gap = plan(network_map, 20, route=["SW1", "SW3"])
    assert not gap.ok and "No link between SW1 and SW3" in gap.findings[0].text
    again = plan(network_map, 20, route=["SW1", "SW2", "SW1"])
    assert any("twice" in finding.text for finding in again.findings)
    assert not plan(network_map, 20, route=["SW1"]).ok
    filled = vlan_path.fill_between(network_map, 20, "SW1", "SW3")
    assert filled[0] == ["SW1", "SW2", "SW3"]
    assert vlan_path.fill_between(network_map, 20, "SW1", "SW3", avoid=["SW2"]) is None


def test_several_links_need_one_chosen():
    network_map = make_map(
        switch("A", (1, 20), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        switch("B", (1,), {"Gi0/1": trunk("1"), "Gi0/2": trunk()}),
        links=[("A", "Gi0/1", "B", "Gi0/1"), ("A", "Gi0/2", "B", "Gi0/2")])
    result = plan(network_map, 20, route=["A", "B"])
    assert not result.ok and "have 2 links" in result.findings[0].text
    graph = vlan_path.Graph(network_map)
    first = next(hop for hop in graph.between("A", "B") if hop.port_on("A") == "Gi0/1")
    result = plan(network_map, 20, route=["A", "B"], route_hops=[first])
    assert result.ok and steps_of(result) == {("A", False): (False, ["Gi0/1"], []), ("B", False): (True, ["Gi0/1"], [])}


# --------------------------------------------------------------------- Gateway (check only)

def test_gateway_outcomes():
    network_map = chain()
    for device in network_map.devices.values():
        device.interfaces_l3 = []
    assert "No gateway" in plan(network_map, 20, b="SW3").gateway.text
    network_map = chain()
    # Carry 20 from a switch in an island of its own: the gateway's island isn't joined
    network_map.devices["SW2"].vlans.append([20, "V20"])
    network_map.devices["SW2"].port_vlans["Gi0/9"] = access(20)
    network_map.links.append(Link("SW2", "Gi0/9", "PC", "eth0"))
    result = plan(network_map, 20, a="SW2", b="SW3")
    assert result.route == ["SW2", "SW3"]
    assert result.gateway.severity == WARNING and "isn't connected" in result.gateway.text


# --------------------------------------------------------------------- Configuration

def test_configuration_and_undo_text():
    result = plan(chain(), 20, "Sales Floor", b="SW3", edge_ports=["Gi0/5"])
    by_device = {step.device: step for step in result.changes}
    text = vlan_path.config(by_device["SW2"], 20)
    assert text.splitlines() == ["configure terminal", "vlan 20", " name Sales_Floor", " exit", "!",
                                 "interface Gi0/1", " switchport trunk allowed vlan add 20", " exit", "!", "end"]
    assert vlan_path.config(by_device["SW3"], 20, save=True).splitlines()[-1] == "write memory"
    sw3 = vlan_path.config(by_device["SW3"], 20)
    assert "interface Gi0/5\n switchport access vlan 20" in sw3 and "switchport mode access" not in sw3
    assert vlan_path.undo(by_device["SW3"], 20).splitlines() == [
        "configure terminal", "interface Gi0/5", " switchport access vlan 10", " exit", "!", "no vlan 20", "end"]
    assert vlan_path.undo(by_device["SW1"], 20).splitlines() == [
        "configure terminal", "interface Gi0/2", " switchport trunk allowed vlan remove 20", " exit", "!", "end"]
    export = vlan_path.export_text(chain(), result)
    assert "! Route: SW1 > SW2 > SW3" in export and "! Undo:" in export


def test_every_trunk_line_adds_rather_than_replaces():
    for network_map, kwargs in ((chain(), {"b": "SW3"}), (triangle(), {"a": "SW1", "b": "SW3"})):
        everything = [item.hop.key for item in plan(network_map, 20, **kwargs).redundant]
        result = plan(network_map, 20, **kwargs, chosen=everything)
        for step in result.changes:
            for line in vlan_path.config(step, 20).splitlines():
                if "allowed vlan" in line:
                    assert line.strip() == "switchport trunk allowed vlan add 20"


def test_verify_after_the_switches_change():
    network_map = chain()
    result = plan(network_map, 20, b="SW3")
    outcome, others = vlan_path.verify(network_map, result)
    assert [bool(problems) for problems in outcome.values()] == [True, True, True] and not others
    network_map.devices["SW1"].port_vlans["Gi0/2"] = trunk("1,20")
    for key in ("SW2", "SW3"):
        network_map.devices[key].vlans.append([20, "V20"])
    network_map.devices["SW2"].port_vlans["Gi0/1"] = trunk("1,20")
    outcome, others = vlan_path.verify(network_map, result)
    assert all(not problems for problems in outcome.values()) and not others
    assert plan(network_map, 20, b="SW3").already


def test_candidates_are_the_way_its_neighbors_and_vtp_servers():
    network_map = chain()
    network_map.devices["SRV"] = switch("SRV", (1,), vtp="server", domain="")
    network_map.devices["SW2"].vtp_mode = "client"
    assert set(vlan_path.candidates(network_map, b="SW3", vlan=20)) == {"SW1", "SW2", "SW3", "CORE", "SRV"}
    assert set(vlan_path.candidates(network_map, route=["SW2", "SW3"])) == {"SW1", "SW2", "SW3", "SRV"}


def test_edge_port_choices_leave_out_members_and_put_links_last():
    network_map = chain()
    sw1 = network_map.devices["SW1"]
    sw1.port_vlans.update({"Gi0/3": access(10), "Gi0/4": trunk(), "Po1": trunk()})
    sw1.port_channels = {"Gi0/4": "Po1"}
    ports = [port for port, _ in vlan_path.edge_port_choices(network_map, "SW1")]
    assert ports == ["Gi0/3", "Po1", "Gi0/1", "Gi0/2"]


def test_hop_text():
    network_map = chain()
    hop = Hop("SW1", "Gi0/2", "SW2", "Gi0/1")
    assert hop.text(network_map) == "SW1 Gi0/2 - SW2 Gi0/1"
    assert hop.text(network_map, start="SW2") == "Gi0/1 - SW1 Gi0/2"


# --------------------------------------------------------------------- Reading spanning tree

def stp_switch(mode):
    device = Device("sw", "Cisco IOS Software, C2960", CISCO_SWITCH)
    for index, name in ((1, "Gi0/1"), (2, "Gi0/2"), (3, "Po1"), (4, "Gi0/3")):
        device.interface(index, name)
    device.vlan(1, "default")
    device.vlan(20, "USERS")
    device.trunk(1, [1, 20])
    device.trunk(3, [1, 20])
    device.lag(4, 3)
    device.set(collect.STP_TYPE, 0, number(mode))
    for bridge_port, if_index in ((1, 1), (2, 2), (3, 3)):
        device.set(collect.BASE_PORT_IFINDEX, bridge_port, number(if_index))
    return device


def test_parsers_for_spanning_tree():
    device = stp_switch(4)
    rows = sorted(device.mib.items())
    assert collect.stp_mode(rows) == "mst" and collect.stp_mode([]) == ""
    bitmap = bytearray(256)
    bitmap[20 // 8] |= 0x80 >> (20 % 8)
    device.set(collect.MST_INSTANCE_ENTRY, 2, 0, string(bytes(256)))
    device.set(collect.MST_INSTANCE_ENTRY, 2, 3, string(bytes(bitmap)))
    rows = sorted(device.mib.items())
    assert collect.mst_instance_of(rows, 20) == 3 and collect.mst_instance_of(rows, 30) == 0
    assert collect.mst_instance_of([], 20) == -1
    device.set(collect.RSTP_PORT_ROLE, 3, 1, number(2))
    device.set(collect.RSTP_PORT_ROLE, 3, 2, number(4))
    device.set(collect.RSTP_PORT_ROLE, 0, 2, number(3))
    roles = collect.rstp_port_roles(sorted(device.mib.items()), 3, {1: 1, 2: 2})
    assert roles == {1: (collect.FORWARDING, "root"), 2: (collect.BLOCKING, "alternate")}
    device.set(collect.STP_PORT_STATE, 1, number(5))
    device.set(collect.STP_PORT_STATE, 2, number(2))
    device.set(collect.STP_PORT_STATE, 3, number(4))
    states = collect.stp_port_states(sorted(device.mib.items()), {1: 1, 2: 2, 3: 3})
    assert states == {1: (collect.FORWARDING, "forwarding"), 2: (collect.BLOCKING, "blocking"),
                      3: (collect.BLOCKING, "learning")}


def read(device, vlan=20):
    network = FakeNetwork()
    network.add("10.0.0.9", device)
    return crawl.read_vlans_of(CrawlSettings(seeds=["10.0.0.9"]), "10.0.0.9", client_factory=network.client,
                               stp_vlan=vlan)


def test_reading_rapid_pvst_port_roles_and_port_channels():
    device = stp_switch(5)
    device.set(collect.RSTP_PORT_ROLE, 20, 1, number(2))
    device.set(collect.RSTP_PORT_ROLE, 20, 3, number(4))
    tables, _ = read(device)
    assert tables.stp_mode == "rapid-pvst" and tables.stp_instance == 20
    view = vlan_path.stp_view(tables)
    assert view.state("Gi0/1") == (collect.FORWARDING, "root") and view.state("Po1") == (collect.BLOCKING, "alternate")
    map_device = MapDevice("sw", "sw", kind=SWITCH, source=SNMP)
    crawl.apply_vlans(map_device, tables)
    assert map_device.stp_mode == "rapid-pvst" and map_device.port_channels == {"Gi0/3": "Po1"}


def test_reading_pvst_port_states_in_the_vlans_context():
    device = stp_switch(1)
    context = device.contexts.setdefault(20, {})
    device.set(collect.BASE_PORT_IFINDEX, 1, number(1), mib=context)
    device.set(collect.BASE_PORT_IFINDEX, 7, number(4), mib=context)
    device.set(collect.STP_PORT_STATE, 1, number(5), mib=context)
    device.set(collect.STP_PORT_STATE, 7, number(2), mib=context)
    tables, _ = read(device)
    assert tables.stp_mode == "pvst" and tables.stp_instance == 20
    assert tables.stp_ports == {1: (collect.FORWARDING, "forwarding"), 4: (collect.BLOCKING, "blocking")}


def test_reading_mst_finds_the_vlans_instance():
    device = stp_switch(4)
    bitmap = bytearray(256)
    bitmap[20 // 8] |= 0x80 >> (20 % 8)
    device.set(collect.MST_INSTANCE_ENTRY, 2, 2, string(bytes(bitmap)))
    device.set(collect.RSTP_PORT_ROLE, 2, 2, number(5))
    tables, _ = read(device)
    assert tables.stp_instance == 2 and tables.stp_ports == {2: (collect.BLOCKING, "backup")}
    assert read(stp_switch(4), vlan=None)[0].stp_read is False


def test_crawls_keep_port_channels_and_stp_mode_without_hosts():
    device = stp_switch(5)
    network = FakeNetwork()
    network.add("10.0.0.9", device)
    settings = CrawlSettings(seeds=["10.0.0.9"], trace=False, collect_hosts=False)
    network_map = crawl.Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    found = next(iter(network_map.devices.values()))
    assert found.stp_mode == "rapid-pvst" and found.port_channels == {"Gi0/3": "Po1"}


def test_routers_and_firewalls_are_endpoints():
    assert vlan_path.ENDPOINT_KINDS == {SWITCH, ROUTER, FIREWALL}


# --------------------------------------------------------------------- Lab images and what counts as a switch

IOL_L2 = "Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M), Version 15.2(CML_NIGHTLY_20190423)"
IOL_L3 = "Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M2"
CISCO_OID = ".".join(str(part) for part in CISCO_SWITCH)


def test_lab_images_and_switchports_decide_switch_or_router():
    both = frozenset({"router", "switch"})  # What IOL announces over CDP, L2 or L3
    assert collect.classify(CISCO_OID, IOL_L2, both, "Linux Unix") == SWITCH
    assert collect.classify(CISCO_OID, IOL_L3, both, "Linux Unix") == ROUTER
    assert collect.classify(CISCO_OID, "Cisco IOS Software, vios_l2 Software (vios_l2-ADVENTERPRISEK9-M)") == SWITCH
    assert collect.classify(CISCO_OID, "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M)") == ROUTER
    plain = "Cisco IOS Software, Version 15.2"
    assert collect.classify(CISCO_OID, plain, frozenset({"router"})) == ROUTER
    assert collect.classify(CISCO_OID, plain, frozenset({"router"}), switchports=True) == SWITCH
    assert collect.classify(CISCO_OID, "Cisco IOS Software, ISR Software", switchports=True) == ROUTER


def test_reading_vlans_again_turns_a_router_with_switchports_into_a_switch():
    device = stp_switch(1)
    device.set(collect.SYS_DESCR, string("Cisco IOS Software, Version 15.2"))
    tables, _ = read(device, vlan=None)
    taken = MapDevice("sw", "sw", kind=ROUTER, source=SNMP, sys_object_id=CISCO_OID, sys_descr="Cisco IOS Software")
    crawl.apply_vlans(taken, tables)
    assert taken.kind == SWITCH
    by_hand = MapDevice("sw", "sw", kind=ROUTER, source=SNMP, sys_object_id=CISCO_OID, corrected={"kind": [SWITCH,
                                                                                                         ROUTER]})
    crawl.apply_vlans(by_hand, tables)
    assert by_hand.kind == ROUTER  # Set by hand: left alone


def test_subinterfaces_arent_port_channels():
    device = Device("r1", IOL_L3, CISCO_SWITCH)
    device.interface(1, "Ethernet0/0")
    device.interface(2, "Ethernet0/0.172")
    device.interface(3, "Ethernet0/1")
    device.interface(4, "Port-channel1")
    device.lag(1, 2)  # ifStackTable puts a subinterface over its port too
    device.lag(3, 4)
    tables, _ = read(device, vlan=None)
    from nomad.netmap.model import short_port
    from nomad.netmap.vlans import device_port_channels
    assert device_port_channels(tables, short_port) == {"Eth0/1": "Po1"}
