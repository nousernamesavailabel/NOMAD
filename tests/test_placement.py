import pytest

from netmap_fakes import CISCO_ROUTER, Device as FakeDevice, FakeNetwork
from test_ipam_server import offline_store, plan, server, team_store  # noqa: F401 (fixture)

from nomad.ipam.client import ServerUnreachable
from nomad.ipam.placement import ADVERTISED, CANCELLED, DONE, IN_PROGRESS, LOCAL, NOTE, PROBLEM, WARNING, \
    PlacementStore, evaluate, move_check
from nomad.ipam.placement_team import TeamPlacementStore
from nomad.ipam.server import ADMIN
from nomad.ipam.store import IpamError, IpamStore
from nomad.ipam.vlan_team import TeamVlanStore
from nomad.ipam.vlans import VlanStore
from nomad.netmap import collect
from nomad.netmap.crawl import CrawlSettings, Crawler
from nomad.netmap.model import Device, Link, NetworkMap
from nomad.netmap.placement import analyze, places


# --------------------------------------------------------------------- VRFs, read over SNMP

def test_vrfs_read_from_cisco_vrf_mib_and_l3vpn_routes():
    network = FakeNetwork()
    router = network.add("10.0.0.1", FakeDevice("r1", "Cisco IOS Software, ISR", CISCO_ROUTER))
    router.interface(1, "GigabitEthernet0/0")
    router.interface(2, "GigabitEthernet0/1.100")
    router.address("10.0.0.1", 1)
    router.address("192.168.1.1", 2)
    router.cisco_vrf(1, "GUEST", [2])
    router.vrf_route("GUEST", "192.168.1.0", 24, "0.0.0.0", 2, kind=3, protocol=2)
    router.vrf_route("GUEST", "172.16.0.0", 16, "192.168.1.254", 2)
    router.vrf_route("GUEST", "10.66.0.0", 16, "0.0.0.0", 2, kind=2)  # A null route: left out
    table = sorted(router.mib.items())
    assert collect.cisco_vrf_interfaces(table, table) == {2: "GUEST"}
    device = Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False), client_factory=network.client,
                     pinger=network.ping).run().devices["r1"]
    assert device.port_vrfs == {"Gi0/1.100": "GUEST"}
    assert device.vrf_routes == {"GUEST": [["172.16.0.0/16", "192.168.1.254", "Gi0/1.100", "ospf"],
                                           ["192.168.1.0/24", "", "Gi0/1.100", "connected"]]}


# --------------------------------------------------------------------- Reading a map

def lab():
    """r1 -- r2, both with OSPF; sw1 and sw2 share VLAN 10 over a trunk (HSRP-style)."""
    network_map = NetworkMap()

    def device(key, interfaces, routes=(), **extra):
        network_map.devices[key] = Device(key, key, source="snmp", interfaces_l3=[list(item) for item in interfaces],
                                          routes=[list(route) for route in routes], **extra)

    device("r1", [("10.0.12.1", 30, "Gi0/0"), ("10.20.5.1", 24, "Gi0/2"), ("192.168.1.1", 24, "Gi0/3"),
                  ("10.30.0.1", 24, "Gi0/4")],
           [("10.0.12.0/30", "", "Gi0/0", "connected"), ("10.40.0.0/24", "10.0.12.2", "Gi0/0", "ospf")])
    device("r2", [("10.0.12.2", 30, "Gi0/0"), ("192.168.1.1", 24, "Gi0/3"), ("10.10.0.1", 24, "Gi0/5"),
                  ("10.40.0.1", 24, "Gi0/6")],
           [("10.0.12.0/30", "", "Gi0/0", "connected"), ("10.30.0.0/24", "10.0.12.1", "Gi0/0", "ospf"),
            ("10.20.0.0/16", "10.0.12.1", "Gi0/0", "ospf")],
           port_vrfs={"Gi0/5": "GUEST"}, vrf_routes={"GUEST": [["10.10.0.0/24", "", "Gi0/5", "connected"]]})
    device("sw1", [("10.50.0.2", 24, "Vlan50")], [("10.30.0.0/24", "10.0.12.1", "Te1/1", "ospf")],
           vlans=[[50, "USERS"]], port_vlans={"Te1/1": {"mode": "trunk", "native": 1, "allowed": "1,50"}})
    device("sw2", [("10.50.0.3", 24, "Vlan50")], vlans=[[50, "USERS"]],
           port_vlans={"Te1/1": {"mode": "trunk", "native": 1, "allowed": "1,50"}})
    network_map.links += [Link("r1", "Gi0/0", "r2", "Gi0/0"), Link("sw1", "Te1/1", "sw2", "Te1/1")]
    return network_map


def test_places_segments_and_advertised():
    found = {(item.vrf, item.cidr): item for item in analyze(lab())}
    assert len(found[("", "10.0.12.0/30")].segments) == 1  # Both ends of the link: one segment
    assert len(found[("", "10.50.0.0/24")].segments) == 1  # Two SVIs on a VLAN trunked between them
    assert found[("", "10.50.0.0/24")].advertised is False
    thirty = found[("", "10.30.0.0/24")]
    assert thirty.advertised and {route.device for route in thirty.learned} == {"r2", "sw1"}
    assert all(route.origin == 0 for route in thirty.learned if route.device == "r2")
    assert found[("", "10.20.5.0/24")].advertised is False
    assert found[("", "10.20.5.0/24")].summaries == [("10.20.0.0/16", ["r2"])]
    assert len(found[("", "192.168.1.0/24")].segments) == 2  # Reused on both routers, unrouted
    assert ("GUEST", "10.10.0.0/24") in found and ("", "10.10.0.0/24") not in found  # In a VRF


@pytest.fixture
def local(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    yield store
    store.close()


def test_findings(local):
    network_map = lab()
    # r2 has 10.30.0.0/24 too, on another port: an advertised subnet in two places
    network_map.devices["r2"].interfaces_l3.append(["10.30.0.9", 24, "Gi0/7"])
    network_map.devices["r2"].routes = [route for route in network_map.devices["r2"].routes
                                        if route[0] != "10.30.0.0/24"]
    network = local.add_network("Lab")
    for cidr in ("10.30.0.0/24", "10.50.0.0/24", "192.168.1.0/24", "10.20.5.0/24", "10.99.0.0/24"):
        local.add_subnet(network.id, cidr)
    vlans, placements = VlanStore(local), PlacementStore(local)
    domain = vlans.add_domain("Site", network.id)
    vlans.set_vlan(domain.id, 60, "MOVED", subnets=["10.50.0.0/24"])  # The map has it in VLAN 50
    vlans.set_vlan(domain.id, 99, "PLANNED", subnets=["10.99.0.0/24"])
    placements.set_placement(network.id, "10.20.5.0/24", "advertised")
    rows = {(row.vrf, row.cidr): row for row in evaluate(network_map, local, vlans, placements, network.id)}

    def texts(cidr, vrf=""):
        return [(finding.severity, finding.text) for finding in rows[(vrf, cidr)].findings]

    assert rows[("", "10.30.0.0/24")].scope == ADVERTISED
    assert any(severity == PROBLEM and "in 2 places" in text for severity, text in texts("10.30.0.0/24"))
    assert rows[("", "192.168.1.0/24")].scope == LOCAL
    assert texts("192.168.1.0/24") == [(NOTE, "Local, in 2 places (a local subnet may be).")]
    assert any(severity == WARNING and "in VLAN 50" in text and "linked to VLAN 60" in text
               for severity, text in texts("10.50.0.0/24"))
    assert any(severity == WARNING and "Marked advertised, but no other device" in text
               for severity, text in texts("10.20.5.0/24"))
    assert any("no device on the map has an address in it" in text for _, text in texts("10.99.0.0/24"))
    assert any("Not a subnet in this IPAM network" in text for _, text in texts("10.40.0.0/24"))
    assert rows[("GUEST", "10.10.0.0/24")].vrf == "GUEST"

    placements.set_placement(network.id, "10.30.0.0/24", LOCAL)  # Leaking: others have routes to it
    rows = {(row.vrf, row.cidr): row for row in evaluate(network_map, local, vlans, placements, network.id)}
    assert any(severity == WARNING and "leaking" in text for severity, text in texts("10.30.0.0/24"))
    placements.set_placement(network.id, "10.30.0.0/24", "auto", one_segment=True)
    rows = {(row.vrf, row.cidr): row for row in evaluate(network_map, local, vlans, placements, network.id)}
    assert not any(severity == PROBLEM for severity, _ in texts("10.30.0.0/24"))
    placements.set_placement(network.id, "10.30.0.0/24")  # Back to automatic: forgotten
    assert placements.placements(network.id).keys() == {"10.20.5.0/24"}


def test_move_workflow(local):
    network = local.add_network("Lab")
    local.add_subnet(network.id, "10.30.0.0/24")
    vlans, placements = VlanStore(local), PlacementStore(local)
    site_a, site_b = vlans.add_domain("A", network.id), vlans.add_domain("B", network.id)
    vlans.set_vlan(site_a.id, 30, "OLD", subnets=["10.30.0.0/24"])
    with pytest.raises(IpamError, match="moving to"):
        placements.plan_move(network.id, "10.30.0.0/24")
    move = placements.plan_move(network.id, "10.30.0.0/24", site_a.id, 30, "r1", site_b.id, 31, "r2",
                                planned_for="Saturday")
    with pytest.raises(IpamError, match="being moved already"):
        placements.plan_move(network.id, "10.30.0.0/24", to_domain_id=site_b.id, to_vlan=32)
    placements.update_move(move.id, status=IN_PROGRESS)

    network_map = lab()  # 10.30.0.0/24 on r1 Gi0/4 (no VLAN): at the old device still
    network_map.devices["r1"].interfaces_l3[-1] = ["10.30.0.1", 24, "Vlan30"]
    row = next(row for row in evaluate(network_map, local, vlans, placements, network.id) if row.cidr == "10.30.0.0/24")
    done, why = move_check(row, row.move, network_map)
    assert not done and "not at the new place yet" in why
    network_map.devices["r2"].interfaces_l3.append(["10.30.0.1", 24, "Vlan31"])  # Up on r2 too: in both places
    row = next(row for row in evaluate(network_map, local, vlans, placements, network.id) if row.cidr == "10.30.0.0/24")
    assert any("both its old and new place" in finding.text for finding in row.findings)
    assert move_check(row, row.move, network_map)[1].startswith("still at the old place too")
    network_map.devices["r1"].interfaces_l3.pop()  # Gone from r1: r2 has it, so its route goes
    network_map.devices["r2"].routes = [route for route in network_map.devices["r2"].routes
                                        if route[0] != "10.30.0.0/24"]
    network_map.devices["sw1"].routes = [["10.30.0.0/24", "10.0.12.2", "Te1/1", "ospf"]]
    row = next(row for row in evaluate(network_map, local, vlans, placements, network.id) if row.cidr == "10.30.0.0/24")
    assert move_check(row, row.move, network_map)[0]

    placements.complete_move(move.id)
    assert placements.move(move.id).status == DONE and placements.open_move(network.id, "10.30.0.0/24") is None
    assert vlans.vlan(site_a.id, 30).subnets == [] and vlans.vlan(site_b.id, 31).subnets == ["10.30.0.0/24"]
    with pytest.raises(IpamError, match="done already"):
        placements.update_move(move.id, status=CANCELLED)
    another = placements.plan_move(network.id, "10.30.0.0/24", site_b.id, 31, "", site_a.id, 30, "")
    placements.update_move(another.id, status=CANCELLED)
    assert placements.open_move(network.id, "10.30.0.0/24") is None and len(placements.moves(network.id)) == 2


def test_placement_and_moves_through_the_tribe(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    alice = team_store(server, tmp_path, "alice")
    vlans, placements = TeamVlanStore(alice), TeamPlacementStore(alice)
    domain = vlans.add_domain("SIPR", network.id)
    vlans.set_vlan(domain.id, 10, "OLD", subnets=["10.0.0.0/24"])
    placements.set_placement(network.id, "10.0.0.0/24", LOCAL, note="reused at every site")
    move = placements.plan_move(network.id, "10.0.0.0/24", from_domain_id=domain.id, from_vlan=10,
                                to_domain_id=domain.id, to_vlan=20)
    bob = team_store(server, tmp_path, "bob")
    bob_placements = TeamPlacementStore(bob)
    assert bob_placements.placement(network.id, "10.0.0.0/24").note == "reused at every site"
    assert bob_placements.open_move(network.id, "10.0.0.0/24").modified_by == "alice (PC)"
    bob_placements.complete_move(move.id)
    with pytest.raises(IpamError, match="changed by bob"):
        placements.update_move(move.id, note="too late")
    alice.sync()
    assert TeamVlanStore(alice).vlan(domain.id, 20).subnets == ["10.0.0.0/24"]
    routed = placements.plan_move(network.id, "10.0.0.0/24", from_domain_id=domain.id, from_vlan=20,
                                  to_device="r2")
    placements.complete_move(routed.id)
    bob.sync()
    assert bob_placements.move(routed.id).status == DONE
    assert TeamVlanStore(bob).vlan(domain.id, 20).subnets == []
    alice.close()
    offline = TeamPlacementStore(offline_store(server, tmp_path))
    assert offline.placement(network.id, "10.0.0.0/24").scope == LOCAL  # Readable offline
    with pytest.raises(ServerUnreachable, match="can't be changed right now"):
        offline.set_placement(network.id, "10.0.0.0/24", ADVERTISED)


@pytest.mark.parametrize("cidr,prefix", [("10.9.0.0/31", 31), ("10.9.0.0/24", 24)])
def test_move_without_vlan(local, cidr, prefix):
    network = local.add_network("Routed")
    subnet = local.add_subnet(network.id, cidr)
    local.set_address(network.id, "10.9.0.1", name="router")
    placements, vlans = PlacementStore(local), VlanStore(local)
    move = placements.plan_move(network.id, cidr, from_device="old", to_device="new")
    network_map = NetworkMap()
    network_map.devices["old"] = Device("old", "old", interfaces_l3=[["10.9.0.1", prefix, "Gi0/1"]])
    network_map.devices["new"] = Device("new", "new", interfaces_l3=[["10.9.0.1", prefix, "Vlan10"]])

    def check():
        row = next(row for row in evaluate(network_map, local, vlans, placements, network.id) if row.cidr == cidr)
        return move_check(row, move, network_map)

    assert not check()[0] and "no VLAN" in check()[1]
    network_map.devices["new"].interfaces_l3 = [["10.9.0.1", prefix, "Gi0/2"]]
    assert not check()[0] and "still at the old place" in check()[1]
    network_map.devices["old"].interfaces_l3 = []
    assert check()[0]
    placements.complete_move(move.id)
    assert placements.move(move.id).status == DONE and vlans.domains() == []
    assert local.subnets(network.id)[0].id == subnet.id
    assert local.address(network.id, "10.9.0.1").name == "router"


def test_move_from_vlan_to_routed(local):
    network = local.add_network("Lab")
    cidr = "10.9.0.0/24"
    local.add_subnet(network.id, cidr)
    vlans, placements = VlanStore(local), PlacementStore(local)
    domain = vlans.add_domain("Site", network.id)
    vlans.set_vlan(domain.id, 10, subnets=[cidr])
    with pytest.raises(IpamError, match="device"):
        placements.plan_move(network.id, cidr, from_domain_id=domain.id, from_vlan=10)
    with pytest.raises(IpamError, match="VLAN and domain"):
        placements.plan_move(network.id, cidr, to_domain_id=domain.id, to_device="r2")
    with pytest.raises(IpamError, match="already"):
        placements.plan_move(network.id, cidr, from_device="r2", to_device=" r2 ")
    move = placements.plan_move(network.id, cidr, from_domain_id=domain.id, from_vlan=10, to_device="r2")
    placements.complete_move(move.id)
    assert vlans.vlan(domain.id, 10).subnets == []
    assert [vlan.vlan for vlan in vlans.vlans(domain.id)] == [10]


def test_watch_notes_subnets_that_move():
    from nomad.netmap.placement import places
    from nomad.netmap.watch import subnet_changes
    before = lab()
    after = lab()
    after.devices["r1"].interfaces_l3 = [item for item in after.devices["r1"].interfaces_l3 if item[0] != "10.30.0.1"]
    after.devices["r2"].interfaces_l3.append(["10.30.0.1", 24, "Gi0/9"])
    after.devices["r2"].interfaces_l3.append(["10.77.0.1", 24, "Gi0/8"])
    lines = [line for _, line in subnet_changes(after, places(before), places(after), {"r1", "r2"})]
    assert lines == ["Subnet 10.30.0.0/24 moved from r1 Gi0/4 to r2 Gi0/9", "Subnet 10.77.0.0/24 appeared on r2 Gi0/8"]
    assert subnet_changes(after, places(before), places(after), {"sw1"}) == []  # Only what was read counts


def test_linked_devices_sharing_a_subnet_are_one_place():
    """A router's routed port linked to a switch's trunk carrying the VLAN of the switch's SVI in the same subnet (the
    VLAN tagged by something the map can't see): one segment. Not when the trunk doesn't carry that VLAN."""
    from nomad.netmap.model import port_key
    assert port_key("Et0/0") == port_key("Ethernet0/0") == port_key("Eth0/0")
    network_map = NetworkMap()
    network_map.devices["rtr"] = Device("rtr", "rtr", source="snmp", interfaces_l3=[["192.168.5.113", 24, "Et0/0"]])
    network_map.devices["sw"] = Device("sw", "sw", source="snmp", interfaces_l3=[["192.168.5.2", 24, "Vl5"]],
                                       vlans=[[5, "LAB"], [57, "OTHER"]],
                                       port_vlans={"Gi0/1": {"mode": "trunk", "native": 57, "allowed": "1,5,57"}})
    network_map.links.append(Link("sw", "Gi0/1", "rtr", "Ethernet0/0"))  # As CDP names the router's port
    [subnet] = analyze(network_map)
    assert len(subnet.segments) == 1
    network_map.devices["sw"].port_vlans["Gi0/1"]["allowed"] = "1,57"
    [subnet] = analyze(network_map)
    assert len(subnet.segments) == 2


def test_unset_interface_addresses_are_left_out():
    """pfSense lists 0.0.0.0 (mask 0) beside an interface's real address: not a subnet holding everything."""
    from nomad.netmap import l3
    network_map = NetworkMap()
    network_map.devices["fw"] = Device("fw", "fw", source="snmp", interfaces_l3=[["0.0.0.0", 0, "vmx0"],
                                                                                 ["10.0.3.1", 24, "vmx0"]])
    assert [cidr for _, cidr in places(network_map)] == ["10.0.3.0/24"]
    nodes, _ = l3.l3_graph(network_map)
    assert [node.label for node in nodes.values() if node.kind == l3.SUBNET] == ["10.0.3.0/24"]


def test_routers_linked_by_a_routed_port_stay_two_places():
    """Two routers each with an SVI-style interface in one subnet, linked only by a routed /30: two places."""
    network_map = NetworkMap()
    for key, address in (("r1", "10.30.0.1"), ("r2", "10.30.0.2")):
        network_map.devices[key] = Device(key, key, source="snmp", interfaces_l3=[
            [address, 24, "Vlan30"], ["10.0.12.1" if key == "r1" else "10.0.12.2", 30, "Gi0/0"]])
    network_map.links.append(Link("r1", "Gi0/0", "r2", "Gi0/0"))
    found = {item.cidr: item for item in analyze(network_map)}
    assert len(found["10.30.0.0/24"].segments) == 2 and len(found["10.0.12.0/30"].segments) == 1


def test_who_advertises_and_who_only_has_an_address():
    """rtr advertises the shared subnet (others' routes lead to it); the switch only has a management SVI in it; home,
    linked to the switch but unread, is a next hop in it: noted as also on it."""
    network_map = NetworkMap()
    network_map.devices["rtr"] = Device("rtr", "rtr", source="snmp", interfaces_l3=[
        ["192.168.5.113", 24, "Et0/0"], ["172.18.0.1", 24, "Et0/1"]],
        routes=[["0.0.0.0/0", "192.168.5.1", "Et0/0", "ospf"], ["192.168.5.0/24", "", "Et0/0", "connected"]])
    network_map.devices["far"] = Device("far", "far", source="snmp", interfaces_l3=[["172.18.0.2", 24, "Et0/0"]],
                                        routes=[["192.168.5.0/24", "172.18.0.1", "Et0/0", "ospf"]])
    network_map.devices["sw"] = Device("sw", "sw", source="snmp", interfaces_l3=[["192.168.5.2", 24, "Vl5"]],
                                       vlans=[[5, "LAB"]],
                                       port_vlans={"Gi0/1": {"mode": "trunk", "native": 57, "allowed": "5"},
                                                   "Gi0/10": {"mode": "trunk", "native": 1, "allowed": "5"}})
    network_map.devices["home"] = Device("home", "home", source="unreachable", mgmt_ip="10.0.0.4")
    network_map.links += [Link("sw", "Gi0/1", "rtr", "Ethernet0/0"), Link("sw", "Gi0/10", "home", "Gi5"),
                          Link("rtr", "Et0/1", "far", "Et0/0")]
    subnet = next(item for item in analyze(network_map) if item.cidr == "192.168.5.0/24")
    assert len(subnet.segments) == 1 and subnet.advertisers == ["rtr"]
    assert subnet.role(network_map, "rtr") == "advertises it"
    assert subnet.role(network_map, "sw") == "address only (it doesn't route)"
    assert subnet.unseen == {"192.168.5.1": ["rtr"]} and subnet.unread == [("home", "sw", "Gi0/10")]


# --------------------------------------------------------------------- Large maps, worked out quickly

def test_summaries_longest_first_and_an_advertised_subnet_inside_another_is_warned():
    """r2's /24 sits inside r1's /16, both advertised: traffic for the /24 goes to r2 (a warning on it). r3's own
    subnet is only covered by summaries, the longest first (the default route isn't one)."""
    network_map = NetworkMap()
    network_map.devices["r1"] = Device("r1", "r1", source="snmp", interfaces_l3=[["10.1.0.1", 16, "Gi0/1"],
                                                                                 ["10.0.13.1", 30, "Gi0/0"]])
    network_map.devices["r2"] = Device("r2", "r2", source="snmp", interfaces_l3=[["10.1.5.1", 24, "Gi0/1"],
                                                                                 ["10.0.23.1", 30, "Gi0/0"]])
    network_map.devices["r3"] = Device("r3", "r3", source="snmp", interfaces_l3=[
        ["10.0.13.2", 30, "Gi0/1"], ["10.0.23.2", 30, "Gi0/2"], ["10.20.5.1", 24, "Gi0/3"]], routes=[
        ["10.1.0.0/16", "10.0.13.1", "Gi0/1", "ospf"], ["10.1.5.0/24", "10.0.23.1", "Gi0/2", "ospf"]])
    for key, hop in (("r1", "10.0.13.2"), ("r2", "10.0.23.2")):
        network_map.devices[key].routes = [["0.0.0.0/0", hop, "Gi0/0", "static"],
                                           ["10.0.0.0/8", hop, "Gi0/0", "static"],
                                           ["10.20.0.0/16", hop, "Gi0/0", "ospf"]]
    found = {item.cidr: item for item in analyze(network_map)}
    assert found["10.20.5.0/24"].summaries == [("10.20.0.0/16", ["r1", "r2"]), ("10.0.0.0/8", ["r1", "r2"])]
    rows = {row.cidr: row for row in evaluate(network_map, None, NoDomains(), None, None)}  # No IPAM network
    assert [finding.text for finding in rows["10.1.5.0/24"].findings if finding.text.startswith("Inside")] == [
        "Inside 10.1.0.0/16, which is advertised from r1 Gi0/1: traffic for it goes here instead."]
    assert not any(finding.text.startswith("Inside") for finding in rows["10.1.0.0/16"].findings)


class NoDomains:
    def domains(self):
        return []


def test_inside_all_matches_inside(local):
    from nomad.ipam.roles import inside, inside_all
    network = local.add_network("Nested")
    for cidr in ("10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.128/25", "10.2.0.0/16", "192.168.0.0/24",
                 "0.0.0.0/0", "2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:2::/64"):
        local.add_subnet(network.id, cidr)
    subnets = local.subnets(network.id)
    found = inside_all(subnets)
    for subnet in subnets:
        assert found.get(subnet.id, []) == inside(subnet, subnets), subnet.cidr


def big_map(sites=10, vlans=10, other_routes=200):
    """Routers at the core, a layer-3 switch per site with a subnet per VLAN, every route everywhere."""
    network_map = NetworkMap()
    every = [(f"10.{site}.{vlan}.0/24", site) for site in range(sites) for vlan in range(vlans)]
    for core in range(2):
        network_map.devices[f"core{core}"] = Device(f"core{core}", f"core{core}", source="snmp", interfaces_l3=[
            [f"192.168.{core}.{site * 4 + 1}", 30, f"Te0/{site}"] for site in range(sites)])
    for site in range(sites):
        network_map.devices[f"sw{site}"] = Device(f"sw{site}", f"sw{site}", source="snmp", interfaces_l3=[
            [f"10.{site}.{vlan}.1", 24, f"Vl{100 + vlan}"] for vlan in range(vlans)] + [
            [f"192.168.{core}.{site * 4 + 2}", 30, f"Gi1/0/{core + 1}"] for core in range(2)],
            vlans=[[100 + vlan, f"v{vlan}"] for vlan in range(vlans)])
        for core in range(2):
            network_map.links.append(Link(f"core{core}", f"Te0/{site}", f"sw{site}", f"Gi1/0/{core + 1}"))
    for key, device in network_map.devices.items():
        device.routes = [[cidr, f"192.168.0.{site * 4 + 2}" if key.startswith("core") else "192.168.0.1", "Gi0/0",
                          "ospf"] for cidr, site in every if key != f"sw{site}"]
        device.routes += [[f"{100 + number // 250}.{number % 250}.0.0/16", "203.0.113.1", "Gi0/0", "bgp"]
                          for number in range(other_routes)]
    return network_map


def test_a_large_map_is_worked_out_quickly(local):
    """Subnet Placement runs on each redraw of the map (for the logical view): a few hundred subnets and a few
    thousand routes took 8 s with each subnet going through every route, and with each IPAM subnet compared with
    every other (re-reading its CIDR each time) a network of 800 subnets took 50 s."""
    import time
    network_map = big_map()
    network = local.add_network("Big")
    for site in range(40):
        local.add_subnet(network.id, f"10.{site}.0.0/16")
        for vlan in range(20):
            local.add_subnet(network.id, f"10.{site}.{vlan}.0/24")
    started = time.perf_counter()
    rows = evaluate(network_map, local, VlanStore(local), PlacementStore(local), network.id)
    took = time.perf_counter() - started
    assert len(rows) > 800 and len(analyze(network_map)) == 120  # 100 VLANs, 20 links
    assert took < 2.0, took  # About 0.15 s now
