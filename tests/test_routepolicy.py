"""Prefix lists and route maps: reading running-config, the changes written (as IOS 15.7 takes them), checks and the
route tester."""
from nomad.netmap import acl, routepolicy
from nomad.netmap.routepolicy import BGP, DISTRIBUTE, PBR, REDIST, ROUTE_MAP, MapEntry, PrefixEntry, PrefixList, \
    RouteMap

RUNNING = """hostname R3
!
ip access-list standard MGMT
 permit 10.18.0.0 0.0.0.255
!
interface Ethernet0/1.100
 encapsulation dot1Q 100
 ip address 10.100.3.1 255.255.255.0
 ip policy route-map PBR
!
router ospf 1
 router-id 10.18.0.13
 area 1 filter-list prefix PALL in
 redistribute connected subnets
 redistribute static metric 20 subnets route-map RMOSPF
 network 10.18.0.13 0.0.0.0 area 1
 default-information originate always route-map RMOSPF
 distribute-list prefix PALL in Ethernet0/1.100
 distribute-list prefix PALL2 in
!
router bgp 65003
 bgp log-neighbor-changes
 neighbor PGTEST peer-group
 neighbor PGTEST remote-as 65009
 neighbor 172.18.0.12 remote-as 65002
 neighbor 172.18.0.12 description R2
 neighbor 172.18.0.99 peer-group PGTEST
 !
 address-family ipv4
  neighbor PGTEST route-map RMOSPF out
  neighbor 172.18.0.12 activate
  neighbor 172.18.0.12 prefix-list PALL out
  neighbor 172.18.0.12 route-map RMTEST in
  neighbor 172.18.0.99 activate
 exit-address-family
!
ip local policy route-map PBR
ip as-path access-list 5 permit ^65002_
ip community-list standard GOLD permit 65000:100
ip prefix-list NTEST description test list
ip prefix-list NTEST seq 5 permit 10.0.0.0/8 le 24
ip prefix-list NTEST seq 10 deny 192.168.1.0/24
ip prefix-list NTEST seq 15 permit 172.16.0.0/12 ge 16 le 24
ip prefix-list NTEST2 seq 5 permit 192.0.2.0/24 le 32
ip prefix-list PALL seq 5 permit 0.0.0.0/0 le 32
ip prefix-list PALL2 seq 5 permit 0.0.0.0/0 le 32
ipv6 prefix-list NTEST6 seq 5 permit 2001:DB8::/32 le 64
!
route-map RMTEST permit 10
 description first entry
 match ip address prefix-list NTEST2
 match tag 5
 continue 30
 set local-preference 300
 set community 4259840001 4259840002
route-map RMTEST deny 20
 match ip address prefix-list NTEST
route-map RMTEST permit 30
!
route-map RMOSPF permit 10
 match ip address prefix-list NTEST2
!
route-map PBR permit 10
 match ip address MGMT
 set ip next-hop 10.100.3.254
!
"""

SHOW_PREFIX = """ip prefix-list NTEST:
   Description: test list
   count: 3, range entries: 2, sequences: 5 - 15, refcount: 2
   seq 5 permit 10.0.0.0/8 le 24 (hit count: 7, refcount: 1)
   seq 10 deny 192.168.1.0/24 (hit count: 0, refcount: 1)
   seq 15 permit 172.16.0.0/12 ge 16 le 24 (hit count: 2, refcount: 1)
"""


def device():
    return acl.parse_running(RUNNING)


def test_reads_prefix_lists():
    found = device()
    ntest = found.prefix_lists[(acl.V4, "NTEST")]
    assert ntest.description == "test list"
    assert [entry.body() for entry in ntest.entries] == ["permit 10.0.0.0/8 le 24", "deny 192.168.1.0/24",
                                                         "permit 172.16.0.0/12 ge 16 le 24"]
    assert [entry.seq for entry in ntest.entries] == [5, 10, 15]
    v6 = found.prefix_lists[(acl.V6, "NTEST6")]
    assert v6.entries[0].prefix == "2001:db8::/32" and v6.entries[0].le == 64
    routepolicy.merge_show_prefix(found, SHOW_PREFIX)
    assert [entry.hits for entry in ntest.entries] == [7, 0, 2]


def test_reads_route_maps():
    rmap = device().route_maps["RMTEST"]
    first = rmap.entries[0]
    assert (first.seq, first.action, first.description, first.cont) == (10, "permit", "first entry", "30")
    assert first.matches == ["ip address prefix-list NTEST2", "tag 5"]
    assert first.sets == ["local-preference 300", "community 65000:1 65000:2"]  # Shown as one number on the device
    assert [(entry.seq, entry.action) for entry in rmap.entries] == [(10, "permit"), (20, "deny"), (30, "permit")]


def test_reads_uses():
    found = device()
    uses = {(use.where, use.name, use.slot) for use in found.policy_uses}
    assert (BGP, "RMTEST", "neighbor 172.18.0.12 route-map in") in uses
    assert (BGP, "PALL", "neighbor 172.18.0.12 prefix-list out") in uses
    assert (BGP, "RMOSPF", "neighbor PGTEST route-map out") in uses
    assert (REDIST, "RMOSPF", "redistribute static") in uses
    assert (REDIST, "", "redistribute connected") in uses  # No route map on it yet
    assert (REDIST, "RMOSPF", "default-information originate") in uses
    assert (DISTRIBUTE, "PALL", "distribute-list prefix in Ethernet0/1.100") in uses
    assert (DISTRIBUTE, "PALL2", "distribute-list prefix in") in uses
    assert (DISTRIBUTE, "PALL", "area 1 filter-list in") in uses
    assert (PBR, "PBR", "ip policy") in uses
    assert (PBR, "PBR", "ip local policy") in uses
    use = next(use for use in found.policy_uses if use.slot == "neighbor 172.18.0.12 route-map in")
    assert use.path == ("router bgp 65003", "address-family ipv4")
    process = found.processes["router bgp 65003"]
    assert process.neighbors["PGTEST"].group and process.neighbors["172.18.0.99"].member_of == "PGTEST"
    assert process.neighbors["172.18.0.12"].remote_as == "65002"
    assert found.as_paths["5"] == [("permit", "^65002_")]
    assert found.communities["GOLD"] == ("standard", [("permit", "65000:100")])
    # The ACL named by a route map is still found as used (by it)
    assert any(item.acl == "MGMT" for item in found.applied)


def test_prefix_list_add_change_delete():
    before = device()
    after = before.copy()
    ntest = after.prefix_lists[(acl.V4, "NTEST")]
    ntest.entries.insert(1, PrefixEntry(0, "permit", "10.200.0.0/16"))  # Between 5 and 10
    ntest.entries[0] = ntest.entries[0].copy(le=25)  # Changed: a new number, in before the old comes out
    del ntest.entries[3]  # 15 goes
    change = routepolicy.prefix_change(before.prefix_lists[(acl.V4, "NTEST")], ntest)
    assert change.lines == ["ip prefix-list NTEST seq 3 permit 10.0.0.0/8 le 25",  # Spread out between 0 and 10
                            "ip prefix-list NTEST seq 6 permit 10.200.0.0/16",
                            "no ip prefix-list NTEST seq 5 permit 10.0.0.0/8 le 24",
                            "no ip prefix-list NTEST seq 15 permit 172.16.0.0/12 ge 16 le 24"]
    assert change.undo == ["ip prefix-list NTEST seq 5 permit 10.0.0.0/8 le 24",
                           "ip prefix-list NTEST seq 15 permit 172.16.0.0/12 ge 16 le 24",
                           "no ip prefix-list NTEST seq 3 permit 10.0.0.0/8 le 25",
                           "no ip prefix-list NTEST seq 6 permit 10.200.0.0/16"]


def test_prefix_list_move_takes_out_first():
    before = device().prefix_lists[(acl.V4, "NTEST")]
    after = before.copy()
    after.entries = [after.entries[2], after.entries[0], after.entries[1]]  # 15 to the top
    change = routepolicy.prefix_change(before, after)
    # IOS won't hold the same entry twice: the old one comes out just before its new place goes in
    assert change.lines == ["no ip prefix-list NTEST seq 15 permit 172.16.0.0/12 ge 16 le 24",
                            "ip prefix-list NTEST seq 2 permit 172.16.0.0/12 ge 16 le 24"]
    assert any("just before" in note for note in change.notes)


def test_prefix_list_typed_number_and_no_room():
    before = PrefixList("L", entries=[PrefixEntry(5, "permit", "10.0.0.0/8"), PrefixEntry(6, "permit", "11.0.0.0/8")])
    after = before.copy()
    after.entries.insert(1, PrefixEntry(0, "permit", "12.0.0.0/8"))
    change = routepolicy.prefix_change(before, after)
    assert "no number free" in change.notes[0]
    assert [entry.seq for entry in change.after.entries] == [10, 20, 30]
    assert change.lines[0] == "no ip prefix-list L seq 5 permit 10.0.0.0/8"  # Renumbered one by one
    typed = before.copy()
    typed.entries.append(PrefixEntry(0, "deny", "0.0.0.0/0", le=32, want_seq=100))
    assert routepolicy.prefix_change(before, typed).lines == ["ip prefix-list L seq 100 deny 0.0.0.0/0 le 32"]


def test_prefix_list_create_and_delete():
    made = PrefixList("NEW", entries=[PrefixEntry(0, "permit", "10.1.0.0/16", le=24)], description="made")
    change = routepolicy.prefix_change(None, made)
    assert change.lines == ["ip prefix-list NEW description made", "ip prefix-list NEW seq 10 permit 10.1.0.0/16 le 24"]
    assert change.undo == ["no ip prefix-list NEW", "no ip prefix-list NEW description"]
    gone = routepolicy.prefix_change(change.after, None)
    assert gone.lines == ["no ip prefix-list NEW", "no ip prefix-list NEW description"]  # The description stays else


def test_route_map_edit_in_place():
    before = device()
    after = before.copy()
    entry = after.route_maps["RMTEST"].entries[0]
    entry.matches = ["ip address prefix-list NTEST2 NTEST", "tag 7"]
    entry.sets = ["local-preference 300", "community 65000:3"]
    entry.cont = ""
    entry.action = "deny"
    change = routepolicy.map_change(before.route_maps["RMTEST"], after.route_maps["RMTEST"])
    assert change.lines == ["route-map RMTEST deny 10",
                            " match ip address prefix-list NTEST",  # Added before the old values come out
                            " match tag 7",
                            " no match tag 5",
                            " no continue 30",
                            " no set community 65000:1 65000:2",  # Out first: set community adds to what's there
                            " set community 65000:3",
                            " exit"]
    assert change.undo == ["route-map RMTEST permit 10",
                           " match tag 5",
                           " no match ip address prefix-list NTEST",
                           " no match tag 7",
                           " continue 30",
                           " no set community 65000:3",
                           " set community 65000:1 65000:2",
                           " exit"]


def test_route_map_acl_and_prefix_list_clash():
    old = MapEntry(10, matches=["ip address 10"])
    new = MapEntry(10, matches=["ip address prefix-list A"])
    lines = routepolicy.match_lines(old.matches, new.matches)
    assert lines == [" no match ip address 10", " match ip address prefix-list A"]


def test_route_map_add_move_delete():
    before = device().route_maps["RMTEST"]
    after = before.copy()
    after.entries = [after.entries[0], MapEntry(0, "permit", ["tag 9"], ["weight 100"]), after.entries[2],
                     after.entries[1]]  # A new one, and 30 above 20: one of them moves
    change = routepolicy.map_change(before, after)
    assert [entry.seq for entry in change.after.entries] == [10, 13, 16, 20]
    assert change.lines == ["route-map RMTEST permit 13", " match tag 9", " set weight 100", " exit",
                            "route-map RMTEST permit 16", " exit",  # 30, made at its new number first
                            "route-map RMTEST permit 10", " continue 16", " exit",  # 10 continues to it there
                            "no route-map RMTEST permit 30"]
    assert "1 added" in change.title and "1 moved" in change.title


def test_route_map_continue_follows_a_move():
    before = RouteMap("M", [MapEntry(10, cont="20"), MapEntry(20, matches=["tag 1"]), MapEntry(30), MapEntry(40)])
    after = before.copy()
    after.entries = [after.entries[0], after.entries[2], after.entries[3], after.entries[1]]
    change = routepolicy.map_change(before, after)
    moved = change.after.entries[3]
    assert moved.seq == 50 and change.after.entries[0].cont == "50"
    assert change.lines == ["route-map M permit 50", " match tag 1", " exit",
                            "route-map M permit 10", " continue 50", " exit",
                            "no route-map M permit 20"]


def test_route_map_create_delete():
    made = RouteMap("NEW", [MapEntry(0, "permit", ["ip address prefix-list A"], ["local-preference 200"])])
    change = routepolicy.map_change(None, made)
    assert change.lines == ["route-map NEW permit 10", " match ip address prefix-list A", " set local-preference 200",
                            " exit"]
    assert change.undo == ["no route-map NEW"]
    assert routepolicy.map_change(change.after, None).lines == ["no route-map NEW"]


def test_apply_and_take_off():
    before = device()
    after = before.copy()
    routepolicy.set_use(after, routepolicy.PolicyUse(ROUTE_MAP, "RMOSPF", BGP, ("router bgp 65003", "address-family ipv4"),
                                                     "neighbor 172.18.0.12 route-map in",
                                                     "neighbor 172.18.0.12 route-map RMOSPF in", "in"))
    connected = next(use for use in after.policy_uses if use.slot == "redistribute connected")
    routepolicy.set_use(after, connected.copy(kind=ROUTE_MAP, name="RMOSPF",
                                              line=routepolicy.redistribution_line(connected.line, "RMOSPF")))
    static = next(use for use in after.policy_uses if use.slot == "redistribute static")
    routepolicy.take_use_off(after, static)
    pbr = next(use for use in after.policy_uses if use.slot == "ip policy")
    routepolicy.take_use_off(after, pbr)
    changes = {change.title: change for change in routepolicy.use_changes(before, after)}
    bgp = changes["Put RMOSPF on BGP 172.18.0.12 in (in place of RMTEST)"]
    assert bgp.lines == ["router bgp 65003", " address-family ipv4", "  neighbor 172.18.0.12 route-map RMOSPF in",
                         " exit-address-family", "exit"]
    assert bgp.undo[2] == "  neighbor 172.18.0.12 route-map RMTEST in"
    redistribute = changes["Put RMOSPF on redistribute connected into router ospf 1"]
    assert redistribute.lines[1] == " redistribute connected subnets route-map RMOSPF"
    assert redistribute.undo[1] == " no redistribute connected route-map RMOSPF"  # Leaves the redistribution
    off = changes["Take RMOSPF off redistribute static into router ospf 1"]
    assert off.lines[1] == " no redistribute static route-map RMOSPF"
    assert off.undo[1] == " redistribute static metric 20 subnets route-map RMOSPF"
    pbr_off = changes["Take PBR off policy routing on Ethernet0/1.100"]
    assert pbr_off.lines == ["interface Ethernet0/1.100", " no ip policy route-map PBR", "exit"]
    # Taken off first, put on last
    text = acl.config_text(list(changes.values()))
    assert text.index("no ip policy") < text.index("route-map RMOSPF in")


def test_order_with_lists_and_maps():
    before = acl.parse_running("hostname X\n")
    after = before.copy()
    after.prefix_lists[(acl.V4, "A")] = PrefixList("A", entries=[PrefixEntry(0, "permit", "10.0.0.0/8")])
    after.route_maps["M"] = RouteMap("M", [MapEntry(0, matches=["ip address prefix-list A"])])
    text = acl.config_text(acl.device_changes(before, after))
    assert text.index("ip prefix-list A") < text.index("route-map M permit 10")


def test_soft_clears():
    before = device()
    after = before.copy()
    after.prefix_lists[(acl.V4, "NTEST2")].entries[0].le = 28  # RMTEST and RMOSPF match it
    clears = routepolicy.bgp_affected(before, after)
    commands = sorted(item.command for item in clears)
    assert commands == ["clear ip bgp 172.18.0.12 soft in", "clear ip bgp peer-group PGTEST soft out"]
    assert routepolicy.clear_command(("router bgp 1", "address-family ipv4 vrf RED"), "10.1.1.1", "in") == \
        "clear ip bgp vrf RED 10.1.1.1 soft in"
    assert routepolicy.clear_command(("router bgp 1", "address-family ipv6"), "2001:db8::1", "out") == \
        "clear bgp ipv6 unicast 2001:db8::1 soft out"


def test_route_tester():
    found = device()
    rmap = found.route_maps["RMTEST"]
    route = routepolicy.route_from_text("192.0.2.0/25", tag="5")
    verdict = routepolicy.evaluate_map(rmap, route, found)
    assert verdict.permitted and [entry.seq for entry in verdict.entries] == [10, 30]  # continue 30
    assert verdict.sets == ["local-preference 300", "community 65000:1 65000:2"]
    verdict = routepolicy.evaluate_map(rmap, routepolicy.route_from_text("10.1.0.0/16"), found)
    assert not verdict.permitted and verdict.entries[0].seq == 20
    permitted, entry, _ = routepolicy.evaluate_prefix_list(found.prefix_lists[(acl.V4, "NTEST")],
                                                           routepolicy.route_from_text("172.16.5.0/24").network)
    assert permitted and entry.seq == 15
    permitted, entry, _ = routepolicy.evaluate_prefix_list(found.prefix_lists[(acl.V4, "NTEST")],
                                                           routepolicy.route_from_text("172.16.0.0/12").network)
    assert not permitted and entry is None  # /12 isn't in ge 16 le 24
    pbr = routepolicy.evaluate_map(found.route_maps["PBR"], routepolicy.route_from_text("10.18.0.0/24"), found)
    assert pbr.permitted


def test_as_path_and_community():
    found = device()
    found.route_maps["X"] = RouteMap("X", [MapEntry(10, matches=["as-path 5", "community GOLD"])])
    route = routepolicy.route_from_text("10.0.0.0/8", as_path="65002 65100", communities="65000:100 no-export")
    assert routepolicy.evaluate_map(found.route_maps["X"], route, found).permitted
    other = routepolicy.route_from_text("10.0.0.0/8", as_path="65100 65002", communities="65000:100")
    assert not routepolicy.evaluate_map(found.route_maps["X"], other, found).permitted


def test_checks():
    plist = PrefixList("L", entries=[PrefixEntry(5, "permit", "10.0.0.0/8", le=24),
                                     PrefixEntry(10, "deny", "10.1.0.0/16"),
                                     PrefixEntry(15, "permit", "10.2.0.0/16", ge=8)])
    found = routepolicy.prefix_findings(plist)
    assert any("never matches" in item.text and item.index == 1 for item in found)
    assert any("IOS won't take it" in item.text and item.index == 2 for item in found)
    rmap = RouteMap("M", [MapEntry(10, cont="5"), MapEntry(20, "deny", ["ip address prefix-list NOPE"], ["weight 1"]),
                          MapEntry(30, matches=["ip address 10", "ip address prefix-list A"])])
    texts = [item.text for item in routepolicy.map_findings(rmap, device())]
    assert any("goes back" in text for text in texts)
    assert any("NOPE" in text for text in texts)
    assert any("set lines do nothing" in text for text in texts)
    assert any("won't take both" in text for text in texts)


def test_unsupported_where_used():
    found = device()
    # RMOSPF is on redistribute static into OSPF: AS-path and community matches mean nothing there
    found.route_maps["RMOSPF"].entries[0].matches.append("as-path 5")
    found.route_maps["RMOSPF"].entries[0].cont = "next"
    texts = [item.text for item in routepolicy.map_findings(found.route_maps["RMOSPF"], found)]
    assert any("match as-path isn't supported for OSPF" in text for text in texts)
    assert any("continue only works in BGP" in text for text in texts)
    found.route_maps["RMTEST"].entries[0].matches.append("tag 9")  # RMTEST is BGP in
    texts = [item.text for item in routepolicy.map_findings(found.route_maps["RMTEST"], found)]
    assert any("match tag isn't supported for a BGP neighbor (in)" in text for text in texts)
