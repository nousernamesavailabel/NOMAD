"""ACLs read from a device's running-config and show access-lists, and edits turned into the fewest safe lines."""
from nomad.netmap import acl
from nomad.netmap.acl import DENY, EXTENDED, HOST, INTERFACE, LINE, OTHER, PERMIT, STANDARD, V4, V6, WILDCARD, \
    Acl, Address, Ports, Rule

RUNNING = """Building configuration...

Current configuration : 4242 bytes
!
hostname R1
!
ip access-list standard MGMT
 permit 10.18.0.0 0.0.0.255
 permit 192.168.1.5
ip access-list extended WEB-IN
 remark allow web
 remark to the server
 permit tcp any host 10.1.1.10 eq www 443
 permit icmp any any echo
 permit tcp any object-group SRV eq 22 time-range WORK
 deny   ip any any log
access-list 101 permit tcp 10.0.0.0 0.255.255.255 any established
access-list 101 remark the rest
access-list 101 deny ip any any
ipv6 access-list V6IN
 sequence 20 permit tcp any any eq 22
 permit icmp any any nd-ns
 deny ipv6 any any
object-group network SRV
 description web servers
 host 10.1.1.10
 10.1.2.0 255.255.255.0
time-range WORK
 periodic weekdays 8:00 to 17:00
interface Ethernet0/0
 description uplink
 ip address 10.18.0.254 255.255.255.0
 ip access-group WEB-IN in
 ipv6 address 2001:DB8::1/64
 ipv6 traffic-filter V6IN in
!
interface Ethernet0/1
 ip address 10.1.1.1 255.255.255.0
 ip access-group 101 out
 shutdown
!
line vty 0 4
 access-class MGMT in vrf-also
 transport input ssh
line vty 5 15
 transport input ssh
!
snmp-server community public RO MGMT
route-map NAT permit 10
 match ip address 101
archive
 path flash:archive
end
"""

SHOW = """Standard IP access list MGMT
    10 permit 10.18.0.0, wildcard bits 0.0.0.255 (12 matches)
    20 permit 192.168.1.5
Extended IP access list WEB-IN
    10 permit tcp any host 10.1.1.10 eq www 443 (5 matches)
    20 permit icmp any any echo
    30 permit tcp any object-group SRV eq 22 time-range WORK (active)
    40 deny ip any any log (1 match)
Extended IP access list 101
    10 permit tcp 10.0.0.0 0.255.255.255 any established
    20 deny ip any any
IPv6 access list V6IN
    permit tcp any any eq 22 (3 matches) sequence 20
    permit icmp any any nd-ns sequence 30
    deny ipv6 any any sequence 40
"""


def device():
    found = acl.parse_running(RUNNING)
    return acl.merge_show(found, acl.parse_show(SHOW))


def bodies(item):
    return [(rule.seq, rule.body(item.family, item.kind)) for rule in item.rules]


# --------------------------------------------------------------------- Reading

def test_reads_every_kind_of_acl():
    found = device()
    assert found.hostname == "R1" and found.archive_path == "flash:archive"
    assert set(found.acls) == {(V4, "MGMT"), (V4, "WEB-IN"), (V4, "101"), (V6, "V6IN")}
    assert found.acl(V4, "MGMT").kind == STANDARD and found.acl(V4, "101").kind == EXTENDED
    assert found.acl(V4, "101").numbered and not found.acl(V6, "V6IN").numbered
    assert bodies(found.acl(V4, "MGMT")) == [(10, "permit 10.18.0.0 0.0.0.255"), (20, "permit 192.168.1.5")]
    assert bodies(found.acl(V4, "WEB-IN")) == [
        (10, "permit tcp any host 10.1.1.10 eq 80 443"), (20, "permit icmp any any echo"),
        (30, "permit tcp any object-group SRV eq 22 time-range WORK"), (40, "deny ip any any log")]
    assert bodies(found.acl(V6, "V6IN")) == [(20, "permit tcp any any eq 22"), (30, "permit icmp any any nd-ns"),
                                             (40, "deny ipv6 any any")]


def test_numbers_and_counts_come_from_show_access_lists():
    found = device()
    assert [rule.hits for rule in found.acl(V4, "WEB-IN").rules] == [5, 0, 0, 1]
    assert [rule.seq for rule in found.acl(V4, "101").rules] == [10, 20]  # running-config has none
    assert found.acl(V4, "MGMT").rules[0].hits == 12
    assert found.hits_read


def test_remarks_stay_with_the_rule_below_them():
    found = device()
    assert found.acl(V4, "WEB-IN").rules[0].remark == "allow web\nto the server"
    assert found.acl(V4, "101").rules[1].remark == "the rest"


def test_where_acls_are_used():
    found = device()
    labels = sorted(use.label() for use in found.applied if use.where != OTHER)
    assert labels == ["Ethernet0/0 in", "Ethernet0/0 in", "Ethernet0/1 out", "line vty 0 4 in"]
    others = {(use.acl, use.text) for use in found.applied if use.where == OTHER}
    assert others == {("MGMT", "snmp-server community public RO MGMT"), ("101", "match ip address 101")}
    assert [use.family for use in found.uses_of((V6, "V6IN"))] == [V6]
    assert found.interfaces["Ethernet0/0"].addresses == [("10.18.0.254", 24)]
    assert found.interfaces["Ethernet0/0"].addresses6 == [("2001:DB8::1", 64)]
    assert found.interfaces["Ethernet0/1"].shutdown


def test_object_groups_and_time_ranges():
    found = device()
    group = found.groups["SRV"]
    assert group.kind == acl.NETWORK and group.description == "web servers"
    assert group.entries == ["host 10.1.1.10", "10.1.2.0 255.255.255.0"]
    assert found.ranges["WORK"].entries == ["periodic weekdays 8:00 to 17:00"]
    assert [item.name for item in found.group_users("SRV")] == ["WEB-IN"]
    assert [item.name for item in found.range_users("WORK")] == ["WEB-IN"]


def test_parse_rule_forms():
    rule = acl.parse_rule("15 deny udp 10.1.0.0 0.0.255.255 range 1000 2000 host 10.2.2.2 neq 53 123 log-input",
                          V4, EXTENDED)
    assert rule.seq == 15 and rule.action == DENY and rule.protocol == "udp"
    assert rule.src == Address(WILDCARD, "10.1.0.0", "0.0.255.255") and rule.src_ports == Ports("range", [1000, 2000])
    assert rule.dst == Address(HOST, "10.2.2.2") and rule.dst_ports == Ports("neq", [53, 123])
    assert rule.log == "log-input"
    rule = acl.parse_rule("permit tcp any any match-all +syn -ack dscp ef", V4, EXTENDED)
    assert rule.tcp_flags == ["match-all", "+syn", "-ack"] and rule.extra == ["dscp", "ef"]
    rule = acl.parse_rule("permit icmp any any 3 13", V4, EXTENDED)
    assert (rule.icmp_type, rule.icmp_code) == (3, 13)
    assert acl.parse_rule("remark hello", V4, EXTENDED) is None
    assert acl.parse_rule("permit 10.1.1.1 0.0.0.0", V4, STANDARD).src == Address(HOST, "10.1.1.1")
    assert acl.parse_rule("permit 0.0.0.0 255.255.255.255", V4, STANDARD).src == Address()


def test_addresses_as_typed():
    assert acl.parse_address_text("10.1.0.0/16") == Address(WILDCARD, "10.1.0.0", "0.0.255.255")
    assert acl.parse_address_text("10.1.0.0 255.255.0.0") == Address(WILDCARD, "10.1.0.0", "0.0.255.255")  # A mask
    assert acl.parse_address_text("host 10.1.1.1") == Address(HOST, "10.1.1.1")
    assert acl.parse_address_text("10.1.1.1/32") == Address(HOST, "10.1.1.1")
    assert acl.parse_address_text("") == Address()
    assert acl.parse_address_text("object-group SRV").group == "SRV"
    assert acl.parse_address_text("2001:db8::/32", V6) == Address(acl.PREFIX, "2001:db8::", prefix=32)
    assert acl.looks_like_mask("255.255.255.0") and not acl.looks_like_mask("0.0.0.255")
    assert acl.stored_address(Address(WILDCARD, "10.1.1.5", "0.0.0.255")) == "10.1.1.0"


def test_where_this_pc_is_reached():
    assert acl.parse_toward("10.18.0.0/24\n  attached to Ethernet0/0") == "Ethernet0/0"
    assert acl.parse_toward("0.0.0.0/0\n  nexthop 10.1.1.254 GigabitEthernet0/1") == "GigabitEthernet0/1"


# --------------------------------------------------------------------- Changes

def test_add_change_and_delete_go_by_number_with_the_new_rule_in_first():
    found = device()
    before = found.acl(V4, "WEB-IN")
    after = before.copy()
    after.rules[0] = after.rules[0].copy(action=DENY)  # Changed
    after.rules.insert(1, Rule(protocol="tcp", dst=Address(HOST, "10.1.1.11"), dst_ports=Ports("eq", [22])))
    del after.rules[2]  # The icmp rule
    change = acl.acl_change(before, after)
    assert change.lines[0] == "ip access-list extended WEB-IN" and change.lines[-1] == " exit"
    body = change.lines[1:-1]
    added = [line for line in body if not line.startswith(" no ") and "remark" not in line]
    assert [line.split(" ", 2)[2] for line in added] == ["deny tcp any host 10.1.1.10 eq 80 443",
                                                          "permit tcp any host 10.1.1.11 eq 22"]
    seqs = [int(line.split()[0]) for line in added]
    assert 0 < seqs[0] < seqs[1] < 30 and not set(seqs) & {10, 20, 30, 40}
    assert body.index(added[-1]) < body.index(" no 10")  # Make before break
    assert " no 20" in body and " remark allow web" in body
    assert "1 added" in change.title and "1 changed" in change.title and "1 removed" in change.title
    # Undo puts the old rules back at their own numbers
    undo = change.undo
    assert " 10 permit tcp any host 10.1.1.10 eq 80 443" in undo and " 20 permit icmp any any echo" in undo
    assert f" no {seqs[0]}" in undo and f" no {seqs[1]}" in undo


def test_moving_a_rule_adds_it_at_its_new_place_then_takes_the_old():
    before = device().acl(V4, "WEB-IN")
    after = before.copy()
    after.rules = [after.rules[1], after.rules[0]] + after.rules[2:]
    change = acl.acl_change(before, after)
    body = [line.strip() for line in change.lines[1:-1]]
    assert len(body) in (2, 4)  # One moved: add it, take the old (with its remarks when it's the remarked one)
    assert any(line.startswith("no ") for line in body)
    final = change.after
    assert [rule.body() for rule in final.rules][:2] == [after.rules[0].body(), after.rules[1].body()]
    assert all(a.seq < b.seq for a, b in zip(final.rules, final.rules[1:]))


def test_no_room_between_numbers_resequences_first():
    before = Acl("T", rules=[Rule(seq=1, protocol="ip"), Rule(seq=2, action=DENY)])
    after = before.copy()
    after.rules.insert(1, Rule(protocol="tcp", dst_ports=Ports("eq", [80])))
    change = acl.acl_change(before, after)
    assert change.lines[0] == "ip access-list resequence T 20 20"  # Room for round numbers between them
    assert " 30 permit tcp any any eq 80" in change.lines
    assert change.undo == ["ip access-list extended T", " no 30", " exit"]
    assert "renumbered" in change.notes[0]


def test_rules_put_above_the_first_get_round_numbers_after_renumbering():
    before = Acl("T", V4, STANDARD, [Rule(seq=10, src=Address(WILDCARD, "10.0.0.0", "0.255.255.255"))])
    after = before.copy()
    after.rules[0:0] = [Rule(src=Address(HOST, f"192.168.1.{number}")) for number in range(1, 11)]
    change = acl.acl_change(before, after)
    assert change.lines[0] == "ip access-list resequence T 110 110"
    assert change.lines[2:12] == [f" {10 * number} permit 192.168.1.{number}" for number in range(1, 11)]
    assert [rule.seq for rule in change.after.rules] == list(range(10, 120, 10))


def test_moving_a_rule_takes_it_out_before_putting_it_back():
    before = Acl("T", rules=[Rule(seq=10, protocol="tcp", dst_ports=Ports("eq", [22])),
                             Rule(seq=20, protocol="tcp", src=Address(HOST, "10.1.1.1"))])
    after = before.copy()
    after.rules.reverse()
    change = acl.acl_change(before, after)
    # IOS quietly drops a rule it has already, so adding the copy first would lose it
    assert change.lines in (["ip access-list extended T", " no 10", " 30 permit tcp any any eq 22", " exit"],
                            ["ip access-list extended T", " no 20", " 5 permit tcp host 10.1.1.1 any", " exit"])
    assert any("come out just before" in note for note in change.notes)


def test_standard_acl_single_addresses_keep_the_devices_order():
    hosts = [Rule(seq=seq, src=Address(HOST, f"192.168.1.{seq // 10}")) for seq in (10, 20, 30)]
    before = Acl("T", V4, STANDARD, hosts + [Rule(seq=40, action=DENY, src=Address(WILDCARD, "192.168.0.0",
                                                                                   "0.0.255.255"))])
    after = before.copy()
    after.rules = [after.rules[2], after.rules[0], after.rules[1], after.rules[3]]  # Hosts reordered: same thing
    assert not acl.acl_change(before, after)
    after.rules = [after.rules[3]] + after.rules[:3]  # The deny over them first: that does change something
    assert acl.acl_change(before, after)


def test_standard_acl_renumbers_the_way_ios_lists_it():
    # IOS lists (and resequences) a standard ACL's single addresses in an order of its own
    before = Acl("T", V4, STANDARD, [Rule(seq=seq, src=Address(HOST, f"192.168.1.{seq}")) for seq in (1, 2, 3)],
                 shown=[1, 3, 2])
    after = before.copy()
    after.rules.insert(1, Rule(src=Address(WILDCARD, "172.16.0.0", "0.0.255.255")))
    change = acl.acl_change(before, after)
    assert change.lines == ["ip access-list resequence T 20 20", "ip access-list standard T",
                            " 30 permit 172.16.0.0 0.0.255.255", " exit"]
    assert "single addresses first" in change.notes[0]
    assert {rule.seq: rule.src.address for rule in change.after.rules if rule.src.kind == HOST} == \
        {20: "192.168.1.1", 40: "192.168.1.3", 60: "192.168.1.2"}


def test_standard_acl_host_under_a_range_waits_for_the_range_to_go():
    before = Acl("T", V4, STANDARD, [Rule(seq=10, src=Address(WILDCARD, "10.0.0.0", "0.255.255.255"))])
    after = before.copy()
    after.rules[0] = Rule(src=Address(HOST, "10.1.1.1"))  # IOS refuses a host under a lower-numbered range
    change = acl.acl_change(before, after)
    assert change.lines == ["ip access-list standard T", " no 10", " 20 permit 10.1.1.1", " exit"]


def test_show_order_is_kept():
    found = acl.merge_show(acl.parse_running("ip access-list standard T\n permit 10.1.1.1\n permit 10.1.1.2\n"),
                           acl.parse_show("Standard IP access list T\n    20 permit 10.1.1.2\n    10 permit 10.1.1.1\n"))
    item = found.acl(V4, "T")
    assert [rule.seq for rule in item.rules] == [10, 20] and item.shown == [20, 10]


def test_ipv6_uses_sequence_words():
    before = device().acl(V6, "V6IN")
    after = before.copy()
    after.rules.pop(0)
    change = acl.acl_change(before, after)
    assert change.lines == ["ipv6 access-list V6IN", " no sequence 20", " exit"]
    assert change.undo == ["ipv6 access-list V6IN", " sequence 20 permit tcp any any eq 22", " exit"]


def test_numbered_acl_is_edited_in_named_mode():
    before = device().acl(V4, "101")
    after = before.copy()
    after.rules.insert(1, Rule(protocol="udp", dst_ports=Ports("eq", [53])))
    change = acl.acl_change(before, after)
    assert change.lines == ["ip access-list extended 101", " 15 permit udp any any eq 53", " exit"]
    assert acl.delete_acl(before).lines == ["no access-list 101"]


def test_create_and_delete():
    made = Acl("NEW", rules=[Rule(protocol="tcp", dst_ports=Ports("eq", [22])), Rule(action=DENY, remark="rest")])
    change = acl.create_acl(made)
    assert change.lines == ["ip access-list extended NEW", " 10 permit tcp any any eq 22", " remark rest",
                            " 20 deny ip any any", " exit"]
    assert change.undo == ["no ip access-list extended NEW"]
    gone = acl.delete_acl(device().acl(V4, "MGMT"))
    assert gone.lines == ["no ip access-list standard MGMT"]
    assert gone.undo[:3] == ["ip access-list standard MGMT", " 10 permit 10.18.0.0 0.0.0.255",
                             " 20 permit 192.168.1.5"]


def test_device_changes_in_a_safe_order():
    before = device()
    after = before.copy()
    after.groups["SRV"].entries.append("host 10.1.1.11")
    after.acls[(V4, "NEW")] = Acl("NEW", rules=[Rule(protocol="tcp", dst=Address(acl.GROUP, group="SRV"))])
    acl.set_applied(after, V4, INTERFACE, "Ethernet0/1", "NEW", "in")
    acl.take_off(after, V4, LINE, "vty 0 4", "MGMT", "in")
    changes = acl.device_changes(before, after)
    text = acl.config_text(changes, revert_minutes=5).splitlines()
    assert text[0] == "configure terminal revert timer 5" and text[-1] == "end"
    order = [text.index(line) for line in ("line vty 0 4", "object-group network SRV", "ip access-list extended NEW",
                                           "interface Ethernet0/1")]
    assert order == sorted(order)  # Off lines first, groups before the ACL naming them, applied last
    assert " no access-class MGMT in" in text and " ip access-group NEW in" in text
    undo = acl.undo_text(changes).splitlines()
    assert " no ip access-group NEW in" in undo and "no ip access-list extended NEW" in undo
    assert " access-class MGMT in" in undo and " no host 10.1.1.11" in undo
    assert acl.device_changes(before, before.copy()) == []


def test_applying_in_place_of_another_puts_it_back_on_undo():
    before = device()
    change = acl.apply_change(before, V4, INTERFACE, "Ethernet0/0", "101", "in")
    assert change.lines == ["interface Ethernet0/0", " ip access-group 101 in", " exit"]
    assert change.undo == ["interface Ethernet0/0", " ip access-group WEB-IN in", " exit"]
    assert "takes the place of WEB-IN" in change.notes[0]


def test_library_rules_are_matched_to_the_device_by_what_they_do():
    before = device().acl(V4, "WEB-IN")
    wanted = before.copy(rules=[rule.copy(seq=seq) for rule, seq in zip(before.rules, (100, 200, 300, 400))])
    wanted.rules.insert(3, Rule(protocol="udp", dst_ports=Ports("eq", [53])))
    aligned = acl.align(before, wanted)
    change = acl.acl_change(before, aligned)
    assert [line.strip() for line in change.lines[1:-1]] == ["35 permit udp any any eq 53"]


def test_store_keeps_library_and_history(tmp_path):
    store = acl.AclStore(tmp_path / "acls.json")
    found = device()
    item = found.acl(V4, "WEB-IN")
    groups, ranges = acl.needed(item, found)
    assert [group.name for group in groups] == ["SRV"] and [entry.name for entry in ranges] == ["WORK"]
    entry = store.add_to_library("Web", acl.library_config(item, groups, ranges))
    store.record("R1", "10.18.0.254", "Change WEB-IN", "configure terminal\nend", "configure terminal\nend", "SSH",
                 "Confirmed")
    again = acl.AclStore(tmp_path / "acls.json")
    again.load()
    assert again.library[0].name == "Web" and again.library[0].id == entry.id
    back = again.library[0].device()
    assert bodies(back.acl(V4, "WEB-IN")) == bodies(item) and "SRV" in back.groups and "WORK" in back.ranges
    assert again.history[0].outcome == "Confirmed"
    assert acl.numbered_kind("10") == STANDARD and acl.numbered_kind("150") == EXTENDED and not acl.numbered_kind("500")
    assert PERMIT == "permit"


def three():
    return Acl("T", rules=[Rule(seq=10, protocol="tcp", dst_ports=Ports("eq", [22])),
                           Rule(seq=20, protocol="udp", dst_ports=Ports("eq", [53])),
                           Rule(seq=30, action=DENY)])


def test_a_number_typed_in_renumbers_the_rule():
    before = three()
    after = before.copy()
    after.rules[1].want_seq = 25
    change = acl.acl_change(before, after)
    # IOS has no renumber: the old one goes (it won't hold the same rule twice), then it's put in at 25
    assert change.lines == ["ip access-list extended T", " no 20", " 25 permit udp any any eq 53", " exit"]
    assert change.undo == ["ip access-list extended T", " no 25", " 20 permit udp any any eq 53", " exit"]
    assert change.numbers == {0: 10, 1: 25, 2: 30}


def test_numbers_typed_in_for_new_rules_and_ones_that_cant_be_had():
    before = three()
    after = before.copy()
    after.rules.insert(1, Rule(protocol="tcp", dst_ports=Ports("eq", [443]), want_seq=12))
    after.rules.insert(2, Rule(protocol="tcp", dst_ports=Ports("eq", [80])))  # Automatic, between 12 and 20
    change = acl.acl_change(before, after)
    assert change.lines == ["ip access-list extended T", " 12 permit tcp any any eq 443",
                            " 16 permit tcp any any eq 80", " exit"]
    taken = before.copy()
    taken.rules.insert(1, Rule(protocol="tcp", dst_ports=Ports("eq", [443]), want_seq=30))  # 30 stays the deny's
    change = acl.acl_change(before, taken)
    assert " 15 permit tcp any any eq 443" in change.lines
    assert any("can't have number 30" in note for note in change.notes)


def test_a_rule_can_take_a_number_another_gives_up():
    before = three()
    after = before.copy()
    after.rules[1] = Rule(protocol="udp", dst_ports=Ports("eq", [123]), want_seq=20)  # Changed, at its own number
    change = acl.acl_change(before, after)
    assert change.lines == ["ip access-list extended T", " no 20", " 20 permit udp any any eq 123", " exit"]


def test_new_acl_keeps_numbers_typed_in():
    made = Acl("NEW", rules=[Rule(protocol="tcp", want_seq=5), Rule(protocol="udp"), Rule(action=DENY, want_seq=100)])
    change = acl.acl_change(None, made)
    assert [line.split()[0] for line in change.lines[1:-1]] == ["5", "10", "100"]
    assert change.numbers == {0: 5, 1: 10, 2: 100}
