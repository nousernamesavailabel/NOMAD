"""What an ACL does to a packet, rules that never match, mistakes IOS takes quietly, and the lockout check."""
import datetime

from nomad.netmap import acl, aclcheck
from nomad.netmap.acl import EXTENDED, STANDARD, V4, V6, Acl
from nomad.netmap.aclcheck import ICMPV6, Packet, TCP, UDP
from nomad.netmap.vlans import ERROR, INFO, WARNING


def make(lines, family=V4, kind=EXTENDED, name="T"):
    item = Acl(name, family, kind)
    acl.fill_rules(item, [line.strip() for line in lines.strip().splitlines()])
    for index, rule in enumerate(item.rules):
        rule.seq = 10 * (index + 1)
    return item


def texts(found, severity=None):
    return [item.text for item in found if severity is None or item.severity == severity]


def test_first_match_wins_with_wildcards_ports_and_the_implicit_deny():
    item = make("""
        permit tcp any host 10.1.1.10 eq 80 443
        deny ip 10.0.0.0 0.255.255.255 any
        permit udp any any range 1000 2000
    """)
    verdict = aclcheck.evaluate(item, Packet("192.168.1.1", "10.1.1.10", TCP, dst_port=443, flags={"syn"}))
    assert verdict.permitted and verdict.rule.seq == 10
    verdict = aclcheck.evaluate(item, Packet("10.9.9.9", "8.8.8.8", UDP, dst_port=1500))
    assert not verdict.permitted and verdict.rule.seq == 20
    assert aclcheck.evaluate(item, Packet("192.168.1.1", "8.8.8.8", UDP, dst_port=1500)).rule.seq == 30
    verdict = aclcheck.evaluate(item, Packet("192.168.1.1", "8.8.8.8", UDP, dst_port=53))
    assert not verdict.permitted and verdict.rule is None and "implicit deny" in verdict.text
    assert aclcheck.evaluate(Acl("EMPTY"), Packet("1.1.1.1", "2.2.2.2")).permitted


def test_non_contiguous_wildcard():
    item = make("permit ip 10.0.0.5 0.255.0.0 any")  # 10.x.0.5
    assert aclcheck.evaluate(item, Packet("10.77.0.5", "1.1.1.1")).permitted
    assert not aclcheck.evaluate(item, Packet("10.77.1.5", "1.1.1.1")).permitted


def test_established_icmp_and_fragments():
    item = make("""
        permit tcp any any established
        permit icmp any any echo-reply
        deny ip any any fragments
        permit ip any any
    """)
    assert aclcheck.evaluate(item, Packet("1.1.1.1", "2.2.2.2", TCP, dst_port=22, flags={"ack"})).rule.seq == 10
    assert aclcheck.evaluate(item, Packet("1.1.1.1", "2.2.2.2", TCP, dst_port=22, flags={"syn"})).rule.seq == 40
    assert aclcheck.evaluate(item, Packet("1.1.1.1", "2.2.2.2", 1, icmp_type=0, icmp_code=0)).rule.seq == 20
    assert aclcheck.evaluate(item, Packet("1.1.1.1", "2.2.2.2", 17, dst_port=9, fragment=True)).rule.seq == 30


def test_object_groups_and_time_ranges():
    found = acl.parse_running("""ip access-list extended T
 permit object-group WEB object-group SRV any time-range WORK
object-group network SRV
 host 10.1.1.10
 10.1.2.0 255.255.255.0
 range 10.1.3.1 10.1.3.20
object-group service WEB
 tcp eq www
 tcp-udp eq domain
time-range WORK
 periodic weekdays 8:00 to 17:00
""")
    item = found.acl(V4, "T")
    monday_noon = datetime.datetime(2026, 10, 12, 12, 0)
    saturday = datetime.datetime(2026, 10, 10, 12, 0)

    def check(src, protocol, port, when=monday_noon):
        packet = Packet(src, "8.8.8.8", protocol, dst_port=port, when=when)
        return aclcheck.evaluate(item, packet, found.groups, found.ranges).permitted
    assert check("10.1.2.77", TCP, 80) and check("10.1.3.5", UDP, 53) and check("10.1.1.10", TCP, 53)
    assert not check("10.1.3.21", TCP, 80) and not check("10.1.2.77", TCP, 443)
    assert not check("10.1.2.77", TCP, 80, saturday)


def test_time_range_windows():
    weekdays = acl.TimeRange("W", ["periodic weekdays 8:00 to 17:00"])
    assert aclcheck.time_range_active(weekdays, datetime.datetime(2026, 10, 12, 8, 0))
    assert not aclcheck.time_range_active(weekdays, datetime.datetime(2026, 10, 12, 17, 1))
    overnight = acl.TimeRange("N", ["periodic friday 22:00 to monday 6:00"])
    assert aclcheck.time_range_active(overnight, datetime.datetime(2026, 10, 11, 3, 0))  # Sunday
    assert not aclcheck.time_range_active(overnight, datetime.datetime(2026, 10, 14, 3, 0))  # Wednesday
    absolute = acl.TimeRange("A", ["absolute start 00:00 1 October 2026 end 23:59 31 October 2026"])
    assert aclcheck.time_range_active(absolute, datetime.datetime(2026, 10, 12))
    assert not aclcheck.time_range_active(absolute, datetime.datetime(2026, 11, 1))


def test_ipv6_neighbor_discovery_is_permitted_before_the_implicit_deny_only():
    item = make("permit tcp any any eq 22", V6)
    packet = Packet("fe80::1", "fe80::2", ICMPV6, icmp_type=135)
    assert aclcheck.evaluate(item, packet).permitted
    killer = make("permit tcp any any eq 22\ndeny ipv6 any any", V6)
    assert not aclcheck.evaluate(killer, packet).permitted
    assert any("neighbor discovery" in text for text in texts(aclcheck.findings(killer), WARNING))
    fixed = make("permit icmp any any nd-ns\npermit icmp any any nd-na\ndeny ipv6 any any", V6)
    assert not any("neighbor discovery" in text for text in texts(aclcheck.findings(fixed)))


def test_shadowed_redundant_and_duplicate_rules():
    item = make("""
        permit tcp any 10.1.1.0 0.0.0.255 eq 80
        deny ip 10.0.0.0 0.255.255.255 any
        permit tcp 10.2.0.0 0.0.255.255 any eq 22
        permit tcp any host 10.1.1.10 eq 80
        permit tcp any 10.1.1.0 0.0.0.255 eq 80
    """)
    found = aclcheck.findings(item)
    warnings = texts(found, WARNING)
    assert "Rule 30 never matches: rule 20 (a deny) takes everything it would." in warnings
    assert "Rule 50 is the same as rule 10, so it never matches anything (IOS keeps only one of them)." in warnings
    assert "Rule 40 isn't needed: rule 10 already permits all of it." in texts(found, INFO)
    assert [item.index for item in found if item.severity == WARNING] == [2, 4]


def test_a_rule_made_unneeded_by_a_later_one():
    item = make("permit tcp any host 10.1.1.10 eq 80\npermit tcp any 10.1.1.0 0.0.0.255 eq 80")
    assert texts(aclcheck.findings(item), INFO) == [
        "Rule 10 isn't needed: rule 20, further down, permits all of it too."]
    blocked = make("permit tcp any host 10.1.1.10 eq 80\ndeny tcp any host 10.1.1.10\n"
                   "permit tcp any 10.1.1.0 0.0.0.255 eq 80")
    assert not any("isn't needed" in text for text in texts(aclcheck.findings(blocked)))


def test_masks_written_as_wildcards_and_bits_under_them():
    item = make("permit ip any 10.1.1.0 255.255.255.0\npermit ip 10.1.1.5 0.0.0.255 any")
    found = aclcheck.findings(item)
    assert any("looks like a subnet mask (a /24 is written 0.0.0.255" in text for text in texts(found, ERROR))
    assert any("IOS keeps it as 10.1.1.0 0.0.0.255" in text for text in texts(found, WARNING))


def test_missing_groups_ports_without_tcp_and_new_rules_named_by_line():
    item = make("permit ip any object-group NOPE\npermit tcp any any eq 22 time-range LATER")
    item.rules.append(acl.Rule(protocol="icmp", dst_ports=acl.Ports("eq", [80])))
    found = aclcheck.findings(item)
    errors = texts(found, ERROR)
    assert any("object group NOPE" in text for text in errors)
    assert "The new rule on line 3 names ports, but only tcp and udp have them." in errors
    assert any("time range LATER" in text for text in texts(found, WARNING))


def test_everything_denied_and_unused_rules():
    item = make("deny ip host 1.1.1.1 any\ndeny ip any any")
    assert any("lets nothing through" in text for text in texts(aclcheck.findings(item)))
    counted = make("permit ip host 1.1.1.1 any\npermit ip host 2.2.2.2 any")
    counted.rules[0].hits, counted.rules[1].hits = 5, 0
    assert any("haven't matched anything" in text and "20" in text for text in texts(aclcheck.findings(counted)))


def test_standard_acl():
    item = make("permit 10.18.0.0 0.0.0.255\ndeny any", kind=STANDARD)
    assert aclcheck.evaluate(item, Packet("10.18.0.9", "1.1.1.1")).permitted
    assert not aclcheck.evaluate(item, Packet("10.19.0.9", "1.1.1.1")).permitted


def test_standard_acl_host_under_a_range_is_refused_by_ios():
    item = make("deny 10.0.0.0 0.255.255.255\npermit 10.1.1.1\npermit 10.2.0.0 0.0.255.255", kind=STANDARD)
    found = aclcheck.findings(item)
    assert any("can't go in" in text and "Rule 20" in text for text in texts(found, ERROR))
    assert not any("Rule 30" in text for text in texts(found, ERROR))  # A range under a range: IOS takes it
    item.shown = [20, 10, 30]
    assert any("in an order of its own" in text for text in texts(aclcheck.findings(item), INFO))


# --------------------------------------------------------------------- Locking yourself out

DEVICE = """ip access-list standard MGMT
 permit 10.18.0.0 0.0.0.255
ip access-list extended EDGE
 permit tcp 10.18.0.0 0.0.0.255 host 10.18.0.254 eq 22
 deny ip any any
interface Ethernet0/0
 ip address 10.18.0.254 255.255.255.0
 ip access-group EDGE in
interface Ethernet0/1
 ip address 10.1.1.1 255.255.255.0
line vty 0 4
 access-class MGMT in
line vty 5 15
 transport input ssh
"""


def test_lockout_from_vty_lines_and_the_interface_in():
    device = acl.parse_running(DEVICE)
    fine = aclcheck.lockout(device, "10.18.0.5", "10.18.0.254")
    assert [item.severity for item in fine] == [INFO] and "can still log in" in fine[0].text
    outside = aclcheck.lockout(device, "192.168.5.5", "10.18.0.254")
    assert [item.severity for item in outside] == [WARNING, ERROR]  # vty 0 4 refuses (5 15 doesn't), EDGE drops
    assert "vty 5 15" in outside[0].text and "EDGE in would drop" in outside[1].text
    device.lines.pop("vty 5 15")
    outside = aclcheck.lockout(device, "192.168.5.5", "10.18.0.254")
    assert [item.severity for item in outside] == [ERROR, ERROR] and "access-class MGMT" in outside[0].text
    acl.set_applied(device, V4, acl.LINE, "vty 0 4", "NOPE", "in")  # An ACL that isn't there lets everyone in
    device.toward_pc = "Ethernet0/0"
    errors = [item for item in aclcheck.lockout(device, "192.168.5.5", "10.18.0.254") if item.severity == ERROR]
    assert len(errors) == 1 and "EDGE in would drop" in errors[0].text


def test_lockout_follows_the_edited_copy():
    device = acl.parse_running(DEVICE)
    device.lines.pop("vty 5 15")
    edited = device.copy()
    edited.acl(V4, "EDGE").rules.insert(0, acl.parse_rule("deny tcp any any eq 22", V4, EXTENDED))
    errors = [item for item in aclcheck.lockout(edited, "10.18.0.5", "10.18.0.254") if item.severity == ERROR]
    assert errors and "new rule on line 1" in errors[0].text.lower()


def test_packet_from_what_is_typed():
    packet = aclcheck.packet_from_text("10.1.1.1", "10.2.2.2", "tcp", "", "www")
    assert packet.dst_port == 80 and packet.flags == {"syn"}
    packet = aclcheck.packet_from_text("10.1.1.1", "10.2.2.2", "icmp", icmp="echo")
    assert (packet.icmp_type, packet.icmp_code) == (8, 0)
    packet = aclcheck.packet_from_text("2001:db8::1", "2001:db8::2", "icmp", icmp="nd-na")
    assert packet.protocol == ICMPV6 and packet.icmp_type == 136
    for bad in (("10.1.1.1", "2001:db8::2", "ip"), ("10.1.1.1", "10.2.2.2", "tcp"), ("x", "10.2.2.2", "ip")):
        try:
            aclcheck.packet_from_text(*bad)
        except ValueError:
            continue
        raise AssertionError(bad)
