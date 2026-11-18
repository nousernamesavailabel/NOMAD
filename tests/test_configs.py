import time

from nomad.configs import apply, diff, fix, noise, pull, standards, text
from nomad.netmap import model

IOS = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:14:22 UTC Tue Nov 17 2026 by jsmith
!
version 17.3
hostname R1
!
interface GigabitEthernet0/1
 description Uplink
 switchport access vlan 10
 shutdown
!
interface GigabitEthernet0/2
 description Spare
!
interface Loopback5
 ip address 5.5.5.5 255.255.255.255
!
ip access-list extended WEB
 10 permit tcp any any eq 80
 20 deny ip any any
!
router bgp 65000
 neighbor 1.1.1.1 remote-as 1
 address-family ipv4
  neighbor 1.1.1.1 activate
 exit-address-family
!
ip route 0.0.0.0 0.0.0.0 1.1.1.1
ip http server
ntp clock-period 17179869
!
end
"""

WANTED = """Building configuration...

Current configuration : 1300 bytes
!
! Last configuration change at 11:00:00 UTC Wed Nov 18 2026 by alice
!
version 17.3
hostname R1
!
interface GigabitEthernet0/1
 description Uplink2
 switchport access vlan 20
 spanning-tree portfast
!
ip access-list extended WEB
 15 permit tcp any any eq 80
 20 permit tcp any any eq 443
 30 deny ip any any
!
router bgp 65000
 neighbor 1.1.1.1 remote-as 1
 address-family ipv4
  neighbor 1.1.1.1 activate
  network 10.0.0.0 mask 255.0.0.0
 exit-address-family
!
ip route 0.0.0.0 0.0.0.0 2.2.2.2
no ip http server
ntp clock-period 17179870
!
end
"""


# ----------------------------------------------------------------- text and noise

def test_parse_keeps_line_numbers_and_modes():
    tree = text.parse(IOS)
    interface = next(node for node in tree if node.line == "interface GigabitEthernet0/1")
    assert IOS.splitlines()[interface.number] == "interface GigabitEthernet0/1"
    assert [child.line for child in interface.children] == ["description Uplink", "switchport access vlan 10",
                                                            "shutdown"]
    assert interface.end == interface.children[-1].number
    bgp = next(node for node in tree if node.line == "router bgp 65000")
    family = bgp.children[1]
    assert family.children[0].path == ["router bgp 65000", "address-family ipv4"]


def test_platform_of_texts():
    assert text.platform_of(IOS) == text.IOS
    assert text.platform_of("!Command: show running-config\n!Time: x\nfeature bgp\n") == text.NXOS
    assert text.platform_of(": Saved\n:\nASA Version 9.16\nhostname fw\n") == text.ASA
    assert text.platform_of('<?xml version="1.0"?>\n<pfsense>\n') == text.PFSENSE
    assert text.hostname_in(IOS) == "R1"
    assert text.hostname_in("<pfsense><system><hostname>fw1</hostname>") == "fw1"


def test_noise_lines_and_fingerprint():
    lines = IOS.splitlines()
    hidden = {lines[number] for number in noise.noise_lines(lines)}
    assert "Building configuration..." in hidden
    assert "Current configuration : 1234 bytes" in hidden
    assert "ntp clock-period 17179869" in hidden
    assert any(line.startswith("! Last configuration change") for line in hidden)
    assert "hostname R1" not in hidden
    changed_noise_only = IOS.replace("1234 bytes", "999 bytes").replace("17179869", "1").replace("jsmith", "bob")
    assert noise.fingerprint(changed_noise_only) == noise.fingerprint(IOS)
    assert noise.fingerprint(IOS.replace("Uplink", "Down")) != noise.fingerprint(IOS)


def test_certificate_data_is_noise_but_short_numbers_are_not():
    config = ["crypto pki certificate chain TP", " certificate ca 01", "  30820322 3082020A A0030201 02020101",
              "  0D06092A 864886F7", "  \tquit", "line vty 0 4", " 10 20"]
    hidden = noise.noise_lines(config)
    assert {2, 3, 4} <= hidden
    assert 6 not in hidden


# ----------------------------------------------------------------- comparing

def test_plain_comparison_rows_line_up_and_hunks_cover_changes():
    result = diff.compare("a\nb\nc\nd", "a\nB\nc\nd\ne", diff.PLAIN)
    assert [(hunk.kind, hunk.a_start, hunk.a_end, hunk.b_start, hunk.b_end) for hunk in result.hunks] == \
        [(diff.CHANGED, 1, 2, 1, 2), (diff.ADDED, 4, 4, 4, 5)]
    assert result.counts() == (2, 1)
    assert [(row.a, row.b) for row in result.rows] == [(0, 0), (1, 1), (2, 2), (3, 3), (None, 4)]


def test_noise_mode_hides_timestamps():
    plain = diff.compare(IOS, IOS.replace("1234", "4321"), diff.PLAIN)
    assert not plain.same
    quiet = diff.compare(IOS, IOS.replace("1234", "4321"), diff.NOISE)
    assert quiet.same
    assert any(row.tag == diff.HIDDEN for row in quiet.rows)


def test_section_mode_moved_block_and_paths():
    a = "hostname R1\ninterface Gi0/1\n description A\n switchport access vlan 10\ninterface Gi0/2\n shutdown\n"
    b = "hostname R1\ninterface Gi0/2\n shutdown\ninterface Gi0/1\n description B\n switchport access vlan 20\n"
    result = diff.compare(a, b, diff.SECTION)
    kinds = sorted((hunk.kind, hunk.path) for hunk in result.hunks)
    assert (diff.MOVED, "") in kinds
    assert kinds.count((diff.CHANGED, "interface Gi0/1")) == 2  # description slot, and the VLAN (last word)
    assert result.summary().startswith("2 changes")
    plain = diff.compare(a, b, diff.PLAIN)
    assert len(plain.changes) > len(result.changes) - 1


def test_take_copies_a_hunk_across():
    result = diff.compare("a\nb\nc", "a\nX\nc", diff.PLAIN)
    [hunk] = result.hunks
    assert diff.take(hunk, result.a_lines, result.b_lines, to_b=True) == ["a", "b", "c"]
    assert diff.take(hunk, result.a_lines, result.b_lines, to_b=False) == ["a", "X", "c"]


def test_inline_lists_both_sides():
    result = diff.compare("a\nb", "a\nc", diff.PLAIN)
    assert [(tag, line) for tag, _, _, line in result.inline()] == [(diff.EQUAL, "a"), (diff.DELETE, "b"),
                                                                    (diff.INSERT, "c")]


def test_large_configs_compare_quickly():
    big = []
    for number in range(6000):
        big += [f"interface Gi1/0/{number}", f" description port {number}", " switchport access vlan 10", "!"]
    other = list(big)
    other[12001] = " description changed"
    del other[400:404]
    started = time.monotonic()
    for mode in (diff.PLAIN, diff.NOISE, diff.SECTION):
        assert not diff.compare(big, other, mode).same
    assert time.monotonic() - started < 10


# ----------------------------------------------------------------- fix commands and what they'd do

def test_fix_commands_take_current_to_wanted():
    lines = fix.fix_commands(IOS, WANTED)
    config = fix.as_config(lines)
    assert config.startswith("configure terminal\n") and config.endswith("end")
    assert "interface GigabitEthernet0/1\n no switchport access vlan 10\n no shutdown" in config
    assert " description Uplink2" in config
    assert "no interface Loopback5" in config
    assert "no interface GigabitEthernet0/2" not in config  # A physical port is emptied, never removed
    assert "interface GigabitEthernet0/2\n no description Spare" in config
    assert " no 10\n 20 permit tcp any any eq 443" not in config  # Removals first...
    assert " no 10\n no 20\n 15 permit tcp any any eq 80\n 20 permit tcp any any eq 443\n 30 deny ip any any" in config
    assert "  network 10.0.0.0 mask 255.0.0.0\n exit-address-family\nexit" in config
    assert "no ip route 0.0.0.0 0.0.0.0 1.1.1.1" in config and "ip route 0.0.0.0 0.0.0.0 2.2.2.2" in config
    assert config.count("no ip http server") == 1
    assert "version" not in config and "ntp clock-period" not in config


def test_fix_then_simulate_reaches_wanted():
    before, after = apply.simulate(IOS, fix.as_config(fix.fix_commands(IOS, WANTED)))
    result = diff.compare(after, WANTED, diff.SECTION)
    leftover = [(hunk.kind, result.a_lines[hunk.a_start:hunk.a_end]) for hunk in result.changes]
    assert leftover == [(diff.REMOVED, ["interface GigabitEthernet0/2"])]  # Emptied, still there


def test_simulate_handles_no_lines_and_slots():
    running = "hostname R1\n!\ninterface Gi0/1\n description A\n shutdown\n!\nip http server\n"
    before, after = apply.simulate(running, "configure terminal\ninterface Gi0/1\n description B\n no shutdown\n"
                                            "exit\nno ip http server\nend")
    assert " description B" in after and " description A" not in after
    assert " shutdown" not in after
    assert "no ip http server" in after and "\nip http server" not in after
    assert "interface Gi0/1" in before


def test_simulate_unindented_commands():
    running = "hostname R1\ninterface Gi0/1\n description A\n"
    _, after = apply.simulate(running, "interface Gi0/1\ndescription B\nip route 0.0.0.0 0.0.0.0 1.1.1.1\n")
    assert "interface Gi0/1\n description B" in after
    assert "\nip route 0.0.0.0 0.0.0.0 1.1.1.1" in after


# ----------------------------------------------------------------- standards

STANDARD = r"""! STANDARD: Access baseline
! applies-to: kind=switch group=Main Campus name=^SW-
hostname {{hostname}}
ntp server 10.1.0.10
ntp server 10.1.0.11
no ip http server
~ ^snmp-server community \S+ RO \S+$
line vty 0 4
 transport input ssh
 ~ ^access-class \S+ in$
~ ^interface GigabitEthernet1/0/
 spanning-tree portfast
logging host {{site}}
"""

SWITCH = """hostname SW-B2-03
ntp server 10.1.0.10
ip http server
snmp-server community public RO 10
interface GigabitEthernet1/0/1
 spanning-tree portfast
interface GigabitEthernet1/0/2
 description x
line vty 0 4
 transport input telnet ssh
 access-class MGMT in
"""
FACTS = {"hostname": "SW-B2-03", "kind": "switch", "groups": ["Main Campus", "B2"], "site": "Main Campus"}


def test_standard_parses_header_and_rules():
    standard = standards.parse(STANDARD)
    assert standard.name == "Access baseline"
    assert standard.applies_to == {"kind": ["switch"], "group": "Main Campus", "name": "^SW-"}
    assert standards.is_standard(STANDARD) and not standards.is_standard(SWITCH)
    kinds = [rule.kind for rule in standard.rules]
    assert kinds.count(standards.PATTERN) == 2 and standards.NEGATED in kinds


def test_standard_applies_by_kind_group_and_name():
    standard = standards.parse(STANDARD)
    assert standards.applies(standard, FACTS)
    assert not standards.applies(standard, dict(FACTS, kind="router"))
    assert not standards.applies(standard, dict(FACTS, groups=["Annex"]))
    assert not standards.applies(standard, dict(FACTS, hostname="R1"))
    assert standards.applies(standards.parse("hostname x"), {})


def test_standard_check_results():
    results = standards.check(standards.parse(STANDARD), SWITCH, FACTS)
    found = {(result.status, result.where, result.rule) for result in results}
    assert (standards.PASS, "", "hostname SW-B2-03") in found
    assert (standards.MISSING, "", "ntp server 10.1.0.11") in found
    assert (standards.FORBIDDEN, "", "no ip http server") in found
    assert (standards.DIFFERENT, "line vty 0 4", "transport input ssh") in found
    assert (standards.PASS, "interface GigabitEthernet1/0/1", "spanning-tree portfast") in found
    assert (standards.MISSING, "interface GigabitEthernet1/0/2", "spanning-tree portfast") in found
    assert (standards.MISSING, "", "logging host Main Campus") in found
    config = fix.as_config(standards.fix_lines(results))
    assert "ntp server 10.1.0.11" in config and "no ip http server" in config
    assert "line vty 0 4\n transport input ssh\nexit" in config
    assert "~" not in config


def test_negated_rule_passes_when_shown_as_no():
    results = standards.check(standards.parse("no ip http server"), "no ip http server\n", {})
    assert [result.status for result in results] == [standards.PASS]


def test_unknown_variable_is_a_problem():
    results = standards.check(standards.parse("snmp-server location {{nowhere}}"), "hostname x", {})
    assert results[0].status == standards.PROBLEM


def test_device_facts_from_map():
    network_map = model.NetworkMap()
    device = model.Device("d1", name="SW1", mgmt_ip="10.0.0.2", kind=model.SWITCH, sys_descr="Cisco IOS Software")
    network_map.devices["d1"] = device
    network_map.groups = [model.Group("g1", "Main Campus", model.SITE), model.Group("g2", "B2", model.BUILDING, "g1")]
    network_map.group_of["d1"] = "g2"
    facts = standards.device_facts(network_map, device)
    assert facts["site"] == "Main Campus" and facts["building"] == "B2"
    assert facts["groups"] == ["Main Campus", "B2"]
    assert facts["platform"] == text.IOS


# ----------------------------------------------------------------- pulling

class FakeShell:
    def __init__(self, answers):
        self.answers = answers
        self.ran = []

    def run(self, command, timeout=30):
        self.ran.append(command)
        return self.answers.get(command, "% Invalid input detected at '^' marker.")


class FakePusher:
    def __init__(self, shell):
        self.the_shell = shell
        self.problems, self.login_labels = {}, {}
        self.forgotten = []

    def shell(self, address, names=()):
        self.login_labels[address] = "saved session R1"
        if self.the_shell is None:
            self.problems[address] = "Authentication failed."
        return self.the_shell

    def forget(self, address):
        self.forgotten.append(address)

    def close(self):
        pass


def test_pull_running_and_startup_with_who_changed():
    shell = FakeShell({"show running-config": IOS, "show startup-config": IOS.replace("Uplink", "Old")})
    pusher = FakePusher(shell)
    result = pull.pull_device(pusher, "10.0.0.1", platform=text.IOS, which=(pull.RUNNING, pull.STARTUP))
    assert result.ok and set(result.texts) == {pull.RUNNING, pull.STARTUP}
    assert result.changed_by == "jsmith"
    assert result.login == "saved session R1"
    assert pusher.forgotten == ["10.0.0.1"]
    assert "show archive log config all" not in shell.ran


def test_pull_asks_archive_log_when_no_user():
    running = IOS.replace(" by jsmith", "")
    log = ("idx   sess           user@line      Logged command\n"
           "    1     1        console@console  |  logging enable\n"
           "    2     2        bob@vty0         |  hostname R1\n")
    shell = FakeShell({"show running-config": running, "show archive log config all": log})
    result = pull.pull_device(FakePusher(shell), "10.0.0.1", platform="")
    assert result.platform == text.IOS
    assert result.changed_by == "bob"


def test_pull_reports_problems():
    assert "Authentication failed" in pull.pull_device(FakePusher(None), "10.0.0.1").problem
    refused = pull.pull_device(FakePusher(FakeShell({})), "10.0.0.1", platform=text.IOS)
    assert not refused.ok and "wouldn't show" in refused.problem


def test_pull_aruba_turns_paging_off():
    shell = FakeShell({"no paging": "", "show running-config": "version 8.10\nhostname wlc\nap-group x\n"})
    result = pull.pull_device(FakePusher(shell), "10.0.0.9", platform=text.ARUBA,
                              which=(pull.RUNNING, pull.STARTUP))
    assert shell.ran[0] == "no paging" and "show startup-config" not in shell.ran
    assert result.ok
