import datetime
from dataclasses import replace

import pytest

from nomad.snmpv3 import V3User
from nomad.switchconfig import ConfigOptions, build, problems, undo

NOW = datetime.datetime(2026, 10, 2, 14, 30)
USER = V3User("nomad", "sha", "authpass1", "aes128", "privpass1")


def options(**changes):
    base = ConfigOptions(community="n0mad-RO", permit=["10.0.0.50", "10.20.0.0/24"], destinations=["10.0.0.50"],
                         access_ports="Gi1/0/1 - 48")
    return replace(base, **changes)


def test_v2c_block():
    assert build(options(), NOW) == [
        "configure terminal",
        "! Set up for NOMAD monitoring (2026-10-02 14:30)",
        "! Who may read SNMP",
        "ip access-list standard NOMAD-SNMP",
        " permit host 10.0.0.50",
        " permit 10.20.0.0 0.0.0.255",
        "exit",
        "snmp-server community n0mad-RO RO NOMAD-SNMP",
        "snmp-server ifindex persist",
        "! Traps to the computers watching",
        "snmp-server enable traps snmp linkdown linkup coldstart warmstart",
        "snmp-server enable traps mac-notification change move",
        "mac address-table notification change",
        "snmp-server host 10.0.0.50 version 2c n0mad-RO",
        "! Syslog to the computers watching",
        "logging host 10.0.0.50",
        "logging trap notifications",
        "! Neighbor discovery, for the map's crawls",
        "cdp run",
        "lldp run",
        "! Access ports: say when something is plugged in",
        "interface range Gi1/0/1 - 48",
        " logging event link-status",
        " logging event power-inline-status",
        " snmp trap link-status",
        " snmp trap mac-notification change added",
        "exit",
        "end",
    ]


def test_v3_block_with_vlan_contexts_and_v3_traps():
    lines = build(options(community="", v3_user=USER, trap_version="v3", source_interface="Vlan10",
                          location="HQ IDF 2", write_memory=True), NOW)
    assert "snmp-server view NOMAD-VIEW iso included" in lines
    assert "snmp-server group NOMAD v3 priv read NOMAD-VIEW access NOMAD-SNMP" in lines
    assert ("snmp-server group NOMAD v3 priv context vlan- match prefix read NOMAD-VIEW access NOMAD-SNMP"
            in lines)
    assert "snmp-server user nomad NOMAD v3 auth sha authpass1 priv aes 128 privpass1 access NOMAD-SNMP" in lines
    assert "snmp-server host 10.0.0.50 version 3 priv nomad" in lines
    assert not any(line.startswith("snmp-server community") for line in lines)
    assert "snmp-server trap-source Vlan10" in lines and "logging source-interface Vlan10" in lines
    assert "snmp-server location HQ IDF 2" in lines
    assert lines[-2:] == ["end", "write memory"]


@pytest.mark.parametrize("user, expected", [
    (V3User("u1", "sha256", "authpass1", "aes256", "privpass1"),
     "snmp-server user u1 NOMAD v3 auth sha-2 256 authpass1 priv aes 256 privpass1 access NOMAD-SNMP"),
    (V3User("u2", "md5", "authpass1", "none"), "snmp-server user u2 NOMAD v3 auth md5 authpass1 access NOMAD-SNMP"),
    (V3User("u3", "none", "", "none"), "snmp-server user u3 NOMAD v3 access NOMAD-SNMP"),
])
def test_v3_user_lines_follow_the_level(user, expected):
    lines = build(options(v3_user=user), NOW)
    assert expected in lines
    level = {"authPriv": "priv", "authNoPriv": "auth", "noAuthNoPriv": "noauth"}[user.level]
    assert f"snmp-server group NOMAD v3 {level} read NOMAD-VIEW access NOMAD-SNMP" in lines


def test_sections_can_be_left_out():
    lines = build(options(access=False, traps=False, cdp=False, lldp=False, access_ports=""), NOW)
    assert lines[2:] == ["! Syslog to the computers watching", "logging host 10.0.0.50", "logging trap notifications",
                         "end"]
    lines = build(options(syslog=False, trap_categories=["snmp", "config"]), NOW)
    assert "snmp-server enable traps config" in lines and "mac address-table notification change" not in lines
    assert " snmp trap mac-notification change added" not in lines and " logging event link-status" not in lines


def test_undo_takes_out_what_was_added():
    lines = undo(options(v3_user=USER, source_interface="Vlan10"))
    assert lines[0] == "configure terminal" and lines[-1] == "end"
    for expected in ("no snmp-server community n0mad-RO", "no snmp-server user nomad NOMAD v3",
                     "no snmp-server group NOMAD v3 priv", "no snmp-server view NOMAD-VIEW iso",
                     "no ip access-list standard NOMAD-SNMP", "no snmp-server host 10.0.0.50 version 2c n0mad-RO",
                     "no logging host 10.0.0.50", "no snmp-server enable traps mac-notification change move",
                     " no snmp trap mac-notification change added", "no snmp-server trap-source"):
        assert expected in lines
    assert "no cdp run" not in lines and "no lldp run" not in lines


@pytest.mark.parametrize("changes, message", [
    ({"community": "", "v3_user": None}, "community string or an SNMPv3 user"),
    ({"community": "has space"}, "spaces"),
    ({"community": "x@y"}, "Leave @ out"),
    ({"permit": []}, "allowed to read"),
    ({"permit": ["10.0.0.300"]}, "isn't an IPv4 address or subnet"),
    ({"destinations": []}, "where traps and syslog"),
    ({"destinations": ["watcher.local"]}, "isn't an IPv4 address"),
    ({"acl": "two words"}, "access list name"),
    ({"access_ports": "every port"}, "isn't an interface range"),
    ({"source_interface": "Vlan 10 x"}, "isn't an interface name"),
    ({"trap_version": "v3"}, "need the SNMPv3 user"),
    ({"v3_user": V3User("u", "sha224", "authpass1", "none")}, "SHA-224"),
    ({"v3_user": V3User("u", "sha", "short", "none")}, "at least 8"),
    ({"v3_user": V3User("u", "sha", "auth pass1", "none")}, "spaces"),
    ({"trap_categories": []}, "which traps"),
    ({"location": "what?"}, "location"),
])
def test_problems(changes, message):
    found = problems(options(**changes))
    assert any(message in problem for problem in found), found
    with pytest.raises(ValueError):
        build(options(**changes))


def test_valid_options_have_no_problems():
    assert problems(options()) == []
    assert problems(options(access_ports="Gi1/0/1-24, Gi2/0/1 - 24", source_interface="Loopback0")) == []


def test_poe_logging_can_be_left_out():
    assert " logging event power-inline-status" in build(options(), NOW)
    lines = build(options(poe=False), NOW)
    assert " logging event power-inline-status" not in lines and " logging event link-status" in lines


def test_more_communities_and_users_can_read():
    """Such as the rest of a map's credentials: each user's security level gets its group, traps go with the first."""
    auth_only = V3User("branch", "sha256", "authpass2", "none")
    lines = build(options(v3_user=USER, more_communities=["branch-ro", "n0mad-RO"], more_users=[auth_only]), NOW)
    assert [line for line in lines if line.startswith("snmp-server community")] == [
        "snmp-server community n0mad-RO RO NOMAD-SNMP", "snmp-server community branch-ro RO NOMAD-SNMP"]
    assert lines.count("snmp-server view NOMAD-VIEW iso included") == 1
    for level in ("priv", "auth"):
        assert f"snmp-server group NOMAD v3 {level} read NOMAD-VIEW access NOMAD-SNMP" in lines
        assert f"snmp-server group NOMAD v3 {level} context vlan- match prefix read NOMAD-VIEW access NOMAD-SNMP" \
            in lines
    assert "snmp-server user branch NOMAD v3 auth sha-2 256 authpass2 access NOMAD-SNMP" in lines
    assert [line for line in lines if line.startswith("snmp-server host")] == [
        "snmp-server host 10.0.0.50 version 2c n0mad-RO"]
    taken_out = undo(options(v3_user=USER, more_communities=["branch-ro"], more_users=[auth_only]))
    for expected in ("no snmp-server community branch-ro", "no snmp-server user branch NOMAD v3",
                     "no snmp-server group NOMAD v3 auth", "no snmp-server group NOMAD v3 priv"):
        assert expected in taken_out
    assert taken_out.count("no snmp-server view NOMAD-VIEW iso") == 1


def test_more_credentials_are_checked_too():
    assert problems(options(community="", more_communities=["branch-ro"], traps=False)) == []
    assert any("community string x@y" in problem for problem in problems(options(more_communities=["x@y"])))
    twin = V3User("nomad", "md5", "authpass2", "none")
    assert any("two SNMPv3 users named nomad" in problem
               for problem in problems(options(v3_user=USER, more_users=[twin])))
    assert any("SHA-224" in problem
               for problem in problems(options(more_users=[V3User("u", "sha224", "authpass1", "none")])))
