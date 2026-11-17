from nomad.configtext import family, separated, separated_text


def test_blocks_get_separators_like_a_running_config():
    lines = ["configure terminal",
             "crypto ikev2 proposal P", " encryption aes-gcm-256",
             "crypto ikev2 keyring K", " peer A", "  address 1.1.1.1",
             "interface Tunnel10", " ip address 10.0.0.1 255.255.255.252",
             "ip route 10.1.0.0 255.255.0.0 Tunnel10", "ip route 10.2.0.0 255.255.0.0 Tunnel10",
             "end"]
    assert separated(lines) == ["configure terminal",
                                "crypto ikev2 proposal P", " encryption aes-gcm-256", "!",
                                "crypto ikev2 keyring K", " peer A", "  address 1.1.1.1", "!",
                                "interface Tunnel10", " ip address 10.0.0.1 255.255.255.252", "!",
                                "ip route 10.1.0.0 255.255.0.0 Tunnel10", "ip route 10.2.0.0 255.255.0.0 Tunnel10",
                                "end"]


def test_runs_of_one_sort_stay_together():
    lines = ["configure terminal", "no crypto ikev2 profile X", "no crypto ikev2 keyring Y",
             "do clear crypto session remote 1.1.1.1", "logging host 10.0.0.5", "logging trap notifications", "end"]
    assert separated(lines) == ["configure terminal", "no crypto ikev2 profile X", "no crypto ikev2 keyring Y", "!",
                                "do clear crypto session remote 1.1.1.1", "!", "logging host 10.0.0.5",
                                "logging trap notifications", "end"]
    assert family("no ip route 1.0.0.0 255.0.0.0 2.2.2.2") == ("ip", "route")
    assert family("snmp-server community x RO") == ("snmp-server",)


def test_exit_closes_a_block_and_end_follows_it():
    lines = ["configure terminal", "vlan 20", " name X", " exit", "interface Gi0/1", " shutdown", "exit", "end",
             "write memory"]
    assert separated(lines) == ["configure terminal", "vlan 20", " name X", " exit", "!", "interface Gi0/1",
                                " shutdown", "exit", "!", "end", "write memory"]


def test_short_changes_and_comments_stay_plain():
    assert separated_text("configure terminal\nno ip sla 5\nend") == "configure terminal\nno ip sla 5\nend"
    lines = ["! Replace before pasting:", "!   <A-WAN-IP>  this router's address", "configure terminal",
             "! Who may read SNMP", "ip access-list standard A", " permit any", "exit", "! Traps", "snmp-server x",
             "end"]
    assert separated(lines) == ["! Replace before pasting:", "!   <A-WAN-IP>  this router's address",
                                "configure terminal", "! Who may read SNMP", "ip access-list standard A",
                                " permit any", "exit", "!", "! Traps", "snmp-server x", "end"]


def test_already_separated_text_comes_back_the_same():
    text = separated_text("configure terminal\ninterface Gi0/1\n shutdown\ninterface Gi0/2\n shutdown\nend")
    assert text == "configure terminal\ninterface Gi0/1\n shutdown\n!\ninterface Gi0/2\n shutdown\n!\nend"
    assert separated_text(text) == text
